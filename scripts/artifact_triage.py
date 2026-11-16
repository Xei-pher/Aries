from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

from common import case_dir, load_case, now_iso
from records import add_lead, context_matches, enforce_material_lead_budget

WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\[^\r\n|\"']+")
UNC_RE = re.compile(r"\\\\[^\\\s|\"']+\\[^\s|\"']+")
FILE_RE = re.compile(r"(?<![\w.-])[^\\/:*?\"<>|\r\n]+\.(?:exe|dll|sys|ps1|bat|cmd|js|vbs|msi|zip|7z|rar|lnk|pf)(?![\w.-])", re.IGNORECASE)
TIME_RE = re.compile(r"\b(20\d\d[-/]\d\d[-/]\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?)\b")
INTEREST_TOKENS = ["vpn", "password", "credential", "secret", "staging", "exfil", "sensitive", "archive", "remote", "admin", "temp"]
SUSPICIOUS_TOKENS = ["mimikatz", "rclone", "psexec", "procdump", "encodedcommand", "frombase64string", "powershell -enc", "cracked", "payload"]


def priority(score: int) -> str:
    return "high" if score >= 65 else "medium" if score >= 45 else "low" if score >= 25 else "informational"


def iter_csvs(manifest: dict):
    for item in manifest.get("results", []):
        if item.get("status") != "complete": continue
        for raw in item.get("outputs", []):
            path = Path(raw)
            if path.is_file() and path.suffix.lower() == ".csv":
                yield item, path


def iter_static_files(manifest: dict):
    for item in manifest.get("results", []):
        if item.get("tool") != "StaticArtifact" or item.get("status") not in {"complete", "partial"}:
            continue
        report_path = next((Path(raw) for raw in item.get("outputs", []) if Path(raw).name == "static-analysis.json"), None)
        if not report_path or not report_path.is_file():
            continue
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for file_record in report.get("files", []):
            if isinstance(file_record, dict):
                yield item, report_path, file_record


def main() -> None:
    ap = argparse.ArgumentParser(description="Triage parsed loose artifacts into cautious investigation leads")
    ap.add_argument("--case", required=True); ap.add_argument("--max-rows", type=int, default=250000); ap.add_argument("--max-leads", type=int, default=100)
    ap.add_argument("--material-lead-limit", type=int, default=12)
    args = ap.parse_args(); load_case(args.case); root = case_dir(args.case)
    manifest_path = root / "output" / "artifacts" / "artifact-baseline-manifest.json"
    if not manifest_path.exists():
        out = root / "output" / "artifact_triage.json"
        out.write_text(json.dumps({"schema_version": "0.3.4", "case": args.case, "generated_utc": now_iso(), "rows_reviewed": 0, "leads": [], "note": "No loose-artifact baseline manifest was available."}, indent=2), encoding="utf-8")
        print(f"No loose-artifact manifest; wrote empty triage: {out}"); return

    manifest = json.loads(manifest_path.read_text(encoding="utf-8")); rows_reviewed = 0; lead_ids = []; observations = []
    for task, report_path, record in iter_static_files(manifest):
        rows_reviewed += 1
        detected = str(record.get("detected_type", ""))
        logical_name = str(record.get("name") or Path(str(task.get("source", "artifact"))).name)
        text_output = record.get("text_output")
        if detected in {"powershell", "batch", "python", "javascript"} and len(lead_ids) < args.max_leads:
            score = 60 if detected == "powershell" else 45
            source = f"StaticArtifact:{report_path.name}:{logical_name}"
            lead = add_lead(
                args.case, lead_type="powershell" if detected == "powershell" else "file",
                value=logical_name, priority=priority(score), score=score, source=source,
                reason=f"Content-based classifier identified {detected} source; static-analysis lead only, never executed",
                context_matches=context_matches(args.case, logical_name),
            )
            lead_ids.append(lead["id"])
            observations.append({
                "lead_id": lead["id"], "source": source, "timestamp": None,
                "artifact_type": task.get("artifact_type"), "value": logical_name,
                "reason": f"Detected {detected} content",
                "text_output": text_output,
            })
    for task, path in iter_csvs(manifest):
        try:
            with path.open("r", newline="", encoding="utf-8-sig", errors="ignore") as handle:
                for row_number, row in enumerate(csv.DictReader(handle), 2):
                    rows_reviewed += 1
                    text = " | ".join(str(value) for value in row.values() if value not in (None, "")); lower = text.lower()
                    when_match = TIME_RE.search(text); when = when_match.group(1).replace("/", "-") if when_match else None
                    entities: list[tuple[str, str, int, str]] = []
                    for value in WINDOWS_PATH_RE.findall(text): entities.append(("file", value.strip(), 35, "Windows path observed in parsed artifact"))
                    for value in UNC_RE.findall(text): entities.append(("other", value.strip(), 45, "UNC/network path observed in parsed artifact"))
                    for value in FILE_RE.findall(text):
                        score = 45 if value.lower().endswith((".exe", ".dll", ".sys", ".ps1")) else 40
                        entities.append(("file", value.strip(), score, "Executable/archive/link name observed in parsed artifact"))
                    interesting = [token for token in INTEREST_TOKENS if token in lower]
                    suspicious = [token for token in SUSPICIOUS_TOKENS if token in lower]
                    if interesting or suspicious:
                        value = next((cell for cell in row.values() if cell and any(token in str(cell).lower() for token in interesting + suspicious)), text[:240])
                        score = 35 + (25 if suspicious else 0) + min(15, 3 * len(interesting))
                        entities.append(("other", str(value).strip(), score, "Artifact keyword requires context/corroboration: " + ", ".join((suspicious + interesting)[:8])))

                    for lead_type, value, score, reason in list(dict.fromkeys(entities)):
                        if len(lead_ids) >= args.max_leads or len(value) < 3: break
                        source = f"{task.get('tool')}:{path.name}:row={row_number}"
                        lead = add_lead(args.case, lead_type=lead_type, value=value, priority=priority(score), score=score, source=source, reason=reason + "; lead only, not a malicious verdict", timestamp=when, context_matches=context_matches(args.case, text))
                        lead_ids.append(lead["id"])
                        if len(observations) < 500:
                            observations.append({"lead_id": lead["id"], "source": source, "timestamp": when, "artifact_type": task.get("artifact_type"), "value": value, "reason": reason})
                    if rows_reviewed >= args.max_rows or len(lead_ids) >= args.max_leads: break
        except (OSError, csv.Error):
            continue
        if rows_reviewed >= args.max_rows or len(lead_ids) >= args.max_leads: break

    out = root / "output" / "artifact_triage.json"
    out.write_text(json.dumps({"schema_version": "0.3.4", "case": args.case, "generated_utc": now_iso(), "rows_reviewed": rows_reviewed, "lead_events": len(lead_ids), "unique_leads": len(set(lead_ids)), "leads": list(dict.fromkeys(lead_ids)), "observations": observations, "note": "Artifact-derived leads are investigation seeds, not malicious verdicts."}, indent=2), encoding="utf-8")
    enforce_material_lead_budget(args.case, args.material_lead_limit, reason="Post-artifact-triage material-lead budget")
    print(f"Artifact triage reviewed {rows_reviewed} row(s) and recorded/updated {len(set(lead_ids))} lead(s).")
    print(f"Artifact triage: {out}")


if __name__ == "__main__":
    main()
