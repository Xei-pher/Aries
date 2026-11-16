from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from common import case_dir, load_case
from records import add_lead, context_matches, enforce_material_lead_budget, load_context

WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\[^\r\n\"']+?\.(?:exe|dll|sys|ps1|bat|cmd|js|vbs|msi|zip|7z|rar)", re.IGNORECASE)
IP_RE = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
DOMAIN_RE = re.compile(r"(?<![@\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w.-])")

SUSPICIOUS_TOKENS = [
    "encodedcommand", " -enc ", "frombase64string", "invoke-expression", "iex(", "downloadstring",
    "invoke-webrequest", "start-bitstransfer", "certutil", "bitsadmin", "rundll32", "regsvr32",
    "mshta", "wscript", "cscript", "powershell -nop", "-w hidden", "mimikatz", "meterpreter",
    "cobalt strike", "beacon", "shellcode", "crackedsoftware", "cracked_software", "payload",
]
USER_WRITABLE_HINTS = ["\\downloads\\", "\\appdata\\local\\temp\\", "\\temp\\", "\\programdata\\", "\\public\\"]
TRAINING_HINTS = ["course_files", "sherlocks", "ghosttrace", "hackthebox", "htb", "ctf", "challenge", "lab"]


def row_text(row: dict[str, str]) -> str:
    return " | ".join(str(v) for v in row.values() if v not in (None, ""))


def first_field(row: dict[str, str], names: list[str]) -> str:
    lowered = {str(k).lower(): str(v) for k, v in row.items() if v is not None}
    for name in names:
        if name.lower() in lowered and lowered[name.lower()]:
            return lowered[name.lower()]
    return ""


def event_id(row: dict[str, str]) -> int | None:
    raw = first_field(row, ["EventId", "EventID", "Id", "Event Id"])
    m = re.search(r"\d+", raw)
    return int(m.group()) if m else None


def event_time(row: dict[str, str]) -> str | None:
    raw = first_field(row, ["TimeCreated", "Time Created", "Timestamp", "UtcTime", "TimeGenerated"])
    return raw or None


def provider(row: dict[str, str], fallback_name: str) -> str:
    return first_field(row, ["Provider", "ProviderName", "Channel", "Source"]) or fallback_name


def extract_image(text: str) -> str | None:
    matches = WINDOWS_PATH_RE.findall(text)
    for path in matches:
        if path.lower().endswith(".exe"):
            return path.strip()
    return matches[0].strip() if matches else None


def useful_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)
    except ValueError:
        return False


def score_process(text: str, image: str | None) -> tuple[int, list[str]]:
    lower = text.lower()
    score = 15
    reasons: list[str] = []
    if image and any(h in image.lower() for h in USER_WRITABLE_HINTS):
        score += 30
        reasons.append("process/file is in a user-writable location")
    hits = [token.strip() for token in SUSPICIOUS_TOKENS if token in lower]
    if hits:
        score += min(40, 15 + 5 * len(hits))
        reasons.append("suspicious execution/content tokens: " + ", ".join(hits[:5]))
    if any(t in lower for t in TRAINING_HINTS):
        score -= 25
        reasons.append("training/lab context keyword present; treat as dual-use until corroborated")
    return max(0, min(100, score)), reasons


def priority_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 45:
        return "medium"
    if score >= 25:
        return "low"
    return "informational"


def iter_manifest_csvs(root: Path):
    manifest_path = root / "output" / "eztools" / "EvtxECmd-Auto" / "baseline-manifest.json"
    if not manifest_path.exists():
        return
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    for item in data.get("results", []):
        parser = item.get("parser") or {}
        csv_path = parser.get("csv_path")
        if csv_path and Path(csv_path).is_file():
            yield item.get("event_log", Path(csv_path).name), Path(csv_path), item.get("tier", 3)


def add_event_leads(case_name: str, log_name: str, row: dict[str, str]) -> list[str]:
    text = row_text(row)
    lower = text.lower()
    eid = event_id(row)
    when = event_time(row)
    src = f"EvtxECmd:{log_name}:EventID={eid if eid is not None else '?'}"
    context = context_matches(case_name, text)
    created: list[str] = []

    # Microsoft Defender detections are authoritative lead seeds, not automatically incident root cause.
    if eid in {1116, 1117}:
        image = extract_image(text)
        hashes = SHA256_RE.findall(text)
        threat = first_field(row, ["Threat Name", "ThreatName", "PayloadData1", "MapDescription"])
        value = image or threat or (hashes[0] if hashes else f"Defender event {eid}")
        score = 95 if eid == 1116 or "detected" in lower else 80
        lead = add_lead(case_name, lead_type="file" if image else "detection", value=value, priority=priority_from_score(score), score=score,
                        source=src, reason="Windows Defender detection/action telemetry", timestamp=when, context_matches=context)
        created.append(lead["id"])
        for digest in hashes[:2]:
            hlead = add_lead(case_name, lead_type="sha256", value=digest.lower(), priority="high", score=85, source=src,
                             reason=f"Hash observed in Defender event related to {value}", timestamp=when, parent_id=lead["id"], context_matches=context)
            created.append(hlead["id"])

    # Sysmon process creation / Security 4688.
    if eid in {1, 4688} or ("sysmon" in log_name.lower() and "process create" in lower):
        image = extract_image(text)
        score, reasons = score_process(text, image)
        if score >= 50 and (image or any(t in lower for t in SUSPICIOUS_TOKENS)):
            value = image or (first_field(row, ["ExecutableInfo", "PayloadData1", "PayloadData2"])[:240] or "process-create-event")
            lead = add_lead(case_name, lead_type="process", value=value, priority=priority_from_score(score), score=score, source=src,
                            reason="; ".join(reasons) or "Process creation requires contextual review", timestamp=when, context_matches=context)
            created.append(lead["id"])
            for digest in SHA256_RE.findall(text)[:2]:
                hlead = add_lead(case_name, lead_type="sha256", value=digest.lower(), priority=priority_from_score(max(45, score)), score=max(45, score),
                                 source=src, reason=f"Hash associated with process lead {lead['id']}", timestamp=when, parent_id=lead["id"], context_matches=context)
                created.append(hlead["id"])

    # Sysmon network/DNS. Seed only when event context itself is interesting, to avoid thousands of ordinary endpoints.
    if eid in {3, 22} or ("sysmon" in log_name.lower() and ("network" in lower or "dns" in lower)):
        proc_score, reasons = score_process(text, extract_image(text))
        interesting = proc_score >= 50 or any(port in lower for port in [":8080", ":8000", ":4444", ":8443", ":1337", ":9001"])
        if interesting:
            for ip in [v for v in IP_RE.findall(text) if useful_ip(v)][:4]:
                lead = add_lead(case_name, lead_type="ip", value=ip, priority=priority_from_score(max(45, proc_score)), score=max(45, proc_score), source=src,
                                reason="Network endpoint associated with an interesting process/event", timestamp=when, context_matches=context)
                created.append(lead["id"])
            if eid == 22:
                for domain in DOMAIN_RE.findall(text)[:4]:
                    lead = add_lead(case_name, lead_type="domain", value=domain.lower(), priority=priority_from_score(max(40, proc_score)), score=max(40, proc_score), source=src,
                                    reason="DNS query associated with an interesting process/event", timestamp=when, context_matches=context)
                    created.append(lead["id"])

    # PowerShell script block/module logging.
    if eid in {4103, 4104} or "powershell" in log_name.lower():
        suspicious = [token.strip() for token in SUSPICIOUS_TOKENS if token in lower]
        if suspicious:
            score = 55 + min(20, 4 * len(suspicious))
            if any(t in lower for t in TRAINING_HINTS):
                score -= 25
            value = first_field(row, ["PayloadData1", "PayloadData2", "ExecutableInfo", "MapDescription"])
            value = (value or "PowerShell suspicious content")[:300]
            lead = add_lead(case_name, lead_type="powershell", value=value, priority=priority_from_score(score), score=score, source=src,
                            reason="PowerShell telemetry contains dual-use/suspicious execution patterns: " + ", ".join(suspicious[:5]), timestamp=when,
                            context_matches=context)
            created.append(lead["id"])

    # Persistence/admin-change seeds.
    if eid in {7045, 4697}:
        value = extract_image(text) or "service-install-event"
        score = 55 + (15 if value != "service-install-event" and any(h in value.lower() for h in USER_WRITABLE_HINTS) else 0)
        lead = add_lead(case_name, lead_type="service", value=value, priority=priority_from_score(score), score=score, source=src,
                        reason="Service installation telemetry", timestamp=when, context_matches=context)
        created.append(lead["id"])
    if eid in {4698, 4702}:
        value = first_field(row, ["PayloadData1", "PayloadData2", "MapDescription"]) or "scheduled-task-event"
        lead = add_lead(case_name, lead_type="scheduled_task", value=value[:300], priority="medium", score=55, source=src,
                        reason="Scheduled task creation/update telemetry", timestamp=when, context_matches=context)
        created.append(lead["id"])
    if eid in {4720, 4728, 4732, 4756}:
        value = first_field(row, ["UserName", "PayloadData1", "PayloadData2"]) or "account-change-event"
        lead = add_lead(case_name, lead_type="user", value=value[:200], priority="medium", score=50, source=src,
                        reason="Account/group modification telemetry", timestamp=when, context_matches=context)
        created.append(lead["id"])

    return created


def main() -> None:
    ap = argparse.ArgumentParser(description="Triage parsed Windows event logs and seed evidence-led Aries leads")
    ap.add_argument("--case", required=True)
    ap.add_argument("--max-events", type=int, default=500000, help="Global safety cap across parsed logs")
    ap.add_argument("--material-lead-limit", type=int, default=12)
    args = ap.parse_args()

    load_case(args.case)
    root = case_dir(args.case)
    context = load_context(args.case)
    counts = Counter()
    lead_ids: set[str] = set()
    sampled = []
    total = 0

    csvs = list(iter_manifest_csvs(root) or [])
    if not csvs:
        report = {
            "schema_version": "0.3.4",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "case": args.case,
            "parsed_event_files": [],
            "events_reviewed": 0,
            "unique_leads_touched": [],
            "counts": {},
            "environment": {"explicit_context_entries": len(context.get("entries", [])), "dual_use_caution": False},
            "lead_event_samples": [],
            "note": "No parsed EvtxECmd CSV outputs were available. Event triage is partial; continue with memory/disk telemetry and document the coverage gap.",
        }
        out = root / "output" / "event_triage.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"No parsed event-log CSVs available. Partial triage report: {out}")
        raise SystemExit(3)

    for log_name, path, tier in csvs:
        try:
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    total += 1
                    counts[f"tier_{tier}"] += 1
                    eid = event_id(row)
                    if eid is not None:
                        counts[f"event_{eid}"] += 1
                    new_ids = add_event_leads(args.case, log_name, row)
                    if new_ids and len(sampled) < 250:
                        sampled.append({"log": log_name, "event_id": eid, "time": event_time(row), "lead_ids": new_ids, "text": row_text(row)[:1200]})
                    lead_ids.update(new_ids)
                    if total >= args.max_events:
                        break
        except OSError as exc:
            counts["read_errors"] += 1
            sampled.append({"log": log_name, "error": str(exc)})
        if total >= args.max_events:
            break

    # Environment caution is not a verdict; it tells later pivoting to demand stronger corroboration.
    training_signals = 0
    for item in sampled:
        text = str(item.get("text", "")).lower()
        if any(token in text for token in TRAINING_HINTS):
            training_signals += 1

    report = {
        "schema_version": "0.3.4",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "case": args.case,
        "parsed_event_files": [str(p) for _, p, _ in csvs],
        "events_reviewed": total,
        "unique_leads_touched": sorted(lead_ids),
        "counts": dict(counts),
        "environment": {
            "explicit_context_entries": len(context.get("entries", [])),
            "training_or_lab_signal_hits_in_lead_events": training_signals,
            "dual_use_caution": training_signals > 0,
        },
        "lead_event_samples": sampled,
        "note": "Leads are investigation seeds, not malicious verdicts. Context and corroboration are required before promotion to confirmed findings.",
    }
    out = root / "output" / "event_triage.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    budget = enforce_material_lead_budget(args.case, args.material_lead_limit, reason="Post-event-triage material-lead budget")
    print(f"Event triage reviewed {total} events and touched {len(lead_ids)} lead(s).")
    print(f"Material lead queue: {len(budget['retained'])} retained, {len(budget['downgraded_to_backlog'])} moved to backlog.")
    print(f"Lead registry: {root / 'leads.jsonl'}")
    print(f"Triage report: {out}")


if __name__ == "__main__":
    main()
