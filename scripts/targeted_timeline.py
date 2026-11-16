from __future__ import annotations

import argparse
import csv
import json
import re
from datetime import datetime
from pathlib import Path

from common import case_dir, load_case, now_iso
from records import materialize_history

TIME_PATTERNS = [
    re.compile(r"\b(20\d\d-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)\b"),
    re.compile(r"\b(20\d\d/\d\d/\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?)\b"),
]
MAX_FILE_BYTES = 150 * 1024 * 1024


def active_leads(root: Path, limit: int = 12) -> list[dict]:
    values = [
        x for x in materialize_history(root / "leads.jsonl", "L")
        if x.get("status") == "active" and x.get("priority") in {"critical", "high"}
    ]
    values.sort(key=lambda item: (item.get("priority") == "critical", int(item.get("score") or 0)), reverse=True)
    return values[:max(1, limit)]


def terms_for_leads(leads: list[dict]) -> dict[str, list[str]]:
    out = {}
    for lead in leads:
        value = str(lead.get("value", "")).strip()
        terms = [value] if value else []
        if "\\" in value:
            terms.append(Path(value.replace("\\", "/")).name)
        out[lead["id"]] = [t for t in dict.fromkeys(terms) if len(t) >= 3]
    return out


def extract_time(line: str) -> str | None:
    for pattern in TIME_PATTERNS:
        m = pattern.search(line)
        if m:
            return m.group(1).replace("/", "-")
    return None


def sortable_time(value: str) -> tuple[int, str]:
    if not value:
        return (1, "")
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
        return (0, dt.isoformat())
    except ValueError:
        return (0, value)


def iter_sources(root: Path):
    bases = [root / "output" / "eztools", root / "output" / "artifacts", root / "output" / "dissect", root / "output" / "volatility"]
    inventory = root / "artifact_inventory.json"
    if inventory.exists():
        try:
            data = json.loads(inventory.read_text(encoding="utf-8"))
            bases.extend(Path(item["path"]) for item in data.get("artifacts", []) if item.get("source_type") == "loose" and item.get("artifact_type") == "text_log")
        except (OSError, json.JSONDecodeError):
            pass
    for base in bases:
        if not base.exists():
            continue
        candidates = [base] if base.is_file() else base.rglob("*")
        for p in candidates:
            if not p.is_file() or p.name.endswith((".stdout.txt", ".stderr.txt")):
                continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            if p.suffix.lower() in {"", ".txt", ".csv", ".json", ".jsonl", ".log"}:
                yield p


def main() -> None:
    ap = argparse.ArgumentParser(description="Build a lead-centered Aries timeline without generating a giant whole-disk timeline")
    ap.add_argument("--case", required=True)
    ap.add_argument("--max-events", type=int, default=2000)
    ap.add_argument("--max-events-per-lead", type=int, default=200)
    args = ap.parse_args()

    load_case(args.case)
    root = case_dir(args.case)
    leads = active_leads(root)
    if not leads:
        timeline_dir = root / "timeline"
        timeline_dir.mkdir(parents=True, exist_ok=True)
        csv_path = timeline_dir / "targeted_timeline.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=["timestamp", "lead_id", "source", "line", "origin", "event"]).writeheader()
        md_path = timeline_dir / "targeted_timeline.md"
        md_path.write_text(f"# Targeted Timeline - {args.case}\n\nNo active leads were available for a targeted timeline.\n", encoding="utf-8")
        print(f"No active leads; wrote empty targeted timeline: {csv_path}")
        return
    lead_terms = terms_for_leads(leads)

    entries: list[dict] = []
    seen: set[tuple[str, str, int]] = set()
    per_lead: dict[str, int] = {}

    # First consume deterministic pivot hits because they are already lead-correlated.
    for hit_file in (root / "output" / "pivots").glob("L-*/hits.jsonl") if (root / "output" / "pivots").exists() else []:
        lead_id = hit_file.parent.name
        for line in hit_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                hit = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = hit.get("timestamp") or extract_time(str(hit.get("text", "")))
            if not ts:
                continue
            key = (lead_id, str(hit.get("source")), int(hit.get("line") or 0))
            if key in seen:
                continue
            if len(entries) >= args.max_events or per_lead.get(lead_id, 0) >= args.max_events_per_lead:
                continue
            seen.add(key)
            entries.append({
                "timestamp": ts,
                "lead_id": lead_id,
                "source": hit.get("source", ""),
                "line": hit.get("line", ""),
                "event": str(hit.get("text", ""))[:3000],
                "origin": "pivot",
            })
            per_lead[lead_id] = per_lead.get(lead_id, 0) + 1

    # Supplement with high-value outputs for lead terms not represented in pivots.
    if len(entries) < args.max_events:
        for path in iter_sources(root):
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as f:
                    for lineno, line in enumerate(f, 1):
                        lower = line.lower()
                        matching = [lid for lid, terms in lead_terms.items() if any(term.lower() in lower for term in terms)]
                        if not matching:
                            continue
                        ts = extract_time(line)
                        if not ts:
                            continue
                        for lid in matching[:4]:
                            if per_lead.get(lid, 0) >= args.max_events_per_lead:
                                continue
                            key = (lid, str(path.relative_to(root)), lineno)
                            if key in seen:
                                continue
                            seen.add(key)
                            entries.append({
                                "timestamp": ts,
                                "lead_id": lid,
                                "source": str(path.relative_to(root)),
                                "line": lineno,
                                "event": line.rstrip()[:3000],
                                "origin": "correlation",
                            })
                            per_lead[lid] = per_lead.get(lid, 0) + 1
                            if len(entries) >= args.max_events:
                                break
                        if len(entries) >= args.max_events:
                            break
            except OSError:
                continue
            if len(entries) >= args.max_events:
                break

    entries.sort(key=lambda e: sortable_time(str(e.get("timestamp", ""))))
    timeline_dir = root / "timeline"
    timeline_dir.mkdir(parents=True, exist_ok=True)
    csv_path = timeline_dir / "targeted_timeline.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["timestamp", "lead_id", "source", "line", "origin", "event"])
        w.writeheader()
        w.writerows(entries)

    md_path = timeline_dir / "targeted_timeline.md"
    lines = [
        f"# Targeted Timeline - {args.case}",
        "",
        f"Generated: {now_iso()}",
        "",
        "This timeline contains only events correlated to active leads. It is intentionally not a whole-disk timeline.",
        "",
        "| Timestamp | Lead | Source | Event |",
        "|---|---|---|---|",
    ]
    for entry in entries[:300]:
        event = str(entry["event"]).replace("|", "\\|").replace("\n", " ")[:500]
        lines.append(f"| {entry['timestamp']} | {entry['lead_id']} | `{entry['source']}` | {event} |")
    if len(entries) > 300:
        lines += ["", f"_Markdown view truncated to 300 of {len(entries)} entries. Use targeted_timeline.csv for the full result._"]
    md_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"Targeted timeline entries: {len(entries)}")
    print(f"CSV: {csv_path}")
    print(f"Markdown: {md_path}")


if __name__ == "__main__":
    main()
