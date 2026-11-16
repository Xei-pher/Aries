from __future__ import annotations

import argparse
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from common import case_dir, load_case, now_iso
from records import add_lead, context_matches, enforce_material_lead_budget, materialize_history, update_lead

IP_RE = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")
URL_RE = re.compile(r"https?://[^\s\"'<>\]\[(){}]+", re.IGNORECASE)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
DOMAIN_RE = re.compile(r"(?<![@\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w.-])")
PATH_RE = re.compile(r"[A-Za-z]:\\[^\r\n\"']+?\.(?:exe|dll|sys|ps1|bat|cmd|js|vbs|msi|zip|7z|rar|lnk|pf)", re.IGNORECASE)
TIME_RE = re.compile(r"\b(20\d\d[-/]\d\d[-/]\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)\b")

MAX_FILE_BYTES = 150 * 1024 * 1024
PRIORITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
TEXT_SUFFIXES = {"", ".txt", ".csv", ".json", ".jsonl", ".log", ".md", ".tsv", ".xml"}
NON_DOMAIN_SUFFIXES = {
    "bat", "cat", "clb", "cmd", "csv", "dat", "dll", "drv", "evtx", "exe", "inf",
    "ini", "json", "lnk", "log", "manifest", "msi", "mui", "pf", "pri", "ps1", "rb",
    "sys", "tlb", "tmp", "txt", "vbs", "vmsg", "xml", "xsd",
}
LIKELY_DOMAIN_TLDS = {
    "app", "biz", "ca", "cloud", "co", "com", "dev", "edu", "gov", "info", "io", "me",
    "mil", "net", "org", "ph", "ru", "site", "tech", "uk", "us", "xyz",
}


def current_leads(root: Path) -> list[dict]:
    values = [item for item in materialize_history(root / "leads.jsonl", "L") if item.get("status") == "active"]
    return sorted(values, key=lambda item: (PRIORITY.get(str(item.get("priority")), 0), int(item.get("score") or 0)), reverse=True)


def search_terms(lead: dict) -> list[str]:
    value = str(lead.get("value", "")).strip(); terms = [value] if value else []
    if "\\" in value: terms.append(Path(value.replace("\\", "/")).name)
    if lead.get("type") == "url":
        try:
            host = urlparse(value).hostname
            if host: terms.append(host)
        except Exception: pass
    return [term for term in dict.fromkeys(terms) if len(term) >= 3]


def iter_search_files(root: Path):
    candidates = [root / "output" / "eztools", root / "output" / "artifacts", root / "output" / "dissect", root / "output" / "volatility", root / "output" / "event_triage.json", root / "output" / "artifact_triage.json", root / "timeline" / "targeted_timeline.csv", root / "notes.md"]
    inventory = root / "artifact_inventory.json"
    if inventory.exists():
        try:
            data = json.loads(inventory.read_text(encoding="utf-8"))
            for item in data.get("artifacts", []):
                if item.get("source_type") == "loose" and item.get("artifact_type") == "text_log":
                    candidates.append(Path(item["path"]))
        except (OSError, json.JSONDecodeError): pass
    seen: set[str] = set()
    for base in candidates:
        paths = [base] if base.is_file() else base.rglob("*") if base.exists() else []
        for path in paths:
            if not path.is_file() or path.name.endswith((".stderr.txt", ".stdout.txt")) or path.suffix.lower() not in TEXT_SUFFIXES: continue
            try:
                key = str(path.resolve()).lower()
                if key in seen or path.stat().st_size > MAX_FILE_BYTES: continue
                seen.add(key); yield path
            except OSError: continue


def useful_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)
    except ValueError: return False


def derive_entities(text: str) -> list[tuple[str, str]]:
    entities: list[tuple[str, str]] = []
    entities += [("sha256", value.lower()) for value in SHA256_RE.findall(text)]
    entities += [("url", value.rstrip(".,;:!?\"'")) for value in URL_RE.findall(text)]
    entities += [("ip", value) for value in IP_RE.findall(text) if useful_ip(value)]
    entities += [("file", value.strip()) for value in PATH_RE.findall(text)]
    for domain in DOMAIN_RE.findall(text):
        suffix = domain.rsplit(".", 1)[-1].lower()
        if suffix not in NON_DOMAIN_SUFFIXES and suffix in LIKELY_DOMAIN_TLDS:
            entities.append(("domain", domain.lower()))
    return list(dict.fromkeys(entities))


def artifact_family(path: Path, root: Path) -> str:
    text = str(path).lower()
    if "evtxecmd" in text or "event_triage" in text: return "windows_event_logs"
    if "volatility" in text: return "memory"
    if "dissect" in text: return "disk_artifacts"
    if "sbecmd" in text: return "shellbags"
    if "recmd" in text: return "registry"
    if "pecmd" in text: return "prefetch"
    if "amcache" in text: return "amcache"
    if "mftecmd" in text: return "filesystem_metadata"
    if "srum" in text: return "srum"
    if "lecmd" in text or "jlecmd" in text: return "shell_links"
    try:
        path.relative_to(root)
        return "case_notes_or_derived"
    except ValueError:
        return "loose_source"


def pivot_plan(lead: dict) -> list[str]:
    lead_type = lead.get("type")
    if lead_type in {"process", "file", "sha256", "detection"}:
        return ["Establish creator/parent and execution context", "Correlate process, network, file, registry and DNS telemetry", "Check Defender plus Prefetch/Amcache/UserAssist/ShimCache", "Check memory process/network/module evidence", "Build a narrow before/after timeline", "Require an explicit bridge before joining another time cluster"]
    if lead_type in {"ip", "domain", "url"}:
        return ["Find every process and user associated with the endpoint", "Separate delivery from callback/C2 behavior", "Correlate DNS, firewall, SRUM, browser and memory network evidence", "Connect downloads to later execution"]
    if lead_type == "user":
        return ["Correlate logons and source IPs", "Find execution, tasks, services and remote access tied to the account", "Review user registry, shellbags, LNK and Jump List artifacts"]
    return ["Search all parsed and registered textual evidence", "Correlate timestamps and independent artifact families", "Close as confirmed, benign, contextual, or unresolved"]


def lead_depth(lead: dict, by_id: dict[str, dict]) -> int:
    if lead.get("depth") is not None: return int(lead.get("depth") or 0)
    depth = 0; parent = lead.get("parent_id"); visited = set()
    while parent and parent in by_id and parent not in visited:
        visited.add(parent); depth += 1; parent = by_id[parent].get("parent_id")
    return depth


def main() -> None:
    ap = argparse.ArgumentParser(description="Aries v0.3 bounded recursive evidence pivot engine")
    ap.add_argument("--case", required=True); ap.add_argument("--max-depth", type=int, default=3)
    ap.add_argument("--max-leads-per-round", type=int, default=12); ap.add_argument("--max-hits-per-lead", type=int, default=500)
    ap.add_argument("--max-related-per-lead", type=int, default=8)
    ap.add_argument("--material-lead-limit", type=int, default=12)
    args = ap.parse_args(); load_case(args.case); root = case_dir(args.case)
    files = list(iter_search_files(root)); pivot_root = root / "output" / "pivots"; pivot_root.mkdir(parents=True, exist_ok=True)
    processed: set[str] = set(); summary: list[dict] = []; round_number = 0

    while round_number <= args.max_depth:
        all_leads = current_leads(root); by_id = {item["id"]: item for item in all_leads}
        batch = [item for item in all_leads if item["id"] not in processed and lead_depth(item, by_id) <= args.max_depth][:max(1, args.max_leads_per_round)]
        if not batch: break
        round_number += 1
        for lead in batch:
            processed.add(lead["id"]); terms = search_terms(lead)
            if not terms: continue
            ldir = pivot_root / lead["id"]; ldir.mkdir(parents=True, exist_ok=True)
            hits = []; related: dict[tuple[str, str], int] = {}; families: set[str] = set()
            for path in files:
                try:
                    with path.open("r", encoding="utf-8", errors="ignore") as handle:
                        for lineno, line in enumerate(handle, 1):
                            if not any(term.lower() in line.lower() for term in terms): continue
                            family = artifact_family(path, root); families.add(family)
                            match = TIME_RE.search(line)
                            hits.append({"lead_id": lead["id"], "source": str(path.relative_to(root)) if path.is_relative_to(root) else str(path), "artifact_family": family, "line": lineno, "timestamp": match.group(1) if match else None, "text": line.rstrip()[:4000], "context_matches": context_matches(args.case, line)})
                            for entity in derive_entities(line):
                                if entity[1].lower() != str(lead.get("value", "")).lower(): related[entity] = related.get(entity, 0) + 1
                            if len(hits) >= args.max_hits_per_lead: break
                except OSError: continue
                if len(hits) >= args.max_hits_per_lead: break
            with (ldir / "hits.jsonl").open("w", encoding="utf-8") as handle:
                for hit in hits: handle.write(json.dumps(hit, ensure_ascii=False) + "\n")

            child_ids = []
            for (entity_type, value), count in sorted(related.items(), key=lambda item: item[1], reverse=True)[:args.max_related_per_lead]:
                if count < 2 and entity_type != "sha256": continue
                score = min(85, max(35, int(lead.get("score") or 40) - 5 + min(20, count * 3)))
                # Co-occurrence inside one parsed source is a search hint, not
                # high-priority evidence. Derived children start medium at
                # most and can be promoted only after independent correlation.
                child_priority = "medium" if score >= 45 else "low"
                child = add_lead(args.case, lead_type=entity_type, value=value, priority=child_priority, score=score, source=f"Pivot:{lead['id']}", reason=f"Co-observed with {lead['id']} in {count} hit(s)", parent_id=lead["id"], context_matches=[])
                update_lead(args.case, child["id"], depth=lead_depth(lead, by_id) + 1)
                if child["id"] != lead["id"]: child_ids.append(child["id"])
            context_count = sum(1 for hit in hits if hit.get("context_matches")); relevance = "context-sensitive" if context_count and context_count >= max(1, len(hits) // 2) else "high" if hits else "unresolved"
            update_lead(args.case, lead["id"], pivot_hits=len(hits), pivoted_utc=now_iso(), pivot_round=round_number, relevance=relevance, child_leads=list(dict.fromkeys(child_ids)), artifact_families=sorted(families), independent_family_count=len(families), pivot_status="corroborated" if len(families) >= 2 else "single-source" if hits else "unresolved")
            plan = {"lead_id": lead["id"], "lead": lead, "depth": lead_depth(lead, by_id), "round": round_number, "search_terms": terms, "hit_count": len(hits), "artifact_families": sorted(families), "independent_family_count": len(families), "context_hit_count": context_count, "relevance": relevance, "child_leads": list(dict.fromkeys(child_ids)), "next_queries": pivot_plan(lead)}
            (ldir / "pivot-plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8"); summary.append(plan)
            print(f"round={round_number} depth={plan['depth']} {lead['id']} {lead.get('type')}={lead.get('value')}: {len(hits)} hit(s), {len(families)} family/families, {len(plan['child_leads'])} child lead(s)")

    budget = enforce_material_lead_budget(args.case, args.material_lead_limit, reason="Post-recursive-pivot material-lead budget")
    remaining = current_leads(root)
    high_open = [item["id"] for item in remaining if PRIORITY.get(str(item.get("priority")), 0) >= PRIORITY["high"] and item.get("pivot_status") in {None, "unresolved", "single-source"}]
    out = pivot_root / "pivot-summary.json"
    out.write_text(json.dumps({"schema_version": "0.3.4", "case": args.case, "generated_utc": now_iso(), "max_depth": args.max_depth, "rounds": round_number, "processed_leads": len(processed), "unresolved_high_priority_leads": high_open, "lead_budget": budget, "leads": summary}, indent=2), encoding="utf-8")
    print(f"Recursive pivot summary: {out}")


if __name__ == "__main__":
    main()
