from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from common import ALL_PHASES, DEFAULT_PHASE_ORDER, PHASE_ORDER, case_dir, load_case, now_iso, save_case, safe_case_name, slug_case_name
from records import (
    add_context as records_add_context,
    add_finding as records_add_finding,
    add_lead as records_add_lead,
    close_lead as records_close_lead,
    load_context,
    materialize_history,
    retract_finding as records_retract_finding,
    update_lead as records_update_lead,
)
from questions import load_questions, record_answer, seed_deterministic_answers

TEXT_EXTENSIONS = {".txt", ".csv", ".json", ".jsonl", ".log", ".md", ".tsv", ".xml", ".yaml", ".yml"}
IP_RE = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")
URL_RE = re.compile(r"https?://[^\s\"'<>\]\[(){}]+", re.IGNORECASE)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
DOMAIN_RE = re.compile(r"(?<![@\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w.-])")
COMMON_NON_DOMAIN_SUFFIXES = {"exe", "dll", "sys", "evtx", "json", "txt", "csv", "log", "xml", "yaml", "yml", "ps1", "bat", "cmd", "lnk", "pf", "db", "sqlite"}
MEMORY_EXTENSIONS = {".raw", ".mem", ".vmem", ".dmp", ".dump", ".lime"}
EWF_FIRST_RE = re.compile(r"^.+\.(?:e01|ex01)$", re.IGNORECASE)
DISK_IMAGE_EXTENSIONS = {".dd", ".img", ".vhd", ".vhdx", ".vmdk", ".qcow", ".qcow2", ".aff4"}
REGISTRY_NAMES = {"ntuser.dat", "usrclass.dat", "system", "software", "sam", "security", "default", "amcache.hve"}
JUMPLIST_SUFFIXES = {".automaticdestinations-ms", ".customdestinations-ms"}
ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"}
ASSESSMENT_SCHEMA_VERSION = "0.5.0"


def file_entry(path: str | None, kind: str) -> dict | None:
    if not path:
        return None
    p = Path(path)
    exists = p.exists()
    stat = p.stat() if exists else None
    return {
        "kind": kind,
        "path": str(p),
        "exists": bool(exists),
        "is_file": p.is_file() if exists else False,
        "is_dir": p.is_dir() if exists else False,
        "size_bytes": stat.st_size if stat and p.is_file() else None,
        "modified_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat() if stat else None,
        "sha256": None,
    }


def evidence_key(evidence: dict, kind: str) -> str:
    if kind in {"e01", "memory", "disk_image"} and kind not in evidence:
        return kind
    index = 1
    while f"source_{index:04d}" in evidence:
        index += 1
    return f"source_{index:04d}"


def build_evidence(paths: list[tuple[Path, str, list[str]]]) -> dict:
    evidence: dict[str, dict] = {}
    for path, kind, excludes in paths:
        entry = file_entry(str(path), kind)
        if not entry:
            continue
        if excludes:
            entry["exclude_paths"] = excludes
        evidence[evidence_key(evidence, kind)] = entry
    return evidence


def init_case(args: argparse.Namespace) -> None:
    name = safe_case_name(args.name)
    root = case_dir(name)
    if (root / "case.json").exists() and not args.force:
        raise SystemExit(f"Case already exists: {root}. Use --force only if you intend to reset case metadata.")

    for rel in [
        "output/dissect",
        "output/volatility",
        "output/eztools",
        "output/search",
        "output/preflight",
        "timeline",
        "extracted/eventlogs",
        "report",
    ]:
        (root / rel).mkdir(parents=True, exist_ok=True)

    sources: list[tuple[Path, str, list[str]]] = []
    for raw, kind in [(getattr(args, "e01", None), "e01"), (getattr(args, "memory", None), "memory"), (getattr(args, "disk", None), "disk_image")]:
        if raw:
            sources.append((Path(raw), kind, []))
    for raw in getattr(args, "artifact", None) or []:
        path = Path(raw)
        sources.append((path, classify_evidence_file(path) if path.is_file() else "artifact_directory", []))
    evidence = build_evidence(sources)

    phases = {
        phase: {
            "status": "pending",
            "attempts": 0,
            "started_utc": None,
            "finished_utc": None,
            "returncode": None,
            "message": "",
        }
        for phase in ALL_PHASES
    }
    data = {
        "schema_version": "0.3.4",
        "name": name,
        "description": args.description or "",
        "created_utc": now_iso(),
        "updated_utc": now_iso(),
        "evidence": evidence,
        "intake_paths": [str(Path(item[0])) for item in sources],
        "investigation": {
            "mode_last": None,
            "phase_order": list(DEFAULT_PHASE_ORDER),
            "optional_phases": ["disk_timeline"],
            "phases": phases,
        },
    }
    save_case(name, data)

    notes = root / "notes.md"
    if not notes.exists() or args.force:
        notes.write_text(f"# Notes - {name}\n\n", encoding="utf-8")
    (root / "findings.jsonl").touch(exist_ok=True)
    (root / "leads.jsonl").touch(exist_ok=True)
    context_path = root / "case_context.json"
    if not context_path.exists():
        context_path.write_text(json.dumps({"schema_version": "0.3.4", "entries": []}, indent=2), encoding="utf-8")
    iocs = root / "iocs.csv"
    if not iocs.exists():
        with iocs.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["type", "value", "source", "notes", "added_utc"])

    # Manifest exists from intake even before hashes are calculated.
    write_evidence_manifest(name, data)

    print(f"Created case: {root}")
    for kind, entry in evidence.items():
        print(f"  {kind}: {entry['path']} (exists={entry['exists']})")


def classify_evidence_file(path: Path) -> str | None:
    if EWF_FIRST_RE.match(path.name):
        return "e01"
    lower_name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix in MEMORY_EXTENSIONS:
        return "memory"
    if suffix in DISK_IMAGE_EXTENSIONS:
        return "disk_image"
    if suffix == ".evtx":
        return "event_log"
    if lower_name == "amcache.hve":
        return "amcache"
    if lower_name == "srudb.dat":
        return "srum"
    if lower_name == "$mft":
        return "mft"
    if lower_name in {"$j", "$usnjrnl$j", "$usnjrnl"}:
        return "usnjrnl"
    if lower_name in REGISTRY_NAMES or suffix in {".hiv", ".hive"}:
        return "registry_hive"
    if suffix == ".pf":
        return "prefetch"
    if suffix == ".lnk":
        return "lnk"
    if suffix in JUMPLIST_SUFFIXES:
        return "jumplist"
    if lower_name.startswith("$i") or lower_name.startswith("$r"):
        return "recycle_bin"
    if lower_name == "activitiescache.db":
        return "windows_timeline"
    if suffix in {".sqlite", ".sqlite3", ".db"} or lower_name in {"history", "places.sqlite", "webcachev01.dat"}:
        return "browser"
    if suffix in ARCHIVE_EXTENSIONS:
        return "archive"
    if suffix in TEXT_EXTENSIONS:
        return "text_log"
    return "artifact"


def discover_evidence(inputs: list[str]) -> list[tuple[Path, str, list[str]]]:
    """Register supplied paths while detecting primary images inside folders.

    Directories remain first-class evidence sources. Top-level disk/memory files
    are separately registered so capability-aware phases can run, and excluded
    from the directory hash to avoid hashing huge captures twice.
    """
    sources: list[tuple[Path, str, list[str]]] = []
    for raw in inputs:
        path = Path(raw)
        if path.is_file():
            sources.append((path, classify_evidence_file(path), []))
        elif path.is_dir():
            primary: list[tuple[Path, str, list[str]]] = []
            for child in sorted(path.iterdir()):
                if not child.is_file():
                    continue
                kind = classify_evidence_file(child)
                if kind in {"e01", "memory", "disk_image"}:
                    primary.append((child, kind, []))
            excludes = [str(item[0].resolve()) for item in primary]
            # A browser upload is registered by passing the case's evidence
            # directory. Do not count that container as a second evidence
            # source when every file inside it is already registered as a
            # primary image or memory capture. Mixed directories remain valid
            # first-class evidence sources for their additional artifacts.
            excluded = {value.lower() for value in excludes}
            has_loose_artifacts = any(
                str(candidate.resolve()).lower() not in excluded
                for candidate in path.rglob("*")
                if candidate.is_file() and not candidate.is_symlink()
            )
            if has_loose_artifacts or not primary:
                sources.append((path, "artifact_directory", excludes))
            sources.extend(primary)
        else:
            raise SystemExit(f"Evidence path does not exist: {path}")

    seen: set[str] = set()
    deduped: list[tuple[Path, str, list[str]]] = []
    for path, kind, excludes in sources:
        key = str(path.resolve()).lower()
        if key not in seen:
            seen.add(key)
            deduped.append((path, kind, excludes))
    return deduped


def same_registered_evidence(data: dict, inputs: list[str]) -> bool:
    expected = sorted(str(Path(raw).resolve()).lower() for raw in inputs)
    stored = data.get("intake_paths")
    if stored:
        actual = sorted(str(Path(raw).resolve()).lower() for raw in stored)
    else:
        actual = sorted(str(Path(entry["path"]).resolve()).lower() for entry in data.get("evidence", {}).values() if entry.get("path"))
    return actual == expected


def infer_case_name(inputs: list[str], sources: list[tuple[Path, str, list[str]]]) -> str:
    if len(inputs) == 1:
        only = Path(inputs[0])
        if only.is_dir():
            return slug_case_name(only.name)
    primary = next((path for path, kind, _ in sources if kind in {"e01", "disk_image", "memory"}), None)
    if primary:
        stem = re.sub(r"\.(?:e01|ex01|raw|mem|vmem|dmp|dump|lime)$", "", primary.name, flags=re.IGNORECASE)
        return slug_case_name(stem)
    return "case"


def auto_case(args: argparse.Namespace) -> None:
    sources = discover_evidence(args.evidence)
    e01_candidates = [path for path, kind, _ in sources if kind in {"e01", "disk_image"}]
    memory_candidates = [path for path, kind, _ in sources if kind == "memory"]
    if len(e01_candidates) > 1:
        choices = "\n  ".join(str(p) for p in e01_candidates)
        raise SystemExit(f"Multiple E01/EWF sets were found. Aries must choose one explicitly:\n  {choices}")
    if len(memory_candidates) > 1:
        choices = "\n  ".join(str(p) for p in memory_candidates)
        raise SystemExit(f"Multiple memory candidates were found. Aries must choose one explicitly:\n  {choices}")
    base_name = slug_case_name(args.name) if args.name else infer_case_name(args.evidence, sources)
    name = base_name
    suffix = 2
    while (case_dir(name) / "case.json").exists():
        existing = load_case(name)
        if same_registered_evidence(existing, args.evidence):
            print(f"Reusing existing case: {case_dir(name)}")
            print(f"CASE_NAME={name}")
            return
        name = f"{base_name}-{suffix}"
        suffix += 1

    evidence = build_evidence(sources)
    init_case(argparse.Namespace(name=name, e01=None, memory=None, disk=None, artifact=[], description=args.description or "", force=False))
    data = load_case(name)
    data["evidence"] = evidence
    data["intake_paths"] = [str(Path(raw)) for raw in args.evidence]
    # Reset applicability after replacing the placeholder evidence map.
    for phase in ALL_PHASES:
        if data["investigation"]["phases"][phase].get("status") == "skipped":
            data["investigation"]["phases"][phase] = {"status": "pending", "attempts": 0, "started_utc": None, "finished_utc": None, "returncode": None, "message": ""}
    save_case(name, data)
    write_evidence_manifest(name, data)
    print(f"CASE_NAME={name}")


def ewf_segments(first: Path) -> list[Path]:
    match = re.match(r"^(?P<base>.+)\.(?P<series>e|ex)(?P<num>\d+)$", first.name, re.IGNORECASE)
    if not match:
        return [first]
    base = match.group("base").lower()
    series = match.group("series").lower()
    candidates: list[tuple[int, Path]] = []
    for candidate in first.parent.iterdir():
        if not candidate.is_file():
            continue
        cm = re.match(r"^(?P<base>.+)\.(?P<series>e|ex)(?P<num>\d+)$", candidate.name, re.IGNORECASE)
        if cm and cm.group("base").lower() == base and cm.group("series").lower() == series:
            candidates.append((int(cm.group("num")), candidate))
    candidates.sort(key=lambda item: item[0])
    return [path for _, path in candidates] or [first]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(16 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def path_snapshot(path: Path) -> dict:
    stat = path.stat()
    return {
        "path": str(path),
        "size_bytes": stat.st_size,
        "modified_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
    }


def directory_files(path: Path, excludes: list[str] | None = None):
    excluded = {str(Path(item).resolve()).lower() for item in (excludes or [])}
    for candidate in sorted(path.rglob("*")):
        if not candidate.is_file() or candidate.is_symlink():
            continue
        try:
            resolved = str(candidate.resolve()).lower()
        except OSError:
            resolved = str(candidate).lower()
        if resolved in excluded:
            continue
        yield candidate


def hash_entry_current(entry: dict, path: Path, kind: str) -> bool:
    if path.is_dir():
        previous = entry.get("file_sha256") or []
        current = list(directory_files(path, entry.get("exclude_paths")))
        if len(previous) != len(current):
            return False
        for old, candidate in zip(previous, current):
            snap = path_snapshot(candidate)
            if old.get("path", "").lower() != snap["path"].lower() or old.get("size_bytes") != snap["size_bytes"] or old.get("modified_utc") != snap["modified_utc"] or not old.get("sha256"):
                return False
        return True
    if not path.is_file():
        return False
    stat = path.stat()
    mtime = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
    if kind == "e01":
        segments = ewf_segments(path)
        previous = entry.get("segment_sha256") or []
        if len(previous) != len(segments):
            return False
        for old, segment in zip(previous, segments):
            snap = path_snapshot(segment)
            if old.get("path", "").lower() != snap["path"].lower() or old.get("size_bytes") != snap["size_bytes"] or old.get("modified_utc") != snap["modified_utc"] or not old.get("sha256"):
                return False
        return True
    return entry.get("size_bytes") == stat.st_size and entry.get("modified_utc") == mtime and bool(entry.get("sha256"))


def write_evidence_manifest(case_name: str, data: dict | None = None) -> Path:
    data = data or load_case(case_name)
    root = case_dir(case_name)
    manifest = {
        "schema_version": "0.3.4",
        "case": case_name,
        "generated_utc": now_iso(),
        "evidence": data.get("evidence", {}),
        "note": "Split EWF sets use per-segment hashes. Artifact directories use per-file hashes. Aries never invents a synthetic combined SHA256.",
    }
    out = root / "evidence_manifest.json"
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return out


def hash_case(args: argparse.Namespace) -> None:
    data = load_case(args.case)
    kinds = [args.which] if args.which != "all" else list(data.get("evidence", {}).keys())
    if not kinds:
        raise SystemExit("No evidence registered in this case.")
    for kind in kinds:
        entry = data.get("evidence", {}).get(kind)
        if not entry:
            print(f"Skipping {kind}: not registered")
            continue
        path = Path(entry["path"])
        if not path.exists():
            raise SystemExit(f"Evidence missing: {path}")
        if not args.force and hash_entry_current(entry, path, kind):
            print(f"Hash current; skipping unchanged {kind}: {path}")
            continue

        if path.is_dir():
            files = list(directory_files(path, entry.get("exclude_paths")))
            records = []
            total_size = 0
            print(f"Hashing artifact directory {path} ({len(files)} file(s))")
            for candidate in files:
                snap = path_snapshot(candidate)
                snap["sha256"] = sha256_file(candidate)
                snap["relative_path"] = str(candidate.relative_to(path))
                total_size += snap["size_bytes"]
                records.append(snap)
                print(f"SHA256 {snap['sha256']}  {snap['relative_path']}")
            entry.update({"exists": True, "is_dir": True, "file_sha256": records, "file_count": len(records), "size_bytes": total_size, "sha256": None, "hash_verified_utc": now_iso()})
        elif kind == "e01":
            segments = ewf_segments(path)
            segment_hashes = []
            total_size = 0
            print(f"Hashing EWF set from {path} ({len(segments)} segment(s))")
            for segment in segments:
                snap = path_snapshot(segment)
                snap["sha256"] = sha256_file(segment)
                total_size += snap["size_bytes"]
                segment_hashes.append(snap)
                print(f"SHA256 {snap['sha256']}  {segment.name}")
            entry.update(
                {
                    "exists": True,
                    "segment_sha256": segment_hashes,
                    "segment_count": len(segment_hashes),
                    "size_bytes": total_size,
                    "sha256": segment_hashes[0]["sha256"] if len(segment_hashes) == 1 else None,
                    "modified_utc": segment_hashes[0]["modified_utc"],
                    "hash_verified_utc": now_iso(),
                }
            )
        else:
            snap = path_snapshot(path)
            digest = sha256_file(path)
            entry.update(snap)
            entry.update({"exists": True, "sha256": digest, "hash_verified_utc": now_iso()})
            print(f"SHA256 {digest}  {path.name}")

    save_case(args.case, data)
    out = write_evidence_manifest(args.case, data)
    print(f"Evidence manifest: {out}")


def status_case(args: argparse.Namespace) -> None:
    data = load_case(args.case)
    root = case_dir(args.case)
    print(f"Case: {data['name']} | schema={data.get('schema_version', 'legacy')}")
    print(f"Directory: {root}")
    print("\nEvidence:")
    for kind, entry in data.get("evidence", {}).items():
        digest = entry.get("sha256") or ("segment hashes" if entry.get("segment_sha256") else "per-file hashes" if entry.get("file_sha256") else "NOT HASHED")
        print(f"  {kind:8} {entry.get('path')} | {digest}")
    print("\nInvestigation phases:")
    phases = data.get("investigation", {}).get("phases", {})
    for phase in DEFAULT_PHASE_ORDER:
        st = phases.get(phase, {})
        attempts = st.get("attempts", 0)
        msg = f" | {st.get('message')}" if st.get("message") else ""
        print(f"  {phase:20} {st.get('status', 'pending'):11} attempts={attempts}{msg}")
    print("\nOptional phases:")
    for phase in ["disk_timeline"]:
        st = phases.get(phase, {})
        print(f"  {phase:20} {st.get('status', 'pending'):11} attempts={st.get('attempts', 0)}")

    leads = materialize_history(root / "leads.jsonl", "L")
    active_leads = [x for x in leads if x.get("status") == "active"]
    findings = materialize_history(root / "findings.jsonl", "F")
    active_findings = [x for x in findings if x.get("status") == "active"]
    context = load_context(args.case).get("entries", [])
    print(f"\nLead registry: {len(active_leads)} active / {len(leads)} total")
    print(f"Findings: {len(active_findings)} active / {len(findings)} total")
    print(f"Context entries: {len(context)}")

    print("\nOutputs:")
    for rel in [
        "evidence_manifest.json", "artifact_inventory.json", "case_context.json", "leads.jsonl", "findings.jsonl",
        "output/event_triage.json", "output/artifact_triage.json", "output/artifacts/artifact-baseline-manifest.json",
        "output/pivots/pivot-summary.json", "output/evidence-assessment.json", "timeline/targeted_timeline.csv",
        "output/orchestration/review-summary.json", "output/orchestration/decisions.jsonl",
        "iocs.csv", "ioc_candidates.csv", "report/report.md"
    ]:
        print(f"  {rel:36} {'present' if (root / rel).exists() else 'missing'}")


def add_finding(args: argparse.Namespace) -> None:
    load_case(args.case)
    root = case_dir(args.case)
    refs: list[str] = []
    for raw in args.evidence_ref or []:
        candidate = (root / raw.replace("\\", "/")).resolve()
        try:
            relative = candidate.relative_to(root.resolve()).as_posix()
        except ValueError:
            raise SystemExit(f"Evidence reference leaves the case directory: {raw}")
        if not candidate.is_file():
            raise SystemExit(f"Evidence reference does not exist: {raw}")
        refs.append(relative)
    bridge_refs: list[str] = []
    for raw in args.bridge_evidence_ref or []:
        candidate = (root / raw.replace("\\", "/")).resolve()
        try:
            relative = candidate.relative_to(root.resolve()).as_posix()
        except ValueError:
            raise SystemExit(f"Bridge evidence reference leaves the case directory: {raw}")
        if not candidate.is_file():
            raise SystemExit(f"Bridge evidence reference does not exist: {raw}")
        bridge_refs.append(relative)
    finding = records_add_finding(
        args.case, kind=args.kind, title=args.title, severity=args.severity, confidence=args.confidence,
        source=args.source, details=args.details, claim_scope=args.claim_scope,
        evidence_refs=refs, artifact_families=args.artifact_family or [],
        behavior=args.behavior or "", attack_techniques=args.attack_technique or [],
        incident_cluster=args.incident_cluster, limitations=args.limitation or [],
        bridge_evidence_refs=bridge_refs, context_resolution=args.context_resolution or "",
    )
    print(f"{args.kind.title()} recorded as {finding['id']}.")


def retract_finding(args: argparse.Namespace) -> None:
    load_case(args.case)
    records_retract_finding(args.case, args.id, args.reason, args.superseded_by)
    print(f"Finding {args.id} retracted.")


def add_lead_cmd(args: argparse.Namespace) -> None:
    load_case(args.case)
    lead = records_add_lead(
        args.case, lead_type=args.type, value=args.value, priority=args.priority, score=args.score, source=args.source, reason=args.reason,
        timestamp=args.timestamp, parent_id=args.parent_id, context_matches=[]
    )
    print(f"Lead {lead['id']} recorded/updated.")


def update_lead_cmd(args: argparse.Namespace) -> None:
    load_case(args.case)
    changes = {}
    for key in ["priority", "score", "relevance", "notes"]:
        value = getattr(args, key, None)
        if value is not None:
            changes[key] = value
    records_update_lead(args.case, args.id, **changes)
    print(f"Lead {args.id} updated.")


def close_lead_cmd(args: argparse.Namespace) -> None:
    load_case(args.case)
    root = case_dir(args.case)
    leads = {item["id"]: item for item in materialize_history(root / "leads.jsonl", "L")}
    lead = leads.get(args.id)
    if not lead:
        raise SystemExit(f"Lead not found: {args.id}")
    reason = (args.reason or "").strip()
    refs = []
    for raw in args.evidence_ref or []:
        candidate = (root / raw.replace("\\", "/")).resolve()
        try:
            relative = candidate.relative_to(root.resolve()).as_posix()
        except ValueError:
            raise SystemExit(f"Evidence reference leaves the case directory: {raw}")
        if not candidate.is_file():
            raise SystemExit(f"Evidence reference does not exist: {raw}")
        refs.append(relative)
    context_ids = {str(item.get("id")) for item in load_context(args.case).get("entries", [])}
    if args.context_id and args.context_id not in context_ids:
        raise SystemExit(f"Context entry does not exist: {args.context_id}")
    if str(lead.get("priority", "medium")) in {"high", "critical"}:
        if len(reason) < 20:
            raise SystemExit("High/critical lead dispositions require a specific reason of at least 20 characters.")
        if not refs and not args.context_id and not args.review_item:
            raise SystemExit("High/critical lead dispositions require --evidence-ref, --context-id, or --review-item. Generic bulk closure is not accepted.")
    records_close_lead(
        args.case, args.id, args.status, reason,
        evidence_refs=refs, context_id=args.context_id, review_item=args.review_item,
    )
    print(f"Lead {args.id} marked {args.status}.")


def list_leads_cmd(args: argparse.Namespace) -> None:
    load_case(args.case)
    leads = materialize_history(case_dir(args.case) / "leads.jsonl", "L")
    if not args.all:
        leads = [x for x in leads if x.get("status") == "active"]
    leads.sort(key=lambda x: int(x.get("score") or 0), reverse=True)
    for lead in leads:
        print(f"{lead.get('id')} [{lead.get('priority')}/{lead.get('score')}] {lead.get('status')} {lead.get('type')}: {lead.get('value')}")
        print(f"  source={lead.get('source')} relevance={lead.get('relevance', 'unassessed')} reason={lead.get('reason', '')}")


def add_context_cmd(args: argparse.Namespace) -> None:
    load_case(args.case)
    item = records_add_context(args.case, context_type=args.type, value=args.value, details=args.details, source=args.source, confidence=args.confidence)
    print(f"Context {item['id']} recorded: {item['type']}={item['value']}")


def list_context_cmd(args: argparse.Namespace) -> None:
    load_case(args.case)
    for item in load_context(args.case).get("entries", []):
        print(f"{item.get('id')} [{item.get('confidence')}] {item.get('type')}: {item.get('value')} | {item.get('details')}")


def add_ioc(args: argparse.Namespace) -> None:
    root = case_dir(args.case)
    load_case(args.case)
    value = args.value.strip()
    if not value:
        raise SystemExit("IOC value cannot be empty.")
    if not args.source or not args.evidence_ref:
        raise SystemExit("Validated IOCs require --source and at least one --evidence-ref.")
    if args.scope != "malicious":
        raise SystemExit("Only maliciously scoped indicators belong in iocs.csv. Keep internal/known-good/context values as leads or case context.")
    refs = []
    found = False
    for raw in args.evidence_ref:
        candidate = (root / raw.replace("\\", "/")).resolve()
        try:
            relative = candidate.relative_to(root.resolve()).as_posix()
        except ValueError:
            raise SystemExit(f"Evidence reference leaves the case directory: {raw}")
        if not candidate.is_file():
            raise SystemExit(f"Evidence reference does not exist: {raw}")
        refs.append(relative)
        try:
            found = found or value.lower() in candidate.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            pass
    if not found:
        raise SystemExit("IOC value does not appear in the cited evidence reference(s).")
    if args.type == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            raise SystemExit("Invalid IP address.")
        if address.is_private and not args.allow_private:
            raise SystemExit("Private/internal IPs require --allow-private plus evidence showing malicious use; ordinary internal context is not a validated IOC.")
    path = root / "iocs.csv"
    existing = set()
    if path.exists():
        with path.open("r", newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                existing.add((row.get("type", "").lower(), row.get("value", "").lower()))
    key = (args.type.lower(), value.lower())
    if key in existing:
        print("IOC already present; no duplicate added.")
        return
    with path.open("a", newline="", encoding="utf-8") as f:
        notes = (args.notes or "").strip()
        evidence_note = "evidence=" + ";".join(refs)
        csv.writer(f).writerow([args.type, value, args.source, "; ".join(item for item in (notes, evidence_note) if item), now_iso()])
    print("Validated IOC added.")


def iter_text_files(root: Path):
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in TEXT_EXTENSIONS:
            yield p


def normalize_url(value: str) -> str:
    return value.rstrip(".,;:!?)\"'")


def scan_iocs(args: argparse.Namespace) -> None:
    root = case_dir(args.case)
    load_case(args.case)
    # v0.3 deliberately avoids giant whole-disk timelines. IOC candidates come from
    # high-value parser outputs plus the targeted timeline.
    scan_roots = [
        root / "output" / "eztools",
        root / "output" / "artifacts",
        root / "output" / "dissect",
        root / "output" / "volatility",
        root / "output" / "pivots",
        root / "output" / "search",
        root / "output" / "artifact_triage.json",
        root / "timeline" / "targeted_timeline.csv",
        root / "notes.md",
    ]
    found: dict[tuple[str, str], set[str]] = {}
    skipped_large: list[str] = []
    max_bytes = int(getattr(args, "max_file_mb", 100)) * 1024 * 1024

    def add(kind: str, value: str, source: Path):
        found.setdefault((kind, value), set()).add(str(source.relative_to(root)))

    files: list[Path] = []
    for sr in scan_roots:
        if sr.is_file():
            files.append(sr)
        elif sr.exists():
            files.extend(iter_text_files(sr))

    for p in files:
        try:
            if p.stat().st_size > max_bytes:
                skipped_large.append(str(p.relative_to(root)))
                continue
            with p.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    for value in URL_RE.findall(line):
                        value = normalize_url(value)
                        add("url", value, p)
                        host = urlparse(value).hostname
                        if host:
                            try:
                                ipaddress.ip_address(host)
                                add("ip", host, p)
                            except ValueError:
                                add("domain", host.lower(), p)
                    for value in IP_RE.findall(line):
                        add("ip", value, p)
                    for value in SHA256_RE.findall(line):
                        add("sha256", value.lower(), p)
                    for value in SHA1_RE.findall(line):
                        add("sha1", value.lower(), p)
                    for value in MD5_RE.findall(line):
                        add("md5", value.lower(), p)
                    for value in DOMAIN_RE.findall(line):
                        suffix = value.rsplit(".", 1)[-1].lower()
                        if suffix not in COMMON_NON_DOMAIN_SUFFIXES:
                            add("domain", value.lower(), p)
        except OSError:
            continue

    out = root / "ioc_candidates.csv"
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["type", "value", "sources", "review_status", "notes"])
        for (kind, value), sources in sorted(found.items()):
            w.writerow([kind, value, "; ".join(sorted(sources)), "REVIEW", ""] )

    manifest = root / "output" / "ioc-scan-manifest.json"
    manifest.write_text(json.dumps({
        "schema_version": "0.3.4",
        "generated_utc": now_iso(),
        "candidate_count": len(found),
        "max_file_mb": int(getattr(args, "max_file_mb", 100)),
        "skipped_large_files": skipped_large,
        "note": "Whole-disk timeline files are intentionally excluded from automatic IOC scanning."
    }, indent=2), encoding="utf-8")
    print(f"Wrote {len(found)} IOC candidates to {out}")
    if skipped_large:
        print(f"Skipped {len(skipped_large)} oversized file(s); see {manifest}")


def load_findings(root: Path) -> list[dict]:
    return materialize_history(root / "findings.jsonl", "F")


def load_iocs(root: Path) -> list[dict]:
    path = root / "iocs.csv"
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        rows = []
        for row in csv.DictReader(f):
            kind = str(row.get("type", "")).strip().lower()
            value = str(row.get("value", "")).strip()
            notes = str(row.get("notes", "")).lower()
            if not kind or not value:
                continue
            if any(token in notes for token in ("not confirmed", "internal context", "known good", "known-good")):
                continue
            if value.lower() in {"explorer.exe", "svchost.exe", "services.exe", "lsass.exe"}:
                continue
            rows.append(row)
        return rows


def significant_timeline_rows(root: Path, findings: list[dict], limit: int = 20) -> list[dict]:
    """Select a compact, finding-centered timeline preview for the report.

    The full targeted timeline remains the authoritative export. This preview
    keeps the Markdown report useful without dumping thousands of pivot rows.
    """
    path = root / "timeline" / "targeted_timeline.csv"
    if not path.is_file() or not findings:
        return []
    finding_text = " ".join(
        str(item.get(key) or "")
        for item in findings
        for key in ("title", "details", "behavior")
    )
    entities = set(re.findall(r"\b[\w.-]+\.(?:exe|dll|sys|zip|7z|rar|ps1|bat|cmd)\b", finding_text, re.IGNORECASE))
    entities.update(IP_RE.findall(finding_text))
    entities.update(re.findall(r"https?://[^\s`'\"<>]+", finding_text, re.IGNORECASE))
    entities = {value.lower().rstrip(".,;)") for value in entities if len(value) >= 4}
    dates = set(re.findall(r"\b20\d\d-\d\d-\d\d\b", finding_text))
    if not entities:
        return []
    selected: list[dict] = []
    seen: set[tuple[str, str]] = set()
    try:
        with path.open("r", newline="", encoding="utf-8-sig", errors="replace") as handle:
            for row in csv.DictReader(handle):
                timestamp = str(row.get("timestamp") or "")
                event = str(row.get("event") or "")
                lower = event.lower()
                if dates and not any(timestamp.startswith(value) for value in dates):
                    continue
                if not any(value in lower for value in entities):
                    continue
                key = (timestamp, re.sub(r"\s+", " ", lower)[:500])
                if key in seen:
                    continue
                seen.add(key)
                selected.append({
                    "timestamp": timestamp,
                    "lead_id": str(row.get("lead_id") or ""),
                    "source": str(row.get("source") or "").replace("\\", "/"),
                    "event": re.sub(r"\s+", " ", event).strip()[:300],
                })
                if len(selected) >= limit:
                    break
    except (OSError, csv.Error):
        return []
    return selected


def report_case(args: argparse.Namespace) -> None:
    seed_deterministic_answers(args.case)
    data = load_case(args.case)
    root = case_dir(args.case)
    findings = load_findings(root)
    active_findings = [x for x in findings if x.get("status") == "active"]
    retracted_findings = [x for x in findings if x.get("status") == "retracted"]
    leads = materialize_history(root / "leads.jsonl", "L")
    active_leads = [x for x in leads if x.get("status") == "active"]
    material_leads = [x for x in active_leads if x.get("priority") in {"critical", "high"}]
    backlog_leads = [x for x in active_leads if x.get("priority") not in {"critical", "high"}]
    context = load_context(args.case).get("entries", [])
    question_state = load_questions(args.case)
    questions = question_state.get("questions", [])
    iocs = load_iocs(root)
    assessment_path = root / "output" / "evidence-assessment.json"
    assessment = json.loads(assessment_path.read_text(encoding="utf-8")) if assessment_path.exists() else {
        "report_ready": False,
        "blocking_issue_count": 1,
        "issues": [{"code": "ASSESSMENT_MISSING", "severity": "high", "message": "Evidence assessment was not run."}],
    }
    if assessment.get("schema_version") != ASSESSMENT_SCHEMA_VERSION:
        assessment = {
            "schema_version": ASSESSMENT_SCHEMA_VERSION,
            "report_ready": False,
            "blocking_issue_count": 1,
            "issues": [{"code": "ASSESSMENT_STALE", "severity": "high", "message": "Evidence assessment predates the analyst-question report gate and must be rerun."}],
        }
    # Assessment is a quality classification, not a report-availability lock.
    # Always preserve the investigation's current state in a report. When the
    # quality checklist has unresolved items, label the output PARTIAL and
    # render every issue instead of trapping the case in a generation loop.
    orchestration_path = root / "output" / "orchestration" / "review-summary.json"
    orchestration = json.loads(orchestration_path.read_text(encoding="utf-8")) if orchestration_path.exists() else None
    out = root / "report" / "report.md"
    out.parent.mkdir(parents=True, exist_ok=True)

    analysis_status_path = root / "output" / "web" / "analysis-status.json"
    try:
        analysis_status = json.loads(analysis_status_path.read_text(encoding="utf-8")) if analysis_status_path.is_file() else {}
    except (OSError, json.JSONDecodeError):
        analysis_status = {}
    if assessment.get("report_ready"):
        report_label = "COMPLETE — READY FOR HUMAN REVIEW"
    elif analysis_status.get("status") == "failed":
        report_label = "PARTIAL REPORT — AI SYNTHESIS UNAVAILABLE; DETERMINISTIC EVIDENCE PRESERVED"
    else:
        report_label = "PARTIAL REPORT — UNRESOLVED ITEMS ARE LISTED BELOW"

    evidence_candidates: dict[str, list[dict]] = {}
    pending_questions = [item for item in questions if item.get("status") == "pending"]
    if pending_questions:
        try:
            from case_datalake import search_index
            excluded = {
                "analyst-questions.json", "investigation-brief.json", "leads.jsonl", "findings.jsonl",
                "case.json", "case_context.json", "artifact_inventory.json", "evidence_manifest.json",
                "iocs.csv", "ioc_candidates.csv", "notes.md", "output/evidence-assessment.json",
                "output/lead-priority-budget.json", "report/report.md",
            }
            scope_entities = re.findall(
                r"\b[\w.-]+\.(?:exe|dll|sys|zip|7z|rar|ps1|bat|cmd|rtf|docx?|xlsx?|pdf|txt)\b|"
                r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])",
                str(data.get("description") or ""),
                re.IGNORECASE,
            )
            entity_hint = " ".join(list(dict.fromkeys(scope_entities))[:12])
            for question in pending_questions[:20]:
                query = f"{question.get('question') or ''} {entity_hint}".strip()
                result = search_index(root, query, limit=16)
                useful = [
                    item for item in result.get("results", [])
                    if str(item.get("path") or "") not in excluded
                    and not str(item.get("path") or "").startswith("report/")
                ][:3]
                if useful:
                    evidence_candidates[str(question.get("id"))] = useful
        except (OSError, ValueError, ImportError):
            evidence_candidates = {}

    brief_path = root / "investigation-brief.json"
    try:
        brief = json.loads(brief_path.read_text(encoding="utf-8")).get("instructions", "") if brief_path.is_file() else ""
    except (OSError, json.JSONDecodeError):
        brief = ""
    scope_text = data.get("description") or brief or "Investigation scope to be finalized by the analyst."
    # load_case() removes only empty upload-container duplicates. Any artifact
    # directory that remains here contains distinct loose evidence and must be
    # represented in the report even if it has not yet been directory-hashed.
    display_evidence = list(data.get("evidence", {}).items())

    lines = [
        f"# Aries DFIR Investigation Report - {data['name']}",
        "",
        f"**Report status:** {report_label}",
        "",
        "## Scope",
        "",
        scope_text,
        "",
        "## Evidence Integrity",
        "",
    ]
    for kind, entry in display_evidence:
        lines.append(f"- **{kind.upper()}**: `{entry.get('path')}`")
        lines.append(f"  - Size: {entry.get('size_bytes') or 'not recorded'} bytes")
        if entry.get("segment_sha256"):
            for segment in entry["segment_sha256"]:
                lines.append(f"  - `{Path(segment['path']).name}` SHA256 `{segment['sha256']}`")
        elif entry.get("file_sha256"):
            lines.append(f"  - Directory manifest: {entry.get('file_count', len(entry['file_sha256']))} file(s), each hashed separately")
        else:
            lines.append(f"  - SHA256: `{entry.get('sha256') or 'not calculated'}`")

    inventory_path = root / "artifact_inventory.json"
    if inventory_path.exists():
        try:
            summary = json.loads(inventory_path.read_text(encoding="utf-8")).get("summary", {})
            lines += ["", "## Artifact Coverage", "", f"- Registered evidence sources: {len(display_evidence)}", f"- Artifacts inventoried: {summary.get('artifacts_found', 0)}", f"- Event logs inventoried: {summary.get('event_logs_found', 0)}", f"- User hives inventoried: {summary.get('user_hives_found', 0)}", f"- Artifact types: `{json.dumps(summary.get('artifact_types', {}), sort_keys=True)}`"]
        except json.JSONDecodeError:
            pass

    lines += ["", "## Known Case Context", ""]
    if context:
        for item in context:
            lines.append(f"- **{item.get('type')}** `{item.get('value')}` ({item.get('confidence')}) — {item.get('details')}")
    else:
        lines.append("No explicit analyst-supplied context has been recorded. Dual-use artifacts require corroboration.")

    confirmed_titles = [item.get("title", "Untitled") for item in active_findings if item.get("kind") == "confirmed"]
    material_titles = [item.get("title", "Untitled") for item in active_findings if item.get("severity") in {"critical", "high", "medium"}]
    answered_count = sum(1 for item in questions if item.get("status") == "answered")
    unresolved_count = sum(1 for item in questions if item.get("status") == "unresolved")
    summary_text = (
        f"The investigation recorded {len(active_findings)} active finding(s), including {len(confirmed_titles)} confirmed conclusion(s). "
        + ("Confirmed conclusions: " + "; ".join(confirmed_titles[:6]) + ". " if confirmed_titles else "")
        + ("Material observed or inferred conclusions: " + "; ".join(material_titles[:8]) + ". " if material_titles else "")
        + (f"Of {len(questions)} analyst-requested questions, {answered_count} were answered and {unresolved_count} were explicitly unresolved." if questions else "No explicit analyst question list was supplied.")
    )

    lines += [
        "",
        "## Executive Summary",
        "",
        summary_text,
    ]
    if analysis_status.get("status") == "failed":
        lines += [
            "",
            f"**AI synthesis status:** unavailable during this run. {analysis_status.get('message') or 'The forensic processing completed, but the configured model did not complete.'}",
            "The report below preserves deterministic results and evidence candidates. Use **Retry AI synthesis** to complete narrative answers without rerunning forensic parsers.",
        ]
    lines += [
        "",
        "## Analyst-Requested Questions",
        "",
    ]
    if questions:
        for question in questions:
            lines += [
                f"### {question.get('id')} — {question.get('question')}",
                "",
                f"- Status: **{str(question.get('status', 'pending')).upper()}**",
                f"- Answer: {question.get('answer') or 'Not answered.'}",
                f"- Confidence: {question.get('confidence', 'unassessed')}",
                f"- Evidence: {', '.join(f'`{ref}`' for ref in question.get('evidence_refs', [])) or 'none'}",
                f"- Causal/cluster bridge evidence: {', '.join(f'`{ref}`' for ref in question.get('bridge_evidence_refs', [])) or 'none'}",
                f"- Limitation: {question.get('limitation') or 'none recorded'}",
            ]
            candidates = evidence_candidates.get(str(question.get("id")), [])
            if candidates and question.get("status") == "pending":
                lines.append("- Deterministic evidence candidates (not an AI conclusion):")
                for candidate in candidates:
                    excerpt = re.sub(r"\s+", " ", str(candidate.get("content") or "")).strip()[:420]
                    lines.append(f"  - `{candidate.get('citation')}` — {excerpt}")
            lines.append("")
    else:
        lines.append("No explicit questions were extracted from the analyst brief.")

    lines += [
        "",
        "## Material Active Leads",
        "",
    ]
    if material_leads:
        lines += ["| ID | Priority | Score | Type | Value | Relevance |", "|---|---|---:|---|---|---|"]
        for lead in sorted(material_leads, key=lambda x: int(x.get("score") or 0), reverse=True)[:12]:
            value = str(lead.get("value", "")).replace("|", "\\|")
            lines.append(f"| {lead.get('id')} | {lead.get('priority')} | {lead.get('score')} | {lead.get('type')} | `{value}` | {lead.get('relevance', 'unassessed')} |")
    else:
        lines.append("No active high/critical leads recorded.")
    if backlog_leads:
        lines.append(f"\n{len(backlog_leads)} medium/low informational lead(s) remain in the searchable backlog and are omitted from this report table.")

    lines += ["", "## Findings", ""]
    if active_findings:
        for finding in active_findings:
            lines += [
                f"### {finding.get('id', '')} — {finding.get('title', 'Untitled')}",
                "",
                f"- Classification: **{finding.get('kind', 'observation')}**",
                f"- Severity: **{finding.get('severity', 'unknown')}**",
                f"- Confidence: **{finding.get('confidence', 'unknown')}**",
                f"- Claim scope: **{finding.get('claim_scope', 'factual')}**",
                f"- Source: `{finding.get('source', '')}`",
                f"- Evidence references: {', '.join(f'`{ref}`' for ref in finding.get('evidence_refs', [])) or 'not structured'}",
                f"- Independent artifact families: {', '.join(finding.get('artifact_families', [])) or 'not structured'}",
                f"- Recorded context matches: {', '.join(finding.get('context_matches', [])) or 'none'}",
                f"- Context resolution: {finding.get('context_resolution') or 'not required / not supplied'}",
                f"- Temporal bridge evidence: {', '.join(f'`{ref}`' for ref in finding.get('bridge_evidence_refs', [])) or 'none'}",
                f"- Observed behavior: {finding.get('behavior') or 'not specified'}",
                f"- Details: {finding.get('details', '')}",
                "",
            ]
    else:
        lines.append("No active structured findings recorded yet.")

    if retracted_findings:
        lines += ["", "### Retracted / Superseded Findings", ""]
        for finding in retracted_findings:
            lines.append(f"- `{finding.get('id')}` ~~{finding.get('title', 'Untitled')}~~ — {finding.get('retracted_reason', 'retracted')}")

    lines += ["", "## Optional Second Opinion", ""]
    if orchestration:
        provenance = orchestration.get("review_provenance", {})
        lines += [
            f"- Snapshot: `{orchestration.get('snapshot_id')}`",
            f"- Reviewers completed: {', '.join(orchestration.get('roles_completed', [])) or 'none'}",
            f"- Reviewer disagreements: **{orchestration.get('disagreement_count', 0)}**",
            f"- Candidate leads proposed: **{len(orchestration.get('candidate_leads', []))}**",
            f"- Advisory report-ready recommendation: **{orchestration.get('report_ready_recommendation', False)}**",
            "- Reviewer agreement is not forensic corroboration; authoritative conclusions remain tied to artifact evidence.",
        ]
        for role in ("investigator", "validator"):
            record = provenance.get(role, {})
            lines.append(
                f"- {role.title()} provenance: source `{record.get('source', 'missing')}`, "
                f"model `{record.get('provider_model', 'unknown')}`, child `{record.get('child_id', 'unknown')}`"
            )
    else:
        lines.append("Not run. A second model opinion is optional and is not required for report readiness.")

    lines += ["", "## Evidence Assessment", "", f"- Report ready: **{assessment.get('report_ready', False)}**", f"- Blocking issues: **{assessment.get('blocking_issue_count', 0)}**"]
    for item in assessment.get("issues", []):
        linked_id = item.get("finding_id") or item.get("lead_id")
        lines.append(f"- **{item.get('severity', 'unknown').upper()} {item.get('code')}**: {item.get('message')}" + (f" (`{linked_id}`)" if linked_id else ""))

    lines += [
        "",
        "## Targeted Timeline",
        "",
    ]
    targeted = root / "timeline" / "targeted_timeline.csv"
    if targeted.exists():
        lines.append("Lead-centered timeline generated at `timeline/targeted_timeline.csv` (Markdown view: `timeline/targeted_timeline.md`).")
        preview = significant_timeline_rows(root, active_findings)
        if preview:
            lines += ["", "### Significant Events", "", "| Time | Lead | Source | Event |", "|---|---|---|---|"]
            for row in preview:
                event = row["event"].replace("|", "\\|")
                source = row["source"].replace("|", "\\|")
                lines.append(f"| {row['timestamp']} | {row['lead_id']} | `{source}` | {event} |")
    else:
        lines.append("No targeted timeline has been generated yet.")
    phase_problems = []
    for phase, state in data.get("investigation", {}).get("phases", {}).items():
        if state.get("status") in {"partial", "failed", "interrupted"} and not (phase == "evidence_assessment" and assessment.get("report_ready")):
            phase_problems.append(f"- **{phase}**: {state.get('status')} — {state.get('message', '')}")

    lines += [
        "",
        "## Indicators of Compromise",
        "",
    ]
    if iocs:
        lines += ["| Type | Value | Source | Notes |", "|---|---|---|---|"]
        for row in iocs:
            lines.append(f"| {row.get('type','')} | `{row.get('value','')}` | {row.get('source','')} | {row.get('notes','')} |")
    else:
        lines.append("No validated IOCs recorded yet. IOC candidates are not verdicts.")

    lines += [
        "",
        "## Analysis",
        "",
        *( [f"- **{item.get('title', 'Untitled')}**: {item.get('details', '')}" for item in active_findings] or ["No active structured findings were available for narrative analysis."] ),
        "",
        "## Limitations",
        "",
        *(phase_problems or ["No partial/failed phase state was recorded. Parser-specific manifests and remaining evidence gaps still require human review."]),
        "",
        "## Recommended Next Steps",
        "",
        *( [f"Resolve or document {item.get('id')}: {item.get('question')}" for item in questions if item.get("status") in {"pending", "unresolved"}] or ["No analyst-requested requirement remains pending or unresolved."] ),
        *( [f"Adjudicate material lead {item.get('id')} ({item.get('value')}) before expanding broad collection." for item in material_leads[:10]] or [] ),
        "",
    ]
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"REPORT_STATUS={'COMPLETE' if assessment.get('report_ready') else 'PARTIAL'}")
    print(f"Report written: {out}")


def reset_phase(args: argparse.Namespace) -> None:
    data = load_case(args.case)
    phases = data["investigation"]["phases"]
    targets = ALL_PHASES if args.phase == "all" else [args.phase]
    for phase in targets:
        phases[phase] = {
            "status": "pending",
            "attempts": phases.get(phase, {}).get("attempts", 0),
            "started_utc": None,
            "finished_utc": None,
            "returncode": None,
            "message": "Reset for rerun.",
        }
    save_case(args.case, data)
    print("Reset phase(s):", ", ".join(targets))


def answer_question_cmd(args: argparse.Namespace) -> None:
    load_case(args.case)
    try:
        record = record_answer(
            args.case,
            args.id,
            status=args.status,
            answer=args.answer or "",
            confidence=args.confidence,
            evidence_refs=args.evidence_ref or [],
            bridge_evidence_refs=args.bridge_evidence_ref or [],
            limitation=args.limitation or "",
        )
    except (KeyError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    print(f"{record['id']} recorded as {record['status']}.")


def list_questions_cmd(args: argparse.Namespace) -> None:
    load_case(args.case)
    print(json.dumps(load_questions(args.case), indent=2, ensure_ascii=False))


def seed_answers_cmd(args: argparse.Namespace) -> None:
    answered = seed_deterministic_answers(args.case)
    print(json.dumps({"case": args.case, "answered": answered, "count": len(answered)}, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Aries v0.3.4 evidence-set case/lead/context manager")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="Create a case")
    p.add_argument("--name", required=True)
    p.add_argument("--e01")
    p.add_argument("--memory")
    p.add_argument("--disk", help="Non-EWF disk image such as DD/IMG/VHD/VMDK")
    p.add_argument("--artifact", action="append", help="Loose artifact file or directory; repeat as needed")
    p.add_argument("--description")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=init_case)

    p = sub.add_parser("auto", help="Create or resume a case from evidence paths")
    p.add_argument("--evidence", action="append", required=True)
    p.add_argument("--name")
    p.add_argument("--description")
    p.set_defaults(func=auto_case)

    p = sub.add_parser("status", help="Show evidence and resumable phase state")
    p.add_argument("--case", required=True)
    p.set_defaults(func=status_case)

    p = sub.add_parser("hash", help="SHA256 evidence and update evidence_manifest.json")
    p.add_argument("--case", required=True)
    p.add_argument("--which", default="all", help="Evidence key from case.json, or all")
    p.add_argument("--force", action="store_true", help="Rehash even when size/mtime/hash metadata says evidence is unchanged")
    p.set_defaults(func=hash_case)

    p = sub.add_parser("finding", help="Record an observation, hypothesis, inference, or confirmed finding")
    p.add_argument("--case", required=True)
    p.add_argument("--kind", choices=["observation", "hypothesis", "inference", "confirmed"], default="observation")
    p.add_argument("--title", required=True)
    p.add_argument("--severity", choices=["informational", "low", "medium", "high", "critical"], default="medium")
    p.add_argument("--confidence", choices=["low", "medium", "high"], default="medium")
    p.add_argument("--source", required=True)
    p.add_argument("--details", required=True)
    p.add_argument("--claim-scope", choices=["factual", "malicious", "attribution", "capability"], default="factual")
    p.add_argument("--evidence-ref", action="append", help="Exact case-relative artifact/output reference; repeat as needed")
    p.add_argument("--artifact-family", action="append", help="Independent evidence family, e.g. sysmon, defender, registry, prefetch, memory")
    p.add_argument("--behavior", help="Observed behavior supporting any ATT&CK mapping or capability claim")
    p.add_argument("--attack-technique", action="append", help="Observed ATT&CK technique ID; repeat as needed")
    p.add_argument("--incident-cluster", help="Cluster identifier used to avoid joining unrelated historical activity")
    p.add_argument("--bridge-evidence-ref", action="append", help="Exact case-relative evidence that bridges distant activity; repeat as needed")
    p.add_argument("--context-resolution", help="Evidence-based reason a recorded benign/training/admin context does not explain this confirmed finding")
    p.add_argument("--limitation", action="append", help="Finding-specific limitation; repeat as needed")
    p.set_defaults(func=add_finding)

    p = sub.add_parser("finding-retract", help="Retract/supersede a prior finding without deleting audit history")
    p.add_argument("--case", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--superseded-by")
    p.set_defaults(func=retract_finding)

    p = sub.add_parser("lead", help="Seed an analyst/event-derived investigation lead")
    p.add_argument("--case", required=True)
    p.add_argument("--type", required=True, choices=["process", "file", "sha256", "ip", "domain", "url", "user", "service", "scheduled_task", "powershell", "detection", "other"])
    p.add_argument("--value", required=True)
    p.add_argument("--priority", choices=["informational", "low", "medium", "high", "critical"], default="medium")
    p.add_argument("--score", type=int, default=50)
    p.add_argument("--source", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--timestamp")
    p.add_argument("--parent-id")
    p.set_defaults(func=add_lead_cmd)

    p = sub.add_parser("lead-list", help="List active leads by default")
    p.add_argument("--case", required=True)
    p.add_argument("--all", action="store_true")
    p.set_defaults(func=list_leads_cmd)

    p = sub.add_parser("lead-update", help="Update lead priority/score/relevance/notes")
    p.add_argument("--case", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--priority", choices=["informational", "low", "medium", "high", "critical"])
    p.add_argument("--score", type=int)
    p.add_argument("--relevance", choices=["high", "medium", "low", "context-sensitive", "unassessed"])
    p.add_argument("--notes")
    p.set_defaults(func=update_lead_cmd)

    p = sub.add_parser("lead-close", help="Close a lead as confirmed, benign, unresolved, contextual, or false-positive")
    p.add_argument("--case", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--status", required=True, choices=["closed", "resolved", "confirmed", "benign", "unresolved", "contextual", "false_positive"])
    p.add_argument("--reason")
    p.add_argument("--evidence-ref", action="append", help="Case-relative artifact supporting this disposition; repeat as needed")
    p.add_argument("--context-id", help="Recorded case-context ID supporting a contextual/benign disposition")
    p.add_argument("--review-item", help="Adjudicated orchestration review item supporting this disposition")
    p.set_defaults(func=close_lead_cmd)

    p = sub.add_parser("context-add", help="Record analyst-known context such as training, acquisition, known-good, or environment facts")
    p.add_argument("--case", required=True)
    p.add_argument("--type", required=True, choices=["training", "evidence_collection", "known_good", "analyst_activity", "environment", "other"])
    p.add_argument("--value", required=True)
    p.add_argument("--details", required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--confidence", choices=["low", "medium", "high"], default="high")
    p.set_defaults(func=add_context_cmd)

    p = sub.add_parser("context-list", help="List recorded case context")
    p.add_argument("--case", required=True)
    p.set_defaults(func=list_context_cmd)

    p = sub.add_parser("ioc", help="Add a validated IOC")
    p.add_argument("--case", required=True)
    p.add_argument("--type", required=True, choices=["ip", "domain", "url", "md5", "sha1", "sha256", "email", "filepath", "other"])
    p.add_argument("--value", required=True)
    p.add_argument("--source")
    p.add_argument("--notes")
    p.add_argument("--evidence-ref", action="append")
    p.add_argument("--scope", choices=["malicious", "context"], default="malicious")
    p.add_argument("--allow-private", action="store_true", help="Allow a private IP only when cited evidence proves malicious use")
    p.set_defaults(func=add_ioc)

    p = sub.add_parser("ioc-scan", help="Extract IOC candidates from high-value case output (huge whole-disk timelines excluded)")
    p.add_argument("--case", required=True)
    p.add_argument("--max-file-mb", type=int, default=100)
    p.set_defaults(func=scan_iocs)

    p = sub.add_parser("report", help="Generate a Markdown report from case state")
    p.add_argument("--case", required=True)
    p.add_argument("--allow-draft", action="store_true", help="Compatibility flag; reports with unresolved issues are generated automatically and labeled PARTIAL")
    p.set_defaults(func=report_case)

    p = sub.add_parser("questions", help="List analyst-requested questions and their answer state")
    p.add_argument("--case", required=True)
    p.set_defaults(func=list_questions_cmd)

    p = sub.add_parser("answer-seed", help="Record deterministic answers such as registered evidence hashes")
    p.add_argument("--case", required=True)
    p.set_defaults(func=seed_answers_cmd)

    p = sub.add_parser("answer", help="Record an evidence-cited answer or explicit unresolved limitation")
    p.add_argument("--case", required=True)
    p.add_argument("--id", required=True, help="Question ID such as Q-001")
    p.add_argument("--status", required=True, choices=["answered", "unresolved"])
    p.add_argument("--answer")
    p.add_argument("--confidence", choices=["high", "medium", "low", "unassessed"], default="medium")
    p.add_argument("--evidence-ref", action="append", help="Exact case-relative evidence reference; repeat as needed")
    p.add_argument("--bridge-evidence-ref", action="append", help="Exact evidence that proves a causal or cross-cluster link; repeat as needed")
    p.add_argument("--limitation", help="Why the requested answer remains unresolved")
    p.set_defaults(func=answer_question_cmd)

    p = sub.add_parser("reset-phase", help="Reset one investigation phase so Aries can rerun it")
    p.add_argument("--case", required=True)
    p.add_argument("--phase", required=True, choices=ALL_PHASES + ["all"])
    p.set_defaults(func=reset_phase)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
