from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from case import classify_evidence_file, directory_files
from common import case_dir, evidence_entries, load_case

STATIC_ARTIFACTS = [
    ("mft", "sysvol/$MFT", "MFTECmd"),
    ("usnjrnl", "sysvol/$Extend/$UsnJrnl:$J", "MFTECmd"),
    ("amcache", "sysvol/Windows/AppCompat/Programs/Amcache.hve", "AmcacheParser"),
    ("srum", "sysvol/Windows/System32/sru/SRUDB.dat", "SrumECmd"),
    ("registry_hive", "sysvol/Windows/System32/config/SYSTEM", "RECmd"),
    ("registry_hive", "sysvol/Windows/System32/config/SOFTWARE", "RECmd"),
    ("registry_hive", "sysvol/Windows/System32/config/SAM", "RECmd"),
    ("registry_hive", "sysvol/Windows/System32/config/SECURITY", "RECmd"),
    ("registry_hive", "sysvol/Windows/System32/config/DEFAULT", "RECmd"),
    ("prefetch_directory", "sysvol/Windows/Prefetch", "PECmd"),
    ("recycle_bin_directory", "sysvol/$Recycle.Bin", "RBCmd"),
]

TIER1_HINTS = [
    ("sysmon%4operational.evtx", "Sysmon process/network/file telemetry"),
    ("windows defender%4operational.evtx", "Defender detections/actions"),
    ("powershell%4operational.evtx", "PowerShell operational telemetry"),
    ("security.evtx", "Authentication/process/audit telemetry"),
    ("system.evtx", "Services/drivers/system changes"),
    ("application.evtx", "Application crash/installer telemetry"),
]

TIER2_HINTS = [
    ("taskscheduler%4operational.evtx", "Scheduled task telemetry"),
    ("wmi-activity%4operational.evtx", "WMI execution telemetry"),
    ("terminalservices", "RDP/Terminal Services telemetry"),
    ("remotedesktopservices", "Remote Desktop telemetry"),
    ("windowsremote", "WinRM/PowerShell remoting telemetry"),
    ("winrm%4operational.evtx", "WinRM telemetry"),
    ("bits-client%4operational.evtx", "BITS transfer telemetry"),
    ("windows firewall", "Firewall telemetry"),
    ("smbclient", "SMB client telemetry"),
    ("smbserver", "SMB server telemetry"),
    ("dns-client", "DNS client telemetry"),
    ("applocker", "Application control telemetry"),
    ("codeintegrity", "Code integrity telemetry"),
    ("grouppolicy", "Group Policy telemetry"),
    ("kernel-pnp", "Device/driver telemetry"),
]

SUGGESTED_TOOLS = {
    "event_log": "EvtxECmd", "registry_hive": "RECmd/SBECmd", "prefetch": "PECmd",
    "amcache": "AmcacheParser", "srum": "SrumECmd", "mft": "MFTECmd",
    "usnjrnl": "MFTECmd", "lnk": "LECmd", "jumplist": "JLECmd",
    "recycle_bin": "RBCmd", "browser": "SQLECmd/manual SQLite review", "windows_timeline": "WxTCmd",
    "archive": "Safe extraction + content-based static analysis; never execute contents", "text_log": "Static text/script analysis + search correlation",
    "artifact": "Content-based static classification; never execute contents",
}


def eventlog_tier(name: str) -> tuple[int, str]:
    lower = name.lower()
    for hint, reason in TIER1_HINTS:
        if hint in lower:
            return 1, reason
    for hint, reason in TIER2_HINTS:
        if hint in lower:
            return 2, reason
    return 3, "Available event telemetry; parse on demand when a lead points here"


def describe_internal(target, internal: str) -> dict:
    p = target.fs.path(internal)
    exists = p.exists()
    item = {"path": internal, "exists": bool(exists), "is_file": False, "is_dir": False, "size_bytes": None}
    if exists:
        try:
            item["is_file"] = p.is_file(); item["is_dir"] = p.is_dir()
            if item["is_file"]:
                item["size_bytes"] = p.stat().st_size
        except Exception as exc:
            item["error"] = str(exc)
    return item


def loose_record(path: Path, source_key: str, source_root: Path) -> dict:
    kind = classify_evidence_file(path)
    stat = path.stat()
    return {
        "artifact_type": kind, "name": path.name, "path": str(path),
        "relative_path": str(path.relative_to(source_root)) if path != source_root else path.name,
        "source_type": "loose", "source_key": source_key, "exists": True,
        "is_file": True, "is_dir": False, "size_bytes": stat.st_size,
        "suggested_tool": SUGGESTED_TOOLS.get(kind, "Manual validation"),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Discover artifacts across disk images and loose evidence sets")
    ap.add_argument("--case", required=True)
    ap.add_argument("--max-loose-files", type=int, default=100000)
    args = ap.parse_args()

    case = load_case(args.case)
    artifacts: list[dict] = []; user_hives: list[dict] = []; eventlogs: list[dict] = []
    errors: list[dict] = []; sources: list[dict] = []

    for source_key, entry in evidence_entries(case):
        kind = str(entry.get("kind") or source_key); path = Path(entry.get("path", ""))
        sources.append({"key": source_key, "kind": kind, "path": str(path), "exists": path.exists()})
        if not path.exists() or kind == "memory":
            continue

        if kind in {"e01", "disk_image"} and path.is_file():
            try:
                # Artifact-only cases must not depend on Dissect being
                # importable. Load it only when an image actually needs it.
                from dissect.target import Target
                target = Target.open(str(path))
                for artifact_type, internal, tool in STATIC_ARTIFACTS:
                    item = describe_internal(target, internal)
                    item.update({"artifact_type": artifact_type, "name": Path(internal).name, "suggested_tool": tool, "source_type": "image", "source_key": source_key})
                    artifacts.append(item)

                users_dir = target.fs.path("sysvol/Users")
                if users_dir.exists() and users_dir.is_dir():
                    for user_dir in users_dir.iterdir():
                        try:
                            if not user_dir.is_dir(): continue
                            for hive_name in ["NTUSER.DAT", "AppData/Local/Microsoft/Windows/UsrClass.dat"]:
                                hive = user_dir / hive_name
                                if hive.exists() and hive.is_file():
                                    record = {"artifact_type": "registry_hive", "name": hive.name, "path": str(hive), "user": user_dir.name, "source_type": "image", "source_key": source_key, "exists": True, "is_file": True, "is_dir": False, "size_bytes": hive.stat().st_size, "suggested_tool": "RECmd/SBECmd"}
                                    user_hives.append(record); artifacts.append(record)
                        except Exception:
                            continue

                logs_dir = target.fs.path("sysvol/Windows/System32/winevt/Logs")
                if logs_dir.exists() and logs_dir.is_dir():
                    for child in logs_dir.iterdir():
                        try:
                            if not child.is_file() or not child.name.lower().endswith(".evtx"): continue
                            tier, reason = eventlog_tier(child.name)
                            record = {"artifact_type": "event_log", "name": child.name, "path": str(child), "size_bytes": child.stat().st_size, "tier": tier, "priority": tier <= 2, "priority_reason": reason, "suggested_tool": "EvtxECmd", "source_type": "image", "source_key": source_key, "exists": True, "is_file": True, "is_dir": False}
                            eventlogs.append(record); artifacts.append(record)
                        except Exception:
                            continue
            except Exception as exc:
                errors.append({"source_key": source_key, "path": str(path), "error": str(exc)})
            continue

        loose_files = [path] if path.is_file() else list(directory_files(path, entry.get("exclude_paths")))
        if len(loose_files) > args.max_loose_files:
            errors.append({"source_key": source_key, "path": str(path), "error": f"Loose-file discovery capped at {args.max_loose_files} of {len(loose_files)} files"})
            loose_files = loose_files[: args.max_loose_files]
        source_root = path if path.is_dir() else path.parent
        for candidate in loose_files:
            try:
                record = loose_record(candidate, source_key, source_root); artifacts.append(record)
                if record["artifact_type"] == "event_log":
                    tier, reason = eventlog_tier(candidate.name)
                    eventlogs.append({**record, "tier": tier, "priority": tier <= 2, "priority_reason": reason})
                if record["artifact_type"] == "registry_hive" and candidate.name.lower() in {"ntuser.dat", "usrclass.dat"}:
                    user_hives.append(record)
            except OSError as exc:
                errors.append({"source_key": source_key, "path": str(candidate), "error": str(exc)})

    eventlogs.sort(key=lambda item: (item.get("tier", 3), item.get("size_bytes") or 0, item.get("name", "").lower()))
    for index, item in enumerate(artifacts, 1): item.setdefault("id", f"A-{index:06d}")
    counts: dict[str, int] = {}
    for item in artifacts:
        kind = str(item.get("artifact_type", "unknown")); counts[kind] = counts.get(kind, 0) + 1
    report = {
        "schema_version": "0.3.4", "generated_utc": datetime.now(timezone.utc).isoformat(),
        "case": args.case, "sources": sources, "artifacts": artifacts, "user_hives": user_hives,
        "event_logs": eventlogs, "errors": errors,
        "summary": {"sources": len(sources), "artifacts_found": len(artifacts), "artifact_types": counts,
                    "user_hives_found": len(user_hives), "event_logs_found": len(eventlogs),
                    "tier1_event_logs": sum(1 for item in eventlogs if item.get("tier") == 1),
                    "tier2_event_logs": sum(1 for item in eventlogs if item.get("tier") == 2),
                    "tier3_event_logs": sum(1 for item in eventlogs if item.get("tier") == 3)},
    }
    out = case_dir(args.case) / "artifact_inventory.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2)); print(f"Artifact inventory: {out}")
    if errors: raise SystemExit(3)


if __name__ == "__main__":
    main()
