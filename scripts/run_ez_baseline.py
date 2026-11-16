from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from dissect.target import Target

from common import aries_root, case_dir, evidence_entries, load_case, run_traced


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_inventory() -> dict:
    path = aries_root() / "config" / "tools.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"eztools": {}}


def resolve_tool(inventory: dict, name: str) -> Path | None:
    entry = inventory.get("eztools", {}).get(name, {})
    preferred = entry.get("preferred")
    return Path(preferred) if preferred and Path(preferred).is_file() else None


def extract(target, internal: str, dest: Path) -> dict:
    src = target.fs.path(internal)
    if not src.exists() or not src.is_file():
        return {"source": internal, "status": "missing"}
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        with src.open("rb") as fin, dest.open("wb") as fout:
            shutil.copyfileobj(fin, fout, length=8 * 1024 * 1024)
    return {
        "source": internal,
        "destination": str(dest),
        "status": "extracted",
        "size_bytes": dest.stat().st_size,
        "sha256": sha256_file(dest),
    }


def safe_csv_name(filename: str) -> str:
    stem = filename[:-5] if filename.lower().endswith(".evtx") else filename
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in stem)[:120]


def find_csv_output(output_dir: Path, csv_name: str) -> Path | None:
    candidates = [output_dir / csv_name, output_dir / f"{csv_name}.csv"]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    # EvtxECmd versions can normalize names slightly. Prefer the newest non-log text artifact beginning with our stem.
    matches = [p for p in output_dir.glob(f"{csv_name}*") if p.is_file() and not p.name.endswith((".stdout.txt", ".stderr.txt"))]
    matches.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def main() -> None:
    ap = argparse.ArgumentParser(description="Aries v0.3.4 event-log baseline for image and loose EVTX evidence")
    ap.add_argument("--case", required=True)
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--max-tier", type=int, choices=[1, 2, 3], default=2, help="Parse Tier 1 and Tier 2 telemetry by default")
    ap.add_argument("--max-logs", type=int, default=30, help="Safety cap for automatic event-log parsing")
    args = ap.parse_args()

    case = load_case(args.case)
    images = {key: Path(entry["path"]) for key, entry in evidence_entries(case) if entry.get("kind") in {"e01", "disk_image"} and Path(entry.get("path", "")).is_file()}

    root = case_dir(args.case)
    artifact_inventory_path = root / "artifact_inventory.json"
    if not artifact_inventory_path.exists():
        raise SystemExit("artifact_inventory.json is missing. Run artifact_discovery.py first.")
    artifacts = json.loads(artifact_inventory_path.read_text(encoding="utf-8"))
    selected_logs = [item for item in artifacts.get("event_logs", []) if int(item.get("tier", 3)) <= args.max_tier]
    selected_logs = selected_logs[: max(1, args.max_logs)]

    inventory = load_inventory()
    evtx = resolve_tool(inventory, "EvtxECmd")
    targets = {}
    extracted_dir = root / "extracted" / "eventlogs"
    output_dir = root / "output" / "eztools" / "EvtxECmd-Auto"
    output_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for item in selected_logs:
        filename = item["name"]
        internal = item["path"]
        if item.get("source_type") == "loose":
            source_path = Path(internal)
            extraction = {"source": str(source_path), "destination": str(source_path), "status": "registered", "size_bytes": source_path.stat().st_size if source_path.is_file() else None}
            dest = source_path
        else:
            source_key = item.get("source_key")
            image = images.get(source_key)
            if not image:
                extraction = {"source": internal, "status": "missing", "reason": f"Image source {source_key} not registered"}
                dest = extracted_dir / filename
            else:
                if source_key not in targets:
                    targets[source_key] = Target.open(str(image))
                dest = extracted_dir / f"{source_key}-{filename}"
                extraction = extract(targets[source_key], internal, dest)
        record = {
            "event_log": filename,
            "tier": item.get("tier", 3),
            "priority_reason": item.get("priority_reason", ""),
            "extraction": extraction,
            "parser": None,
        }
        if extraction.get("status") not in {"extracted", "registered"}:
            results.append(record)
            continue
        if not evtx:
            record["parser"] = {"status": "skipped", "reason": "EvtxECmd not found in C:\\Tools inventory"}
            results.append(record)
            continue

        csv_name = safe_csv_name(filename)
        cmd = [str(evtx), "-f", str(dest), "--csv", str(output_dir), "--csvf", csv_name]
        print(f"[EvtxECmd][T{item.get('tier', 3)}]", subprocess.list2cmdline(cmd))
        try:
            proc = run_traced(args.case, "eventlog:EvtxECmd", cmd, cwd=evtx.parent, capture_output=True, text=True, errors="replace", timeout=args.timeout)
            stdout_path = output_dir / f"{csv_name}.stdout.txt"
            stderr_path = output_dir / f"{csv_name}.stderr.txt"
            stdout_path.write_text(proc.stdout or "", encoding="utf-8", errors="replace")
            stderr_path.write_text(proc.stderr or "", encoding="utf-8", errors="replace")
            csv_path = find_csv_output(output_dir, csv_name)
            status = "complete" if proc.returncode == 0 and csv_path else ("partial" if proc.returncode == 0 else "failed")
            record["parser"] = {
                "status": status,
                "returncode": proc.returncode,
                "command": cmd,
                "stdout": str(stdout_path),
                "stderr": str(stderr_path),
                "output_directory": str(output_dir),
                "csv_path": str(csv_path) if csv_path else None,
            }
        except subprocess.TimeoutExpired:
            record["parser"] = {"status": "timeout", "returncode": "timeout", "command": cmd}
        results.append(record)

    manifest = {
        "schema_version": "0.3.4",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "case": args.case,
        "evtxecmd": str(evtx) if evtx else None,
        "max_tier": args.max_tier,
        "selected_event_logs": len(selected_logs),
        "results": results,
    }
    out = output_dir / "baseline-manifest.json"
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    good = [r for r in results if r.get("parser", {}).get("status") == "complete"]
    partial = [r for r in results if r.get("parser", {}).get("status") == "partial"]
    failures = [r for r in results if r.get("parser", {}).get("status") in {"failed", "timeout", "skipped"}]
    print(f"Event-log baseline: {len(good)} complete, {len(partial)} partial, {len(failures)} failed/skipped of {len(results)} selected logs.")
    print(f"Manifest: {out}")
    if partial or failures:
        raise SystemExit(3)
    raise SystemExit(0)


if __name__ == "__main__":
    main()
