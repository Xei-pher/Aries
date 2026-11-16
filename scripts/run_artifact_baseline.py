from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from common import aries_root, case_dir, load_case, now_iso, run_traced
from static_artifact import process_archive, process_file

ROUTES = {
    "prefetch": [("PECmd", [])],
    "amcache": [("AmcacheParser", [])],
    "srum": [("SrumECmd", [])],
    "mft": [("MFTECmd", [])],
    "usnjrnl": [("MFTECmd", [])],
    "lnk": [("LECmd", [])],
    "jumplist": [("JLECmd", [])],
    "recycle_bin": [("RBCmd", [])],
    "windows_timeline": [("WxTCmd", [])],
}


def load_tools() -> dict:
    path = aries_root() / "config" / "tools.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"eztools": {}}


def resolve_tool(inventory: dict, name: str) -> Path | None:
    raw = inventory.get("eztools", {}).get(name, {}).get("preferred")
    return Path(raw) if raw and Path(raw).is_file() else None


def safe_name(value: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in value)[:100]


def routes_for(item: dict) -> list[tuple[str, list[str]]]:
    kind = item.get("artifact_type")
    name = str(item.get("name", "")).lower()
    if kind == "registry_hive":
        routes = [("RECmd", [])]
        if name in {"ntuser.dat", "usrclass.dat"}:
            routes.append(("SBECmd", []))
        return routes
    return ROUTES.get(str(kind), [])


def is_static_candidate(item: dict) -> bool:
    return str(item.get("artifact_type")) in {"archive", "text_log", "artifact"}


def find_recmd_batch(tool: Path) -> Path | None:
    candidates = []
    for base in [tool.parent, tool.parent.parent]:
        if not base.exists(): continue
        candidates.extend(base.rglob("*.reb"))
    ranked = sorted({path for path in candidates if path.is_file()}, key=lambda path: (0 if "dfir" in path.name.lower() else 1 if "kroll" in path.name.lower() else 2, len(str(path))))
    return ranked[0] if ranked else None


def main() -> None:
    ap = argparse.ArgumentParser(description="Parse supported loose Windows forensic artifacts with deterministic tool routing")
    ap.add_argument("--case", required=True)
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--max-artifacts", type=int, default=500)
    args = ap.parse_args()

    load_case(args.case)
    root = case_dir(args.case)
    inventory_path = root / "artifact_inventory.json"
    if not inventory_path.exists():
        raise SystemExit("artifact_inventory.json is missing. Run artifact_discovery first.")
    discovered = json.loads(inventory_path.read_text(encoding="utf-8"))
    candidates = [
        item for item in discovered.get("artifacts", [])
        if item.get("source_type") == "loose" and item.get("is_file") and (routes_for(item) or is_static_candidate(item))
    ]
    candidates = candidates[: max(1, args.max_artifacts)]
    tools = load_tools()
    output_root = root / "output" / "artifacts"
    output_root.mkdir(parents=True, exist_ok=True)
    results = []

    for item in candidates:
        source = Path(item["path"])
        if is_static_candidate(item):
            task_name = safe_name(f"{item.get('id', 'artifact')}-Static-{source.name}")
            output_dir = output_root / task_name
            if item.get("artifact_type") == "archive":
                extraction_dir = root / "extracted" / "archives" / safe_name(f"{item.get('id', 'artifact')}-{source.stem}")
                analysis = process_archive(source, extraction_dir, output_dir, args.timeout)
            else:
                analysis = process_file(source, output_dir)
            record = {
                "artifact_id": item.get("id"), "artifact_type": item.get("artifact_type"),
                "source": str(source), "tool": "StaticArtifact", "output_directory": str(output_dir),
                "status": analysis.get("status"), "reason": analysis.get("reason"),
                "backend": analysis.get("backend"), "outputs": analysis.get("outputs", []),
                "members_analyzed": analysis.get("members_analyzed", 0),
            }
            results.append(record)
            continue
        for tool_name, extra in routes_for(item):
            tool = resolve_tool(tools, tool_name)
            task_name = safe_name(f"{item.get('id', 'artifact')}-{tool_name}-{source.name}")
            output_dir = output_root / task_name
            output_dir.mkdir(parents=True, exist_ok=True)
            record = {"artifact_id": item.get("id"), "artifact_type": item.get("artifact_type"), "source": str(source), "tool": tool_name, "output_directory": str(output_dir)}
            if not tool:
                record.update({"status": "skipped", "reason": f"{tool_name} not found in C:\\Tools inventory"})
                results.append(record)
                continue
            if tool_name == "RECmd":
                batch = find_recmd_batch(tool)
                if not batch:
                    record.update({"status": "skipped", "reason": "RECmd batch file (.reb) was not found beside the installed tool"})
                    results.append(record)
                    continue
                cmd = [str(tool), "-f", str(source), "--bn", str(batch), "--csv", str(output_dir)]
                record["batch_file"] = str(batch)
            else:
                cmd = [str(tool), "-f", str(source), *extra, "--csv", str(output_dir)]
            print(f"[{tool_name}]", subprocess.list2cmdline(cmd))
            try:
                proc = run_traced(args.case, f"artifact:{tool_name}", cmd, cwd=tool.parent, capture_output=True, text=True, errors="replace", timeout=args.timeout)
                stdout_path = output_dir / "stdout.txt"; stderr_path = output_dir / "stderr.txt"
                stdout_path.write_text(proc.stdout or "", encoding="utf-8", errors="replace")
                stderr_path.write_text(proc.stderr or "", encoding="utf-8", errors="replace")
                outputs = [str(p) for p in output_dir.rglob("*") if p.is_file() and p.name not in {"stdout.txt", "stderr.txt"}]
                status = "complete" if proc.returncode == 0 and outputs else "partial" if proc.returncode == 0 else "failed"
                record.update({"status": status, "returncode": proc.returncode, "command": cmd, "outputs": outputs, "stdout": str(stdout_path), "stderr": str(stderr_path)})
            except subprocess.TimeoutExpired:
                record.update({"status": "timeout", "returncode": "timeout", "command": cmd})
            results.append(record)

    manifest = {"schema_version": "0.5.0", "generated_utc": now_iso(), "case": args.case, "selected_artifacts": len(candidates), "results": results,
                "inventory_only_types": ["browser/WebCache"],
                "note": "Archives and text-like loose artifacts were safely extracted/classified without execution. Source evidence remained read-only; all output was written inside the case workspace."}
    out = output_root / "artifact-baseline-manifest.json"
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    complete = sum(1 for item in results if item.get("status") == "complete")
    bad = [item for item in results if item.get("status") != "complete"]
    print(f"Loose-artifact baseline: {complete} complete, {len(bad)} partial/failed/skipped task(s), {len(candidates)} artifact(s) selected.")
    for item in bad:
        print(
            "ARTIFACT_RESULT "
            f"status={item.get('status')} tool={item.get('tool')} "
            f"source={item.get('source')} reason={item.get('reason') or 'No reason recorded'}"
        )
    print(f"Manifest: {out}")
    if candidates and complete == 0 and any(item.get("status") in {"failed", "timeout"} for item in results):
        raise SystemExit(2)
    if bad:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
