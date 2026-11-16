from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from common import aries_root, case_dir, evidence_path, load_case, run_traced

QUICK = [
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline",
    "windows.netscan",
    "windows.netstat",
    "windows.malfind",
    "windows.svcscan",
    "windows.registry.hivelist",
]

FULL_EXTRA = [
    "windows.filescan",
    "windows.handles",
    "windows.dlllist",
    "windows.modules",
    "windows.driverscan",
    "windows.envars",
    "windows.getsids",
    "windows.sessions",
    "windows.consoles",
]


def find_vol() -> str:
    local = aries_root() / ".venv" / "Scripts" / "vol.exe"
    if local.exists():
        return str(local)
    found = shutil.which("vol")
    if found:
        return found
    raise FileNotFoundError("Volatility CLI 'vol' was not found. Run install-aries.ps1.")


def run_plugin(case_name: str, vol: str, memory: Path, plugin: str, output: Path, timeout: int) -> dict:
    cmd = [vol, "-f", str(memory), plugin]
    started = datetime.now(timezone.utc).isoformat()
    try:
        proc = run_traced(case_name, f"volatility:{plugin}", cmd, text=True, capture_output=True, timeout=timeout, errors="replace")
        output.write_text(proc.stdout, encoding="utf-8", errors="replace")
        err = output.with_suffix(".stderr.txt")
        if proc.stderr:
            err.write_text(proc.stderr, encoding="utf-8", errors="replace")
        return {"plugin": plugin, "returncode": proc.returncode, "output": str(output), "started_utc": started}
    except subprocess.TimeoutExpired as exc:
        output.write_text(exc.stdout or "", encoding="utf-8", errors="replace")
        output.with_suffix(".stderr.txt").write_text(f"Timed out after {timeout} seconds\n{exc.stderr or ''}", encoding="utf-8", errors="replace")
        return {"plugin": plugin, "returncode": "timeout", "output": str(output), "started_utc": started}


def main() -> None:
    ap = argparse.ArgumentParser(description="Run an Aries Volatility baseline (partial failures return exit code 3)")
    ap.add_argument("--case", required=True)
    ap.add_argument("--mode", choices=["quick", "full"], default="quick")
    ap.add_argument("--memory", help="Override memory path registered in case")
    ap.add_argument("--timeout", type=int, default=1800)
    args = ap.parse_args()

    case = load_case(args.case)
    memory = Path(args.memory) if args.memory else evidence_path(case, "memory")
    if not memory or not memory.is_file():
        raise SystemExit(f"Memory evidence is missing or unreadable: {memory}")

    vol = find_vol()
    out_dir = case_dir(args.case) / "output" / "volatility"
    out_dir.mkdir(parents=True, exist_ok=True)
    plugins = QUICK + (FULL_EXTRA if args.mode == "full" else [])
    results = []
    for plugin in plugins:
        safe = plugin.replace(".", "_")
        print(f"[Volatility] {plugin}")
        results.append(run_plugin(args.case, vol, memory, plugin, out_dir / f"{safe}.txt", args.timeout))

    manifest = out_dir / f"run-{args.mode}-manifest.json"
    manifest.write_text(json.dumps({"memory": str(memory), "vol": vol, "results": results}, indent=2), encoding="utf-8")
    ok = sum(1 for r in results if r["returncode"] == 0)
    failed = [r for r in results if r["returncode"] != 0]
    print(f"Completed {ok}/{len(results)} plugins successfully. Manifest: {manifest}")
    if results and ok == 0 and failed:
        raise SystemExit(2)
    if failed:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
