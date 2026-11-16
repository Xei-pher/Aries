from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from common import aries_root, case_dir, load_case, run_traced


def load_inventory() -> dict:
    path = aries_root() / "config" / "tools.json"
    if not path.exists():
        raise SystemExit(f"Tool inventory missing: {path}. Run scripts\\tool_inventory.py first.")
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_tool(inventory: dict, requested: str) -> Path:
    tools = inventory.get("eztools", {})
    for name, entry in tools.items():
        if name.lower() == requested.lower():
            preferred = entry.get("preferred")
            if preferred and Path(preferred).is_file():
                return Path(preferred)
            raise SystemExit(f"EZ Tool '{name}' is not available in the current inventory.")
    available = ", ".join(sorted(tools))
    raise SystemExit(f"Unknown EZ Tool '{requested}'. Inventory contains: {available}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Run an inventoried Zimmerman CLI tool and preserve stdout/stderr/command metadata in the case",
        epilog="Example: python run_eztool.py --case Demo --tool EvtxECmd -- -f C:\\Aries\\cases\\Demo\\extracted\\Security.evtx --csv out",
    )
    ap.add_argument("--case", required=True)
    ap.add_argument("--tool", required=True, help="Tool stem, e.g. MFTECmd, EvtxECmd, PECmd")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("arguments", nargs=argparse.REMAINDER, help="Arguments passed verbatim to the tool; place them after --")
    args = ap.parse_args()

    load_case(args.case)
    inventory = load_inventory()
    exe = resolve_tool(inventory, args.tool)
    passthrough = list(args.arguments)
    if passthrough and passthrough[0] == "--":
        passthrough = passthrough[1:]

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = case_dir(args.case) / "output" / "eztools" / f"{exe.stem}-{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    cmd = [str(exe), *passthrough]

    metadata = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "tool": exe.stem,
        "executable": str(exe),
        "arguments": passthrough,
        "working_directory": str(run_dir),
    }
    (run_dir / "command.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print("Running:", subprocess.list2cmdline(cmd))
    print("Working directory:", run_dir)

    try:
        proc = run_traced(args.case, f"eztool:{exe.stem}", cmd, cwd=run_dir, capture_output=True, text=True, errors="replace", timeout=args.timeout)
        (run_dir / "stdout.txt").write_text(proc.stdout or "", encoding="utf-8", errors="replace")
        (run_dir / "stderr.txt").write_text(proc.stderr or "", encoding="utf-8", errors="replace")
        metadata["returncode"] = proc.returncode
    except subprocess.TimeoutExpired as exc:
        (run_dir / "stdout.txt").write_text(exc.stdout or "", encoding="utf-8", errors="replace")
        (run_dir / "stderr.txt").write_text(f"Timed out after {args.timeout} seconds\n{exc.stderr or ''}", encoding="utf-8", errors="replace")
        metadata["returncode"] = "timeout"

    (run_dir / "command.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"Result: {metadata['returncode']}. Output preserved under {run_dir}")
    raise SystemExit(metadata["returncode"] if isinstance(metadata["returncode"], int) else 124)


if __name__ == "__main__":
    main()
