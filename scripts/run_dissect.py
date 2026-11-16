from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from common import aries_root, case_dir, evidence_entries, evidence_path, load_case, run_traced

QUICK = [
    "osinfo",
    "users",
    "runkeys",
    "services",
    "tasks",
    "powershell_history",
    "network_history",
    "remoteaccess",
    "prefetch",
    "shimcache",
    "amcache",
    "userassist",
    # Access-path artifacts are cheap enough for the default baseline and are
    # required before concluding whether a document was opened locally or over
    # a network share.
    "shellbags",
    "mru.recentdocs",
    "jumplist",
    "lnk",
]

TIMELINE = [
    "mft.timeline",
    "usnjrnl",
    "sru.application_timeline",
]

FULL_EXTRA = [
    "browser.history",
    "recyclebin",
    "usb",
    "firewall",
    "wer",
    "defender.evtx",
    "defender.mplog",
    "remoteaccess.logs",
    "sru",
]


def cli(name: str) -> str:
    local = aries_root() / ".venv" / "Scripts" / f"{name}.exe"
    if local.exists():
        return str(local)
    found = shutil.which(name)
    if found:
        return found
    raise FileNotFoundError(f"Dissect CLI '{name}' not found. Run install-aries.ps1.")


def run_capture(case_name: str, component: str, cmd: list[str], out: Path, timeout: int) -> int | str:
    try:
        proc = run_traced(case_name, component, cmd, text=True, capture_output=True, timeout=timeout, errors="replace")
        out.write_text(proc.stdout, encoding="utf-8", errors="replace")
        if proc.stderr:
            out.with_suffix(out.suffix + ".stderr.txt").write_text(proc.stderr, encoding="utf-8", errors="replace")
        return proc.returncode
    except subprocess.TimeoutExpired as exc:
        out.write_text(exc.stdout or "", encoding="utf-8", errors="replace")
        out.with_suffix(out.suffix + ".stderr.txt").write_text(f"Timed out after {timeout} seconds\n{exc.stderr or ''}", encoding="utf-8", errors="replace")
        return "timeout"


def main() -> None:
    ap = argparse.ArgumentParser(description="Run an Aries Dissect baseline (partial failures return exit code 3)")
    ap.add_argument("--case", required=True)
    ap.add_argument("--mode", choices=["quick", "timeline", "full"], default="quick")
    ap.add_argument("--e01", help="Override E01 path registered in case")
    ap.add_argument("--timeout", type=int, default=1800)
    args = ap.parse_args()

    case = load_case(args.case)
    image = Path(args.e01) if args.e01 else evidence_path(case, "e01")
    if not image:
        image = next((Path(entry["path"]) for _, entry in evidence_entries(case) if entry.get("kind") == "disk_image" and entry.get("path")), None)
    if not image or not image.is_file():
        raise SystemExit(f"Disk image evidence is missing or unreadable: {image}")

    tq = cli("target-query")
    ti = cli("target-info")
    out_dir = case_dir(args.case) / "output" / "dissect"
    out_dir.mkdir(parents=True, exist_ok=True)
    timeline_dir = case_dir(args.case) / "timeline"
    timeline_dir.mkdir(parents=True, exist_ok=True)

    print("[Dissect] target-info")
    info_rc = run_capture(args.case, "dissect:target-info", [ti, str(image)], out_dir / "target-info.txt", args.timeout)
    print("[Dissect] available plugins")
    plugins_path = out_dir / "available-plugins.txt"
    list_rc = run_capture(args.case, "dissect:list-plugins", [tq, str(image), "--no-cache", "-l"], plugins_path, args.timeout)
    available_text = plugins_path.read_text(encoding="utf-8", errors="ignore") if plugins_path.exists() else ""

    if args.mode == "quick":
        functions = QUICK
    elif args.mode == "timeline":
        functions = TIMELINE
    else:
        functions = QUICK + FULL_EXTRA

    results = []
    for function in functions:
        if available_text and function not in available_text:
            print(f"[Dissect] skip unavailable: {function}")
            results.append({"function": function, "returncode": "unavailable"})
            continue
        safe = function.replace(".", "_")
        dest_dir = timeline_dir if function in TIMELINE else out_dir
        dest = dest_dir / f"{safe}.txt"
        print(f"[Dissect] {function}")
        rc = run_capture(args.case, f"dissect:{function}", [tq, str(image), "--no-cache", "-q", "-s", "-f", function], dest, args.timeout)
        results.append({"function": function, "returncode": rc, "output": str(dest)})

    manifest = out_dir / f"run-{args.mode}-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "image": str(image),
                "target_info_returncode": info_rc,
                "plugin_list_returncode": list_rc,
                "generated_utc": datetime.now(timezone.utc).isoformat(),
                "results": results,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    ok = sum(1 for r in results if r.get("returncode") == 0)
    failed = [r for r in results if r.get("returncode") not in {0, "unavailable"}]
    print(f"Completed {ok}/{len(results)} selected functions successfully. Manifest: {manifest}")
    if results and ok == 0 and failed:
        raise SystemExit(2)
    if failed:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
