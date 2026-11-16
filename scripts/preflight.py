from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from common import aries_root, case_dir, evidence_capabilities, load_case, run_traced

CORE_EZ = ["EvtxECmd", "MFTECmd", "PECmd", "RECmd", "SBECmd", "AmcacheParser", "SrumECmd", "JLECmd", "LECmd", "RBCmd", "WxTCmd"]


def run_probe(case_name: str, component: str, cmd: list[str], timeout: int = 20) -> dict:
    try:
        proc = run_traced(case_name, component, cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
        text = (proc.stdout or "") + "\n" + (proc.stderr or "")
        low = text.lower()
        runtime_problem = any(
            phrase in low
            for phrase in [
                "you must install or update .net",
                "framework was not found",
                "a fatal error occurred",
                "failed to load hostfxr",
            ]
        )
        return {
            "ok": not runtime_problem,
            "returncode": proc.returncode,
            "runtime_problem": runtime_problem,
            "preview": text.strip()[:1000],
        }
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "returncode": "timeout", "runtime_problem": False, "preview": f"Timed out after {timeout}s"}
    except OSError as exc:
        return {"ok": False, "returncode": "error", "runtime_problem": False, "preview": str(exc)}


def main() -> None:
    ap = argparse.ArgumentParser(description="Aries v0.3 capability-aware DFIR preflight")
    ap.add_argument("--case", required=True)
    ap.add_argument("--tools-root", default=r"C:\Tools")
    args = ap.parse_args()

    case = load_case(args.case)
    capabilities = evidence_capabilities(case)
    root = aries_root()
    out_dir = case_dir(args.case) / "output" / "preflight"
    out_dir.mkdir(parents=True, exist_ok=True)

    python = root / ".venv" / "Scripts" / "python.exe"
    vol = root / ".venv" / "Scripts" / "vol.exe"
    tq = root / ".venv" / "Scripts" / "target-query.exe"
    ti = root / ".venv" / "Scripts" / "target-info.exe"
    inventory_script = root / "scripts" / "tool_inventory.py"

    checks: dict[str, dict] = {}
    checks["aries_root"] = {"ok": root.exists(), "path": str(root)}
    checks["python"] = {"ok": python.is_file(), "path": str(python)}
    checks["volatility"] = {"ok": vol.is_file(), "path": str(vol)}
    checks["dissect_target_query"] = {"ok": tq.is_file(), "path": str(tq)}
    checks["dissect_target_info"] = {"ok": ti.is_file(), "path": str(ti)}
    checks["tools_root"] = {"ok": Path(args.tools_root).exists(), "path": args.tools_root}

    if vol.is_file():
        checks["volatility_probe"] = run_probe(args.case, "preflight:volatility", [str(vol), "-h"])
    if tq.is_file():
        checks["dissect_probe"] = run_probe(args.case, "preflight:dissect", [str(tq), "-h"])

    # Refresh inventory using the same interpreter Aries will use.
    inventory_rc = None
    if python.is_file() and inventory_script.is_file():
        proc = run_traced(args.case, "preflight:tool-inventory", [str(python), str(inventory_script), "--tools-root", args.tools_root], capture_output=True, text=True, errors="replace")
        inventory_rc = proc.returncode
        (out_dir / "tool_inventory.stdout.txt").write_text(proc.stdout or "", encoding="utf-8", errors="replace")
        (out_dir / "tool_inventory.stderr.txt").write_text(proc.stderr or "", encoding="utf-8", errors="replace")
    checks["tool_inventory_refresh"] = {"ok": inventory_rc == 0, "returncode": inventory_rc}

    inventory_path = root / "config" / "tools.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8")) if inventory_path.exists() else {"eztools": {}}

    ez_checks: dict[str, dict] = {}
    for name in CORE_EZ:
        entry = inventory.get("eztools", {}).get(name, {})
        preferred = entry.get("preferred")
        result = {"found": bool(preferred), "path": preferred, "probe": None}
        if preferred and Path(preferred).is_file():
            # Eric Zimmerman CLIs support help output; a runtime/framework failure is more important than the exact exit code.
            result["probe"] = run_probe(args.case, f"preflight:{name}", [preferred, "-h"])
        ez_checks[name] = result

    dotnet = shutil.which("dotnet")
    dotnet_info = {"found": bool(dotnet), "path": dotnet, "runtimes": []}
    if dotnet:
        try:
            proc = run_traced(args.case, "preflight:dotnet-runtimes", [dotnet, "--list-runtimes"], capture_output=True, text=True, timeout=20, errors="replace")
            dotnet_info["returncode"] = proc.returncode
            dotnet_info["runtimes"] = [line for line in (proc.stdout or "").splitlines() if line.strip()]
        except Exception as exc:
            dotnet_info["error"] = str(exc)

    try:
        usage = shutil.disk_usage(root)
        free_gb = round(usage.free / (1024**3), 2)
        disk_space = {"ok": free_gb >= 10, "free_gb": free_gb, "warning_threshold_gb": 10}
    except OSError as exc:
        disk_space = {"ok": False, "error": str(exc)}

    evidence_checks = {}
    for kind, entry in case.get("evidence", {}).items():
        path = Path(entry.get("path", ""))
        readable = path.is_file() or path.is_dir()
        evidence_checks[kind] = {"kind": entry.get("kind", kind), "path": str(path), "readable": readable, "is_file": path.is_file(), "is_dir": path.is_dir(), "size_bytes": path.stat().st_size if path.is_file() else None}

    required_checks = ["aries_root", "python", "tools_root", "tool_inventory_refresh"]
    if "memory" in capabilities:
        required_checks.append("volatility")
    if "disk" in capabilities:
        required_checks.extend(["dissect_target_query", "dissect_target_info"])
    core_ok = all(checks.get(name, {}).get("ok") for name in required_checks) and all(item.get("readable") for item in evidence_checks.values())

    warnings = []
    if not disk_space.get("ok"):
        warnings.append("Less than 10 GB free on the Aries workspace volume; large extraction/timeline jobs may fail.")
    for name, item in ez_checks.items():
        if not item.get("found"):
            warnings.append(f"{name} not found under {args.tools_root}.")
        elif item.get("probe") and not item["probe"].get("ok"):
            warnings.append(f"{name} was found but its help probe failed; inspect runtime/dependency output before relying on it.")

    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "case": args.case,
        "capabilities": sorted(capabilities),
        "required_checks": required_checks,
        "core_ready": core_ok,
        "checks": checks,
        "evidence": evidence_checks,
        "disk_space": disk_space,
        "dotnet": dotnet_info,
        "eztools": ez_checks,
        "warnings": warnings,
    }
    out = out_dir / "preflight.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Aries preflight: {'READY' if core_ok else 'FAILED'}")
    print(f"Report: {out}")
    for warning in warnings:
        print(f"WARNING: {warning}")
    raise SystemExit(0 if core_ok else 2)


if __name__ == "__main__":
    main()
