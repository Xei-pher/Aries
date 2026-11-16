from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from common import ALL_PHASES, DEFAULT_PHASE_ORDER, DONE_STATUSES, case_dir, evidence_capabilities, load_case, mark_phase, reset_running_phases, run_traced, save_case


def status_from_returncode(returncode: int | str) -> tuple[str, str]:
    if returncode == 0:
        return "complete", "Phase completed."
    if returncode == 3:
        return "partial", "Phase completed with warnings/partial parser failures. Review its manifest before relying on absent results."
    if returncode == 4:
        return "waiting", "Optional phase is waiting for external input."
    if returncode == 5:
        return "degraded", "Optional second-opinion execution failed; the default investigation does not require it."
    if returncode == 6:
        return "blocked", "The phase was safely blocked by an unmet evidence/report gate. Resolve the recorded blockers and rerun it."
    return "failed", "Review preserved tool output/errors."


def concise_output(text: str, max_lines: int = 40, max_chars: int = 12_000) -> str:
    lines = text.splitlines()
    markers = ("STATUS=", "CASE_NAME=", "NEXT_", "REPORT_", "SUMMARY", "manifest", "ERROR", "WARNING")
    selected = [line for line in lines if any(marker.lower() in line.lower() for marker in markers)]
    selected.extend(lines[-12:])
    unique = list(dict.fromkeys(line for line in selected if line.strip()))[-max_lines:]
    rendered = "\n".join(unique)
    return rendered[-max_chars:]


def run_command(case_name: str, phase: str, cmd: list[str], timeout: int, concise: bool = False) -> dict:
    print(f"\n=== {phase} ===")
    print(subprocess.list2cmdline(cmd))
    mark_phase(case_name, phase, "running", command=cmd)
    started = datetime.now(timezone.utc).isoformat()
    try:
        proc = run_traced(case_name, f"phase:{phase}", cmd, text=True, capture_output=True, errors="replace", timeout=timeout)
        log_dir = case_dir(case_name) / "output" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        log_path = log_dir / f"{stamp}-{phase}.log"
        log_path.write_text(
            f"COMMAND={subprocess.list2cmdline(cmd)}\nRETURN_CODE={proc.returncode}\n\nSTDOUT\n{proc.stdout}\n\nSTDERR\n{proc.stderr}",
            encoding="utf-8",
        )
        if concise:
            rendered = concise_output("\n".join(part for part in (proc.stdout, proc.stderr) if part))
            if rendered:
                print(rendered)
            print(f"PHASE_LOG={log_path}")
        else:
            if proc.stdout:
                print(proc.stdout.rstrip())
            if proc.stderr:
                print(proc.stderr.rstrip(), file=sys.stderr)
        status, message = status_from_returncode(proc.returncode)
        mark_phase(case_name, phase, status, returncode=proc.returncode, message=message)
        return {"phase": phase, "returncode": proc.returncode, "status": status, "started_utc": started}
    except subprocess.TimeoutExpired as exc:
        if exc.stdout:
            print(exc.stdout, file=sys.stdout)
        if exc.stderr:
            print(exc.stderr, file=sys.stderr)
        mark_phase(case_name, phase, "failed", returncode="timeout", message=f"Phase timed out after {timeout} seconds and can be resumed safely.")
        return {"phase": phase, "returncode": "timeout", "status": "failed", "started_utc": started}


def phase_command(case_name: str, phase: str, mode: str, timeout: int) -> list[str] | None:
    python = Path(sys.executable)
    scripts = Path(__file__).resolve().parent
    if phase == "preflight":
        return [str(python), str(scripts / "preflight.py"), "--case", case_name]
    if phase == "evidence_integrity":
        return [str(python), str(scripts / "case.py"), "hash", "--case", case_name, "--which", "all"]
    if phase == "artifact_discovery":
        return [str(python), str(scripts / "artifact_discovery.py"), "--case", case_name]
    if phase == "eventlog_baseline":
        return [str(python), str(scripts / "run_ez_baseline.py"), "--case", case_name, "--timeout", str(timeout), "--max-tier", "2"]
    if phase == "event_triage":
        return [str(python), str(scripts / "event_triage.py"), "--case", case_name]
    if phase == "artifact_baseline":
        return [str(python), str(scripts / "run_artifact_baseline.py"), "--case", case_name, "--timeout", str(timeout)]
    if phase == "artifact_triage":
        return [str(python), str(scripts / "artifact_triage.py"), "--case", case_name]
    if phase == "memory_baseline":
        return [str(python), str(scripts / "run_volatility.py"), "--case", case_name, "--mode", mode, "--timeout", str(timeout)]
    if phase == "disk_baseline":
        return [str(python), str(scripts / "run_dissect.py"), "--case", case_name, "--mode", "full" if mode == "full" else "quick", "--timeout", str(timeout)]
    if phase == "pivot":
        return [str(python), str(scripts / "pivot.py"), "--case", case_name]
    if phase == "targeted_timeline":
        return [str(python), str(scripts / "targeted_timeline.py"), "--case", case_name]
    if phase == "orchestration_review":
        return [str(python), str(scripts / "orchestration.py"), "--case", case_name]
    if phase == "evidence_assessment":
        return [str(python), str(scripts / "evidence_assessment.py"), "--case", case_name]
    if phase == "ioc_scan":
        return [str(python), str(scripts / "case.py"), "ioc-scan", "--case", case_name]
    if phase == "report":
        return [str(python), str(scripts / "case.py"), "report", "--case", case_name]
    if phase == "disk_timeline":
        return [str(python), str(scripts / "run_dissect.py"), "--case", case_name, "--mode", "timeline", "--timeout", str(timeout)]
    return None


def phase_skip_reason(case_name: str, phase: str) -> str | None:
    if phase not in {"eventlog_baseline", "event_triage"}:
        return None
    inventory = case_dir(case_name) / "artifact_inventory.json"
    if not inventory.is_file():
        return None
    try:
        data = json.loads(inventory.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not data.get("event_logs"):
        return "No event logs were discovered in this evidence set."
    return None


def active_phases(case: dict, no_hash: bool) -> list[str]:
    caps = evidence_capabilities(case)
    active = list(DEFAULT_PHASE_ORDER)
    if "artifacts" not in caps:
        active = [p for p in active if p not in {"artifact_discovery", "eventlog_baseline", "event_triage", "artifact_baseline", "artifact_triage"}]
    if "disk" not in caps:
        active = [p for p in active if p != "disk_baseline"]
    if "memory" not in caps:
        active = [p for p in active if p != "memory_baseline"]
    if no_hash:
        active = [p for p in active if p != "evidence_integrity"]
    return active


def choose_next(case: dict, phases: list[str]) -> str | None:
    state = case.get("investigation", {}).get("phases", {})
    for phase in phases:
        status = state.get(phase, {}).get("status", "pending")
        if status not in DONE_STATUSES or (phase == "evidence_assessment" and status == "partial"):
            return phase
    return None


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Aries v0.3.4 evidence-set, recursive, single-agent investigation coordinator."
    )
    ap.add_argument("--case", help="Existing case name")
    ap.add_argument("--evidence", action="append", help="Evidence file/folder; if no --case, Aries creates/resumes the case")
    ap.add_argument("--name")
    ap.add_argument("--description")
    ap.add_argument("--mode", choices=["quick", "full"], default="quick")
    ap.add_argument("--all", action="store_true", help="Run all remaining DEFAULT phases sequentially. Normal agent work should still review leads between phases.")
    ap.add_argument("--concise", action="store_true", help="Write complete phase output to case logs and print only a bounded operational summary.")
    ap.add_argument("--phase", choices=ALL_PHASES, help="Run one named phase. disk_timeline is optional and no longer part of the normal baseline.")
    ap.add_argument("--no-hash", action="store_true", help="Explicitly skip evidence integrity hashing for this run")
    ap.add_argument("--timeout", type=int, default=7200, help="Per-phase timeout in seconds")
    args = ap.parse_args()

    if not args.case and not args.evidence:
        ap.error("provide --case or --evidence")
    if args.case and args.evidence:
        ap.error("use either --case or --evidence, not both")

    if not args.case:
        auto_cmd = [str(Path(sys.executable)), str(Path(__file__).resolve().parent / "case.py"), "auto"]
        for item in args.evidence or []:
            auto_cmd += ["--evidence", item]
        if args.name:
            auto_cmd += ["--name", args.name]
        if args.description:
            auto_cmd += ["--description", args.description]
        proc = subprocess.run(auto_cmd, text=True, capture_output=True, errors="replace")
        if proc.stdout:
            print(proc.stdout.rstrip())
        if proc.stderr:
            print(proc.stderr.rstrip(), file=sys.stderr)
        if proc.returncode != 0:
            raise SystemExit(proc.returncode)
        line = next((line for line in proc.stdout.splitlines() if line.startswith("CASE_NAME=")), None)
        if not line:
            raise SystemExit("Case creation/resume did not return CASE_NAME.")
        args.case = line.split("=", 1)[1].strip()

    interrupted = reset_running_phases(args.case)
    if interrupted:
        print("Recovered interrupted phase state:", ", ".join(interrupted))

    case = load_case(args.case)
    case["investigation"]["mode_last"] = args.mode
    save_case(args.case, case)
    phases = active_phases(case, args.no_hash)

    if args.no_hash:
        state = load_case(args.case)["investigation"]["phases"]["evidence_integrity"]
        if state.get("status") not in DONE_STATUSES:
            mark_phase(args.case, "evidence_integrity", "skipped", message="Explicitly skipped with --no-hash.")

    if args.phase:
        targets = [args.phase]
    elif args.all:
        targets = []
        current = load_case(args.case)
        for phase in phases:
            status = current["investigation"]["phases"][phase]["status"]
            if status not in DONE_STATUSES or (phase == "evidence_assessment" and status == "partial"):
                targets.append(phase)
    else:
        next_phase = choose_next(load_case(args.case), phases)
        targets = [next_phase] if next_phase else []

    if not targets:
        print(f"Case {args.case}: all applicable v0.3.4 default phases are complete/partial/skipped.")
        print(f"CASE_NAME={args.case}")
        print("INVESTIGATION_BASELINE=COMPLETE")
        print("Optional whole-disk timeline: investigate.py --case CASE --phase disk_timeline")
        raise SystemExit(0)

    results = []
    for phase in targets:
        if phase is None:
            continue
        skip_reason = phase_skip_reason(args.case, phase)
        if skip_reason:
            mark_phase(args.case, phase, "skipped", message=skip_reason)
            print(f"\n=== {phase} ===\nSKIPPED: {skip_reason}")
            continue
        cmd = phase_command(args.case, phase, args.mode, args.timeout)
        if not cmd:
            continue
        result = run_command(args.case, phase, cmd, args.timeout, args.concise)
        results.append(result)
        if result["status"] in {"failed", "waiting", "degraded", "blocked"} and args.all:
            reason = "the required input is available" if result["status"] == "waiting" else "reviewing/fixing it"
            print(f"Stopping --all run at {result['status']} phase: {phase}. Resume after {reason}.")
            break

    root = case_dir(args.case)
    manifest = root / "output" / "investigation-state.json"
    state = load_case(args.case)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(state.get("investigation", {}), indent=2), encoding="utf-8")
    next_phase = choose_next(state, active_phases(state, False))

    print(f"\nCASE_NAME={args.case}")
    print(f"STATE={root / 'case.json'}")
    if next_phase:
        print(f"NEXT_PHASE={next_phase}")
        print(f"Resume: {Path(sys.executable)} {Path(__file__).resolve()} --case {args.case} --mode {args.mode}")
    else:
        print("INVESTIGATION_BASELINE=COMPLETE")
        print("Optional whole-disk timeline remains available with --phase disk_timeline")

    if any(r["status"] == "failed" for r in results):
        raise SystemExit(2)
    if any(r["status"] == "waiting" for r in results):
        raise SystemExit(4)
    if any(r["status"] == "degraded" for r in results):
        raise SystemExit(5)
    if any(r["status"] == "blocked" for r in results):
        raise SystemExit(6)
    if any(r["status"] == "partial" for r in results):
        raise SystemExit(3)


if __name__ == "__main__":
    main()
