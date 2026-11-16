from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

from common import append_command_event, case_dir


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT_ROOT / "scripts"


def run_step(case_name: str, component: str, command: list[str], *, timeout: int | None = None) -> int:
    command_id = append_command_event(case_name, "started", component, command)
    try:
        result = subprocess.run(
            command,
            cwd=str(PROJECT_ROOT),
            env={**os.environ, "ARIES_ROOT": os.environ.get("ARIES_ROOT", str(PROJECT_ROOT)), "PYTHONUNBUFFERED": "1"},
            check=False,
            timeout=timeout,
        )
        append_command_event(
            case_name, "finished", component, command,
            command_id=command_id, returncode=result.returncode,
        )
        return result.returncode
    except subprocess.TimeoutExpired as exc:
        append_command_event(
            case_name, "failed", component, command,
            command_id=command_id, returncode="timeout", error=f"Timed out after {timeout} seconds",
        )
        print(f"{component} timed out after {timeout} seconds; deterministic evidence and checkpoints were preserved.", file=sys.stderr, flush=True)
        return 124
    except OSError as exc:
        append_command_event(
            case_name, "failed", component, command,
            command_id=command_id, returncode="launch_error", error=str(exc),
        )
        print(f"{component} could not start: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 127


def _usage_totals(path: Path) -> tuple[int, int, float]:
    try:
        value = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (OSError, json.JSONDecodeError):
        return (0, 0, 0.0)
    calls = int(value.get("api_calls") or 0)
    total = int(value.get("total_tokens") or value.get("tokens") or 0)
    if not total:
        total = sum(int(value.get(key) or 0) for key in ("input_tokens", "output_tokens", "prompt_tokens", "completion_tokens"))
    return (calls, total, float(value.get("estimated_cost_usd") or 0.0))


def run_model_with_budget(
    case_name: str,
    command: list[str],
    usage_path: Path,
    *,
    timeout: int,
    max_api_calls: int,
    max_total_tokens: int,
    max_cost_usd: float,
) -> tuple[int, str | None]:
    """Run one model process with wall-clock and observable usage limits."""
    component = "web:bounded_analysis"
    command_id = append_command_event(case_name, "started", component, command)
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            cwd=str(PROJECT_ROOT),
            env={**os.environ, "ARIES_ROOT": os.environ.get("ARIES_ROOT", str(PROJECT_ROOT)), "PYTHONUNBUFFERED": "1"},
        )
    except OSError as exc:
        append_command_event(case_name, "failed", component, command, command_id=command_id, returncode="launch_error", error=str(exc))
        return (127, "launch_error")

    budget_reason: str | None = None
    while process.poll() is None:
        elapsed = time.monotonic() - started
        calls, tokens, cost = _usage_totals(usage_path)
        if elapsed > timeout:
            budget_reason = f"wall-clock limit reached ({timeout}s)"
        elif max_api_calls > 0 and calls >= max_api_calls:
            budget_reason = f"API-call limit reached ({calls}/{max_api_calls})"
        elif max_total_tokens > 0 and tokens >= max_total_tokens:
            budget_reason = f"token limit reached ({tokens}/{max_total_tokens})"
        elif max_cost_usd > 0 and cost >= max_cost_usd:
            budget_reason = f"cost limit reached (${cost:.4f}/${max_cost_usd:.2f})"
        if budget_reason:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            break
        time.sleep(0.5)

    rc = process.returncode if process.returncode is not None else 124
    if not budget_reason:
        calls, tokens, cost = _usage_totals(usage_path)
        if max_api_calls > 0 and calls > max_api_calls:
            budget_reason = f"API-call limit exceeded before final usage was observable ({calls}/{max_api_calls})"
        elif max_total_tokens > 0 and tokens > max_total_tokens:
            budget_reason = f"token limit exceeded before final usage was observable ({tokens}/{max_total_tokens})"
        elif max_cost_usd > 0 and cost > max_cost_usd:
            budget_reason = f"cost limit exceeded before final usage was observable (${cost:.4f}/${max_cost_usd:.2f})"
    if budget_reason:
        rc = 124
        print(f"Model synthesis budget reached: {budget_reason}. Deterministic evidence and a partial report were preserved.", file=sys.stderr, flush=True)
    append_command_event(
        case_name,
        "failed" if rc else "finished",
        component,
        command,
        command_id=command_id,
        returncode=rc,
        error=budget_reason,
    )
    return (rc, budget_reason)


def write_analysis_status(root: Path, usage_path: Path, model_rc: int, *, skipped: bool = False, budget_reason: str | None = None, budget: dict | None = None) -> dict:
    try:
        usage = json.loads(usage_path.read_text(encoding="utf-8")) if usage_path.is_file() else {}
    except (OSError, json.JSONDecodeError):
        usage = {}
    if skipped:
        status = "skipped"
        message = "AI synthesis was skipped because deterministic processing did not produce a usable case state."
    elif budget_reason:
        status = "budget_exceeded"
        message = f"AI synthesis stopped at its configured budget: {budget_reason}. Deterministic evidence and a partial report were preserved."
    elif usage.get("failed") is True or model_rc != 0:
        status = "failed"
        message = "The configured model/provider did not complete the synthesis pass. Deterministic evidence and a partial report were preserved."
    elif usage.get("completed") is True:
        status = "completed"
        message = "AI synthesis completed."
    else:
        status = "unknown"
        message = "The model process ended without a verifiable completion marker. Deterministic evidence and a partial report were preserved."
    record = {
        "schema_version": "1",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "message": message,
        "model_returncode": model_rc,
        "usage": {key: usage.get(key) for key in ("completed", "failed", "api_calls", "total_tokens", "input_tokens", "output_tokens", "model", "provider", "estimated_cost_usd")},
        "budget": budget or {},
    }
    path = root / "output" / "web" / "analysis-status.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description="Aries web workflow: deterministic parsing, bounded AI analysis, final assessment/report")
    parser.add_argument("--case", required=True)
    parser.add_argument("--mode", choices=["quick", "full"], default="quick")
    parser.add_argument("--prompt-file", required=True)
    parser.add_argument("--usage-file", required=True)
    parser.add_argument("--profile", default="aries")
    parser.add_argument("--analysis-only", action="store_true", help="Retry only AI synthesis and final report generation using existing parsed outputs")
    parser.add_argument("--analysis-timeout", type=int, default=900, help="Hard limit for the AI synthesis pass in seconds")
    parser.add_argument("--max-api-calls", type=int, default=36, help="Stop when observable usage reaches this many provider calls")
    parser.add_argument("--max-total-tokens", type=int, default=4000000, help="Stop when observable usage reaches this many tokens")
    parser.add_argument("--max-cost-usd", type=float, default=5.0, help="Stop when observable usage reaches this estimated cost")
    args = parser.parse_args()

    root = case_dir(args.case)
    prompt_path = Path(args.prompt_file)
    if not prompt_path.is_file():
        raise SystemExit(f"Analysis prompt file is missing: {prompt_path}")

    if args.analysis_only:
        print("ARIES_WEB_STAGE=REPORT_SYNTHESIS_RETRY", flush=True)
        print("Completed forensic parsers are being reused; only AI synthesis and report finalization will run.", flush=True)
        pipeline_rc = 0
    else:
        print("ARIES_WEB_STAGE=DETERMINISTIC_PIPELINE", flush=True)
        pipeline_rc = run_step(args.case, "web:deterministic_pipeline", [
            sys.executable, str(SCRIPTS / "investigate.py"),
            "--case", args.case, "--mode", args.mode, "--all", "--concise",
        ])
    print(f"ARIES_PIPELINE_RETURN_CODE={pipeline_rc}", flush=True)

    # Record exact non-interpretive answers before any provider call. This
    # guarantees that evidence hashes and similar registered facts survive a
    # free-model outage and appear in the partial report.
    run_step(args.case, "web:deterministic_answer_seed", [
        sys.executable, str(SCRIPTS / "case.py"), "answer-seed", "--case", args.case,
    ])

    # 0 = complete, 3 = useful partial coverage, 6 = evidence gate blocked.
    # All three leave useful parsed case outputs. Hard parser/preflight failures
    # skip the paid model turn instead of asking it to reason over missing data.
    if pipeline_rc in {0, 3, 6}:
        print("ARIES_WEB_STAGE=BOUNDED_ANALYSIS", flush=True)
        prompt = prompt_path.read_text(encoding="utf-8", errors="replace")
        model_rc, budget_reason = run_model_with_budget(args.case, [
            "hermes", "-p", args.profile, "-z", prompt,
            "--usage-file", str(Path(args.usage_file)),
        ], Path(args.usage_file), timeout=max(60, args.analysis_timeout), max_api_calls=args.max_api_calls,
            max_total_tokens=args.max_total_tokens, max_cost_usd=args.max_cost_usd)
    else:
        model_rc = 125
        budget_reason = None
        print("ARIES_WEB_STAGE=ANALYSIS_SKIPPED", flush=True)
        print("Model analysis was skipped because deterministic evidence processing failed before producing a usable case state.", flush=True)
    print(f"ARIES_MODEL_RETURN_CODE={model_rc}", flush=True)
    analysis = write_analysis_status(
        root, Path(args.usage_file), model_rc,
        skipped=pipeline_rc not in {0, 3, 6}, budget_reason=budget_reason,
        budget={"analysis_timeout_seconds": args.analysis_timeout, "max_api_calls": args.max_api_calls,
                "max_total_tokens": args.max_total_tokens, "max_cost_usd": args.max_cost_usd},
    )
    print(f"ARIES_ANALYSIS_STATUS={analysis['status'].upper()}", flush=True)

    # These are deterministic and always run, even when the provider is down
    # or the model returns no final message. The report will be READY or REVIEW
    # REQUIRED based on durable case state.
    print("ARIES_WEB_STAGE=FINAL_ASSESSMENT", flush=True)
    run_step(args.case, "web:final_assessment", [
        sys.executable, str(SCRIPTS / "investigate.py"),
        "--case", args.case, "--phase", "evidence_assessment", "--concise",
    ])
    print("ARIES_WEB_STAGE=FINAL_REPORT", flush=True)
    report_rc = run_step(args.case, "web:final_report", [
        sys.executable, str(SCRIPTS / "investigate.py"),
        "--case", args.case, "--phase", "report", "--concise",
    ])
    report_path = root / "report" / "report.md"
    if report_rc != 0 or not report_path.is_file():
        raise SystemExit(report_rc or 1)
    print(f"ARIES_WEB_WORKFLOW=COMPLETE\nREPORT_PATH={report_path}", flush=True)


if __name__ == "__main__":
    main()
