from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]


def run_code(root: Path, code: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["ARIES_ROOT"] = str(root)
    env["PYTHONPATH"] = os.pathsep.join([str(PROJECT / "web"), str(PROJECT / "scripts")])
    return subprocess.run([sys.executable, "-c", code], env=env, text=True, capture_output=True)


def test_web_service_creates_uploads_and_registers_case(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import asyncio
import json
from service import create_draft_case, upload_target, record_uploaded_file, register_case, case_overview

create_draft_case("web-case", "Web intake test")
target = upload_target("web-case", "Artifact With Spaces.evtx")
target.parent.mkdir(parents=True, exist_ok=True)
target.write_bytes(b"test artifact")
record_uploaded_file("web-case", target, target.stat().st_size, "0" * 64)
asyncio.run(register_case("web-case", "Web intake test"))
overview = case_overview("web-case")
print(json.dumps({"registered": overview["registered"], "evidence": len(overview["evidence"]), "status": overview["status"]}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout.strip().splitlines()[-1])
    assert value["registered"] is True
    assert value["evidence"] >= 1
    assert value["status"] == "ready"


def test_web_service_rejects_traversal_and_exports_metadata_only_bundle(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import asyncio
import json
import zipfile
from service import create_draft_case, upload_target, record_uploaded_file, register_case, build_review_bundle

create_draft_case("bundle", "Bundle test")
try:
    upload_target("bundle", "safe.evtx", "../outside.evtx")
    raise SystemExit("traversal was accepted")
except ValueError:
    pass
target = upload_target("bundle", "safe.evtx")
target.parent.mkdir(parents=True, exist_ok=True)
target.write_bytes(b"evidence bytes must never enter review bundle")
record_uploaded_file("bundle", target, target.stat().st_size, "0" * 64)
asyncio.run(register_case("bundle", "Bundle test"))
bundle = build_review_bundle("bundle")
with zipfile.ZipFile(bundle) as archive:
    names = archive.namelist()
print(json.dumps({"names": names, "has_evidence": any(name.startswith("evidence/") for name in names)}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout.strip().splitlines()[-1])
    assert value["has_evidence"] is False
    assert "case.json" in value["names"]


def test_static_console_has_no_remote_runtime_dependencies() -> None:
    index = (PROJECT / "web" / "static" / "index.html").read_text(encoding="utf-8")
    script = (PROJECT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "https://" not in index
    assert "/api/cases" in script
    assert "demoCase" in script
    assert "xhr.upload.onprogress" in script
    assert "X-Aries-Size" in script
    assert "/api/model" in script
    assert 'id="closeNewCase" type="button"' in index
    assert 'id="cancelNewCase" type="button"' in index


def test_raw_streaming_upload_records_exact_bytes(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import json
from fastapi.testclient import TestClient
from service import create_draft_case
from app import app

create_draft_case("raw-upload", "Streaming test")
payload = b"streamed evidence bytes"
with TestClient(app) as client:
    response = client.post(
        "/api/cases/raw-upload/artifacts",
        content=payload,
        headers={
            "Content-Type": "application/octet-stream",
            "X-Aries-Filename": "sample.evtx",
            "X-Aries-Relative-Path": "sample.evtx",
            "X-Aries-Size": str(len(payload)),
        },
    )
print(json.dumps({"status": response.status_code, "body": response.json()}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout.strip().splitlines()[-1])
    assert value["status"] == 201
    assert value["body"]["size_bytes"] == len(b"streamed evidence bytes")
    assert (root / "cases" / "raw-upload" / "evidence" / "sample.evtx").read_bytes() == b"streamed evidence bytes"


def test_hermes_model_output_parser_handles_common_formats(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import json
from service import clean_config_value
print(json.dumps({
    "plain": clean_config_value("openrouter/example/free-model\n"),
    "equals": clean_config_value("model = openai/gpt-example\n"),
    "unset": clean_config_value("model: unset\n"),
}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout.strip())
    assert value == {"plain": "openrouter/example/free-model", "equals": "openai/gpt-example", "unset": ""}


def test_model_status_does_not_mistake_base_url_for_model(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import json
import os
from pathlib import Path
from service import hermes_config_value

bin_dir = Path(os.environ["ARIES_ROOT"]) / "fake-bin"
bin_dir.mkdir(parents=True, exist_ok=True)
fake = bin_dir / "hermes"
fake.write_text("#!/bin/sh\nprintf 'provider: nous\\nmodel: upstage/solar-mini4:free\\nbase_url: https://example.invalid/v1\\n'\n", encoding="utf-8")
fake.chmod(0o755)
os.environ["PATH"] = str(bin_dir) + os.pathsep + os.environ.get("PATH", "")
print(json.dumps({"model": hermes_config_value("model")}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.strip()) == {"model": "upstage/solar-mini4:free"}


def test_web_uses_cross_version_hermes_oneshot_interface(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import json
from service import hermes_one_shot_args
args = hermes_one_shot_args("prompt with `quotes` and spaces")
print(json.dumps(args))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    args = json.loads(result.stdout.strip())
    assert args == ["hermes", "-p", "aries", "-z", "prompt with `quotes` and spaces"]
    assert "--oneshot" not in args
    assert "--query-file" not in args


def test_case_deletion_is_confirmed_contained_and_complete(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import json
from service import create_draft_case, delete_case, case_root

create_draft_case("delete-me", "Deletion test")
(case_root("delete-me") / "evidence" / "sample.evtx").write_bytes(b"evidence")
create_draft_case("keep-me", "Must survive")
try:
    delete_case("delete-me", "wrong-name")
    raise SystemExit("incorrect confirmation was accepted")
except ValueError:
    pass
delete_case("delete-me", "delete-me")
print(json.dumps({"deleted": not case_root("delete-me").exists(), "preserved": case_root("keep-me").exists()}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout.strip())
    assert value == {"deleted": True, "preserved": True}


def test_activity_snapshot_contains_auditable_case_events(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import json
from service import create_draft_case, append_web_audit, activity_snapshot
create_draft_case("audit", "Audit test")
append_web_audit("audit", "test_action", command="investigate.py --all")
snapshot = activity_snapshot("audit")
print(json.dumps({"has_created": "CASE_CREATED" in snapshot["text"], "has_action": "TEST_ACTION" in snapshot["text"], "has_command": "investigate.py --all" in snapshot["text"]}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout.strip())
    assert value == {"has_created": True, "has_action": True, "has_command": True}


def test_diagnostics_bundle_contains_logs_but_never_source_evidence(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import json
import zipfile
from service import create_draft_case, case_root, append_web_audit, build_diagnostic_bundle

create_draft_case("diagnostics", "Diagnostics test")
root = case_root("diagnostics")
(root / "evidence" / "victim.E01").write_bytes(b"source evidence must stay out")
(root / "output" / "web").mkdir(parents=True, exist_ok=True)
(root / "output" / "web" / "investigation.log").write_text("exact launch error", encoding="utf-8")
append_web_audit("diagnostics", "investigation_launch_failed", error="exact launch error")
(root / "output" / "artifacts" / "A-1").mkdir(parents=True, exist_ok=True)
(root / "output" / "artifacts" / "artifact-baseline-manifest.json").write_text('{"results": []}', encoding="utf-8")
(root / "output" / "artifacts" / "A-1" / "static-analysis.json").write_text('{"status": "failed"}', encoding="utf-8")
bundle = build_diagnostic_bundle("diagnostics")
with zipfile.ZipFile(bundle) as archive:
    names = archive.namelist()
    metadata = json.loads(archive.read("diagnostics-metadata.json"))
print(json.dumps({
    "has_metadata": metadata["aries_web_version"] == "0.5.0-dev",
    "has_log": "output/web/investigation.log" in names,
    "has_state": "web-state.json" in names,
    "has_artifact_failure": "output/artifacts/artifact-baseline-manifest.json" in names and "output/artifacts/A-1/static-analysis.json" in names,
    "has_evidence": any(name.startswith("evidence/") for name in names),
}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout.strip().splitlines()[-1])
    assert value == {"has_metadata": True, "has_log": True, "has_state": True, "has_artifact_failure": True, "has_evidence": False}


def test_stopped_investigation_preserves_real_log_error(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import json
from service import create_draft_case, case_root, save_web_state, case_overview

create_draft_case("stopped", "Stopped process test")
log = case_root("stopped") / "output" / "web" / "investigation.log"
log.parent.mkdir(parents=True, exist_ok=True)
log.write_text("provider authentication failed: invalid API key", encoding="utf-8")
save_web_state("stopped", status="investigating", investigation_pid=99999999, investigation_log=str(log))
overview = case_overview("stopped")
print(json.dumps({"status": overview["status"], "last_error": overview["last_error"]}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout.strip().splitlines()[-1])
    assert value["status"] == "interrupted"
    assert "provider authentication failed" in value["last_error"]


def test_stop_investigation_terminates_process_group_and_unlocks_case(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import json
import subprocess
import sys
from service import create_draft_case, save_web_state, stop_investigation, investigation_running

create_draft_case("halt", "Stop test")
proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
save_web_state("halt", status="investigating", investigation_pid=proc.pid)
stopped = stop_investigation("halt")
proc.wait(timeout=5)
print(json.dumps({"status": stopped["status"], "running": investigation_running("halt"), "returncode": proc.returncode}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout.strip().splitlines()[-1])
    assert value["status"] == "stopped"
    assert value["running"] is False
    assert value["returncode"] != 0


def test_live_command_trace_records_start_finish_and_redacts_secrets(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import json
import sys
from service import create_draft_case, activity_snapshot
from common import run_traced

create_draft_case("trace", "Command trace test")
result = run_traced("trace", "test:command", [sys.executable, "-c", "print('done')", "--token", "secret-value"], capture_output=True, text=True)
activity = activity_snapshot("trace")
print(json.dumps({
    "returncode": result.returncode,
    "has_start": "START test:command" in activity["text"],
    "has_finish": "FINISHED test:command" in activity["text"],
    "has_redaction": "<redacted>" in activity["text"],
    "leaked": "secret-value" in activity["text"],
}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout.strip().splitlines()[-1])
    assert value == {"returncode": 0, "has_start": True, "has_finish": True, "has_redaction": True, "leaked": False}


def test_static_console_exposes_activity_and_confirmed_deletion() -> None:
    index = (PROJECT / "web" / "static" / "index.html").read_text(encoding="utf-8")
    script = (PROJECT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert 'id="terminalDrawer"' in index
    assert 'id="deleteCaseConfirmation"' in index
    assert "/activity" in script
    assert 'method: "DELETE"' in script
    assert 'id="caseError"' in index
    assert 'id="downloadDiagnostics"' in index
    assert "/diagnostics" in script
    assert "Starting evidence workflow" in script
    assert 'id="stopButton"' in index
    assert 'id="terminalStopButton"' in index
    assert "/stop" in script
    assert "setInterval(refreshActivity, 1000)" in script


def test_report_available_is_distinct_from_report_ready(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import json
from service import create_draft_case, case_root, case_overview
from common import load_case, save_case

create_draft_case("truth", "Readiness truth test")
root = case_root("truth")
(root / "evidence" / "sample.evtx").write_bytes(b"event")
import asyncio
from service import register_case
asyncio.run(register_case("truth", "Readiness truth test"))
(root / "report").mkdir(parents=True, exist_ok=True)
(root / "report" / "report.md").write_text("stale report", encoding="utf-8")
(root / "output" / "evidence-assessment.json").write_text(json.dumps({"schema_version": "0.5.0", "report_ready": False, "blocking_issue_count": 2, "issues": [{"code": "TEST_GAP"}]}), encoding="utf-8")
case = load_case("truth")
case["investigation"]["phases"]["evidence_assessment"]["status"] = "partial"
case["investigation"]["phases"]["report"]["status"] = "complete"
save_case("truth", case)
overview = case_overview("truth")
print(json.dumps({"available": overview["report_available"], "ready": overview["report_ready"]}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.strip().splitlines()[-1]) == {"available": True, "ready": False}


def test_finished_session_auto_finalizes_ready_assessment(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import asyncio
import json
from service import create_draft_case, case_root, case_overview, register_case, save_web_state
from common import load_case, save_case

create_draft_case("finish", "Auto-finalization test")
root = case_root("finish")
(root / "evidence" / "sample.evtx").write_bytes(b"event")
asyncio.run(register_case("finish", "Auto-finalization test"))
(root / "output" / "evidence-assessment.json").write_text(json.dumps({"schema_version": "0.5.0", "generated_utc": "2026-11-11T00:00:00+00:00", "report_ready": True, "blocking_issue_count": 0, "issues": []}), encoding="utf-8")
case = load_case("finish")
case["investigation"]["phases"]["evidence_assessment"]["status"] = "partial"
case["investigation"]["phases"]["report"]["status"] = "blocked"
save_case("finish", case)
save_web_state("finish", status="investigating", investigation_pid=99999999)
overview = case_overview("finish")
case = load_case("finish")
print(json.dumps({"available": overview["report_available"], "ready": overview["report_ready"], "status": overview["status"], "assessment": case["investigation"]["phases"]["evidence_assessment"]["status"], "report": case["investigation"]["phases"]["report"]["status"]}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.strip().splitlines()[-1]) == {"available": True, "ready": True, "status": "complete", "assessment": "complete", "report": "complete"}


def test_existing_blocked_case_becomes_review_required_without_model(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import asyncio
import json
from service import create_draft_case, case_root, case_overview, register_case, save_investigation_brief, save_web_state
from common import load_case, save_case

create_draft_case("upgrade", "Blocked-case migration")
root = case_root("upgrade")
(root / "evidence" / "sample.evtx").write_bytes(b"event")
asyncio.run(register_case("upgrade", "Blocked-case migration"))
save_investigation_brief("upgrade", "Who accessed the file?")
(root / "output" / "evidence-assessment.json").write_text(json.dumps({"schema_version": "0.4.11", "report_ready": False, "blocking_issue_count": 1, "issues": []}), encoding="utf-8")
case = load_case("upgrade")
case["investigation"]["phases"]["evidence_assessment"]["status"] = "partial"
case["investigation"]["phases"]["report"]["status"] = "blocked"
save_case("upgrade", case)
save_web_state("upgrade", status="blocked", last_error="model ended without a final response")
overview = case_overview("upgrade")
case = load_case("upgrade")
assessment = json.loads((root / "output" / "evidence-assessment.json").read_text())
print(json.dumps({"available": overview["report_available"], "ready": overview["report_ready"], "status": overview["status"], "assessment_schema": assessment["schema_version"], "report": case["investigation"]["phases"]["report"]["status"]}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.strip().splitlines()[-1]) == {"available": True, "ready": False, "status": "partial_report", "assessment_schema": "0.5.0", "report": "complete"}


def test_dashboard_counts_only_material_active_leads() -> None:
    script = (PROJECT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert '$(("#leadMetric"))' not in script
    assert '$("#leadMetric").textContent = material.length;' in script


def test_analysis_prompt_starts_from_completed_processing_and_requires_checkpoints(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import json
from service import build_analysis_prompt
prompt = build_analysis_prompt("case-one", "quick", "Who accessed the confidential files?")
print(json.dumps({
    "completed_first": "deterministic evidence-processing workflow has already run" in prompt,
    "does_not_supervise_pipeline": "Run this exact coordinator command first" not in prompt,
    "answers": "case.py answer" in prompt,
    "checkpoint": "Checkpoint useful work immediately" in prompt,
    "facts_survive": "does not need to be labeled \"confirmed malicious\"" in prompt,
    "private_ip": "private IP is not benign" in prompt,
    "no_framework_tests": "Never run Hermes verification, pytest, framework tests" in prompt,
}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.strip()) == {
        "completed_first": True,
        "does_not_supervise_pipeline": True,
        "answers": True,
        "checkpoint": True,
        "facts_survive": True,
        "private_ip": True,
        "no_framework_tests": True,
    }


def test_web_workflow_orders_processing_before_model_and_always_finalizes(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import json
import sys
from pathlib import Path
from types import SimpleNamespace
import web_workflow

root = Path(__import__("os").environ["ARIES_ROOT"])
case = root / "cases" / "ordered"
(case / "report").mkdir(parents=True, exist_ok=True)
prompt = root / "analysis.txt"
prompt.write_text("answer the questions", encoding="utf-8")
calls = []

def fake_run(command, **kwargs):
    calls.append([str(item) for item in command])
    if command[0] == "hermes":
        return SimpleNamespace(returncode=29)
    if "--phase" in command and "report" in command:
        (case / "report" / "report.md").write_text("report", encoding="utf-8")
    return SimpleNamespace(returncode=0)

class FakePopen:
    def __init__(self, command, **kwargs):
        calls.append([str(item) for item in command])
        self.returncode = 29
    def poll(self):
        return self.returncode

web_workflow.PROJECT_ROOT = root
web_workflow.SCRIPTS = root / "scripts"
web_workflow.case_dir = lambda name: root / "cases" / name
web_workflow.append_command_event = lambda *args, **kwargs: "cmd"
web_workflow.subprocess.run = fake_run
web_workflow.subprocess.Popen = FakePopen
sys.argv = ["web_workflow.py", "--case", "ordered", "--prompt-file", str(prompt), "--usage-file", str(root / "usage.json")]
web_workflow.main()
print(json.dumps(calls))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    calls = json.loads(result.stdout.strip().splitlines()[-1])
    assert "investigate.py" in calls[0][1]
    assert "--all" in calls[0]
    assert "answer-seed" in calls[1]
    assert calls[2][0] == "hermes"
    assert calls[3][-2:] == ["evidence_assessment", "--concise"]
    assert calls[4][-2:] == ["report", "--concise"]
    status = json.loads((root / "cases" / "ordered" / "output" / "web" / "analysis-status.json").read_text())
    assert status["status"] == "failed"


def test_dashboard_distinguishes_processing_from_unresolved_analysis() -> None:
    index = (PROJECT / "web" / "static" / "index.html").read_text(encoding="utf-8")
    script = (PROJECT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert '<span>Processing</span>' in index
    assert "analyst request(s) unresolved" in script
    assert "Retry AI synthesis" in script
    assert "Retry artifact processing" in script
    assert "Partial report available" in script


def test_failed_static_artifact_requires_processing_retry_and_resets_dependents(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    code = r'''
import asyncio
import json
from service import create_draft_case, case_root, register_case, artifact_processing_retry_required, reset_artifact_processing_chain
from common import load_case, save_case

create_draft_case("retry-static", "Static retry test")
root = case_root("retry-static")
(root / "evidence" / "malware.rar").write_bytes(b"rar placeholder")
asyncio.run(register_case("retry-static", "Static retry test"))
(root / "output" / "artifacts").mkdir(parents=True, exist_ok=True)
(root / "output" / "artifacts" / "artifact-baseline-manifest.json").write_text(json.dumps({
    "results": [{"status": "failed", "source": "malware.rar", "reason": "OSError: invalid metadata"}]
}), encoding="utf-8")
case = load_case("retry-static")
for phase in ("artifact_baseline", "artifact_triage", "pivot", "targeted_timeline", "evidence_assessment", "ioc_scan", "report"):
    case["investigation"]["phases"][phase]["status"] = "complete"
case["investigation"]["phases"]["artifact_baseline"]["status"] = "partial"
save_case("retry-static", case)
before = artifact_processing_retry_required("retry-static")
changed = reset_artifact_processing_chain("retry-static")
case = load_case("retry-static")
print(json.dumps({
    "required": before,
    "changed": changed,
    "statuses": {phase: case["investigation"]["phases"][phase]["status"] for phase in changed},
    "discovery": case["investigation"]["phases"]["artifact_discovery"]["status"],
}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout.strip().splitlines()[-1])
    assert value["required"] is True
    assert value["changed"] == ["artifact_baseline", "artifact_triage", "pivot", "targeted_timeline", "evidence_assessment", "ioc_scan", "report"]
    assert set(value["statuses"].values()) == {"pending"}
    assert value["discovery"] == "pending"
