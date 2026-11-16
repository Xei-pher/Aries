from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def run(root: Path, script: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["ARIES_ROOT"] = str(root)
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args], env=env, text=True, capture_output=True)


def make_case(tmp_path: Path, name: str = "orchestration") -> tuple[Path, Path]:
    root = tmp_path / "Aries"
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"memory")
    result = run(root, "case.py", "init", "--name", name, "--memory", str(evidence))
    assert result.returncode == 0, result.stderr
    case_root = root / "cases" / name
    parsed = case_root / "output" / "volatility" / "network.txt"
    parsed.parent.mkdir(parents=True, exist_ok=True)
    parsed.write_text("sample.exe connected 10.0.0.5\n", encoding="utf-8")
    return root, case_root


def valid_review(manifest: dict, role: str, *, candidate: bool = False) -> dict:
    task = manifest["tasks"][role]
    packet = json.loads(Path(manifest["review_packet_path"]).read_text(encoding="utf-8"))
    return {
        "schema_version": "0.3.3",
        "case": manifest["case"],
        "snapshot_id": manifest["snapshot_id"],
        "task_id": task["task_id"],
        "role": role,
        "summary": f"Independent {role} review complete.",
        "lead_reviews": [{
            "lead_id": lead_id,
            "assessment": "unresolved",
            "rationale": "Bounded test review.",
            "evidence_refs": [],
        } for lead_id in packet.get("valid_ids", {}).get("lead_ids", [])],
        "finding_reviews": [{
            "finding_id": finding_id,
            "decision": "needs_more_evidence",
            "recommended_kind": "inference",
            "rationale": "Bounded test review.",
            "evidence_refs": [],
        } for finding_id in packet.get("valid_ids", {}).get("finding_ids", [])],
        "candidate_leads": ([{
            "type": "ip",
            "value": "10.0.0.5",
            "priority": "high",
            "reason": "Present in bounded memory parser output.",
            "parent_id": None,
            "evidence_refs": ["output/volatility/network.txt"],
        }] if candidate else []),
        "contradictions": [],
        "evidence_gaps": [],
        "report_blockers": [],
    }


def submit(root: Path, case_root: Path, manifest: dict, role: str, review: dict, *, suffix: str = "") -> subprocess.CompletedProcess[str]:
    inbox = case_root / "output" / "orchestration" / f"{role}-inbox{suffix}.json"
    inbox.write_text(json.dumps(review), encoding="utf-8")
    return run(
        root, "orchestration.py", "--case", manifest["case"],
        "--submit-review", role, "--input", str(inbox),
        "--delegation-id", f"deleg_{role}{suffix or '_1'}",
        "--child-id", f"child-{role}{suffix or '-1'}",
        "--provider-model", "test/strong-model",
    )


def test_orchestration_prepares_immutable_bounded_tasks(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    assert run(root, "case.py", "lead", "--case", "orchestration", "--type", "process", "--value", "sample.exe", "--priority", "high", "--score", "80", "--source", "test", "--reason", "test").returncode == 0
    huge = case_root / "output" / "volatility" / "large.txt"
    huge.write_text(("sample.exe connected 10.0.0.5 " + "x" * 4000 + "\n") * 1500, encoding="utf-8")
    result = run(root, "orchestration.py", "--case", "orchestration")
    assert result.returncode == 4
    assert "ORCHESTRATION_STATUS=AWAITING_REVIEWS" in result.stdout
    manifest = json.loads((case_root / "output" / "orchestration" / "active.json").read_text())
    snapshot = json.loads(Path(manifest["snapshot_path"]).read_text())
    packet_path = Path(manifest["review_packet_path"])
    packet = json.loads(packet_path.read_text())
    assert manifest["review_policy"]["required_reviews"] == 2
    assert manifest["review_policy"]["max_parallel_children"] == 1
    assert manifest["review_policy"]["self_authored_reviews_permitted"] is False
    assert manifest["review_policy"]["reviewers_may_modify_case"] is False
    assert {item["path"] for item in snapshot["source_catalog"]} >= {"output/volatility/network.txt"}
    assert all(item["review_allowed"] is False for item in snapshot["source_catalog"])
    assert str(tmp_path / "memory.raw") not in {item["path"] for item in snapshot["source_catalog"]}
    assert packet_path.stat().st_size < 40_000
    assert packet["budget"]["estimated_tokens"] <= 8_000
    assert len(packet["active_leads"]) <= 12
    assert len(packet["evidence_excerpts"]) <= 24
    for role in ("investigator", "validator"):
        assert Path(manifest["tasks"][role]["task_path"]).is_file()
        assert Path(manifest["tasks"][role]["output_schema_path"]).is_file()
        task_text = Path(manifest["tasks"][role]["task_path"]).read_text()
        envelope_path = Path(manifest["tasks"][role]["delegate_envelope_path"])
        envelope = json.loads(envelope_path.read_text())
        assert envelope_path.is_file()
        assert envelope["goal"]
        assert envelope["output_schema"]["properties"]["finding_reviews"]["maxItems"] == 0
        assert "Do not call any tool" in envelope["context"]
        assert str(envelope_path) in task_text
        assert "must not open" in task_text


def test_placeholder_delegation_provenance_is_rejected(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 4
    manifest = json.loads((case_root / "output" / "orchestration" / "active.json").read_text())
    inbox = case_root / "output" / "orchestration" / "fake-review.json"
    inbox.write_text(json.dumps(valid_review(manifest, "investigator")), encoding="utf-8")
    result = run(
        root, "orchestration.py", "--case", "orchestration", "--submit-review", "investigator",
        "--input", str(inbox), "--delegation-id", "none", "--child-id", "none", "--provider-model", "none",
    )
    assert result.returncode == 2
    assert "Placeholder delegation provenance is forbidden" in result.stderr


def test_reviewer_must_cover_every_bounded_lead(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    assert run(root, "case.py", "lead", "--case", "orchestration", "--type", "process", "--value", "sample.exe", "--priority", "high", "--score", "80", "--source", "test", "--reason", "test").returncode == 0
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 4
    manifest = json.loads((case_root / "output" / "orchestration" / "active.json").read_text())
    review = valid_review(manifest, "investigator")
    review["lead_reviews"] = []
    result = submit(root, case_root, manifest, "investigator", review, suffix="-incomplete")
    assert result.returncode == 2
    assert "must review every bounded snapshot ID" in result.stderr


def test_two_valid_reviews_merge_without_mutating_case_records(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    run(root, "case.py", "lead", "--case", "orchestration", "--type", "process", "--value", "sample.exe", "--priority", "medium", "--score", "60", "--source", "test", "--reason", "test")
    before_leads = (case_root / "leads.jsonl").read_bytes()
    before_findings = (case_root / "findings.jsonl").read_bytes()
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 4
    manifest = json.loads((case_root / "output" / "orchestration" / "active.json").read_text())
    for role in ("investigator", "validator"):
        submitted = submit(root, case_root, manifest, role, valid_review(manifest, role, candidate=True))
        assert submitted.returncode == 0, submitted.stderr
    result = run(root, "orchestration.py", "--case", "orchestration")
    assert result.returncode == 0, result.stderr
    summary = json.loads((case_root / "output" / "orchestration" / "review-summary.json").read_text())
    assert summary["status"] == "complete"
    assert summary["roles_completed"] == ["investigator", "validator"]
    assert summary["candidate_leads"][0]["proposed_by"] == ["investigator", "validator"]
    assert (case_root / "leads.jsonl").read_bytes() == before_leads
    assert (case_root / "findings.jsonl").read_bytes() == before_findings


def test_invalid_or_fabricated_evidence_reference_keeps_phase_waiting(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 4
    manifest = json.loads((case_root / "output" / "orchestration" / "active.json").read_text())
    bad = valid_review(manifest, "investigator", candidate=True)
    bad["candidate_leads"][0]["evidence_refs"] = ["../../invented.csv"]
    rejected = submit(root, case_root, manifest, "investigator", bad)
    assert rejected.returncode == 2
    assert "reference must be case-relative" in rejected.stderr
    result = run(root, "orchestration.py", "--case", "orchestration")
    assert result.returncode == 4
    assert "review was not registered" in result.stdout


def test_optional_review_candidate_does_not_block_assessment(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 4
    manifest = json.loads((case_root / "output" / "orchestration" / "active.json").read_text())
    for role in ("investigator", "validator"):
        assert submit(root, case_root, manifest, role, valid_review(manifest, role, candidate=True)).returncode == 0
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 0
    assessment = run(root, "evidence_assessment.py", "--case", "orchestration")
    assert assessment.returncode == 0
    report = json.loads((case_root / "output" / "evidence-assessment.json").read_text())
    assert report["report_ready"] is True
    assert report["second_opinion"]["required_for_report"] is False
    assert not any(item["code"].startswith("UNADJUDICATED_REVIEW") for item in report["issues"])


def test_coordinator_records_waiting_as_resumable_not_failed(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    result = run(root, "investigate.py", "--case", "orchestration", "--phase", "orchestration_review")
    assert result.returncode == 4
    case = json.loads((case_root / "case.json").read_text())
    state = case["investigation"]["phases"]["orchestration_review"]
    assert state["status"] == "waiting"
    assert state["attempts"] == 1
    assert "ORCHESTRATION_STATUS=AWAITING_REVIEWS" in result.stdout


def test_stale_optional_review_does_not_block_assessment(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 4
    manifest = json.loads((case_root / "output" / "orchestration" / "active.json").read_text())
    for role in ("investigator", "validator"):
        assert submit(root, case_root, manifest, role, valid_review(manifest, role)).returncode == 0
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 0
    assert run(root, "case.py", "lead", "--case", "orchestration", "--type", "file", "--value", "new.exe", "--priority", "medium", "--score", "50", "--source", "lead agent", "--reason", "Added after review").returncode == 0
    assessment = run(root, "evidence_assessment.py", "--case", "orchestration")
    assert assessment.returncode == 0
    report = json.loads((case_root / "output" / "evidence-assessment.json").read_text())
    assert report["report_ready"] is True
    assert not any(item["code"] == "ORCHESTRATION_REVIEW_STALE" for item in report["issues"])


def test_directly_written_reviews_without_receipts_are_rejected(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 4
    manifest = json.loads((case_root / "output" / "orchestration" / "active.json").read_text())
    for role in ("investigator", "validator"):
        Path(manifest["tasks"][role]["response_path"]).write_text(json.dumps(valid_review(manifest, role)), encoding="utf-8")
    result = run(root, "orchestration.py", "--case", "orchestration")
    assert result.returncode == 4
    assert "review was not registered through --submit-review" in result.stdout


def test_three_provider_failures_mark_orchestration_degraded(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 4
    for _ in range(3):
        failure = run(root, "orchestration.py", "--case", "orchestration", "--record-failure", "investigator", "--reason", "Provider rate limited delegated child", "--error-code", "429")
        assert failure.returncode == 0
    result = run(root, "orchestration.py", "--case", "orchestration")
    assert result.returncode == 5
    assert "ORCHESTRATION_STATUS=DEGRADED" in result.stdout
    manifest = json.loads((case_root / "output" / "orchestration" / "active.json").read_text())
    assert manifest["tasks"]["investigator"]["status"] == "failed"


def test_billing_failure_is_non_retryable_and_immediately_degraded(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 4
    failure = run(root, "orchestration.py", "--case", "orchestration", "--record-failure", "investigator", "--reason", "Provider reports insufficient credits", "--error-code", "billing_error")
    assert failure.returncode == 0
    assert "non-retryable" in failure.stdout
    manifest = json.loads((case_root / "output" / "orchestration" / "active.json").read_text())
    assert manifest["tasks"]["investigator"]["failure_count"] == 1
    assert manifest["tasks"]["investigator"]["status"] == "failed"
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 5


def test_foreign_case_content_is_rejected_at_submission(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 4
    manifest = json.loads((case_root / "output" / "orchestration" / "active.json").read_text())
    review = valid_review(manifest, "investigator")
    review["summary"] = r"Continue from C:\Aries\cases\SOC2026-08-04\report\report_v1.md"
    result = submit(root, case_root, manifest, "investigator", review)
    assert result.returncode == 2
    assert "foreign case path" in result.stderr


def test_candidate_value_must_appear_in_cited_evidence(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 4
    manifest = json.loads((case_root / "output" / "orchestration" / "active.json").read_text())
    review = valid_review(manifest, "investigator", candidate=True)
    review["candidate_leads"][0]["value"] = "5.255.85.128"
    result = submit(root, case_root, manifest, "investigator", review)
    assert result.returncode == 2
    assert "does not appear in its cited evidence" in result.stderr


def test_unresolved_high_priority_disposition_blocks_only_when_material_to_scope(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    assert run(root, "case.py", "lead", "--case", "orchestration", "--type", "ip", "--value", "10.0.0.5", "--priority", "high", "--score", "80", "--source", "test", "--reason", "Needs review").returncode == 0
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 4
    manifest = json.loads((case_root / "output" / "orchestration" / "active.json").read_text())
    for role in ("investigator", "validator"):
        assert submit(root, case_root, manifest, role, valid_review(manifest, role)).returncode == 0
    assert run(root, "orchestration.py", "--case", "orchestration").returncode == 0
    closed = run(root, "case.py", "lead-close", "--case", "orchestration", "--id", "L-0001", "--status", "unresolved", "--reason", "Evidence remains incomplete after bounded review.", "--evidence-ref", "output/volatility/network.txt")
    assert closed.returncode == 0, closed.stderr
    assessment = run(root, "evidence_assessment.py", "--case", "orchestration")
    report = json.loads((case_root / "output" / "evidence-assessment.json").read_text())
    assert assessment.returncode == 0
    issue = next(item for item in report["issues"] if item["code"] == "UNRESOLVED_HIGH_PRIORITY_LEAD")
    assert issue["blocking"] is False

    (case_root / "analyst-questions.json").write_text(json.dumps({
        "schema_version": "3",
        "case": "orchestration",
        "questions": [{
            "id": "Q-001",
            "question": "What activity involved 10.0.0.5?",
            "status": "answered",
            "answer": "The available network output contains 10.0.0.5, but its role remains unresolved.",
            "confidence": "low",
            "evidence_refs": ["output/volatility/network.txt"],
            "bridge_evidence_refs": [],
            "limitation": "",
        }],
    }), encoding="utf-8")
    assessment = run(root, "evidence_assessment.py", "--case", "orchestration")
    report = json.loads((case_root / "output" / "evidence-assessment.json").read_text())
    assert assessment.returncode == 3
    assert any(item["code"] == "UNRESOLVED_MATERIAL_HIGH_PRIORITY_LEAD" and item["blocking"] for item in report["issues"])
