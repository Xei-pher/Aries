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


def make_case(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "Aries"
    result = run(root, "case.py", "init", "--name", "gates")
    assert result.returncode == 0, result.stderr
    return root, root / "cases" / "gates"


def test_report_is_generated_with_review_required_without_ready_assessment(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    result = run(root, "case.py", "report", "--case", "gates")
    assert result.returncode == 0
    assert "REPORT_STATUS=PARTIAL" in result.stdout
    text = (case_root / "report" / "report.md").read_text(encoding="utf-8")
    assert "PARTIAL REPORT — UNRESOLVED ITEMS ARE LISTED BELOW" in text


def test_legacy_draft_override_uses_same_review_required_label(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    result = run(root, "case.py", "report", "--case", "gates", "--allow-draft")
    assert result.returncode == 0, result.stderr
    text = (case_root / "report" / "report.md").read_text(encoding="utf-8")
    assert "PARTIAL REPORT — UNRESOLVED ITEMS ARE LISTED BELOW" in text


def test_high_priority_lead_cannot_be_generically_closed(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    parsed = case_root / "output" / "search" / "evidence.txt"
    parsed.write_text("suspicious.exe", encoding="utf-8")
    assert run(root, "case.py", "lead", "--case", "gates", "--type", "process", "--value", "suspicious.exe", "--priority", "high", "--score", "80", "--source", "test", "--reason", "Needs investigation").returncode == 0
    rejected = run(root, "case.py", "lead-close", "--case", "gates", "--id", "L-0001", "--status", "contextual", "--reason", "Generic bulk disposition with no structured basis.")
    assert rejected.returncode != 0
    accepted = run(root, "case.py", "lead-close", "--case", "gates", "--id", "L-0001", "--status", "confirmed", "--reason", "Exact process value appears in the cited parsed evidence.", "--evidence-ref", "output/search/evidence.txt")
    assert accepted.returncode == 0, accepted.stderr
    record = json.loads((case_root / "leads.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert record["closure_basis"]["evidence_refs"] == ["output/search/evidence.txt"]


def test_single_source_recursive_lead_is_advisory_not_report_blocker(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    created = run(root, "case.py", "lead", "--case", "gates", "--type", "url", "--value", "https://technet.microsoft.com/example", "--priority", "high", "--score", "85", "--source", "Pivot:L-0001", "--reason", "Co-observed in one parsed source")
    assert created.returncode == 0, created.stderr
    assessment = run(root, "evidence_assessment.py", "--case", "gates")
    assert assessment.returncode == 0, assessment.stderr
    payload = json.loads((case_root / "output" / "evidence-assessment.json").read_text(encoding="utf-8"))
    assert payload["report_ready"] is True
    assert any(item["code"] == "DERIVED_SINGLE_SOURCE_LEAD" and not item["blocking"] for item in payload["issues"])


def test_ioc_requires_value_source_and_evidence(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    parsed = case_root / "output" / "search" / "network.txt"
    parsed.write_text("sample.exe connected to 10.0.0.5", encoding="utf-8")
    empty = run(root, "case.py", "ioc", "--case", "gates", "--type", "sha256", "--value", "")
    assert empty.returncode != 0
    private = run(root, "case.py", "ioc", "--case", "gates", "--type", "ip", "--value", "10.0.0.5", "--source", "Sysmon", "--evidence-ref", "output/search/network.txt")
    assert private.returncode != 0
    accepted = run(root, "case.py", "ioc", "--case", "gates", "--type", "ip", "--value", "10.0.0.5", "--source", "Sysmon", "--evidence-ref", "output/search/network.txt", "--allow-private")
    assert accepted.returncode == 0, accepted.stderr


def test_confirmed_malicious_requires_direct_signal_or_three_families(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    first = case_root / "output" / "search" / "sysmon.txt"
    second = case_root / "output" / "search" / "prefetch.txt"
    first.write_text("suspicious.exe executed", encoding="utf-8")
    second.write_text("suspicious.exe prefetch entry", encoding="utf-8")
    added = run(
        root, "case.py", "finding", "--case", "gates", "--kind", "confirmed",
        "--title", "Suspicious executable was malicious", "--source", "test", "--details", "Two weak execution artifacts only",
        "--claim-scope", "malicious", "--evidence-ref", "output/search/sysmon.txt", "--evidence-ref", "output/search/prefetch.txt",
        "--artifact-family", "sysmon", "--artifact-family", "prefetch",
    )
    assert added.returncode == 0, added.stderr
    assessed = run(root, "evidence_assessment.py", "--case", "gates")
    assert assessed.returncode == 3
    report = json.loads((case_root / "output" / "evidence-assessment.json").read_text(encoding="utf-8"))
    assert any(item["code"] == "MALICIOUS_PROMOTION_TOO_WEAK" and item["blocking"] for item in report["issues"])


def test_recorded_context_automatically_downgrades_confirmation(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    evidence = case_root / "output" / "search" / "training.txt"
    evidence.write_text("course_files PowerShell execution", encoding="utf-8")
    context = run(root, "case.py", "context-add", "--case", "gates", "--type", "training", "--value", "course_files", "--details", "Known legitimate course material", "--source", "analyst", "--confidence", "high")
    assert context.returncode == 0, context.stderr
    added = run(
        root, "case.py", "finding", "--case", "gates", "--kind", "confirmed", "--title", "course_files PowerShell was malicious",
        "--source", "test", "--details", "Activity in the known training directory", "--claim-scope", "malicious",
        "--evidence-ref", "output/search/training.txt", "--artifact-family", "powershell", "--artifact-family", "filesystem",
    )
    assert added.returncode == 0, added.stderr
    finding = json.loads((case_root / "findings.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert finding["kind"] == "inference"
    assert finding["context_matches"]
    assert "Downgraded" in finding["validation_warning"]


def test_finding_rejects_missing_evidence_reference(tmp_path: Path) -> None:
    root, _ = make_case(tmp_path)
    result = run(
        root, "case.py", "finding", "--case", "gates", "--kind", "inference", "--title", "Unsupported claim",
        "--source", "test", "--details", "Missing source", "--evidence-ref", "output/does-not-exist.txt",
    )
    assert result.returncode != 0
    assert "does not exist" in (result.stderr + result.stdout)


def test_access_location_claim_requires_path_bearing_artifact(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    prefetch = case_root / "output" / "dissect" / "prefetch.txt"
    prefetch.parent.mkdir(parents=True, exist_ok=True)
    prefetch.write_text("WORDPAD.EXE referenced CONFIDENTIAL.RTF", encoding="utf-8")
    added = run(
        root, "case.py", "finding", "--case", "gates", "--kind", "inference",
        "--title", "Confidential file opened from local drive (not network)",
        "--source", "Prefetch", "--details", "No UNC path was observed in Prefetch.",
        "--evidence-ref", "output/dissect/prefetch.txt", "--artifact-family", "prefetch",
    )
    assert added.returncode == 0, added.stderr
    assessed = run(root, "evidence_assessment.py", "--case", "gates")
    assert assessed.returncode == 3
    report = json.loads((case_root / "output" / "evidence-assessment.json").read_text(encoding="utf-8"))
    assert any(item["code"] == "ACCESS_LOCATION_UNCORROBORATED" and item["blocking"] for item in report["issues"])


def test_quick_dissect_baseline_includes_access_path_artifacts() -> None:
    source = (SCRIPTS / "run_dissect.py").read_text(encoding="utf-8")
    quick = source.split("QUICK = [", 1)[1].split("]", 1)[0]
    for plugin in ("shellbags", "mru.recentdocs", "jumplist", "lnk"):
        assert f'"{plugin}"' in quick
