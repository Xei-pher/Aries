from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT / "scripts"


def run(root: Path, script: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["ARIES_ROOT"] = str(root)
    env["PYTHONPATH"] = os.pathsep.join([str(PROJECT / "web"), str(SCRIPTS)])
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args], env=env, text=True, capture_output=True)


def run_code(root: Path, code: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["ARIES_ROOT"] = str(root)
    env["PYTHONPATH"] = os.pathsep.join([str(PROJECT / "web"), str(SCRIPTS)])
    return subprocess.run([sys.executable, "-c", code], env=env, text=True, capture_output=True)


def make_case(tmp_path: Path, name: str = "lake") -> tuple[Path, Path]:
    root = tmp_path / "Aries"
    result = run(root, "case.py", "init", "--name", name)
    assert result.returncode == 0, result.stderr
    return root, root / "cases" / name


def test_case_datalake_indexes_parsed_outputs_with_line_citations(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    parsed = case_root / "output" / "search" / "sysmon.txt"
    parsed.parent.mkdir(parents=True, exist_ok=True)
    parsed.write_text(
        "Event 1 process creation\nImage: C:\\Users\\soc20\\Downloads\\CrackedSoftware.exe\n"
        "Event 3 destination 192.168.112.153:8080\n",
        encoding="utf-8",
    )
    raw = case_root / "evidence" / "raw-secret.txt"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text("RAW_EVIDENCE_MUST_NOT_BE_INDEXED", encoding="utf-8")
    result = run(root, "case_datalake.py", "--case", "lake", "--query", "CrackedSoftware 192.168.112.153")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"]["raw_evidence_indexed"] is False
    assert payload["status"]["indexed_files"] >= 1
    assert any(item["path"] == "output/search/sysmon.txt" for item in payload["results"])
    assert any(item["citation"].startswith("output/search/sysmon.txt:L") for item in payload["results"])
    assert all(not item["path"].startswith("evidence/") for item in payload["results"])
    assert "RAW_EVIDENCE_MUST_NOT_BE_INDEXED" not in json.dumps(payload)


def test_datalake_refreshes_when_case_output_changes(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path)
    parsed = case_root / "output" / "search" / "events.txt"
    parsed.parent.mkdir(parents=True, exist_ok=True)
    parsed.write_text("first entity alpha.exe\n", encoding="utf-8")
    first = json.loads(run(root, "case_datalake.py", "--case", "lake").stdout)
    parsed.write_text("first entity alpha.exe\nsecond entity beta.exe\n", encoding="utf-8")
    second = json.loads(run(root, "case_datalake.py", "--case", "lake", "--query", "beta.exe").stdout)
    assert first["fingerprint"] != second["status"]["fingerprint"]
    assert second["status"]["refreshed"] is True
    assert any("beta.exe" in item["content"] for item in second["results"])


def test_datalake_works_without_sqlite_fts5(tmp_path: Path, monkeypatch) -> None:
    root, case_root = make_case(tmp_path, "plain")
    parsed = case_root / "output" / "dissect" / "shellbags.txt"
    parsed.parent.mkdir(parents=True, exist_ok=True)
    parsed.write_text(r"UNC path \\192.168.70.128\SHAREDJJ\docs\Confidential.rtf", encoding="utf-8")
    monkeypatch.setenv("ARIES_DATALAKE_DISABLE_FTS5", "1")
    result = run(root, "case_datalake.py", "--case", "plain", "--query", "shellbags network location")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"]["search_backend"] == "sqlite_like"
    assert any("192.168.70.128" in item["content"] for item in payload["results"])


def test_datalake_recovers_from_corrupt_database(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path, "recover")
    parsed = case_root / "output" / "dissect" / "lnk.txt"
    parsed.parent.mkdir(parents=True, exist_ok=True)
    parsed.write_text(r"lnk_net_name=\\192.168.70.128\SHAREDJJ", encoding="utf-8")
    first = run(root, "case_datalake.py", "--case", "recover")
    assert first.returncode == 0, first.stderr
    (case_root / "output" / "datalake" / "case-index.sqlite").write_bytes(b"not a sqlite database")
    result = run(root, "case_datalake.py", "--case", "recover", "--query", "SHAREDJJ")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert "recovered_from" in payload["status"]
    assert any("SHAREDJJ" in item["content"] for item in payload["results"])


def test_investigation_brief_is_saved_and_injected(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path, "brief")
    code = r'''
import json
from common import load_case, save_case
from service import save_investigation_brief, read_investigation_brief, build_investigation_prompt
brief = "Focus on 8 August. course_files is legitimate training. Determine persistence."
case = load_case("brief")
for phase in ("evidence_assessment", "ioc_scan", "report"):
    case["investigation"]["phases"][phase]["status"] = "complete"
save_case("brief", case)
saved = save_investigation_brief("brief", brief)
prompt = build_investigation_prompt("brief", "quick", brief)
case = load_case("brief")
print(json.dumps({"saved": saved, "loaded": read_investigation_brief("brief"), "in_prompt": brief in prompt, "context_rule": "case_context.json" in prompt, "reset": {phase: case["investigation"]["phases"][phase]["status"] for phase in ("evidence_assessment", "ioc_scan", "report")}}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout.strip())
    assert payload["in_prompt"] is True
    assert payload["context_rule"] is True
    assert payload["loaded"]["instructions"] == payload["saved"]["instructions"]
    assert payload["reset"] == {"evidence_assessment": "pending", "ioc_scan": "pending", "report": "pending"}
    assert (case_root / "investigation-brief.json").is_file()


def test_analyst_requests_are_gated_and_rendered_in_report(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path, "questions")
    code = r'''
import json
from service import save_investigation_brief
saved = save_investigation_brief("questions", "Who accessed the document?\nList all accessed files with full paths.")
print(json.dumps(saved))
'''
    saved = run_code(root, code)
    assert saved.returncode == 0, saved.stderr
    assert json.loads(saved.stdout)["question_count"] == 2

    pending = run(root, "evidence_assessment.py", "--case", "questions")
    assert pending.returncode == 3
    pending_state = json.loads((case_root / "output" / "evidence-assessment.json").read_text())
    assert sum(item["code"] == "ANALYST_QUESTION_UNANSWERED" for item in pending_state["issues"]) == 2

    source = case_root / "output" / "search" / "access.txt"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("IEUser opened C:\\Confidential.rtf", encoding="utf-8")
    answered = run(root, "case.py", "answer", "--case", "questions", "--id", "Q-001", "--status", "answered", "--answer", "IEUser accessed the document.", "--confidence", "high", "--evidence-ref", "output/search/access.txt")
    assert answered.returncode == 0, answered.stderr
    unresolved = run(root, "case.py", "answer", "--case", "questions", "--id", "Q-002", "--status", "unresolved", "--answer", "Only one accessed path was recovered.", "--confidence", "low", "--limitation", "The available parser output does not enumerate every accessed file.")
    assert unresolved.returncode == 0, unresolved.stderr

    ready = run(root, "evidence_assessment.py", "--case", "questions")
    assert ready.returncode == 0, ready.stderr
    assessment = json.loads((case_root / "output" / "evidence-assessment.json").read_text())
    assert assessment["report_ready"] is True
    assert assessment["issue_count"] == 1
    assert assessment["blocking_issue_count"] == 0

    report = run(root, "case.py", "report", "--case", "questions")
    assert report.returncode == 0, report.stderr
    text = (case_root / "report" / "report.md").read_text(encoding="utf-8")
    assert "## Analyst-Requested Questions" in text
    assert "IEUser accessed the document." in text
    assert "List all accessed files with full paths." in text
    assert "output/search/access.txt" in text


def test_causal_answer_requires_explicit_bridge_evidence(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path, "causal-answer")
    code = r'''
from service import save_investigation_brief
save_investigation_brief("causal-answer", "What installed the companion service?")
'''
    assert run_code(root, code).returncode == 0
    source = case_root / "output" / "search" / "services.csv"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("time,service,parent\n2026-01-01,KslD,sample.exe\n", encoding="utf-8")
    answer = run(
        root, "case.py", "answer", "--case", "causal-answer", "--id", "Q-001",
        "--status", "answered", "--answer", "KslD was installed by sample.exe as companion staging.",
        "--confidence", "high", "--evidence-ref", "output/search/services.csv",
    )
    assert answer.returncode == 0, answer.stderr
    blocked = run(root, "evidence_assessment.py", "--case", "causal-answer")
    assert blocked.returncode == 3
    issues = json.loads((case_root / "output" / "evidence-assessment.json").read_text())["issues"]
    assert any(item["code"] == "ANSWER_CAUSAL_LINK_UNSUPPORTED" and item["blocking"] for item in issues)

    bridged = run(
        root, "case.py", "answer", "--case", "causal-answer", "--id", "Q-001",
        "--status", "answered", "--answer", "KslD was installed by sample.exe as companion staging.",
        "--confidence", "high", "--evidence-ref", "output/search/services.csv",
        "--bridge-evidence-ref", "output/search/services.csv",
    )
    assert bridged.returncode == 0, bridged.stderr
    assert run(root, "evidence_assessment.py", "--case", "causal-answer").returncode == 0


def test_broad_incident_brief_creates_investigation_and_deliverable_requirements(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path, "broad")
    brief = (
        "Investigate suspicious activity on this compromised workstation. "
        "The SOC team mentioned suspicious network activity around the timeframe. "
        "Ignore older unrelated activity. Create a report and timeline of this activity."
    )
    code = f'''
import json
from service import save_investigation_brief
print(json.dumps(save_investigation_brief("broad", {brief!r})))
'''
    saved = run_code(root, code)
    assert saved.returncode == 0, saved.stderr
    questions = json.loads((case_root / "analyst-questions.json").read_text())["questions"]
    assert len(questions) == 3
    assert any(item["kind"] == "deliverable" and "timeline" in item["question"].lower() for item in questions)
    assert any("network" in item["question"].lower() for item in questions)

    assessment = run(root, "evidence_assessment.py", "--case", "broad")
    assert assessment.returncode == 3
    issues = json.loads((case_root / "output" / "evidence-assessment.json").read_text())["issues"]
    assert any(item["code"] == "INCIDENT_SYNTHESIS_MISSING" and item["blocking"] for item in issues)


def test_appcompat_write_cannot_be_promoted_as_timestomping(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path, "appcompat")
    source = case_root / "output" / "events.txt"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("Sysmon Event 13 AppCompatFlags Compatibility Assistant Store write", encoding="utf-8")
    finding = run(
        root, "case.py", "finding", "--case", "appcompat", "--kind", "observation",
        "--title", "Compatibility Assistant timestamp manipulation (T1099)",
        "--source", "Sysmon", "--details", "AppCompat registry write was treated as timestomping.",
        "--evidence-ref", "output/events.txt", "--artifact-family", "registry",
    )
    assert finding.returncode == 0, finding.stderr
    assessment = run(root, "evidence_assessment.py", "--case", "appcompat")
    assert assessment.returncode == 3
    issues = json.loads((case_root / "output" / "evidence-assessment.json").read_text())["issues"]
    assert any(item["code"] == "APPCOMPAT_TIMESTOMP_OVERCLAIM" and item["blocking"] for item in issues)


def test_report_embeds_compact_finding_centered_timeline(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path, "timeline-report")
    source = case_root / "output" / "events.txt"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("CrackedSoftware.exe connected to 192.168.112.153", encoding="utf-8")
    timeline = case_root / "timeline" / "targeted_timeline.csv"
    timeline.parent.mkdir(parents=True, exist_ok=True)
    timeline.write_text(
        "timestamp,lead_id,source,line,origin,event\n"
        '2026-08-08 08:42:34,L-0001,output/events.txt,1,pivot,"CrackedSoftware.exe downloaded from 192.168.112.153"\n',
        encoding="utf-8",
    )
    finding = run(
        root, "case.py", "finding", "--case", "timeline-report", "--kind", "observation",
        "--title", "CrackedSoftware.exe activity on 2026-08-08", "--source", "Sysmon",
        "--details", "CrackedSoftware.exe communicated with 192.168.112.153.",
        "--evidence-ref", "output/events.txt", "--artifact-family", "sysmon",
    )
    assert finding.returncode == 0, finding.stderr
    assert run(root, "evidence_assessment.py", "--case", "timeline-report").returncode == 0
    assert run(root, "case.py", "report", "--case", "timeline-report").returncode == 0
    report = (case_root / "report" / "report.md").read_text(encoding="utf-8")
    assert "### Significant Events" in report
    assert "2026-08-08 08:42:34" in report
    assert "CrackedSoftware.exe downloaded" in report


def test_deterministic_hash_answer_survives_model_outage(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path, "hash-seed")
    code = r'''
from service import save_investigation_brief
save_investigation_brief("hash-seed", "What is the hash value for the given forensic image?")
'''
    assert run_code(root, code).returncode == 0
    (case_root / "evidence_manifest.json").write_text(json.dumps({
        "evidence": {"e01": {"path": r"C:\Evidence\disk.E01", "sha256": "a" * 64}}
    }), encoding="utf-8")
    seeded = run(root, "case.py", "answer-seed", "--case", "hash-seed")
    assert seeded.returncode == 0, seeded.stderr
    question = json.loads((case_root / "analyst-questions.json").read_text())["questions"][0]
    assert question["status"] == "answered"
    assert question["answer_source"] == "deterministic"
    assert "a" * 64 in question["answer"]
    assert question["evidence_refs"] == ["evidence_manifest.json"]


def test_partial_report_contains_provider_status_and_evidence_candidates(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path, "partial")
    code = r'''
from service import save_investigation_brief
save_investigation_brief("partial", "Which user accessed Confidential.rtf?")
'''
    assert run_code(root, code).returncode == 0
    parsed = case_root / "output" / "dissect" / "lnk.txt"
    parsed.parent.mkdir(parents=True, exist_ok=True)
    parsed.write_text(r"IEUser opened \\192.168.70.128\SHAREDJJ\docs\Confidential.rtf", encoding="utf-8")
    status = case_root / "output" / "web" / "analysis-status.json"
    status.parent.mkdir(parents=True, exist_ok=True)
    status.write_text(json.dumps({"status": "failed", "message": "Provider returned HTTP 429."}), encoding="utf-8")
    assert run(root, "evidence_assessment.py", "--case", "partial").returncode == 3
    report = run(root, "case.py", "report", "--case", "partial")
    assert report.returncode == 0, report.stderr
    text = (case_root / "report" / "report.md").read_text(encoding="utf-8")
    assert "PARTIAL REPORT — AI SYNTHESIS UNAVAILABLE" in text
    assert "Provider returned HTTP 429" in text
    assert "Deterministic evidence candidates" in text
    assert "Confidential.rtf" in text


def test_open_high_lead_is_disclosed_but_does_not_block_report_completion(tmp_path: Path) -> None:
    root, case_root = make_case(tmp_path, "lead-advisory")
    lead = run(root, "case.py", "lead", "--case", "lead-advisory", "--type", "process", "--value", "unknown.exe", "--priority", "high", "--score", "75", "--source", "test", "--reason", "Needs review")
    assert lead.returncode == 0, lead.stderr
    assessment = run(root, "evidence_assessment.py", "--case", "lead-advisory")
    assert assessment.returncode == 0, assessment.stderr
    payload = json.loads((case_root / "output" / "evidence-assessment.json").read_text())
    item = next(entry for entry in payload["issues"] if entry["code"] == "OPEN_HIGH_PRIORITY_LEAD")
    assert item["blocking"] is False
    assert payload["report_ready"] is True


def test_assistant_packet_is_bounded_for_windows_command_line(tmp_path: Path) -> None:
    root, _ = make_case(tmp_path, "bounded")
    code = r'''
import json
from service import assistant_context_packet
results = [{"citation": f"output/huge.txt:L{i}-L{i+1}", "path": "output/huge.txt", "content": "X" * 10000} for i in range(30)]
packet = assistant_context_packet("bounded", "Q" * 2000, {"results": results, "terms": ["test"], "status": {}})
encoded = json.dumps(packet, ensure_ascii=False)
print(json.dumps({"characters": len(encoded), "excerpt_characters": sum(len(item["content"]) for item in packet["retrieval"]["excerpts"])}))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["excerpt_characters"] <= 12_000
    assert payload["characters"] < 24_000


def test_assistant_history_is_case_scoped(tmp_path: Path) -> None:
    root, _ = make_case(tmp_path, "history")
    code = r'''
import json
from service import append_assistant_history, load_assistant_history
append_assistant_history("history", {"question": "What happened?", "answer": "Observed execution.", "sources": ["output/a.txt:L1-L2"]})
print(json.dumps(load_assistant_history("history")))
'''
    result = run_code(root, code)
    assert result.returncode == 0, result.stderr
    records = json.loads(result.stdout.strip())
    assert records == [{"question": "What happened?", "answer": "Observed execution.", "sources": ["output/a.txt:L1-L2"]}]


def test_web_exposes_case_assistant_and_optional_brief() -> None:
    index = (PROJECT / "web" / "static" / "index.html").read_text(encoding="utf-8")
    script = (PROJECT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    app = (PROJECT / "web" / "app.py").read_text(encoding="utf-8")
    assert 'id="assistantButton"' in index
    assert 'id="investigationInstructions"' in index
    assert 'id="investigationDialog"' in index
    assert "/assistant/history" in script
    assert "instructions" in script
    assert 'Field(default="", max_length=12000)' in app
    assert 'question: str = Field(min_length=1, max_length=2000)' in app
