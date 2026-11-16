from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def run(root: Path, script: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy(); env["ARIES_ROOT"] = str(root)
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    return subprocess.run([sys.executable, str(scripts / script), *args], env=env, text=True, capture_output=True)


def test_loose_artifact_folder_is_first_class_evidence(tmp_path: Path) -> None:
    root = tmp_path / "Aries"; evidence = tmp_path / "Baggage" / "C" / "Users" / "steve"
    evidence.mkdir(parents=True); (evidence / "UsrClass.dat").write_bytes(b"registry")
    (tmp_path / "Baggage" / "ConsoleLog.txt").write_text("artifact log", encoding="utf-8")
    proc = run(root, "case.py", "auto", "--evidence", str(tmp_path / "Baggage"))
    assert proc.returncode == 0, proc.stderr
    case = json.loads((root / "cases" / "Baggage" / "case.json").read_text())
    entry = next(iter(case["evidence"].values()))
    assert entry["kind"] == "artifact_directory"
    phases = case["investigation"]["phases"]
    assert phases["artifact_discovery"]["status"] == "pending"
    assert phases["artifact_baseline"]["status"] == "pending"
    assert phases["disk_baseline"]["status"] == "skipped"
    assert phases["memory_baseline"]["status"] == "skipped"
    assert run(root, "case.py", "hash", "--case", "Baggage").returncode == 0
    case = json.loads((root / "cases" / "Baggage" / "case.json").read_text())
    entry = next(iter(case["evidence"].values()))
    assert entry["file_count"] == 2
    assert all(item["sha256"] for item in entry["file_sha256"])


def test_high_impact_confirmation_requires_corroboration(tmp_path: Path) -> None:
    root = tmp_path / "Aries"; artifact = tmp_path / "UsrClass.dat"; artifact.write_bytes(b"registry")
    assert run(root, "case.py", "init", "--name", "discipline", "--artifact", str(artifact)).returncode == 0
    evidence = root / "cases" / "discipline" / "output" / "artifacts" / "driver.csv"
    evidence.parent.mkdir(parents=True, exist_ok=True); evidence.write_text("driver path in temp", encoding="utf-8")
    proc = run(root, "case.py", "finding", "--case", "discipline", "--kind", "confirmed", "--claim-scope", "malicious", "--title", "Suspicious driver", "--source", "registry", "--details", "driver path in temp", "--artifact-family", "registry", "--evidence-ref", "output/artifacts/driver.csv")
    assert proc.returncode == 0, proc.stderr
    history = [json.loads(line) for line in (root / "cases" / "discipline" / "findings.jsonl").read_text().splitlines()]
    assert history[0]["kind"] == "inference"
    assert "Downgraded" in history[0]["validation_warning"]


def test_finding_downgrade_normalizes_title_and_duplicate_is_merged(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    assert run(root, "case.py", "init", "--name", "dedupe").returncode == 0
    evidence = root / "cases" / "dedupe" / "output" / "events.txt"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("sample.exe connected 10.0.0.5", encoding="utf-8")
    common = (
        "finding", "--case", "dedupe", "--kind", "confirmed", "--claim-scope", "factual",
        "--title", "Confirmed sample.exe connection to 10.0.0.5", "--source", "Sysmon",
        "--details", "sample.exe connected to 10.0.0.5", "--behavior", "sample.exe connected to 10.0.0.5",
        "--incident-cluster", "cluster-1", "--artifact-family", "sysmon", "--evidence-ref", "output/events.txt",
    )
    assert run(root, "case.py", *common).returncode == 0
    assert run(root, "case.py", *common).returncode == 0
    lines = [json.loads(line) for line in (root / "cases" / "dedupe" / "findings.jsonl").read_text().splitlines()]
    assert lines[0]["kind"] == "inference"
    assert lines[0]["title"].startswith("Evidence-supported:")
    assert len([line for line in lines if line.get("event") == "create"]) == 1
    assert any(line.get("event") == "update" and line.get("changes", {}).get("deduplicated") for line in lines)


def test_recursive_pivot_processes_child_leads(tmp_path: Path) -> None:
    root = tmp_path / "Aries"; mem = tmp_path / "memory.raw"; mem.write_bytes(b"x")
    assert run(root, "case.py", "init", "--name", "recursive", "--memory", str(mem)).returncode == 0
    assert run(root, "case.py", "lead", "--case", "recursive", "--type", "process", "--value", "sample.exe", "--priority", "high", "--score", "80", "--source", "seed", "--reason", "test").returncode == 0
    out = root / "cases" / "recursive" / "output" / "volatility"; out.mkdir(parents=True, exist_ok=True)
    out.joinpath("network.txt").write_text("2026-01-01 10:00:00 sample.exe connected 10.10.10.10 SHA256=" + "a" * 64 + "\n" + "2026-01-01 10:00:01 sample.exe connected 10.10.10.10 SHA256=" + "a" * 64 + "\n", encoding="utf-8")
    proc = run(root, "pivot.py", "--case", "recursive", "--max-depth", "2")
    assert proc.returncode == 0, proc.stderr
    summary = json.loads((root / "cases" / "recursive" / "output" / "pivots" / "pivot-summary.json").read_text())
    assert summary["processed_leads"] >= 2
    assert any(item["depth"] == 1 for item in summary["leads"])
