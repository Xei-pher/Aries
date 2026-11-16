from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def run_case(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["ARIES_ROOT"] = str(root)
    script = Path(__file__).parents[1] / "scripts" / "case.py"
    return subprocess.run([sys.executable, str(script), *args], text=True, capture_output=True, env=env)


def test_auto_creates_case_from_folder(tmp_path: Path) -> None:
    aries = tmp_path / "aries"
    evidence = tmp_path / "Incident Alpha"
    evidence.mkdir()
    (evidence / "host.E01").write_bytes(b"disk")
    (evidence / "host.raw").write_bytes(b"memory")

    proc = run_case(aries, "auto", "--evidence", str(evidence))
    assert proc.returncode == 0, proc.stderr
    assert "CASE_NAME=Incident-Alpha" in proc.stdout

    data = json.loads((aries / "cases" / "Incident-Alpha" / "case.json").read_text())
    assert data["evidence"]["e01"]["path"].endswith("host.E01")
    assert data["evidence"]["memory"]["path"].endswith("host.raw")


def test_auto_reuses_same_case(tmp_path: Path) -> None:
    aries = tmp_path / "aries"
    evidence = tmp_path / "CaseOne"
    evidence.mkdir()
    (evidence / "disk.E01").write_bytes(b"disk")

    first = run_case(aries, "auto", "--evidence", str(evidence))
    second = run_case(aries, "auto", "--evidence", str(evidence))
    assert first.returncode == 0
    assert second.returncode == 0
    assert "Reusing existing case" in second.stdout
    assert "CASE_NAME=CaseOne" in second.stdout


def test_auto_counts_single_primary_image_as_one_evidence_source(tmp_path: Path) -> None:
    aries = tmp_path / "aries"
    evidence = tmp_path / "one-image"
    evidence.mkdir()
    (evidence / "victim.E01").write_bytes(b"disk")

    proc = run_case(aries, "auto", "--evidence", str(evidence))
    assert proc.returncode == 0, proc.stderr
    data = json.loads((aries / "cases" / "one-image" / "case.json").read_text())
    assert len(data["evidence"]) == 1
    assert next(iter(data["evidence"].values()))["kind"] == "e01"


def test_auto_keeps_mixed_artifact_directory_beside_primary_image(tmp_path: Path) -> None:
    aries = tmp_path / "aries"
    evidence = tmp_path / "mixed"
    evidence.mkdir()
    (evidence / "victim.E01").write_bytes(b"disk")
    (evidence / "Security.evtx").write_bytes(b"event")

    proc = run_case(aries, "auto", "--evidence", str(evidence))
    assert proc.returncode == 0, proc.stderr
    data = json.loads((aries / "cases" / "mixed" / "case.json").read_text())
    assert len(data["evidence"]) == 2
    assert {entry["kind"] for entry in data["evidence"].values()} == {"e01", "artifact_directory"}


def test_auto_refuses_multiple_memory_candidates(tmp_path: Path) -> None:
    aries = tmp_path / "aries"
    evidence = tmp_path / "ambiguous"
    evidence.mkdir()
    (evidence / "one.raw").write_bytes(b"1")
    (evidence / "two.mem").write_bytes(b"2")

    proc = run_case(aries, "auto", "--evidence", str(evidence))
    assert proc.returncode != 0
    assert "Multiple memory candidates" in proc.stderr
