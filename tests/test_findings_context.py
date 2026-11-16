from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def run(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy(); env["ARIES_ROOT"] = str(root)
    script = Path(__file__).resolve().parents[1] / "scripts" / "case.py"
    return subprocess.run([sys.executable, str(script), *args], env=env, text=True, capture_output=True)


def test_finding_retraction_and_context(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    assert run(root, "init", "--name", "ctx").returncode == 0
    first = run(root, "finding", "--case", "ctx", "--kind", "confirmed", "--title", "Course malware", "--source", "history", "--details", "looked bad")
    assert first.returncode == 0
    assert "F-0001" in first.stdout
    assert run(root, "finding-retract", "--case", "ctx", "--id", "F-0001", "--reason", "Analyst confirmed training activity").returncode == 0
    assert run(root, "context-add", "--case", "ctx", "--type", "training", "--value", "course_files", "--details", "Known legitimate course material", "--source", "analyst", "--confidence", "high").returncode == 0
    assert run(root, "report", "--case", "ctx", "--allow-draft").returncode == 0
    report = (root / "cases" / "ctx" / "report" / "report.md").read_text()
    assert "Retracted / Superseded Findings" in report
    assert "course_files" in report
