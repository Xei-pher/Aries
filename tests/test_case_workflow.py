from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
from pathlib import Path


def run(script: Path, *args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(script), *args], env=env, text=True, capture_output=True, check=True)


def test_case_workflow(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    root.mkdir()
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"aries-test-evidence")

    scripts = Path(__file__).resolve().parents[1] / "scripts"
    env = os.environ.copy()
    env["ARIES_ROOT"] = str(root)

    run(scripts / "case.py", "init", "--name", "TEST-001", "--memory", str(evidence), env=env)
    run(scripts / "case.py", "hash", "--case", "TEST-001", "--which", "memory", env=env)
    run(
        scripts / "case.py",
        "finding",
        "--case",
        "TEST-001",
        "--title",
        "Suspicious command line",
        "--source",
        "output/volatility/windows_cmdline.txt",
        "--details",
        "powershell.exe -enc ...",
        "--severity",
        "high",
        "--confidence",
        "medium",
        env=env,
    )
    parsed = root / "cases" / "TEST-001" / "output" / "search" / "network.txt"
    parsed.parent.mkdir(parents=True, exist_ok=True)
    parsed.write_text("Observed connection to evil.example", encoding="utf-8")
    run(
        scripts / "case.py",
        "ioc",
        "--case",
        "TEST-001",
        "--type",
        "domain",
        "--value",
        "evil.example",
        "--source",
        "test",
        "--evidence-ref",
        "output/search/network.txt",
        env=env,
    )
    run(scripts / "case.py", "report", "--case", "TEST-001", "--allow-draft", env=env)

    case = json.loads((root / "cases" / "TEST-001" / "case.json").read_text())
    assert case["evidence"]["memory"]["sha256"]
    report = (root / "cases" / "TEST-001" / "report" / "report.md").read_text()
    assert "Suspicious command line" in report
    assert "evil.example" in report
