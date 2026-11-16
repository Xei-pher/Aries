from __future__ import annotations

import csv
import os
import subprocess
import sys
from pathlib import Path


def test_ioc_scan(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    root.mkdir()
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    env = os.environ.copy()
    env["ARIES_ROOT"] = str(root)

    subprocess.run([sys.executable, str(scripts / "case.py"), "init", "--name", "IOC-TEST"], env=env, check=True)
    output = root / "cases" / "IOC-TEST" / "output" / "search" / "sample.txt"
    output.write_text("Contact https://bad.example/path from 203.0.113.5 sha256=" + "a" * 64, encoding="utf-8")
    subprocess.run([sys.executable, str(scripts / "case.py"), "ioc-scan", "--case", "IOC-TEST"], env=env, check=True)

    with (root / "cases" / "IOC-TEST" / "ioc_candidates.csv").open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    values = {(r["type"], r["value"]) for r in rows}
    assert ("url", "https://bad.example/path") in values
    assert ("domain", "bad.example") in values
    assert ("ip", "203.0.113.5") in values
    assert ("sha256", "a" * 64) in values
