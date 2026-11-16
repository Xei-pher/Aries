from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
from pathlib import Path


def run(root: Path, script: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy(); env["ARIES_ROOT"] = str(root)
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    return subprocess.run([sys.executable, str(scripts / script), *args], env=env, text=True, capture_output=True)


def test_pivot_correlates_and_builds_targeted_timeline(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    mem = tmp_path / "memory.raw"; mem.write_bytes(b"x")
    assert run(root, "case.py", "init", "--name", "pivot", "--memory", str(mem)).returncode == 0
    proc = run(root, "case.py", "lead", "--case", "pivot", "--type", "process", "--value", "CrackedSoftware.exe", "--priority", "high", "--score", "80", "--source", "test", "--reason", "seed")
    assert proc.returncode == 0, proc.stderr
    out = root / "cases" / "pivot" / "output" / "volatility"; out.mkdir(parents=True, exist_ok=True)
    (out / "windows_cmdline.txt").write_text('2026-08-08 08:56:15 CrackedSoftware.exe connected 192.168.112.153 SHA256=' + 'b'*64 + '\n', encoding='utf-8')
    (out / "windows_netstat.txt").write_text('2026-08-08 08:56:16 CrackedSoftware.exe 192.168.112.153:8080\n', encoding='utf-8')

    proc = run(root, "pivot.py", "--case", "pivot")
    assert proc.returncode == 0, proc.stderr
    summary = json.loads((root / "cases" / "pivot" / "output" / "pivots" / "pivot-summary.json").read_text())
    assert summary["leads"][0]["hit_count"] >= 2

    proc = run(root, "targeted_timeline.py", "--case", "pivot")
    assert proc.returncode == 0, proc.stderr
    with (root / "cases" / "pivot" / "timeline" / "targeted_timeline.csv").open(newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    assert any("CrackedSoftware.exe" in row["event"] for row in rows)
