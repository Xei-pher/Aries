from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def test_split_ewf_hashes_each_segment(tmp_path: Path) -> None:
    package = Path(__file__).resolve().parents[1]
    scripts = package / "scripts"
    root = tmp_path / "aries"
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    first = evidence / "disk.E01"
    second = evidence / "disk.E02"
    first.write_bytes(b"first segment")
    second.write_bytes(b"second segment")

    env = os.environ.copy()
    env["ARIES_ROOT"] = str(root)

    subprocess.run(
        [sys.executable, str(scripts / "case.py"), "init", "--name", "split", "--e01", str(first)],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [sys.executable, str(scripts / "case.py"), "hash", "--case", "split", "--which", "e01"],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    case = json.loads((root / "cases" / "split" / "case.json").read_text(encoding="utf-8"))
    entry = case["evidence"]["e01"]
    assert entry["segment_count"] == 2
    assert len(entry["segment_sha256"]) == 2
    assert entry["sha256"] is None
    assert entry["size_bytes"] == first.stat().st_size + second.stat().st_size
