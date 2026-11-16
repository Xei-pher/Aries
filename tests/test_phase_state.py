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


def test_new_case_has_resumable_phases_and_manifest(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    evidence = tmp_path / "host.raw"
    evidence.write_bytes(b"memory")
    proc = run_case(root, "init", "--name", "phase-test", "--memory", str(evidence))
    assert proc.returncode == 0, proc.stderr
    case = json.loads((root / "cases" / "phase-test" / "case.json").read_text())
    assert case["schema_version"] == "0.3.4"
    assert "orchestration_review" not in case["investigation"]["phase_order"]
    assert case["investigation"]["phases"]["preflight"]["status"] == "pending"
    assert case["investigation"]["phases"]["disk_baseline"]["status"] == "skipped"
    assert case["investigation"]["phases"]["memory_baseline"]["status"] == "pending"
    assert (root / "cases" / "phase-test" / "evidence_manifest.json").exists()


def test_hash_reuse_does_not_rehash_unchanged_memory(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"aries-hash-reuse")
    assert run_case(root, "init", "--name", "hash-test", "--memory", str(evidence)).returncode == 0
    first = run_case(root, "hash", "--case", "hash-test")
    second = run_case(root, "hash", "--case", "hash-test")
    assert first.returncode == 0
    assert second.returncode == 0
    assert "Hash current; skipping unchanged memory" in second.stdout
    manifest = json.loads((root / "cases" / "hash-test" / "evidence_manifest.json").read_text())
    assert manifest["evidence"]["memory"]["sha256"]


def test_finding_classification_is_preserved(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"x")
    assert run_case(root, "init", "--name", "finding-test", "--memory", str(evidence)).returncode == 0
    proc = run_case(
        root,
        "finding",
        "--case", "finding-test",
        "--kind", "hypothesis",
        "--title", "Possible C2",
        "--source", "output/volatility/windows_netstat.txt",
        "--details", "Connection requires corroboration.",
    )
    assert proc.returncode == 0, proc.stderr
    finding = json.loads((root / "cases" / "finding-test" / "findings.jsonl").read_text().strip())
    assert finding["kind"] == "hypothesis"
