from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def test_v020_phase_migration_maps_eventlog_state(tmp_path: Path) -> None:
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    root = tmp_path / "Aries"
    case_root = root / "cases" / "old"
    case_root.mkdir(parents=True)
    case = {
        "schema_version": "0.2.0",
        "name": "old",
        "evidence": {"e01": {"path": str(tmp_path / "disk.E01")}},
        "investigation": {
            "phases": {
                "preflight": {"status": "complete", "attempts": 1},
                "eztools_baseline": {"status": "complete", "attempts": 1, "message": "old event baseline"},
            }
        },
    }
    (tmp_path / "disk.E01").write_bytes(b"x")
    (case_root / "case.json").write_text(json.dumps(case), encoding="utf-8")
    env = os.environ.copy(); env["ARIES_ROOT"] = str(root)
    proc = subprocess.run([sys.executable, str(scripts / "case.py"), "status", "--case", "old"], env=env, text=True, capture_output=True)
    assert proc.returncode == 0, proc.stderr
    migrated = json.loads((case_root / "case.json").read_text())
    assert migrated["schema_version"] == "0.3.4"
    assert "artifact_baseline" in migrated["investigation"]["phases"]
    assert "evidence_assessment" in migrated["investigation"]["phases"]
    assert "orchestration_review" in migrated["investigation"]["phases"]
    assert migrated["investigation"]["phases"]["eventlog_baseline"]["status"] == "complete"
    assert migrated["investigation"]["phases"]["event_triage"]["status"] == "pending"


def test_v030_migration_resets_stale_assessment_and_report(tmp_path: Path) -> None:
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    root = tmp_path / "Aries"
    case_root = root / "cases" / "v030"
    case_root.mkdir(parents=True)
    memory = tmp_path / "memory.raw"
    memory.write_bytes(b"x")
    case = {
        "schema_version": "0.3.0",
        "name": "v030",
        "evidence": {"memory": {"kind": "memory", "path": str(memory)}},
        "investigation": {
            "phases": {
                "evidence_assessment": {"status": "complete", "attempts": 1},
                "report": {"status": "complete", "attempts": 1},
            }
        },
    }
    (case_root / "case.json").write_text(json.dumps(case), encoding="utf-8")
    env = os.environ.copy()
    env["ARIES_ROOT"] = str(root)
    result = subprocess.run([sys.executable, str(scripts / "case.py"), "status", "--case", "v030"], env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    migrated = json.loads((case_root / "case.json").read_text())
    assert migrated["investigation"]["phases"]["orchestration_review"]["status"] == "skipped"
    assert migrated["investigation"]["phases"]["evidence_assessment"]["status"] == "pending"
    assert migrated["investigation"]["phases"]["report"]["status"] == "pending"


def test_v032_migration_skips_review_without_resetting_parsers(tmp_path: Path) -> None:
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    root = tmp_path / "Aries"
    case_root = root / "cases" / "v032"
    case_root.mkdir(parents=True)
    memory = tmp_path / "memory.raw"
    memory.write_bytes(b"x")
    case = {
        "schema_version": "0.3.2",
        "name": "v032",
        "evidence": {"memory": {"kind": "memory", "path": str(memory)}},
        "investigation": {
            "phases": {
                "memory_baseline": {"status": "complete", "attempts": 1},
                "orchestration_review": {"status": "complete", "attempts": 1},
                "evidence_assessment": {"status": "complete", "attempts": 1},
                "report": {"status": "complete", "attempts": 1},
            }
        },
    }
    (case_root / "case.json").write_text(json.dumps(case), encoding="utf-8")
    env = os.environ.copy()
    env["ARIES_ROOT"] = str(root)
    result = subprocess.run([sys.executable, str(scripts / "case.py"), "status", "--case", "v032"], env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    migrated = json.loads((case_root / "case.json").read_text())
    assert migrated["investigation"]["phases"]["memory_baseline"]["status"] == "complete"
    assert migrated["investigation"]["phases"]["orchestration_review"]["status"] == "skipped"
    assert migrated["investigation"]["phases"]["evidence_assessment"]["status"] == "pending"
    assert migrated["investigation"]["phases"]["report"]["status"] == "pending"


def test_v033_waiting_review_is_removed_from_critical_path(tmp_path: Path) -> None:
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    root = tmp_path / "Aries"
    case_root = root / "cases" / "waiting"
    case_root.mkdir(parents=True)
    case = {
        "schema_version": "0.3.3",
        "name": "waiting",
        "evidence": {},
        "investigation": {"phases": {
            "targeted_timeline": {"status": "complete", "attempts": 1},
            "orchestration_review": {"status": "waiting", "attempts": 2},
            "evidence_assessment": {"status": "blocked", "attempts": 1},
            "report": {"status": "blocked", "attempts": 1},
        }},
    }
    (case_root / "case.json").write_text(json.dumps(case), encoding="utf-8")
    env = os.environ.copy(); env["ARIES_ROOT"] = str(root)
    result = subprocess.run([sys.executable, str(scripts / "case.py"), "status", "--case", "waiting"], env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    migrated = json.loads((case_root / "case.json").read_text())
    assert migrated["schema_version"] == "0.3.4"
    assert migrated["investigation"]["phases"]["targeted_timeline"]["status"] == "complete"
    assert migrated["investigation"]["phases"]["orchestration_review"]["status"] == "skipped"
    assert migrated["investigation"]["phases"]["evidence_assessment"]["status"] == "pending"
    assert migrated["investigation"]["phases"]["report"]["status"] == "pending"
    assert "orchestration_review" not in migrated["investigation"]["phase_order"]
