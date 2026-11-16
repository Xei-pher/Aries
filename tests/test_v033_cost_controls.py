from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def run(root: Path, script: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["ARIES_ROOT"] = str(root)
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args], env=env, text=True, capture_output=True)


def test_material_lead_budget_preserves_overflow_as_backlog(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"memory")
    assert run(root, "case.py", "init", "--name", "budget", "--memory", str(evidence)).returncode == 0
    for index in range(30):
        result = run(
            root, "case.py", "lead", "--case", "budget", "--type", "file",
            "--value", f"suspicious-{index}.exe", "--priority", "high",
            "--score", str(70 + (index % 20)), "--source", "test", "--reason", "budget test",
        )
        assert result.returncode == 0

    code = "from records import enforce_material_lead_budget; enforce_material_lead_budget('budget', 24, reason='test')"
    env = os.environ.copy()
    env["ARIES_ROOT"] = str(root)
    env["PYTHONPATH"] = str(SCRIPTS)
    result = subprocess.run([sys.executable, "-c", code], env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr

    history = [json.loads(line) for line in (root / "cases" / "budget" / "leads.jsonl").read_text().splitlines()]
    priorities: dict[str, str] = {}
    for item in history:
        if item.get("event") == "create":
            priorities[item["id"]] = item["priority"]
        elif item.get("event") == "update" and "priority" in item.get("changes", {}):
            priorities[item["id"]] = item["changes"]["priority"]
    assert sum(value in {"high", "critical"} for value in priorities.values()) == 24
    assert sum(value == "medium" for value in priorities.values()) == 6
    audit = json.loads((root / "cases" / "budget" / "output" / "lead-priority-budget.json").read_text())
    assert len(audit["downgraded_to_backlog"]) == 6


def test_concise_phase_writes_full_log(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"memory")
    assert run(root, "case.py", "init", "--name", "concise", "--memory", str(evidence)).returncode == 0
    result = run(root, "investigate.py", "--case", "concise", "--phase", "preflight", "--concise")
    assert result.returncode in {0, 2, 3}
    assert "PHASE_LOG=" in result.stdout
    logs = list((root / "cases" / "concise" / "output" / "logs").glob("*-preflight.log"))
    assert len(logs) == 1
    assert "COMMAND=" in logs[0].read_text()
