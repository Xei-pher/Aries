from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
from pathlib import Path


def run(root: Path, script: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["ARIES_ROOT"] = str(root)
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    return subprocess.run([sys.executable, str(scripts / script), *args], env=env, text=True, capture_output=True)


def test_event_triage_seeds_defender_and_sysmon_leads(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    evidence = tmp_path / "disk.E01"
    evidence.write_bytes(b"fake")
    assert run(root, "case.py", "init", "--name", "evt", "--e01", str(evidence)).returncode == 0

    out = root / "cases" / "evt" / "output" / "eztools" / "EvtxECmd-Auto"
    out.mkdir(parents=True, exist_ok=True)
    defender = out / "Microsoft-Windows-Windows_Defender_4Operational"
    sysmon = out / "Microsoft-Windows-Sysmon_4Operational"
    headers = ["TimeCreated", "EventId", "Provider", "PayloadData1", "ExecutableInfo", "Payload"]
    with defender.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(headers)
        w.writerow(["2026-08-08 08:43:59.884", "1116", "Defender", "Trojan:Win32/Meterpreter.RPZ!MTB", r"C:\Users\soc20\Downloads\cracked_software\CrackedSoftware.exe", "SHA256=" + "a"*64])
    with sysmon.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(headers)
        w.writerow(["2026-08-08 08:43:59.000", "1", "Sysmon", "Process Create", r"C:\Users\soc20\Downloads\cracked_software\CrackedSoftware.exe", "Hashes=SHA256=" + "a"*64])
        w.writerow(["2026-08-08 08:44:00.000", "3", "Sysmon", "Network Connect", r"C:\Users\soc20\Downloads\cracked_software\CrackedSoftware.exe", "DestinationIp=192.168.112.153 DestinationPort=8080"])
    manifest = {
        "results": [
            {"event_log": "Microsoft-Windows-Windows Defender%4Operational.evtx", "tier": 1, "parser": {"csv_path": str(defender)}},
            {"event_log": "Microsoft-Windows-Sysmon%4Operational.evtx", "tier": 1, "parser": {"csv_path": str(sysmon)}},
        ]
    }
    (out / "baseline-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    proc = run(root, "event_triage.py", "--case", "evt")
    assert proc.returncode == 0, proc.stderr
    lines = [json.loads(x) for x in (root / "cases" / "evt" / "leads.jsonl").read_text().splitlines() if x.strip()]
    values = {str(x.get("value", "")).lower() for x in lines if x.get("event") == "create"}
    assert any("crackedsoftware.exe" in v for v in values)
    assert "a" * 64 in values
    assert "192.168.112.153" in values


def test_defender_config_change_is_not_a_detection_and_duplicate_events_do_not_bloat_history(tmp_path: Path) -> None:
    root = tmp_path / "Aries"
    evidence = tmp_path / "disk.E01"
    evidence.write_bytes(b"fake")
    assert run(root, "case.py", "init", "--name", "defender", "--e01", str(evidence)).returncode == 0

    out = root / "cases" / "defender" / "output" / "eztools" / "EvtxECmd-Auto"
    out.mkdir(parents=True, exist_ok=True)
    parsed = out / "Defender.csv"
    headers = ["TimeCreated", "EventId", "Provider", "PayloadData1", "ExecutableInfo", "Payload"]
    with parsed.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(headers)
        w.writerow(["2026-01-01", "5007", "Defender", "Threat configuration changed", "", "Severe threat settings"])
        for _ in range(3):
            w.writerow(["2026-08-08", "1116", "Defender", "Trojan:Win32/Test", r"C:\Users\u\Downloads\bad.exe", "SHA256=" + "b"*64])
    (out / "baseline-manifest.json").write_text(json.dumps({"results": [{"event_log": "Microsoft-Windows-Windows Defender%4Operational.evtx", "tier": 1, "parser": {"csv_path": str(parsed)}}]}), encoding="utf-8")
    proc = run(root, "event_triage.py", "--case", "defender")
    assert proc.returncode == 0, proc.stderr
    lines = [json.loads(x) for x in (root / "cases" / "defender" / "leads.jsonl").read_text().splitlines() if x.strip()]
    creates = [item for item in lines if item.get("event") == "create"]
    assert not any("5007" in str(item.get("source")) for item in creates)
    assert sum("bad.exe" in str(item.get("value", "")).lower() for item in creates) == 1
    assert len(lines) == 2  # one file lead and one hash lead; duplicate rows add no no-op updates
