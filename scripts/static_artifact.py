from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


MAX_ARCHIVE_MEMBERS = 5_000
MAX_ARCHIVE_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024 * 1024

STATIC_PATTERNS = {
    "network_or_proxy": re.compile(r"(?i)proxy|System\.Net\.(?:Sockets|WebClient)|TcpClient|HttpWebRequest|https?://|wss?://"),
    "keylogging": re.compile(r"(?i)GetAsyncKeyState|GetKeyboardState|SetWindowsHookEx|WH_KEYBOARD|keylog"),
    "persistence": re.compile(r"(?i)CurrentVersion\\Run|schtasks(?:\.exe)?|Register-ScheduledTask|New-Service|sc(?:\.exe)?\s+create|Startup"),
    "upload_or_exfiltration": re.compile(r"(?i)UploadFile|UploadString|Invoke-WebRequest|Invoke-RestMethod|WebClient|curl(?:\.exe)?|Start-BitsTransfer"),
    "sleep_or_reconnect": re.compile(r"(?i)Start-Sleep|Threading\.Thread\]::Sleep|sleep\s*\("),
    "dll_or_native_api": re.compile(r"(?i)DllImport|Add-Type|user32\.dll|kernel32\.dll|advapi32\.dll|wininet\.dll"),
    "regex": re.compile(r"(?i)\[regex\]|-match\b|Regex\s*\("),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_member_name(value: str) -> Path:
    normalized = value.replace("\\", "/").strip()
    pure = PurePosixPath(normalized)
    if not normalized or "\x00" in normalized or pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"Unsafe archive member path: {value!r}")
    if pure.parts and re.match(r"^[A-Za-z]:$", pure.parts[0]):
        raise ValueError(f"Drive-qualified archive member path: {value!r}")
    return Path(*pure.parts)


def decode_text(data: bytes) -> tuple[str | None, str | None]:
    if not data:
        return "", "utf-8"
    encodings = []
    if data.startswith(b"\xff\xfe"):
        encodings.append("utf-16-le")
    elif data.startswith(b"\xfe\xff"):
        encodings.append("utf-16-be")
    elif data.startswith(b"\xef\xbb\xbf"):
        encodings.append("utf-8-sig")
    if data[1::2].count(0) > max(2, len(data) // 6):
        encodings.append("utf-16-le")
    encodings.extend(["utf-8", "windows-1252"])
    for encoding in dict.fromkeys(encodings):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        if not text:
            return text, encoding
        printable = sum(char.isprintable() or char in "\r\n\t" for char in text)
        if printable / len(text) >= 0.85:
            return text.lstrip("\ufeff"), encoding
    return None, None


def classify_text(text: str, name: str) -> tuple[str, list[str]]:
    lower = text.lower()
    reasons: list[str] = []
    powershell_tokens = ["$env:", "new-object", "invoke-", "start-sleep", "add-type", "param(", "function ", "[dllimport"]
    count = sum(token in lower for token in powershell_tokens)
    if name.lower().endswith(".ps1") or count >= 2 or ("$" in text and "function " in lower):
        reasons.append(f"PowerShell syntax/content indicators matched ({count})")
        return "powershell", reasons
    if name.lower().endswith((".bat", ".cmd")) or re.search(r"(?im)^\s*@?echo\s+(?:off|on)\b", text):
        return "batch", ["Batch syntax detected"]
    if name.lower().endswith(".py") or re.search(r"(?m)^\s*(?:def|import|from)\s+[A-Za-z_]", text):
        return "python", ["Python syntax detected"]
    if name.lower().endswith((".js", ".jse")) or re.search(r"(?m)\b(?:function|const|let|var)\s+[A-Za-z_$]", text):
        return "javascript", ["JavaScript syntax detected"]
    return "text", ["Printable text content detected"]


def analyze_text_file(source: Path, content_dir: Path, sequence: int, logical_name: str) -> dict:
    # Some Windows archive tools preserve metadata that makes Path.stat() fail
    # with EINVAL even though the recovered file can still be opened normally.
    # Archive members are already bounded by MAX_MEMBER_BYTES, so read once and
    # derive size/hash from the bytes instead of depending on file metadata.
    with source.open("rb") as handle:
        data = handle.read(MAX_MEMBER_BYTES + 1)
    if len(data) > MAX_MEMBER_BYTES:
        raise ValueError(f"Recovered member exceeds the {MAX_MEMBER_BYTES}-byte limit: {logical_name}")
    size = len(data)
    record = {
        "name": logical_name,
        "size_bytes": size,
        "sha256": hashlib.sha256(data).hexdigest(),
        "detected_type": "binary_or_unsupported",
        "text_output": None,
        "encoding": None,
        "line_count": None,
        "signal_hits": [],
    }
    if size > MAX_TEXT_BYTES:
        record["note"] = f"Text extraction skipped above {MAX_TEXT_BYTES} bytes"
        return record
    text, encoding = decode_text(data)
    if text is None:
        record["note"] = "Content did not meet the printable-text threshold; it was not executed"
        return record
    detected, reasons = classify_text(text, logical_name)
    content_dir.mkdir(parents=True, exist_ok=True)
    output = content_dir / f"source-{sequence:04d}-{Path(logical_name).name or 'unnamed'}.txt"
    output.write_text(text, encoding="utf-8", newline="")
    lines = text.splitlines()
    hits = []
    for number, line in enumerate(lines, 1):
        categories = [name for name, pattern in STATIC_PATTERNS.items() if pattern.search(line)]
        if categories:
            hits.append({"line": number, "categories": categories, "text": line[:1000]})
        if len(hits) >= 500:
            break
    record.update({
        "detected_type": detected,
        "classification_reasons": reasons,
        "encoding": encoding,
        "line_count": len(lines),
        "text_output": str(output),
        "signal_hits": hits,
    })
    return record


def _validate_limits(members: list[tuple[str, int]]) -> list[tuple[Path, int]]:
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise ValueError(f"Archive contains {len(members)} members; limit is {MAX_ARCHIVE_MEMBERS}")
    validated: list[tuple[Path, int]] = []
    expanded = 0
    for name, size in members:
        relative = safe_member_name(name)
        if size < 0 or size > MAX_MEMBER_BYTES:
            raise ValueError(f"Archive member exceeds the {MAX_MEMBER_BYTES}-byte limit: {name}")
        expanded += size
        if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
            raise ValueError(f"Archive expanded size exceeds {MAX_ARCHIVE_EXPANDED_BYTES} bytes")
        validated.append((relative, size))
    return validated


def extract_zip(source: Path, destination: Path) -> list[Path]:
    extracted: list[Path] = []
    with zipfile.ZipFile(source) as archive:
        files = [item for item in archive.infolist() if not item.is_dir()]
        validated = _validate_limits([(item.filename, item.file_size) for item in files])
        for item, (relative, _) in zip(files, validated):
            unix_mode = (item.external_attr >> 16) & 0o170000
            if unix_mode == 0o120000:
                raise ValueError(f"Archive symlink is not allowed: {item.filename}")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with archive.open(item) as src, target.open("xb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
            except RuntimeError as exc:
                raise ValueError(f"Encrypted ZIP member could not be extracted: {item.filename}") from exc
            extracted.append(target)
    return extracted


def extract_tar(source: Path, destination: Path) -> list[Path]:
    extracted: list[Path] = []
    with tarfile.open(source, "r:*") as archive:
        files = [item for item in archive.getmembers() if item.isfile()]
        if any(item.issym() or item.islnk() for item in archive.getmembers()):
            raise ValueError("Archive links are not allowed")
        validated = _validate_limits([(item.name, item.size) for item in files])
        for item, (relative, _) in zip(files, validated):
            src = archive.extractfile(item)
            if src is None:
                continue
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with src, target.open("xb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
            extracted.append(target)
    return extracted


def find_7zip() -> Path | None:
    for name in ("7z.exe", "7zz.exe", "7z", "7zz"):
        found = shutil.which(name)
        if found:
            return Path(found)
    candidates = []
    for variable in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        base = os.environ.get(variable)
        if base:
            candidates.extend([Path(base) / "7-Zip" / "7z.exe", Path(base) / "7-Zip" / "7zz.exe"])
    return next((path for path in candidates if path.is_file()), None)


def external_members(tool: Path, source: Path, timeout: int) -> list[tuple[str, int]]:
    proc = subprocess.run([str(tool), "l", "-slt", "-ba", str(source)], text=True, capture_output=True, errors="replace", timeout=timeout, check=False)
    if proc.returncode != 0:
        raise ValueError((proc.stderr or proc.stdout or "7-Zip listing failed").strip()[-1000:])
    records = []
    current: dict[str, str] = {}
    for line in proc.stdout.splitlines() + [""]:
        if not line.strip():
            if current.get("Path") and current.get("Folder", "-") != "+":
                if current.get("Symbolic Link") or current.get("Hard Link"):
                    raise ValueError(f"Archive links are not allowed: {current['Path']}")
                try:
                    records.append((current["Path"], int(current.get("Size", "0") or 0)))
                except ValueError:
                    pass
            current = {}
            continue
        if " = " in line:
            key, value = line.split(" = ", 1)
            current[key.strip()] = value.strip()
    return records


def extract_external(source: Path, destination: Path, timeout: int) -> tuple[list[Path], str]:
    tool = find_7zip()
    if not tool:
        raise ValueError("RAR/7z extraction requires 7-Zip (7z.exe or 7zz.exe) on PATH or in Program Files")
    validated = _validate_limits(external_members(tool, source, timeout))
    proc = subprocess.run([str(tool), "x", "-y", "-bd", "-bb0", f"-o{destination}", str(source)], text=True, capture_output=True, errors="replace", timeout=timeout, check=False)
    if proc.returncode != 0:
        raise ValueError((proc.stderr or proc.stdout or "7-Zip extraction failed").strip()[-1000:])
    # Use the validated 7-Zip member list as the source of truth. Walking the
    # extracted tree calls stat() on every item and can fail on Windows when an
    # otherwise readable member has malformed archive timestamps/attributes.
    files: list[Path] = []
    for relative, _ in validated:
        path = destination / relative
        try:
            with path.open("rb") as handle:
                handle.read(1)
        except OSError as exc:
            raise ValueError(f"7-Zip listed a member that could not be opened safely: {relative}: {exc}") from exc
        files.append(path)
    return files, str(tool)


def process_archive(source: Path, extraction_dir: Path, output_dir: Path, timeout: int = 1800) -> dict:
    if extraction_dir.exists():
        shutil.rmtree(extraction_dir)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    extraction_dir.mkdir(parents=True, exist_ok=True)
    content_dir = output_dir / "content"
    backend = ""
    try:
        if zipfile.is_zipfile(source):
            files = extract_zip(source, extraction_dir)
            backend = "python-zipfile"
        elif tarfile.is_tarfile(source):
            files = extract_tar(source, extraction_dir)
            backend = "python-tarfile"
        else:
            files, backend = extract_external(source, extraction_dir, timeout)
        analyses = [analyze_text_file(path, content_dir, index, path.relative_to(extraction_dir).as_posix()) for index, path in enumerate(sorted(files), 1)]
        status = "complete" if files else "partial"
        reason = "" if files else "Archive contained no regular files"
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError, subprocess.TimeoutExpired) as exc:
        files = []
        analyses = []
        status = "failed"
        reason = f"{type(exc).__name__}: {exc}"
    report = {
        "schema_version": "1",
        "source": str(source),
        "source_sha256": sha256_file(source),
        "status": status,
        "backend": backend or None,
        "reason": reason or None,
        "extraction_directory": str(extraction_dir),
        "members_analyzed": len(analyses),
        "files": analyses,
        "safety": {
            "source_read_only": True,
            "recovered_content_executed": False,
            "path_traversal_rejected": True,
            "links_rejected": True,
            "expanded_size_limit": MAX_ARCHIVE_EXPANDED_BYTES,
        },
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "static-analysis.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    report["outputs"] = [str(report_path), *[str(Path(item["text_output"])) for item in analyses if item.get("text_output")]]
    return report


def process_file(source: Path, output_dir: Path) -> dict:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    analysis = analyze_text_file(source, output_dir / "content", 1, source.name)
    status = "complete" if analysis.get("text_output") else "partial"
    report = {
        "schema_version": "1",
        "source": str(source),
        "source_sha256": analysis["sha256"],
        "status": status,
        "backend": "content-classifier",
        "reason": None if status == "complete" else analysis.get("note"),
        "members_analyzed": 1,
        "files": [analysis],
        "safety": {"source_read_only": True, "recovered_content_executed": False},
    }
    report_path = output_dir / "static-analysis.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    report["outputs"] = [str(report_path), *([analysis["text_output"]] if analysis.get("text_output") else [])]
    return report
