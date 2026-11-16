from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from common import case_dir, safe_case_name


SCHEMA_VERSION = "2"
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_CHUNKS = 100_000
CHUNK_CHARS = 5_000
CHUNK_LINES = 60
OVERLAP_LINES = 5
TEXT_SUFFIXES = {
    ".csv", ".json", ".jsonl", ".log", ".md", ".ndjson", ".text", ".tsv", ".txt", ".xml", ".yaml", ".yml"
}
ROOT_FILES = {
    "artifact_inventory.json", "case.json", "case_context.json", "evidence_manifest.json",
    "findings.jsonl", "iocs.csv", "ioc_candidates.csv", "leads.jsonl", "notes.md",
    "investigation-brief.json", "analyst-questions.json",
}
EXCLUDED_PREFIXES = (
    "evidence/", "extracted/", "output/datalake/", "output/web/", "output/logs/",
)
_INDEX_LOCKS: dict[str, threading.Lock] = {}
_INDEX_LOCKS_GUARD = threading.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def datalake_dir(root: Path) -> Path:
    return root / "output" / "datalake"


def database_path(root: Path) -> Path:
    return datalake_dir(root) / "case-index.sqlite"


def manifest_path(root: Path) -> Path:
    return datalake_dir(root) / "manifest.json"


def index_lock(root: Path) -> threading.Lock:
    key = str(root.resolve()).lower()
    with _INDEX_LOCKS_GUARD:
        return _INDEX_LOCKS.setdefault(key, threading.Lock())


def eligible_source(root: Path, path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        return False
    if relative in ROOT_FILES:
        return True
    if any(relative.startswith(prefix) for prefix in EXCLUDED_PREFIXES):
        return False
    if not (relative.startswith("output/") or relative.startswith("timeline/") or relative.startswith("report/")):
        return False
    return path.suffix.lower() in TEXT_SUFFIXES


def discover_sources(root: Path) -> tuple[list[Path], list[dict[str, Any]]]:
    sources: list[Path] = []
    skipped: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not eligible_source(root, path):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        relative = path.relative_to(root).as_posix()
        if size > MAX_SOURCE_BYTES:
            skipped.append({"path": relative, "reason": "source_too_large", "size_bytes": size})
            continue
        sources.append(path)
    return sources, skipped


def source_fingerprint(root: Path, sources: Iterable[Path]) -> str:
    digest = hashlib.sha256()
    for path in sources:
        stat = path.stat()
        digest.update(path.relative_to(root).as_posix().encode("utf-8", errors="replace"))
        digest.update(f"\0{stat.st_size}\0{stat.st_mtime_ns}\n".encode())
    return digest.hexdigest()


def iter_chunks(path: Path) -> Iterable[tuple[int, int, str]]:
    lines: list[tuple[int, str]] = []
    chars = 0
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line_number, line in enumerate(handle, 1):
            text = line.rstrip("\r\n")
            if not text and not lines:
                continue
            if len(text) > CHUNK_CHARS:
                if lines:
                    content = "\n".join(item[1] for item in lines).strip()
                    if content:
                        yield lines[0][0], lines[-1][0], content
                    lines = []
                    chars = 0
                for offset in range(0, len(text), CHUNK_CHARS):
                    segment = text[offset: offset + CHUNK_CHARS].strip()
                    if segment:
                        yield line_number, line_number, segment
                continue
            lines.append((line_number, text))
            chars += len(text) + 1
            if len(lines) >= CHUNK_LINES or chars >= CHUNK_CHARS:
                content = "\n".join(item[1] for item in lines).strip()
                if content:
                    yield lines[0][0], lines[-1][0], content
                lines = lines[-OVERLAP_LINES:]
                chars = sum(len(item[1]) + 1 for item in lines)
    if lines:
        content = "\n".join(item[1] for item in lines).strip()
        if content:
            yield lines[0][0], lines[-1][0], content


def read_manifest(root: Path) -> dict[str, Any] | None:
    path = manifest_path(root)
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
    except (OSError, json.JSONDecodeError):
        return None


def _build_index_locked(root: Path, *, force: bool = False) -> dict[str, Any]:
    root = root.resolve()
    sources, skipped = discover_sources(root)
    fingerprint = source_fingerprint(root, sources)
    current = read_manifest(root)
    db_path = database_path(root)
    if (
        not force
        and current
        and current.get("schema_version") == SCHEMA_VERSION
        and current.get("fingerprint") == fingerprint
        and db_path.is_file()
    ):
        return {**current, "refreshed": False}

    lake = datalake_dir(root)
    lake.mkdir(parents=True, exist_ok=True)
    # A fixed .building filename can remain locked briefly on Windows after an
    # interrupted build (or by endpoint scanning), which previously degraded
    # every subsequent assistant query. Each rebuild now owns a unique file.
    temporary = lake / f"case-index.{os.getpid()}.{threading.get_ident()}.sqlite.building"
    chunks = 0
    indexed_files = 0
    backend = "sqlite_like"
    with sqlite3.connect(temporary) as db:
        db.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("CREATE TABLE documents (path TEXT PRIMARY KEY, size_bytes INTEGER NOT NULL, modified_ns INTEGER NOT NULL, chunk_count INTEGER NOT NULL)")
        db.execute("CREATE TABLE chunks (id INTEGER PRIMARY KEY, path TEXT NOT NULL, line_start INTEGER NOT NULL, line_end INTEGER NOT NULL, content TEXT NOT NULL)")
        db.execute("CREATE INDEX chunks_path_idx ON chunks(path)")
        fts5 = os.environ.get("ARIES_DATALAKE_DISABLE_FTS5", "").strip().lower() not in {"1", "true", "yes"}
        if fts5:
            try:
                db.execute("CREATE VIRTUAL TABLE chunks_fts USING fts5(content, tokenize='unicode61')")
                backend = "sqlite_fts5"
            except sqlite3.OperationalError:
                fts5 = False
        for path in sources:
            relative = path.relative_to(root).as_posix()
            file_chunks = 0
            try:
                for line_start, line_end, content in iter_chunks(path):
                    if chunks >= MAX_CHUNKS:
                        skipped.append({"path": relative, "reason": "case_chunk_limit"})
                        break
                    cursor = db.execute(
                        "INSERT INTO chunks(path, line_start, line_end, content) VALUES (?, ?, ?, ?)",
                        (relative, line_start, line_end, content),
                    )
                    if fts5:
                        db.execute("INSERT INTO chunks_fts(rowid, content) VALUES (?, ?)", (cursor.lastrowid, content))
                    chunks += 1
                    file_chunks += 1
            except OSError as exc:
                skipped.append({"path": relative, "reason": "read_error", "detail": str(exc)})
                continue
            stat = path.stat()
            db.execute(
                "INSERT INTO documents(path, size_bytes, modified_ns, chunk_count) VALUES (?, ?, ?, ?)",
                (relative, stat.st_size, stat.st_mtime_ns, file_chunks),
            )
            indexed_files += 1
            if chunks >= MAX_CHUNKS:
                break
        for key, value in {"schema_version": SCHEMA_VERSION, "fingerprint": fingerprint, "updated_utc": now_iso(), "search_backend": backend}.items():
            db.execute("INSERT INTO metadata(key, value) VALUES (?, ?)", (key, value))
        db.commit()
    temporary.replace(db_path)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "updated_utc": now_iso(),
        "fingerprint": fingerprint,
        "indexed_files": indexed_files,
        "indexed_chunks": chunks,
        "skipped_files": skipped,
        "database": db_path.relative_to(root).as_posix(),
        "search_backend": backend,
        "scope": "active_case_only",
        "raw_evidence_indexed": False,
        "refreshed": True,
    }
    manifest_path(root).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def build_index(root: Path, *, force: bool = False) -> dict[str, Any]:
    root = root.resolve()
    with index_lock(root):
        return _build_index_locked(root, force=force)


def search_terms(query: str) -> list[str]:
    values = re.findall(r"[A-Za-z0-9_@.:\\/\-]{2,}", query)
    stop = {"about", "case", "did", "does", "from", "have", "into", "that", "the", "this", "what", "when", "where", "which", "with", "were", "was"}
    unique: list[str] = []
    for value in values:
        normalized = value.strip(".:/\\-").lower()
        if len(normalized) < 2 or normalized in stop or normalized in unique:
            continue
        unique.append(normalized)
    return unique[:16]


def _rows_from_database(root: Path, terms: list[str], limit: int) -> list[sqlite3.Row]:
    rows: list[sqlite3.Row] = []
    with sqlite3.connect(database_path(root)) as db:
        db.row_factory = sqlite3.Row
        tables = {str(row[0]) for row in db.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')")}
        if terms and "chunks_fts" in tables:
            expression = " OR ".join('"' + term.replace('"', '""') + '"' for term in terms)
            try:
                rows = db.execute(
                    "SELECT c.path, c.line_start, c.line_end, c.content, bm25(chunks_fts) AS score "
                    "FROM chunks_fts JOIN chunks c ON c.id = chunks_fts.rowid "
                    "WHERE chunks_fts MATCH ? ORDER BY score LIMIT ?",
                    (expression, limit),
                ).fetchall()
            except sqlite3.OperationalError:
                rows = []
        if terms and not rows:
            clauses = " OR ".join("lower(content) LIKE ?" for _ in terms)
            parameters = [f"%{term.lower()}%" for term in terms]
            candidates = db.execute(
                f"SELECT path, line_start, line_end, content FROM chunks WHERE {clauses} LIMIT ?",
                (*parameters, max(limit * 8, 64)),
            ).fetchall()
            ranked = sorted(
                candidates,
                key=lambda row: sum(str(row["content"]).lower().count(term.lower()) for term in terms),
                reverse=True,
            )
            rows = [dict(row) | {"score": -float(sum(str(row["content"]).lower().count(term.lower()) for term in terms))} for row in ranked[:limit]]
        if not rows:
            rows = db.execute(
                "SELECT path, line_start, line_end, content, 0.0 AS score FROM chunks ORDER BY id DESC LIMIT ?",
                (min(limit, 12),),
            ).fetchall()
    return rows


def _direct_search(root: Path, terms: list[str], limit: int, error: Exception) -> dict[str, Any]:
    """Last-resort bounded search when SQLite itself is unavailable or unwritable."""
    sources, skipped = discover_sources(root)
    ranked: list[tuple[int, dict[str, Any]]] = []
    scanned_chunks = 0
    for path in sources:
        relative = path.relative_to(root).as_posix()
        try:
            for line_start, line_end, content in iter_chunks(path):
                scanned_chunks += 1
                lower = content.lower()
                score = sum(lower.count(term.lower()) for term in terms) if terms else 1
                if score:
                    ranked.append((score, {
                        "path": relative,
                        "line_start": line_start,
                        "line_end": line_end,
                        "citation": f"{relative}:L{line_start}-L{line_end}",
                        "content": content,
                        "score": -float(score),
                    }))
                if scanned_chunks >= MAX_CHUNKS:
                    break
        except OSError as exc:
            skipped.append({"path": relative, "reason": "read_error", "detail": str(exc)})
        if scanned_chunks >= MAX_CHUNKS:
            break
    ranked.sort(key=lambda item: item[0], reverse=True)
    return {
        "results": [item[1] for item in ranked[:limit]],
        "status": {
            "status": "degraded",
            "search_backend": "direct_text_fallback",
            "indexed_files": len(sources),
            "indexed_chunks": scanned_chunks,
            "scope": "active_case_only",
            "raw_evidence_indexed": False,
            "warning": f"SQLite index unavailable; used direct case-text search ({type(error).__name__}: {error})",
            "skipped_files": skipped,
        },
    }


def search_index(root: Path, query: str, *, limit: int = 24) -> dict[str, Any]:
    root = root.resolve()
    terms = search_terms(query)
    try:
        status = build_index(root)
        rows = _rows_from_database(root, terms, limit)
    except (OSError, sqlite3.Error) as first_error:
        try:
            status = build_index(root, force=True)
            rows = _rows_from_database(root, terms, limit)
            status = {**status, "recovered_from": f"{type(first_error).__name__}: {first_error}"}
        except (OSError, sqlite3.Error) as second_error:
            fallback = _direct_search(root, terms, limit, second_error)
            return {"query": query, "terms": terms, **fallback}
    results = [{
        "path": row["path"],
        "line_start": int(row["line_start"]),
        "line_end": int(row["line_end"]),
        "citation": f"{row['path']}:L{row['line_start']}-L{row['line_end']}",
        "content": str(row["content"]),
        "score": float(row["score"]),
    } for row in rows]
    return {"query": query, "terms": terms, "results": results, "status": status}


def status_for_case(root: Path) -> dict[str, Any]:
    manifest = read_manifest(root)
    if not manifest:
        return {"status": "not_built", "indexed_files": 0, "indexed_chunks": 0, "scope": "active_case_only"}
    return {"status": "ready", **manifest}


def main() -> None:
    parser = argparse.ArgumentParser(description="Build or search the Aries case-scoped forensic data lake")
    parser.add_argument("--case", required=True)
    parser.add_argument("--query")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    root = case_dir(safe_case_name(args.case))
    if args.query:
        print(json.dumps(search_index(root, args.query), indent=2))
    else:
        print(json.dumps(build_index(root, force=args.force), indent=2))


if __name__ == "__main__":
    main()
