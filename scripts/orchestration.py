from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common import case_dir, load_case, now_iso
from records import append_jsonl, load_context, materialize_history, read_jsonl


ROLES = ("investigator", "validator")
SCHEMA_VERSION = "0.3.3"
ORCHESTRATION_REVISION = 3
MAX_REVIEW_FAILURES = 3
TEXT_EXTENSIONS = {".txt", ".csv", ".json", ".jsonl", ".log", ".md", ".tsv", ".xml", ".yaml", ".yml"}
SNAPSHOT_JSON_LIMIT = 2 * 1024 * 1024
TIMELINE_SAMPLE_LIMIT = 80
CATALOG_FILE_LIMIT = 5 * 1024 * 1024
LIST_LIMIT = 250
REVIEW_LEAD_LIMIT = 12
REVIEW_FINDING_LIMIT = 16
REVIEW_EXCERPT_LIMIT = 24
REVIEW_EXCERPTS_PER_LEAD = 2
REVIEW_PACKET_MAX_CHARS = 32_000
REVIEW_PACKET_MAX_ESTIMATED_TOKENS = 8_000
REVIEW_SCAN_TOTAL_BYTES = 50 * 1024 * 1024
FOREIGN_CASE_PATH_RE = re.compile(r"(?i)(?:[A-Z]:[\\/])?Aries[\\/]cases[\\/]([A-Za-z0-9._-]+)")


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_item_id(prefix: str, value: str) -> str:
    return f"{prefix}-{sha256_bytes(value.strip().lower().encode('utf-8'))[:10].upper()}"


def safe_relative(root: Path, candidate: str) -> tuple[str | None, str | None]:
    raw = str(candidate or "").strip().replace("\\", "/")
    if not raw:
        return None, "empty evidence reference"
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts:
        return None, f"reference must be case-relative: {candidate}"
    resolved = (root / path).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return None, f"reference leaves case directory: {candidate}"
    if not resolved.is_file():
        return None, f"referenced evidence file does not exist: {candidate}"
    return resolved.relative_to(root.resolve()).as_posix(), None


def compact_evidence(case: dict[str, Any]) -> list[dict[str, Any]]:
    output = []
    for key, entry in case.get("evidence", {}).items():
        output.append(
            {
                "key": key,
                "kind": entry.get("kind"),
                "source_name": Path(str(entry.get("path") or "unknown")).name,
                "exists": entry.get("exists"),
                "size_bytes": entry.get("size_bytes"),
                "sha256": entry.get("sha256"),
                "segment_count": entry.get("segment_count"),
                "file_count": entry.get("file_count"),
                "hash_verified_utc": entry.get("hash_verified_utc"),
            }
        )
    return output


def read_json_summary(path: Path) -> Any:
    if not path.is_file():
        return None
    size = path.stat().st_size
    if size > SNAPSHOT_JSON_LIMIT:
        return {"omitted": True, "reason": "file exceeds snapshot JSON limit", "size_bytes": size}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {"unreadable_json": True, "size_bytes": size}


def timeline_sample(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"present": False, "rows": []}
    rows = []
    truncated = False
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for index, line in enumerate(handle):
            if index >= TIMELINE_SAMPLE_LIMIT + 1:
                truncated = True
                break
            rows.append(line.rstrip("\r\n"))
    return {"present": True, "sample_line_count": len(rows), "truncated": truncated, "rows": rows}


def artifact_family(relative: str) -> str:
    lower = relative.lower()
    if "volatility" in lower:
        return "memory"
    if "eztools" in lower or "event_triage" in lower:
        return "event_logs"
    if "artifacts" in lower or "artifact_triage" in lower:
        return "loose_artifacts"
    if "dissect" in lower:
        return "disk"
    if "pivots" in lower:
        return "correlation"
    if "timeline" in lower:
        return "timeline"
    return "case_metadata"


def source_catalog(root: Path) -> list[dict[str, Any]]:
    candidates: list[Path] = []
    for base in (root / "output", root / "timeline"):
        if not base.exists():
            continue
        for item in base.rglob("*"):
            if not item.is_file() or item.suffix.lower() not in TEXT_EXTENSIONS:
                continue
            relative = item.relative_to(root).as_posix()
            if relative.startswith("output/orchestration/"):
                continue
            candidates.append(item)
    for name in ("artifact_inventory.json", "case_context.json", "leads.jsonl", "findings.jsonl", "notes.md"):
        item = root / name
        if item.is_file():
            candidates.append(item)

    catalog = []
    for item in sorted(set(candidates), key=lambda value: value.as_posix().lower()):
        relative = item.relative_to(root).as_posix()
        size = item.stat().st_size
        catalog.append(
            {
                "path": relative,
                "artifact_family": artifact_family(relative),
                "size_bytes": size,
                "review_allowed": False,
                "reason": "catalog only; delegated reviewers use the bounded review packet",
            }
        )
    return catalog[:1000]


def relevant_state_files(root: Path) -> list[Path]:
    paths = []
    for relative in (
        "leads.jsonl",
        "findings.jsonl",
        "case_context.json",
        "artifact_inventory.json",
        "output/event_triage.json",
        "output/artifact_triage.json",
        "output/pivots/pivot-summary.json",
        "timeline/targeted_timeline.csv",
    ):
        candidate = root / relative
        if candidate.is_file():
            paths.append(candidate)
    pivot_root = root / "output" / "pivots"
    if pivot_root.exists():
        paths.extend(sorted(p for p in pivot_root.rglob("pivot-plan.json") if p.is_file()))
    return sorted(set(paths), key=lambda value: value.as_posix().lower())


def state_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    for path in relevant_state_files(root):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(relative + b"\0")
        digest.update(str(path.stat().st_size).encode("ascii") + b"\0")
        digest.update(sha256_file(path).encode("ascii") + b"\n")
    return digest.hexdigest()


def build_snapshot(case_name: str) -> dict[str, Any]:
    case = load_case(case_name)
    root = case_dir(case_name)
    leads = materialize_history(root / "leads.jsonl", "L")
    findings = materialize_history(root / "findings.jsonl", "F")
    active_leads = [item for item in leads if item.get("status") == "active"]
    active_findings = [item for item in findings if item.get("status") == "active"]
    active_leads.sort(key=lambda item: int(item.get("score") or 0), reverse=True)
    summary_paths = {
        "artifact_inventory": root / "artifact_inventory.json",
        "event_triage": root / "output" / "event_triage.json",
        "artifact_triage": root / "output" / "artifact_triage.json",
        "pivot_summary": root / "output" / "pivots" / "pivot-summary.json",
    }
    pivot_plans = []
    pivot_root = root / "output" / "pivots"
    if pivot_root.exists():
        for path in sorted(pivot_root.rglob("pivot-plan.json"))[:LIST_LIMIT]:
            pivot_plans.append({"path": path.relative_to(root).as_posix(), "content": read_json_summary(path)})

    return {
        "schema_version": SCHEMA_VERSION,
        "case": case_name,
        "generated_utc": now_iso(),
        "purpose": "Immutable reasoning snapshot for independent delegated review; not authoritative evidence.",
        "evidence": compact_evidence(case),
        "phase_state": {
            key: {"status": value.get("status"), "message": value.get("message", "")}
            for key, value in case.get("investigation", {}).get("phases", {}).items()
        },
        "known_context": load_context(case_name).get("entries", []),
        "active_leads": active_leads[:LIST_LIMIT],
        "active_findings": active_findings[:LIST_LIMIT],
        "summaries": {key: read_json_summary(path) for key, path in summary_paths.items()},
        "pivot_plans": pivot_plans,
        "targeted_timeline": timeline_sample(root / "timeline" / "targeted_timeline.csv"),
        "source_catalog": source_catalog(root),
        "constraints": {
            "case_root": str(root),
            "read_only_review": True,
            "no_source_evidence_access": True,
            "no_parser_execution": True,
            "no_case_writes": True,
            "no_subdelegation": True,
            "allowed_sources": "The delegated reviewer receives a separate bounded review packet and may not browse case files.",
        },
    }


def compact_summary(value: Any, max_chars: int = 12_000) -> Any:
    if value is None:
        return None
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if len(encoded) <= max_chars:
        return value
    if isinstance(value, dict):
        return {
            "truncated": True,
            "keys": list(value)[:100],
            "summary_excerpt": encoded[:max_chars],
        }
    if isinstance(value, list):
        return {"truncated": True, "item_count": len(value), "items": value[:25]}
    return str(value)[:max_chars]


def evidence_excerpts(root: Path, leads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates = [root / item["path"] for item in source_catalog(root) if item.get("size_bytes", 0) <= CATALOG_FILE_LIMIT]
    excerpts: list[dict[str, Any]] = []
    scanned = 0
    for lead in leads:
        needle = str(lead.get("value") or "").strip()
        if len(needle) < 4:
            continue
        normalized = needle.lower().replace("\\", "/")
        lead_hits = 0
        for path in candidates:
            if scanned >= REVIEW_SCAN_TOTAL_BYTES or len(excerpts) >= REVIEW_EXCERPT_LIMIT:
                return excerpts
            try:
                size = path.stat().st_size
                scanned += size
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line_no, line in enumerate(text.splitlines(), 1):
                if normalized not in line.lower().replace("\\", "/"):
                    continue
                relative = path.relative_to(root).as_posix()
                excerpts.append({
                    "lead_id": lead.get("id"),
                    "value": needle,
                    "source": relative,
                    "artifact_family": artifact_family(relative),
                    "line": line_no,
                    "text": line[:800],
                })
                lead_hits += 1
                if lead_hits >= REVIEW_EXCERPTS_PER_LEAD or len(excerpts) >= REVIEW_EXCERPT_LIMIT:
                    break
            if lead_hits >= REVIEW_EXCERPTS_PER_LEAD:
                break
    return excerpts


def fit_review_packet(packet: dict[str, Any]) -> dict[str, Any]:
    """Deterministically shrink a packet until it fits the delegation budget."""
    def chars() -> int:
        return len(json.dumps(packet, ensure_ascii=False, separators=(",", ":")))

    while chars() > REVIEW_PACKET_MAX_CHARS and packet.get("evidence_excerpts"):
        packet["evidence_excerpts"].pop()
    rows = packet.get("targeted_timeline", {}).get("rows", [])
    while chars() > REVIEW_PACKET_MAX_CHARS and rows:
        rows.pop()
    while chars() > REVIEW_PACKET_MAX_CHARS and packet.get("active_findings"):
        packet["active_findings"].pop()
    while chars() > REVIEW_PACKET_MAX_CHARS and len(packet.get("active_leads", [])) > 8:
        packet["active_leads"].pop()
    packet_chars = chars()
    packet["budget"] = {
        "max_characters": REVIEW_PACKET_MAX_CHARS,
        "actual_characters": packet_chars,
        "estimated_tokens": (packet_chars + 3) // 4,
        "max_estimated_tokens": REVIEW_PACKET_MAX_ESTIMATED_TOKENS,
    }
    if chars() > REVIEW_PACKET_MAX_CHARS:
        packet["summaries"] = {key: {"omitted": True, "reason": "review packet budget"} for key in packet.get("summaries", {})}
        packet["budget"]["actual_characters"] = chars()
        packet["budget"]["estimated_tokens"] = (chars() + 3) // 4
    if chars() > REVIEW_PACKET_MAX_CHARS:
        raise ValueError("Unable to fit delegated review packet within the configured budget")
    return packet


def build_review_packet(case_name: str, snapshot: dict[str, Any], snapshot_id: str) -> dict[str, Any]:
    root = case_dir(case_name)
    leads = list(snapshot.get("active_leads") or [])[:REVIEW_LEAD_LIMIT]
    findings = list(snapshot.get("active_findings") or [])[:REVIEW_FINDING_LIMIT]
    packet = {
        "schema_version": SCHEMA_VERSION,
        "case": case_name,
        "snapshot_id": snapshot_id,
        "generated_utc": now_iso(),
        "purpose": "Self-contained, bounded evidence packet for delegated read-only review.",
        "evidence": snapshot.get("evidence", []),
        "phase_state": snapshot.get("phase_state", {}),
        "known_context": snapshot.get("known_context", [])[:50],
        "active_leads": leads,
        "active_findings": findings,
        "summaries": {key: compact_summary(value) for key, value in snapshot.get("summaries", {}).items()},
        "pivot_plans": [
            {"path": item.get("path"), "content": compact_summary(item.get("content"), 4_000)}
            for item in (snapshot.get("pivot_plans") or [])[:REVIEW_LEAD_LIMIT]
        ],
        "targeted_timeline": snapshot.get("targeted_timeline", {}),
        "evidence_excerpts": evidence_excerpts(root, leads),
        "constraints": {
            "self_contained": True,
            "read_only_review": True,
            "no_case_file_access": True,
            "no_parser_execution": True,
            "no_case_writes": True,
            "no_subdelegation": True,
            "citation_rule": "Evidence refs must cite source paths already present in evidence_excerpts or summary metadata.",
        },
    }
    packet["valid_ids"] = {
        "lead_ids": [str(item.get("id")) for item in leads if item.get("id")],
        "finding_ids": [str(item.get("id")) for item in findings if item.get("id")],
    }
    return fit_review_packet(packet)


def response_schema(case_name: str, role: str, snapshot_id: str, task_id: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "case": case_name,
        "snapshot_id": snapshot_id,
        "task_id": task_id,
        "role": role,
        "summary": "Short independent assessment",
        "lead_reviews": [
            {"lead_id": "L-0001", "assessment": "corroborated|single_source|contextual|contradicted|unresolved", "rationale": "...", "evidence_refs": ["case-relative/path"]}
        ],
        "finding_reviews": [
            {"finding_id": "F-0001", "decision": "accept|downgrade|reject|needs_more_evidence", "recommended_kind": "observation|hypothesis|inference|confirmed", "rationale": "...", "evidence_refs": ["case-relative/path"]}
        ],
        "candidate_leads": [
            {"type": "process|file|sha256|ip|domain|url|user|service|other", "value": "...", "priority": "critical|high|medium|low|informational", "reason": "...", "parent_id": "L-0001 or null", "evidence_refs": ["case-relative/path"]}
        ],
        "contradictions": [{"description": "...", "affected_ids": ["L-0001", "F-0001"], "evidence_refs": ["case-relative/path"]}],
        "evidence_gaps": [{"description": "...", "affected_ids": ["L-0001"]}],
        "report_blockers": [{"code": "SHORT_CODE", "severity": "high|medium|low", "message": "...", "affected_ids": ["F-0001"], "evidence_refs": ["case-relative/path"]}],
    }


def packet_evidence_refs(root: Path, packet: dict[str, Any]) -> list[str]:
    refs: set[str] = set()
    for item in packet.get("evidence_excerpts", []):
        if isinstance(item, dict) and item.get("source"):
            refs.add(str(item["source"]))
    for item in packet.get("pivot_plans", []):
        if isinstance(item, dict) and item.get("path"):
            refs.add(str(item["path"]))
    for relative in (
        "artifact_inventory.json", "leads.jsonl", "findings.jsonl", "case_context.json",
        "output/event_triage.json", "output/artifact_triage.json",
        "output/pivots/pivot-summary.json", "timeline/targeted_timeline.csv",
    ):
        if (root / relative).is_file():
            refs.add(relative)
    return sorted(relative for relative in refs if safe_relative(root, relative)[1] is None)


def output_json_schema(case_name: str, role: str, snapshot_id: str, task_id: str, packet: dict[str, Any]) -> dict[str, Any]:
    root = case_dir(case_name)
    allowed_refs = packet_evidence_refs(root, packet)
    evidence_item: dict[str, Any] = {"type": "string"}
    if allowed_refs:
        evidence_item["enum"] = allowed_refs
    evidence_refs = {"type": "array", "items": evidence_item, "uniqueItems": True}
    affected_ids = {"type": "array", "items": {"type": "string"}}
    lead_ids = list(packet.get("valid_ids", {}).get("lead_ids") or [])
    finding_ids = list(packet.get("valid_ids", {}).get("finding_ids") or [])
    lead_id_schema: dict[str, Any] = {"type": "string"}
    finding_id_schema: dict[str, Any] = {"type": "string"}
    if lead_ids:
        lead_id_schema["enum"] = lead_ids
    if finding_ids:
        finding_id_schema["enum"] = finding_ids
    return {
        "type": "object",
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "case": {"const": case_name},
            "snapshot_id": {"const": snapshot_id},
            "task_id": {"const": task_id},
            "role": {"const": role},
            "summary": {"type": "string", "minLength": 1},
            "lead_reviews": {
                "type": "array",
                "minItems": len(lead_ids),
                "maxItems": len(lead_ids),
                "items": {
                    "type": "object",
                    "properties": {
                        "lead_id": lead_id_schema,
                        "assessment": {"enum": ["corroborated", "single_source", "contextual", "contradicted", "unresolved"]},
                        "rationale": {"type": "string"},
                        "evidence_refs": evidence_refs,
                    },
                    "required": ["lead_id", "assessment", "rationale", "evidence_refs"],
                },
            },
            "finding_reviews": {
                "type": "array",
                "minItems": len(finding_ids),
                "maxItems": len(finding_ids),
                "items": {
                    "type": "object",
                    "properties": {
                        "finding_id": finding_id_schema,
                        "decision": {"enum": ["accept", "downgrade", "reject", "needs_more_evidence"]},
                        "recommended_kind": {"enum": ["observation", "hypothesis", "inference", "confirmed"]},
                        "rationale": {"type": "string"},
                        "evidence_refs": evidence_refs,
                    },
                    "required": ["finding_id", "decision", "rationale", "evidence_refs"],
                },
            },
            "candidate_leads": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string"},
                        "value": {"type": "string"},
                        "priority": {"enum": ["critical", "high", "medium", "low", "informational"]},
                        "reason": {"type": "string"},
                        "parent_id": {"type": ["string", "null"]},
                        "evidence_refs": evidence_refs,
                    },
                    "required": ["type", "value", "priority", "reason", "evidence_refs"],
                },
            },
            "contradictions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"description": {"type": "string"}, "affected_ids": affected_ids, "evidence_refs": evidence_refs},
                    "required": ["description", "affected_ids", "evidence_refs"],
                },
            },
            "evidence_gaps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"description": {"type": "string"}, "affected_ids": affected_ids},
                    "required": ["description", "affected_ids"],
                },
            },
            "report_blockers": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string"},
                        "severity": {"enum": ["high", "medium", "low"]},
                        "message": {"type": "string"},
                        "affected_ids": affected_ids,
                        "evidence_refs": evidence_refs,
                    },
                    "required": ["code", "severity", "message", "affected_ids", "evidence_refs"],
                },
            },
        },
        "required": ["schema_version", "case", "snapshot_id", "task_id", "role", "summary", "lead_reviews", "finding_reviews", "candidate_leads", "contradictions", "evidence_gaps", "report_blockers"],
        "additionalProperties": False,
    }


def delegate_envelope(case_name: str, role: str, task_id: str, packet: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    mission = (
        "Independently identify missed correlations, unfinished pivots, and corroborating or contradictory evidence."
        if role == "investigator"
        else "Skeptically attempt to falsify or downgrade conclusions and identify overclaims, contradictions, and evidence gaps."
    )
    context = {
        "instruction": (
            f"You are the independent Aries {role} reviewer. {mission} "
            "The evidence packet below is complete and self-contained. Do not call any tool, read any file, browse, run a parser, write data, or delegate. "
            "Review only IDs listed in valid_ids. If finding_ids is empty, finding_reviews must be empty. "
            "Use only evidence_refs permitted by the native output schema. Return only the required JSON object."
        ),
        "review_packet": packet,
    }
    return {
        "goal": f"Complete the bounded independent {role} review for Aries case {case_name}, task {task_id}.",
        "context": json.dumps(context, ensure_ascii=False, separators=(",", ":")),
        "output_schema": schema,
        "execution_rules": {
            "single_delegate_task_call": True,
            "child_tool_calls_permitted": False,
            "parent_repair_permitted": False,
            "on_failure": "Record the provider/child failure and stop. Never author or repair reviewer JSON.",
        },
    }


def task_markdown(case_name: str, role: str, snapshot_id: str, task_id: str, packet_path: Path, response_path: Path, schema_path: Path, envelope_path: Path) -> str:
    if role == "investigator":
        mission = (
            "Independently look for missed correlations, unfinished pivots, useful child leads, and evidence that corroborates or contradicts active leads. "
            "Do not decide guilt from suspicious appearance."
        )
    else:
        mission = (
            "Act as a skeptical forensic reviewer. Try to falsify or downgrade current findings, detect attribution/capability/ATT&CK/temporal overclaims, "
            "and identify evidence gaps. Do not see or rely on the investigator review."
        )
    return f"""# Aries delegated {role} review

Task ID: `{task_id}`  
Snapshot ID: `{snapshot_id}`
Case: `{case_name}`

## Mission

{mission}

## Inputs

The lead agent reads `{envelope_path}` exactly once and passes its `goal`, `context`, and `output_schema` fields directly to one `delegate_task` call. The child receives the bounded packet inline and must not open `{packet_path}`, `{schema_path}`, or any other file.

## Hard restrictions

- Do not write or modify any file.
- Do not open arbitrary case files or expand beyond the supplied packet.
- Do not run Volatility, Dissect, EvtxECmd, EZ Tools, or another parser.
- Do not spawn another agent.
- Do not create, close, promote, retract, or edit leads/findings.
- Do not treat agreement with another model as corroborating evidence.
- Cite only existing case-relative files. Never invent a path or claim to have inspected a file you did not inspect.
- Work only on case `{case_name}`. If unrelated case/task content appears in your context, ignore it and mention the contamination as a report blocker.
- Return one JSON object only: no Markdown fences and no prose outside JSON.

The Aries lead agent—not you—will save your returned JSON to a temporary inbox file and register it with the v0.3.3 `--submit-review` command. Directly writing `{response_path}` without a provenance receipt is rejected.

## Required response

The native JSON Schema is stored at `{schema_path}` and embedded in `{envelope_path}`. Do not invent IDs or evidence paths; the schema enumerates the values permitted for this snapshot.
"""


def load_active(root: Path) -> dict[str, Any] | None:
    path = root / "output" / "orchestration" / "active.json"
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        return None


def prepare(case_name: str, *, force: bool = False) -> dict[str, Any]:
    root = case_dir(case_name)
    orchestration_root = root / "output" / "orchestration"
    current_fingerprint = state_fingerprint(root)
    active = load_active(root)
    if (
        not force and active and active.get("schema_version") == SCHEMA_VERSION
        and active.get("orchestration_revision") == ORCHESTRATION_REVISION
        and active.get("state_fingerprint") == current_fingerprint
    ):
        snapshot_dir = orchestration_root / str(active.get("snapshot_id"))
        if (snapshot_dir / "snapshot.json").is_file() and (snapshot_dir / "review-packet.json").is_file():
            return active

    snapshot = build_snapshot(case_name)
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    digest = sha256_bytes(canonical)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot_id = f"S-{stamp}-{digest[:10]}"
    snapshot["snapshot_id"] = snapshot_id
    snapshot["state_fingerprint"] = current_fingerprint

    snapshot_dir = orchestration_root / snapshot_id
    snapshot_path = snapshot_dir / "snapshot.json"
    write_json_atomic(snapshot_path, snapshot)
    snapshot_sha256 = sha256_file(snapshot_path)
    review_packet = build_review_packet(case_name, snapshot, snapshot_id)
    packet_path = snapshot_dir / "review-packet.json"
    write_json_atomic(packet_path, review_packet)
    packet_sha256 = sha256_file(packet_path)
    reviews_dir = snapshot_dir / "reviews"
    reviews_dir.mkdir(parents=True, exist_ok=True)

    tasks = {}
    for role in ROLES:
        task_id = f"T-{snapshot_id[2:]}-{role.upper()}"
        task_path = snapshot_dir / f"{role}-task.md"
        schema_path = snapshot_dir / f"{role}-output-schema.json"
        response_path = reviews_dir / f"{role}.json"
        receipt_path = reviews_dir / f"{role}.receipt.json"
        envelope_path = snapshot_dir / f"{role}-delegate-envelope.json"
        schema = output_json_schema(case_name, role, snapshot_id, task_id, review_packet)
        write_json_atomic(schema_path, schema)
        write_json_atomic(envelope_path, delegate_envelope(case_name, role, task_id, review_packet, schema))
        task_path.write_text(task_markdown(case_name, role, snapshot_id, task_id, packet_path, response_path, schema_path, envelope_path), encoding="utf-8")
        tasks[role] = {
            "task_id": task_id,
            "task_path": str(task_path),
            "output_schema_path": str(schema_path),
            "response_path": str(response_path),
            "receipt_path": str(receipt_path),
            "delegate_envelope_path": str(envelope_path),
            "status": "pending",
            "failure_count": 0,
        }

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "orchestration_revision": ORCHESTRATION_REVISION,
        "case": case_name,
        "snapshot_id": snapshot_id,
        "created_utc": now_iso(),
        "status": "awaiting_reviews",
        "state_fingerprint": current_fingerprint,
        "snapshot_path": str(snapshot_path),
        "snapshot_sha256": snapshot_sha256,
        "review_packet_path": str(packet_path),
        "review_packet_sha256": packet_sha256,
        "review_packet_size_bytes": packet_path.stat().st_size,
        "review_packet_estimated_tokens": review_packet.get("budget", {}).get("estimated_tokens"),
        "roles": list(ROLES),
        "tasks": tasks,
        "review_policy": {
            "authoritative_writer": "aries_lead",
            "required_reviews": 2,
            "max_parallel_children": 1,
            "max_delegation_depth": 1,
            "sequential_reviews": True,
            "required_submission_command": True,
            "self_authored_reviews_permitted": False,
            "max_failures_per_role": MAX_REVIEW_FAILURES,
            "max_reviewer_iterations": 24,
            "max_review_packet_estimated_tokens": REVIEW_PACKET_MAX_ESTIMATED_TOKENS,
            "reviewers_may_modify_case": False,
            "reviewer_agreement_is_evidence": False,
        },
    }
    write_json_atomic(snapshot_dir / "manifest.json", manifest)
    write_json_atomic(orchestration_root / "active.json", manifest)
    return manifest


def parse_review(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        text = fenced.group(1)
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("review root must be a JSON object")
    return value


def validate_refs(root: Path, owner: str, refs: Any, errors: list[str]) -> list[str]:
    if refs is None:
        return []
    if not isinstance(refs, list):
        errors.append(f"{owner}.evidence_refs must be a list")
        return []
    valid = []
    for raw in refs:
        relative, error = safe_relative(root, str(raw))
        if error:
            errors.append(f"{owner}: {error}")
        elif relative and relative not in valid:
            valid.append(relative)
    return valid


def iter_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from iter_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_strings(child)


def value_present_in_refs(root: Path, value: str, refs: list[str]) -> bool:
    needle = value.strip().lower()
    slash_needle = needle.replace("\\", "/")
    if not needle:
        return False
    for relative in refs:
        path = root / relative
        try:
            if path.stat().st_size > CATALOG_FILE_LIMIT:
                continue
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        if needle in text or slash_needle in text.replace("\\", "/"):
            return True
    return False


def validate_review(root: Path, manifest: dict[str, Any], role: str, value: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    expected_task = manifest["tasks"][role]["task_id"]
    for key, expected in (("schema_version", SCHEMA_VERSION), ("case", manifest["case"]), ("snapshot_id", manifest["snapshot_id"]), ("task_id", expected_task), ("role", role)):
        if value.get(key) != expected:
            errors.append(f"{key} must equal {expected!r}")
    if not isinstance(value.get("summary"), str) or not value.get("summary", "").strip():
        errors.append("summary must be a non-empty string")

    normalized = {**value}
    for text in iter_strings(normalized):
        for foreign_case in FOREIGN_CASE_PATH_RE.findall(text):
            if foreign_case.lower() != str(manifest["case"]).lower():
                errors.append(f"foreign case path is not allowed: {foreign_case}")
    list_fields = ("lead_reviews", "finding_reviews", "candidate_leads", "contradictions", "evidence_gaps", "report_blockers")
    for field in list_fields:
        if field not in normalized:
            normalized[field] = []
        if not isinstance(normalized[field], list):
            errors.append(f"{field} must be a list")
            normalized[field] = []

    enums = {
        "lead_reviews": ("assessment", {"corroborated", "single_source", "contextual", "contradicted", "unresolved"}),
        "finding_reviews": ("decision", {"accept", "downgrade", "reject", "needs_more_evidence"}),
        "candidate_leads": ("priority", {"critical", "high", "medium", "low", "informational"}),
        "report_blockers": ("severity", {"high", "medium", "low"}),
    }
    known_leads = {str(item.get("id")) for item in materialize_history(root / "leads.jsonl", "L")}
    known_findings = {str(item.get("id")) for item in materialize_history(root / "findings.jsonl", "F")}
    for field, items in ((name, normalized[name]) for name in list_fields):
        cleaned = []
        for index, item in enumerate(items):
            owner = f"{field}[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{owner} must be an object")
                continue
            item = dict(item)
            if "evidence_refs" in item:
                item["evidence_refs"] = validate_refs(root, owner, item.get("evidence_refs"), errors)
            if field in enums:
                key, choices = enums[field]
                if item.get(key) not in choices:
                    errors.append(f"{owner}.{key} must be one of {sorted(choices)}")
            if field == "lead_reviews" and not str(item.get("lead_id", "")).startswith("L-"):
                errors.append(f"{owner}.lead_id is required")
            elif field == "lead_reviews" and str(item.get("lead_id")) not in known_leads:
                errors.append(f"{owner}.lead_id does not exist in the case")
            if field == "finding_reviews" and not str(item.get("finding_id", "")).startswith("F-"):
                errors.append(f"{owner}.finding_id is required")
            elif field == "finding_reviews" and str(item.get("finding_id")) not in known_findings:
                errors.append(f"{owner}.finding_id does not exist in the case")
            if field == "candidate_leads" and (not str(item.get("type", "")).strip() or not str(item.get("value", "")).strip() or not str(item.get("reason", "")).strip()):
                errors.append(f"{owner} requires type, value, and reason")
            if field == "candidate_leads" and not item.get("evidence_refs"):
                errors.append(f"{owner} requires at least one exact evidence reference")
            elif field == "candidate_leads" and not value_present_in_refs(root, str(item.get("value", "")), item.get("evidence_refs", [])):
                errors.append(f"{owner}.value does not appear in its cited evidence")
            if field == "candidate_leads" and item.get("parent_id") and str(item.get("parent_id")) not in known_leads:
                errors.append(f"{owner}.parent_id does not exist in the case")
            if field in {"lead_reviews", "finding_reviews"} and not str(item.get("rationale", "")).strip():
                errors.append(f"{owner}.rationale must be non-empty")
            cleaned.append(item)
        normalized[field] = cleaned
    try:
        packet = json.loads(Path(manifest["review_packet_path"]).read_text(encoding="utf-8"))
        valid_ids = packet.get("valid_ids", {})
        for field, id_field, expected_key in (
            ("lead_reviews", "lead_id", "lead_ids"),
            ("finding_reviews", "finding_id", "finding_ids"),
        ):
            expected = [str(item) for item in valid_ids.get(expected_key, [])]
            observed = [str(item.get(id_field, "")) for item in normalized.get(field, []) if isinstance(item, dict)]
            missing = sorted(set(expected) - set(observed))
            unexpected = sorted(set(observed) - set(expected))
            duplicates = sorted({item for item in observed if observed.count(item) > 1})
            if missing:
                errors.append(f"{field} must review every bounded snapshot ID; missing {missing}")
            if unexpected:
                errors.append(f"{field} contains IDs outside the bounded snapshot: {unexpected}")
            if duplicates:
                errors.append(f"{field} contains duplicate IDs: {duplicates}")
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        errors.append(f"could not validate bounded review coverage: {exc}")
    return normalized, errors


def consensus(reviews: dict[str, dict[str, Any]], field: str, id_field: str, decision_field: str) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for role, review in reviews.items():
        for item in review.get(field, []):
            object_id = str(item.get(id_field, ""))
            if not object_id:
                continue
            entry = grouped.setdefault(object_id, {id_field: object_id, "reviews": {}})
            entry["reviews"][role] = item
    output = []
    for object_id, entry in sorted(grouped.items()):
        decisions = {role: item.get(decision_field) for role, item in entry["reviews"].items()}
        distinct = set(decisions.values())
        if len(decisions) < len(ROLES):
            status = "single_reviewer"
        elif len(distinct) == 1:
            status = f"unanimous_{next(iter(distinct))}"
        else:
            status = "disagreement"
        prefix = "OF" if id_field == "finding_id" else "OL"
        output.append({"item_id": stable_item_id(prefix, object_id), **entry, "decisions": decisions, "consensus": status})
    return output


def merge_reviews(root: Path, manifest: dict[str, Any], reviews: dict[str, dict[str, Any]]) -> dict[str, Any]:
    finding_consensus = consensus(reviews, "finding_reviews", "finding_id", "decision")
    lead_consensus = consensus(reviews, "lead_reviews", "lead_id", "assessment")

    candidate_index: dict[tuple[str, str], dict[str, Any]] = {}
    contradictions = []
    gaps = []
    blockers = []
    for role, review in reviews.items():
        for item in review.get("candidate_leads", []):
            key = (str(item.get("type", "")).lower(), str(item.get("value", "")).strip().lower())
            item_id = stable_item_id("OC", f"{key[0]}:{key[1]}")
            entry = candidate_index.setdefault(key, {"item_id": item_id, **item, "proposed_by": [], "review_only": True})
            if role not in entry["proposed_by"]:
                entry["proposed_by"].append(role)
        for item in review.get("contradictions", []):
            description = str(item.get("description", ""))
            contradictions.append({"item_id": stable_item_id("OX", description), **item, "reported_by": role})
        for item in review.get("evidence_gaps", []):
            value = item if isinstance(item, dict) else {"description": str(item)}
            description = str(value.get("description", ""))
            gaps.append({"item_id": stable_item_id("OG", description), **value, "reported_by": role})
        for item in review.get("report_blockers", []):
            key = f"{item.get('code', '')}:{item.get('message', '')}"
            blockers.append({"item_id": stable_item_id("OB", key), **item, "reported_by": role})

    disagreements = [item for item in finding_consensus + lead_consensus if item["consensus"] in {"disagreement", "single_reviewer"}]
    adverse_findings = [
        item
        for item in finding_consensus
        if any(value in {"downgrade", "reject", "needs_more_evidence"} for value in item["decisions"].values())
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "case": manifest["case"],
        "snapshot_id": manifest["snapshot_id"],
        "generated_utc": now_iso(),
        "status": "complete",
        "roles_completed": sorted(reviews),
        "review_summaries": {role: review.get("summary", "") for role, review in reviews.items()},
        "review_provenance": {
            role: manifest["tasks"][role].get("provenance", {}) for role in sorted(reviews)
        },
        "finding_consensus": finding_consensus,
        "lead_consensus": lead_consensus,
        "candidate_leads": list(candidate_index.values()),
        "contradictions": contradictions,
        "evidence_gaps": gaps,
        "report_blockers": blockers,
        "disagreement_count": len(disagreements),
        "adverse_finding_review_count": len(adverse_findings),
        "report_ready_recommendation": not blockers and not disagreements and not adverse_findings,
        "authority_note": "Delegated reviews are advisory. They do not create evidence or mutate authoritative leads/findings. The Aries lead must adjudicate proposals using cited case evidence.",
    }


def summary_item_ids(summary: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for field in ("finding_consensus", "lead_consensus", "candidate_leads", "contradictions", "evidence_gaps", "report_blockers"):
        for item in summary.get(field, []):
            if isinstance(item, dict) and item.get("item_id"):
                ids.add(str(item["item_id"]))
    return ids


def materialize_decisions(root: Path) -> dict[str, dict[str, Any]]:
    current: dict[str, dict[str, Any]] = {}
    for item in read_jsonl(root / "output" / "orchestration" / "decisions.jsonl"):
        item_id = str(item.get("item_id", ""))
        if item_id:
            current[item_id] = item
    return current


def record_decision(case_name: str, item_id: str, decision: str, reason: str) -> int:
    root = case_dir(case_name)
    summary_path = root / "output" / "orchestration" / "review-summary.json"
    if not summary_path.is_file():
        print("No completed orchestration review summary exists.", file=sys.stderr)
        return 2
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if item_id not in summary_item_ids(summary):
        print(f"Unknown orchestration item: {item_id}", file=sys.stderr)
        return 2
    append_jsonl(
        root / "output" / "orchestration" / "decisions.jsonl",
        {
            "schema_version": SCHEMA_VERSION,
            "timestamp_utc": now_iso(),
            "snapshot_id": summary.get("snapshot_id"),
            "item_id": item_id,
            "decision": decision,
            "reason": reason,
            "authority": "aries_lead",
        },
    )
    print(f"Orchestration item {item_id} marked {decision}.")
    return 0


def print_waiting(manifest: dict[str, Any], validation_errors: dict[str, list[str]] | None = None) -> None:
    print("ORCHESTRATION_STATUS=AWAITING_REVIEWS")
    print(f"SNAPSHOT_ID={manifest['snapshot_id']}")
    print(f"SNAPSHOT={manifest['snapshot_path']}")
    print(f"REVIEW_PACKET={manifest['review_packet_path']}")
    print(f"REVIEW_PACKET_ESTIMATED_TOKENS={manifest.get('review_packet_estimated_tokens', 'unknown')}")
    for role in ROLES:
        task = manifest["tasks"][role]
        print(f"{role.upper()}_TASK={task['task_path']}")
        print(f"{role.upper()}_SCHEMA={task['output_schema_path']}")
        print(f"{role.upper()}_DELEGATE_ENVELOPE={task.get('delegate_envelope_path', '')}")
        print(f"{role.upper()}_RESPONSE={task['response_path']}")
        print(f"{role.upper()}_STATUS={task.get('status', 'pending')}")
    if validation_errors:
        print("REVIEW_VALIDATION_ERRORS=" + json.dumps(validation_errors, ensure_ascii=False))
    next_role = next((role for role in ROLES if manifest["tasks"][role].get("status") != "submitted"), None)
    if next_role:
        print(f"NEXT_REVIEW_ROLE={next_role}")
    print("LEAD_AGENT_ACTION=Read NEXT_REVIEW_ROLE_DELEGATE_ENVELOPE once and pass its goal/context/output_schema unchanged to exactly one delegate_task call. The child must make zero tool calls. If status/schema validation fails, record the failure and stop; never repair or author reviewer JSON. Submit only the exact successful child JSON with real delegation provenance.")


def save_manifest(root: Path, manifest: dict[str, Any]) -> None:
    snapshot_dir = Path(manifest["snapshot_path"]).parent
    write_json_atomic(snapshot_dir / "manifest.json", manifest)
    write_json_atomic(root / "output" / "orchestration" / "active.json", manifest)


def submit_review(case_name: str, role: str, input_path: str, delegation_id: str, child_id: str, provider_model: str) -> int:
    root = case_dir(case_name)
    manifest = load_active(root)
    if not manifest or manifest.get("schema_version") != SCHEMA_VERSION:
        print("No active v0.3.3 orchestration round exists.", file=sys.stderr)
        return 2
    if role not in ROLES:
        print(f"Unknown review role: {role}", file=sys.stderr)
        return 2
    if role == "validator" and manifest["tasks"]["investigator"].get("status") != "submitted":
        print("Submit the investigator review before delegating the validator.", file=sys.stderr)
        return 2
    if not all(str(item).strip() for item in (delegation_id, child_id, provider_model)):
        print("Delegation ID, child ID, and provider/model are required.", file=sys.stderr)
        return 2
    placeholders = {"none", "null", "unknown", "n/a", "na", "-", "test"}
    if any(str(item).strip().lower() in placeholders for item in (delegation_id, child_id, provider_model)):
        print("Placeholder delegation provenance is forbidden; submit the real delegated-child identifiers and provider/model.", file=sys.stderr)
        return 2
    source = Path(input_path)
    if not source.is_file():
        print(f"Review input does not exist: {source}", file=sys.stderr)
        return 2
    try:
        raw = parse_review(source)
        normalized, errors = validate_review(root, manifest, role, raw)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        normalized, errors = {}, [str(exc)]
    if errors:
        print("Review rejected: " + json.dumps(errors, ensure_ascii=False), file=sys.stderr)
        return 2
    for other in ROLES:
        provenance = manifest["tasks"][other].get("provenance", {})
        if other != role and (provenance.get("delegation_id"), provenance.get("child_id")) == (delegation_id, child_id):
            print("Each role requires a distinct delegated child execution.", file=sys.stderr)
            return 2
    response_path = Path(manifest["tasks"][role]["response_path"])
    write_json_atomic(response_path, normalized)
    response_sha256 = sha256_file(response_path)
    provenance = {
        "schema_version": SCHEMA_VERSION,
        "case": case_name,
        "snapshot_id": manifest["snapshot_id"],
        "task_id": manifest["tasks"][role]["task_id"],
        "role": role,
        "source": "delegated_child",
        "delegation_id": delegation_id,
        "child_id": child_id,
        "provider_model": provider_model,
        "submitted_utc": now_iso(),
        "response_sha256": response_sha256,
    }
    write_json_atomic(Path(manifest["tasks"][role]["receipt_path"]), provenance)
    manifest["tasks"][role]["status"] = "submitted"
    manifest["tasks"][role]["provenance"] = provenance
    manifest["status"] = "awaiting_validator" if role == "investigator" else "reviews_submitted"
    save_manifest(root, manifest)
    print(f"Accepted delegated {role} review for snapshot {manifest['snapshot_id']}.")
    return 0


def record_failure(case_name: str, role: str, reason: str, error_code: str | None = None) -> int:
    root = case_dir(case_name)
    manifest = load_active(root)
    if not manifest or role not in ROLES:
        print("No compatible active orchestration round/role exists.", file=sys.stderr)
        return 2
    task = manifest["tasks"][role]
    task["failure_count"] = int(task.get("failure_count") or 0) + 1
    task["last_failure"] = {"timestamp_utc": now_iso(), "reason": reason, "error_code": error_code or ""}
    append_jsonl(root / "output" / "orchestration" / "review-failures.jsonl", {
        "schema_version": SCHEMA_VERSION, "case": case_name, "snapshot_id": manifest["snapshot_id"],
        "role": role, "timestamp_utc": now_iso(), "reason": reason, "error_code": error_code or "",
        "failure_count": task["failure_count"],
    })
    non_retryable = any(token in f"{error_code or ''} {reason}".lower() for token in (
        "billing", "credit", "quota", "insufficient funds", "authentication", "invalid api key",
    ))
    if non_retryable or task["failure_count"] >= MAX_REVIEW_FAILURES:
        task["status"] = "failed"
        manifest["status"] = "degraded"
        if non_retryable:
            print(f"{role} review hit a non-retryable provider/billing error; orchestration is DEGRADED. Aries will not spend tokens retrying it.")
        else:
            print(f"{role} review reached {MAX_REVIEW_FAILURES} failures; orchestration is DEGRADED and cannot be represented as independent review.")
    else:
        task["status"] = "retryable_failed"
        manifest["status"] = f"awaiting_{role}_retry"
        print(f"Recorded {role} review failure {task['failure_count']}/{MAX_REVIEW_FAILURES}; retry after provider backoff.")
    save_manifest(root, manifest)
    return 0


def run(case_name: str, *, force: bool = False) -> int:
    load_case(case_name)
    root = case_dir(case_name)
    manifest = prepare(case_name, force=force)
    snapshot_path = Path(manifest["snapshot_path"])
    if not snapshot_path.is_file() or sha256_file(snapshot_path) != manifest.get("snapshot_sha256"):
        print("Snapshot integrity validation failed. Create a new snapshot with --new-snapshot.", file=sys.stderr)
        return 2
    packet_path = Path(manifest.get("review_packet_path", ""))
    if not packet_path.is_file() or sha256_file(packet_path) != manifest.get("review_packet_sha256"):
        print("Review-packet integrity validation failed. Create a new snapshot with --new-snapshot.", file=sys.stderr)
        return 2

    current_fingerprint = state_fingerprint(root)
    if current_fingerprint != manifest.get("state_fingerprint"):
        manifest = prepare(case_name, force=True)
        print("Case reasoning state changed; Aries preserved the old snapshot and created a fresh review round.")
        print_waiting(manifest)
        return 4

    failed_roles = [role for role in ROLES if manifest["tasks"][role].get("status") == "failed"]
    if failed_roles:
        manifest["status"] = "degraded"
        save_manifest(root, manifest)
        print("ORCHESTRATION_STATUS=DEGRADED")
        print("FAILED_ROLES=" + ",".join(failed_roles))
        print("Independent review did not complete. Do not author replacement reviews and do not claim two-reviewer validation. Start a new snapshot after fixing provider access/rate limits.")
        return 5

    reviews: dict[str, dict[str, Any]] = {}
    validation_errors: dict[str, list[str]] = {}
    for role in ROLES:
        path = Path(manifest["tasks"][role]["response_path"])
        receipt_path = Path(manifest["tasks"][role]["receipt_path"])
        if manifest["tasks"][role].get("status") != "submitted":
            validation_errors[role] = ["review was not registered through --submit-review"]
            continue
        if not path.is_file():
            validation_errors[role] = ["response file is missing"]
            continue
        if not receipt_path.is_file():
            validation_errors[role] = ["delegated-review provenance receipt is missing"]
            continue
        try:
            raw = parse_review(path)
            normalized, errors = validate_review(root, manifest, role, raw)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            expected_receipt = {
                "schema_version": SCHEMA_VERSION,
                "case": case_name,
                "snapshot_id": manifest["snapshot_id"],
                "task_id": manifest["tasks"][role]["task_id"],
                "role": role,
                "source": "delegated_child",
                "response_sha256": sha256_file(path),
            }
            for key, expected in expected_receipt.items():
                if receipt.get(key) != expected:
                    errors.append(f"receipt {key} must equal {expected!r}")
            for key in ("delegation_id", "child_id", "provider_model", "submitted_utc"):
                if not str(receipt.get(key, "")).strip():
                    errors.append(f"receipt {key} is required")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            normalized, errors = {}, [str(exc)]
        if errors:
            validation_errors[role] = errors
        else:
            reviews[role] = normalized

    snapshot_dir = snapshot_path.parent
    write_json_atomic(
        snapshot_dir / "review-validation.json",
        {
            "schema_version": "0.3.3",
            "generated_utc": now_iso(),
            "snapshot_id": manifest["snapshot_id"],
            "valid_roles": sorted(reviews),
            "errors": validation_errors,
        },
    )
    if validation_errors:
        print_waiting(manifest, validation_errors)
        return 4

    identities = {
        (
            manifest["tasks"][role].get("provenance", {}).get("delegation_id"),
            manifest["tasks"][role].get("provenance", {}).get("child_id"),
        )
        for role in ROLES
    }
    if len(identities) != len(ROLES):
        print_waiting(manifest, {"provenance": ["investigator and validator must come from distinct delegated child executions"]})
        return 4

    summary = merge_reviews(root, manifest, reviews)
    summary_path = snapshot_dir / "review-summary.json"
    write_json_atomic(summary_path, summary)
    write_json_atomic(root / "output" / "orchestration" / "review-summary.json", summary)
    manifest["status"] = "complete"
    manifest["completed_utc"] = now_iso()
    manifest["review_summary_path"] = str(summary_path)
    for role in ROLES:
        manifest["tasks"][role]["status"] = "complete"
        manifest["tasks"][role]["response_sha256"] = sha256_file(Path(manifest["tasks"][role]["response_path"]))
    write_json_atomic(snapshot_dir / "manifest.json", manifest)
    write_json_atomic(root / "output" / "orchestration" / "active.json", manifest)
    print("ORCHESTRATION_STATUS=COMPLETE")
    print(f"SNAPSHOT_ID={manifest['snapshot_id']}")
    print(f"REVIEW_SUMMARY={summary_path}")
    print(f"REPORT_READY_RECOMMENDATION={str(summary['report_ready_recommendation']).upper()}")
    print("The lead agent must adjudicate candidate leads and challenged findings before evidence assessment. Reviewer agreement is not forensic corroboration.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare, validate, and merge Aries v0.3.3 provenance-tracked delegated reviews")
    parser.add_argument("--case", required=True)
    parser.add_argument("--new-snapshot", action="store_true", help="Preserve the current round and create a new immutable snapshot")
    parser.add_argument("--resolve", metavar="ITEM_ID", help="Record the lead agent's disposition for one advisory review item")
    parser.add_argument("--decision", choices=["resolved", "dismissed", "deferred"])
    parser.add_argument("--reason")
    parser.add_argument("--submit-review", choices=list(ROLES), metavar="ROLE", help="Register one completed delegated-child JSON response")
    parser.add_argument("--input", help="Temporary JSON file containing the child response")
    parser.add_argument("--delegation-id")
    parser.add_argument("--child-id")
    parser.add_argument("--provider-model")
    parser.add_argument("--record-failure", choices=list(ROLES), metavar="ROLE", help="Record a child/provider failure without fabricating a review")
    parser.add_argument("--error-code")
    args = parser.parse_args()
    if args.submit_review:
        required = (args.input, args.delegation_id, args.child_id, args.provider_model)
        if not all(required):
            parser.error("--submit-review requires --input, --delegation-id, --child-id, and --provider-model")
        raise SystemExit(submit_review(args.case, args.submit_review, args.input, args.delegation_id, args.child_id, args.provider_model))
    if args.record_failure:
        if not args.reason:
            parser.error("--record-failure requires --reason")
        raise SystemExit(record_failure(args.case, args.record_failure, args.reason, args.error_code))
    if args.resolve:
        if not args.decision or not args.reason:
            parser.error("--resolve requires --decision and --reason")
        raise SystemExit(record_decision(args.case, args.resolve, args.decision, args.reason))
    if args.decision or args.reason:
        parser.error("--decision/--reason require --resolve")
    raise SystemExit(run(args.case, force=args.new_snapshot))


if __name__ == "__main__":
    main()
