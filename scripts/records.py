from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from common import case_dir, now_iso

PRIORITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
DEFAULT_MATERIAL_LEAD_LIMIT = 12

ENTITY_RE = re.compile(
    r"(?:\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-fA-F0-9]{32,64}\b|"
    r"\b[\w.-]+\.(?:exe|dll|sys|ps1|bat|cmd|zip|rar|7z)\b)",
    re.IGNORECASE,
)


def _normalized_claim_text(value: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", value.lower()).split())


def _claim_entities(*values: str) -> set[str]:
    return {match.group(0).lower() for value in values for match in ENTITY_RE.finditer(value or "")}


def _normalized_title(title: str, kind: str) -> str:
    if kind == "confirmed":
        return title
    return re.sub(r"^\s*confirmed\s*[:\-–—]?\s*", "Evidence-supported: ", title, flags=re.IGNORECASE)


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                out.append(value)
        except json.JSONDecodeError:
            continue
    return out


def next_id(records: list[dict[str, Any]], prefix: str) -> str:
    highest = 0
    for record in records:
        value = str(record.get("id", ""))
        if value.startswith(prefix + "-"):
            try:
                highest = max(highest, int(value.split("-", 1)[1]))
            except ValueError:
                pass
    return f"{prefix}-{highest + 1:04d}"


def materialize_history(path: Path, prefix: str) -> list[dict[str, Any]]:
    """Materialize append-only create/update/retract records into current objects.

    Legacy v0.2 finding lines without event/id are treated as active create records.
    """
    history = read_jsonl(path)
    current: dict[str, dict[str, Any]] = {}
    legacy_counter = 0
    for record in history:
        event = record.get("event")
        rid = record.get("id")
        if not rid:
            legacy_counter += 1
            rid = f"{prefix}-LEGACY-{legacy_counter:04d}"
            record = {**record, "id": rid, "event": "create", "status": record.get("status", "active")}
            event = "create"
        if event in (None, "create"):
            current[rid] = {**record, "id": rid, "event": "create", "status": record.get("status", "active")}
        elif rid in current and event == "update":
            patch = record.get("changes") or {}
            current[rid].update(patch)
            current[rid]["updated_utc"] = record.get("timestamp_utc") or now_iso()
        elif rid in current and event == "retract":
            current[rid]["status"] = "retracted"
            current[rid]["retracted_utc"] = record.get("timestamp_utc") or now_iso()
            current[rid]["retracted_reason"] = record.get("reason", "")
            current[rid]["superseded_by"] = record.get("superseded_by")
        elif rid in current and event == "close":
            current[rid]["status"] = record.get("status", "closed")
            current[rid]["closed_utc"] = record.get("timestamp_utc") or now_iso()
            if record.get("reason"):
                current[rid]["closed_reason"] = record["reason"]
            if record.get("closure_basis"):
                current[rid]["closure_basis"] = record["closure_basis"]
    return list(current.values())


def add_finding(
    case_name: str, *, kind: str, title: str, severity: str, confidence: str,
    source: str, details: str, claim_scope: str = "factual",
    evidence_refs: list[str] | None = None, artifact_families: list[str] | None = None,
    behavior: str = "", attack_techniques: list[str] | None = None,
    incident_cluster: str | None = None, limitations: list[str] | None = None,
    bridge_evidence_refs: list[str] | None = None, context_resolution: str = "",
) -> dict[str, Any]:
    path = case_dir(case_name) / "findings.jsonl"
    history = read_jsonl(path)
    rid = next_id(history, "F")
    record = {
        "event": "create",
        "id": rid,
        "timestamp_utc": now_iso(),
        "status": "active",
        "kind": kind,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "source": source,
        "details": details,
        "claim_scope": claim_scope,
        "evidence_refs": list(dict.fromkeys(evidence_refs or [])),
        "artifact_families": list(dict.fromkeys(artifact_families or [])),
        "behavior": behavior,
        "attack_techniques": list(dict.fromkeys(attack_techniques or [])),
        "incident_cluster": incident_cluster,
        "bridge_evidence_refs": list(dict.fromkeys(bridge_evidence_refs or [])),
        "context_matches": context_matches(case_name, f"{title} {details} {behavior}"),
        "context_resolution": context_resolution.strip(),
        "limitations": limitations or [],
    }
    if kind == "confirmed" and len(record["artifact_families"]) < 2:
        record["kind"] = "inference"
        record["validation_warning"] = "Downgraded from confirmed: confirmed findings require at least two independent artifact families."
    if record["kind"] == "confirmed" and record["context_matches"] and not record["context_resolution"]:
        record["kind"] = "inference"
        record["validation_warning"] = "Downgraded from confirmed: the claim intersects recorded case context and no evidence-based context resolution was supplied."
    record["title"] = _normalized_title(record["title"], record["kind"])

    # Merge repeated model restatements of the same conclusion. The history is
    # still append-only; this emits an update against the original finding.
    new_entities = _claim_entities(record["title"], record["details"], record["behavior"])
    new_behavior = _normalized_claim_text(record["behavior"])
    new_title = _normalized_claim_text(record["title"])
    for existing in materialize_history(path, "F"):
        if existing.get("status") != "active":
            continue
        if str(existing.get("claim_scope") or "factual") != str(record["claim_scope"]):
            continue
        if str(existing.get("incident_cluster") or "") != str(record.get("incident_cluster") or ""):
            continue
        existing_entities = _claim_entities(str(existing.get("title") or ""), str(existing.get("details") or ""), str(existing.get("behavior") or ""))
        same_behavior = bool(new_behavior and new_behavior == _normalized_claim_text(str(existing.get("behavior") or "")))
        same_title = bool(new_title and new_title == _normalized_claim_text(str(existing.get("title") or "")))
        entity_overlap = len(new_entities & existing_entities) >= 2
        if not (same_behavior or same_title or entity_overlap):
            continue
        changes = {
            "evidence_refs": list(dict.fromkeys(list(existing.get("evidence_refs") or []) + record["evidence_refs"])),
            "bridge_evidence_refs": list(dict.fromkeys(list(existing.get("bridge_evidence_refs") or []) + record["bridge_evidence_refs"])),
            "artifact_families": list(dict.fromkeys(list(existing.get("artifact_families") or []) + record["artifact_families"])),
            "attack_techniques": list(dict.fromkeys(list(existing.get("attack_techniques") or []) + record["attack_techniques"])),
            "limitations": list(dict.fromkeys(list(existing.get("limitations") or []) + record["limitations"])),
            "details": record["details"] if len(record["details"]) > len(str(existing.get("details") or "")) else existing.get("details", ""),
            "deduplicated": True,
        }
        append_jsonl(path, {"event": "update", "id": existing["id"], "timestamp_utc": now_iso(), "changes": changes})
        return {**existing, **changes}
    append_jsonl(path, record)
    return record


def retract_finding(case_name: str, finding_id: str, reason: str, superseded_by: str | None = None) -> None:
    path = case_dir(case_name) / "findings.jsonl"
    current = {item["id"]: item for item in materialize_history(path, "F")}
    if finding_id not in current:
        raise KeyError(f"Finding not found: {finding_id}")
    append_jsonl(path, {"event": "retract", "id": finding_id, "timestamp_utc": now_iso(), "reason": reason, "superseded_by": superseded_by})


def add_lead(
    case_name: str,
    *,
    lead_type: str,
    value: str,
    priority: str,
    score: int,
    source: str,
    reason: str,
    timestamp: str | None = None,
    parent_id: str | None = None,
    context_matches: list[str] | None = None,
) -> dict[str, Any]:
    path = case_dir(case_name) / "leads.jsonl"
    current = materialize_history(path, "L")
    norm = value.strip().lower()
    for item in current:
        if item.get("status") == "active" and item.get("type") == lead_type and str(item.get("value", "")).strip().lower() == norm:
            # Add a provenance update instead of duplicating the lead.
            sources = list(item.get("sources") or [item.get("source")])
            if source and source not in sources:
                sources.append(source)
            new_score = max(int(item.get("score") or 0), int(score))
            changes: dict[str, Any] = {}
            if sources != list(item.get("sources") or [item.get("source")]):
                changes["sources"] = sources
            if new_score != int(item.get("score") or 0):
                changes["score"] = new_score
            if PRIORITY_ORDER.get(priority, 0) > PRIORITY_ORDER.get(str(item.get("priority", "low")), 0):
                changes["priority"] = priority
            if changes:
                append_jsonl(path, {"event": "update", "id": item["id"], "timestamp_utc": now_iso(), "changes": changes})
            updated = {**item, **changes}
            return updated

    history = read_jsonl(path)
    rid = next_id(history, "L")
    record = {
        "event": "create",
        "id": rid,
        "timestamp_utc": now_iso(),
        "status": "active",
        "type": lead_type,
        "value": value,
        "priority": priority,
        "score": max(0, min(100, int(score))),
        "source": source,
        "sources": [source] if source else [],
        "reason": reason,
        "observed_time": timestamp,
        "parent_id": parent_id,
        "context_matches": context_matches or [],
    }
    append_jsonl(path, record)
    return record


def update_lead(case_name: str, lead_id: str, **changes: Any) -> None:
    path = case_dir(case_name) / "leads.jsonl"
    current = {item["id"]: item for item in materialize_history(path, "L")}
    if lead_id not in current:
        raise KeyError(f"Lead not found: {lead_id}")
    append_jsonl(path, {"event": "update", "id": lead_id, "timestamp_utc": now_iso(), "changes": changes})


def enforce_material_lead_budget(
    case_name: str,
    limit: int = DEFAULT_MATERIAL_LEAD_LIMIT,
    *,
    reason: str = "Deterministic material-lead budget",
) -> dict[str, Any]:
    """Keep only the strongest active high/critical leads in the material queue.

    Overflow is not discarded. It is explicitly downgraded to the medium-priority
    backlog and remains available for later pivots or analyst promotion.
    """
    limit = max(1, int(limit))
    path = case_dir(case_name) / "leads.jsonl"
    material = [
        item for item in materialize_history(path, "L")
        if item.get("status") == "active" and item.get("priority") in {"critical", "high"}
    ]

    def rank(item: dict[str, Any]) -> tuple[int, int, int, int, int, str]:
        families = len(set(item.get("artifact_families") or []))
        sources = len(set(filter(None, item.get("sources") or [item.get("source")])))
        value = Path(str(item.get("value") or "").replace("\\", "/")).name.lower()
        reason = f"{item.get('reason', '')} {' '.join(str(v) for v in item.get('sources') or [])}".lower()
        common = value in {
            "explorer.exe", "cmd.exe", "powershell.exe", "svchost.exe", "conhost.exe",
            "rundll32.exe", "notepad.exe", "mpdefendercoreservice.exe",
        }
        suspicious_context = any(token in reason for token in ("detection", "malware", "encoded", "suspicious", "alert"))
        noise_penalty = -1 if common and not suspicious_context else 0
        return (
            PRIORITY_ORDER.get(str(item.get("priority", "low")), 0),
            noise_penalty,
            int(item.get("score") or 0),
            families,
            sources,
            str(item.get("id", "")),
        )

    material.sort(key=rank, reverse=True)
    retained = material[:limit]
    overflow = material[limit:]
    for item in overflow:
        append_jsonl(path, {
            "event": "update",
            "id": item["id"],
            "timestamp_utc": now_iso(),
            "changes": {
                "priority": "medium",
                "material_queue": "backlog",
                "original_priority": item.get("original_priority") or item.get("priority"),
                "budget_reason": reason,
            },
        })

    result = {
        "schema_version": "0.3.4",
        "generated_utc": now_iso(),
        "limit": limit,
        "material_before": len(material),
        "retained": [item.get("id") for item in retained],
        "downgraded_to_backlog": [item.get("id") for item in overflow],
        "reason": reason,
    }
    out = case_dir(case_name) / "output" / "lead-priority-budget.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def close_lead(
    case_name: str, lead_id: str, status: str, reason: str = "", *,
    evidence_refs: list[str] | None = None, context_id: str | None = None,
    review_item: str | None = None,
) -> None:
    if status not in {"closed", "resolved", "confirmed", "benign", "unresolved", "contextual", "false_positive"}:
        raise ValueError("Invalid lead close status")
    path = case_dir(case_name) / "leads.jsonl"
    current = {item["id"]: item for item in materialize_history(path, "L")}
    if lead_id not in current:
        raise KeyError(f"Lead not found: {lead_id}")
    append_jsonl(path, {
        "event": "close", "id": lead_id, "timestamp_utc": now_iso(),
        "status": status, "reason": reason,
        "closure_basis": {
            "evidence_refs": list(dict.fromkeys(evidence_refs or [])),
            "context_id": context_id,
            "review_item": review_item,
        },
    })


def load_context(case_name: str) -> dict[str, Any]:
    path = case_dir(case_name) / "case_context.json"
    if not path.exists():
        return {"schema_version": "0.3.4", "entries": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data.setdefault("entries", [])
            return data
    except json.JSONDecodeError:
        pass
    return {"schema_version": "0.3.4", "entries": []}


def save_context(case_name: str, data: dict[str, Any]) -> Path:
    path = case_dir(case_name) / "case_context.json"
    data["schema_version"] = "0.3.4"
    data["updated_utc"] = now_iso()
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def add_context(case_name: str, *, context_type: str, value: str, details: str, source: str, confidence: str) -> dict[str, Any]:
    data = load_context(case_name)
    entries = data.setdefault("entries", [])
    for item in entries:
        if item.get("type") == context_type and str(item.get("value", "")).lower() == value.lower():
            item.update({"details": details, "source": source, "confidence": confidence, "updated_utc": now_iso()})
            save_context(case_name, data)
            return item
    cid = f"C-{len(entries) + 1:04d}"
    entry = {"id": cid, "type": context_type, "value": value, "details": details, "source": source, "confidence": confidence, "created_utc": now_iso()}
    entries.append(entry)
    save_context(case_name, data)
    return entry


def context_matches(case_name: str, text: str) -> list[str]:
    hay = text.lower()
    matches: list[str] = []
    for item in load_context(case_name).get("entries", []):
        value = str(item.get("value", "")).strip()
        if value and value.lower() in hay:
            matches.append(item.get("id", value))
    return matches
