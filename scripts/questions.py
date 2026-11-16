from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from common import case_dir, now_iso


SCHEMA_VERSION = "3"
QUESTION_RE = re.compile(r"(?:^|\n)\s*(?:Question\s+\d+\s*[:.)-]?\s*)?([^\n?]{4,}\?)", re.IGNORECASE)
REQUEST_RE = re.compile(
    r"^(?:investigate|analyze|reconstruct|correlate|trace|review|summarize|create|list|provide|identify|determine|find|state|describe|explain|enumerate|report|show|confirm|verify)\b",
    re.IGNORECASE,
)


def questions_path(case_name: str) -> Path:
    return case_dir(case_name) / "analyst-questions.json"


def extract_questions(text: str) -> list[str]:
    values: list[str] = []
    normalized = "\n".join(" ".join(line.split()).strip() for line in (text or "").splitlines())
    # A web brief is usually prose, not a numbered questionnaire. Split prose
    # sentences so imperative requests such as "Investigate ..." and
    # "Create a report and timeline ..." become durable report requirements.
    for raw_line in normalized.splitlines():
        for raw_sentence in re.split(r"(?<=[?.!])\s+", raw_line):
            line = re.sub(r"^(?:[-*]|\d+[.)])\s*", "", raw_sentence).strip()
            match = QUESTION_RE.match("\n" + line)
            request = match.group(1).strip() if match else (line if REQUEST_RE.match(line) else "")
            if request and request not in values:
                values.append(request)

    lower = normalized.lower()
    # Preserve material allegations as explicit investigative requirements even
    # when the analyst states them as context rather than a grammatical request.
    if "suspicious network" in lower and not any("network" in item.lower() for item in values):
        values.append("Identify and explain the suspicious network activity described in the analyst brief.")
    if any(token in lower for token in ("compromised workstation", "suspected compromise", "suspicious activity")) and not values:
        values.append("Determine what material suspicious activity occurred within the analyst-defined scope.")
    return values


def request_kind(value: str) -> str:
    lower = value.lower()
    if any(token in lower for token in ("report", "timeline", "narrative", "executive summary")):
        return "deliverable"
    return "investigative"


def load_questions(case_name: str) -> dict[str, Any]:
    path = questions_path(case_name)
    try:
        value = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (OSError, json.JSONDecodeError):
        value = {}
    if not isinstance(value, dict):
        value = {}
    value.setdefault("schema_version", SCHEMA_VERSION)
    value.setdefault("case", case_name)
    value.setdefault("questions", [])
    return value


def save_questions(case_name: str, data: dict[str, Any]) -> Path:
    path = questions_path(case_name)
    data["schema_version"] = SCHEMA_VERSION
    data["case"] = case_name
    data["updated_utc"] = now_iso()
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def sync_questions(case_name: str, brief: str) -> dict[str, Any]:
    existing = load_questions(case_name)
    by_text = {str(item.get("question")): item for item in existing.get("questions", []) if item.get("question")}
    records: list[dict[str, Any]] = []
    for index, question in enumerate(extract_questions(brief), 1):
        prior = by_text.get(question, {})
        records.append({
            "id": f"Q-{index:03d}",
            "question": question,
            "kind": prior.get("kind", request_kind(question)),
            "status": prior.get("status", "pending"),
            "answer": prior.get("answer", ""),
            "confidence": prior.get("confidence", "unassessed"),
            "evidence_refs": list(prior.get("evidence_refs") or []),
            "bridge_evidence_refs": list(prior.get("bridge_evidence_refs") or []),
            "limitation": prior.get("limitation", ""),
            "answered_utc": prior.get("answered_utc"),
        })
    data = {"schema_version": SCHEMA_VERSION, "case": case_name, "questions": records}
    save_questions(case_name, data)
    return data


def record_answer(
    case_name: str,
    question_id: str,
    *,
    status: str,
    answer: str,
    confidence: str,
    evidence_refs: list[str] | None = None,
    bridge_evidence_refs: list[str] | None = None,
    limitation: str = "",
) -> dict[str, Any]:
    if status not in {"answered", "unresolved"}:
        raise ValueError("Answer status must be answered or unresolved")
    if confidence not in {"high", "medium", "low", "unassessed"}:
        raise ValueError("Answer confidence must be high, medium, low, or unassessed")
    answer = answer.strip()
    limitation = limitation.strip()
    if status == "answered" and not answer:
        raise ValueError("An answered question requires answer text")
    if status == "unresolved" and not (answer or limitation):
        raise ValueError("An unresolved question requires an explanation or limitation")
    root = case_dir(case_name).resolve()
    def validate_refs(values: list[str] | None) -> list[str]:
        refs: list[str] = []
        for raw in values or []:
            relative = str(raw).replace("\\", "/").strip().lstrip("/")
            candidate = (root / relative).resolve()
            try:
                candidate.relative_to(root)
            except ValueError as exc:
                raise ValueError(f"Evidence reference leaves the case directory: {raw}") from exc
            if not candidate.is_file():
                raise ValueError(f"Evidence reference does not exist: {raw}")
            if relative not in refs:
                refs.append(relative)
        return refs

    refs = validate_refs(evidence_refs)
    bridge_refs = validate_refs(bridge_evidence_refs)
    if status == "answered" and not refs:
        raise ValueError("An answered question requires at least one exact case-relative evidence reference")

    data = load_questions(case_name)
    record = next((item for item in data.get("questions", []) if item.get("id") == question_id), None)
    if record is None:
        raise KeyError(f"Analyst question not found: {question_id}")
    record.update({
        "status": status,
        "answer": answer,
        "confidence": confidence,
        "evidence_refs": refs,
        "bridge_evidence_refs": bridge_refs,
        "limitation": limitation,
        "answered_utc": now_iso(),
    })
    save_questions(case_name, data)
    return record


def seed_deterministic_answers(case_name: str) -> list[str]:
    """Answer only requirements that can be resolved without interpretation."""
    data = load_questions(case_name)
    root = case_dir(case_name)
    manifest_path = root / "evidence_manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {}
    except (OSError, json.JSONDecodeError):
        manifest = {}
    answered: list[str] = []
    evidence = manifest.get("evidence") if isinstance(manifest, dict) else {}
    if not isinstance(evidence, dict):
        evidence = {}
    hashes: list[str] = []
    for item in evidence.values():
        if not isinstance(item, dict):
            continue
        segments = item.get("segment_sha256") or []
        if isinstance(segments, list) and segments:
            for segment in segments:
                if isinstance(segment, dict) and segment.get("sha256"):
                    hashes.append(f"{Path(str(segment.get('path') or 'evidence')).name}: SHA256 {segment['sha256']}")
        elif item.get("sha256"):
            hashes.append(f"{Path(str(item.get('path') or 'evidence')).name}: SHA256 {item['sha256']}")
    hashes = list(dict.fromkeys(hashes))
    if not hashes:
        return answered
    for item in data.get("questions", []):
        text = str(item.get("question") or "").lower()
        if item.get("status") != "pending":
            continue
        if "hash" in text and any(token in text for token in ("forensic image", "evidence image", "disk image", "given image")):
            item.update({
                "status": "answered",
                "answer": "; ".join(hashes),
                "confidence": "high",
                "evidence_refs": ["evidence_manifest.json"],
                "limitation": "",
                "answered_utc": now_iso(),
                "answer_source": "deterministic",
            })
            answered.append(str(item.get("id")))
    if answered:
        save_questions(case_name, data)
    return answered

