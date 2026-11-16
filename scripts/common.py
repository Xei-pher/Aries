from __future__ import annotations

import json
import os
import re
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_PHASE_ORDER = [
    "preflight",
    "evidence_integrity",
    "artifact_discovery",
    "eventlog_baseline",
    "event_triage",
    "artifact_baseline",
    "artifact_triage",
    "memory_baseline",
    "disk_baseline",
    "pivot",
    "targeted_timeline",
    "evidence_assessment",
    "ioc_scan",
    "report",
]
OPTIONAL_PHASES = ["orchestration_review", "disk_timeline"]
ALL_PHASES = DEFAULT_PHASE_ORDER + OPTIONAL_PHASES
# Backwards-compatible name used by older code/tests.
PHASE_ORDER = DEFAULT_PHASE_ORDER
DONE_STATUSES = {"complete", "partial", "skipped"}
TERMINAL_STATUSES = DONE_STATUSES | {"failed", "interrupted", "degraded", "blocked"}
PHASE_STATUSES = {"pending", "running", "waiting", *TERMINAL_STATUSES}
SCHEMA_VERSION = "0.3.4"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def aries_root() -> Path:
    return Path(os.environ.get("ARIES_ROOT", r"C:\Aries"))


def safe_case_name(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise ValueError("Case name may contain only letters, numbers, dot, underscore, and hyphen.")
    return name


def slug_case_name(value: str) -> str:
    value = value.strip().replace(" ", "-")
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-._")
    return safe_case_name(value or "case")


def case_dir(name: str) -> Path:
    return aries_root() / "cases" / safe_case_name(name)


def case_json_path(name: str) -> Path:
    return case_dir(name) / "case.json"


def _redacted_command(command: list[str]) -> list[str]:
    """Keep the command trace useful without recording common CLI secret values."""
    hidden_after = {"--api-key", "--token", "--password", "--secret", "--authorization"}
    rendered: list[str] = []
    hide_next = False
    for raw in command:
        value = str(raw)
        if hide_next:
            rendered.append("<redacted>")
            hide_next = False
            continue
        lowered = value.lower()
        if lowered in hidden_after:
            rendered.append(value)
            hide_next = True
            continue
        if any(lowered.startswith(flag + "=") for flag in hidden_after):
            rendered.append(value.split("=", 1)[0] + "=<redacted>")
            continue
        rendered.append(value)
    return rendered


def append_command_event(
    case_name: str,
    event: str,
    component: str,
    command: list[str],
    *,
    command_id: str | None = None,
    returncode: int | str | None = None,
    duration_seconds: float | None = None,
    error: str | None = None,
) -> str:
    """Append one line to the live command audit and return its correlation ID."""
    command_id = command_id or uuid.uuid4().hex[:12]
    safe_command = _redacted_command(command)
    record = {
        "timestamp_utc": now_iso(),
        "event": event,
        "command_id": command_id,
        "component": component,
        "launcher_pid": os.getpid(),
        "command": safe_command,
        "command_line": subprocess.list2cmdline(safe_command),
        "returncode": returncode,
        "duration_seconds": round(duration_seconds, 3) if duration_seconds is not None else None,
        "error": error,
    }
    path = case_dir(case_name) / "output" / "web" / "command-audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        handle.flush()
    return command_id


def run_traced(case_name: str, component: str, command: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a subprocess while exposing its command and completion live to the web console."""
    command = [str(item) for item in command]
    command_id = append_command_event(case_name, "started", component, command)
    started = time.monotonic()
    try:
        result = subprocess.run(command, **kwargs)
    except subprocess.TimeoutExpired as exc:
        append_command_event(
            case_name, "timeout", component, command, command_id=command_id,
            returncode="timeout", duration_seconds=time.monotonic() - started, error=str(exc),
        )
        raise
    except OSError as exc:
        append_command_event(
            case_name, "failed", component, command, command_id=command_id,
            returncode="launch_error", duration_seconds=time.monotonic() - started, error=str(exc),
        )
        raise
    append_command_event(
        case_name, "finished", component, command, command_id=command_id,
        returncode=result.returncode, duration_seconds=time.monotonic() - started,
    )
    return result


def phase_template(message: str = "") -> dict[str, Any]:
    return {
        "status": "pending",
        "attempts": 0,
        "started_utc": None,
        "finished_utc": None,
        "returncode": None,
        "message": message,
    }


def migrate_phase_state(data: dict[str, Any]) -> None:
    """Migrate older phase names/state without destroying completed work."""
    inv = data.setdefault("investigation", {})
    phases = inv.setdefault("phases", {})

    # v0.2.0 called the automatic EvtxECmd phase eztools_baseline.
    if "eventlog_baseline" not in phases and "eztools_baseline" in phases:
        phases["eventlog_baseline"] = dict(phases["eztools_baseline"])
        phases["eventlog_baseline"]["message"] = (
            phases["eventlog_baseline"].get("message", "") + " [migrated from eztools_baseline]"
        ).strip()

    # v0.3 adds loose-artifact parsing and a report gate. They start pending so
    # upgraded cases can benefit without invalidating completed v0.2.2 work.
    phases.setdefault("artifact_baseline", phase_template("Added by v0.3 evidence-set migration."))
    phases.setdefault("artifact_triage", phase_template("Added by v0.3 evidence-set migration."))
    phases.setdefault("evidence_assessment", phase_template("Added by v0.3 evidence-discipline migration."))

    # v0.3.1 added a human-visible, two-reviewer orchestration checkpoint. If an
    # older case already produced an assessment/report, reset only those derived
    # phases so they cannot silently bypass the new review gate.
    if "orchestration_review" not in phases:
        phases["orchestration_review"] = phase_template("Added by v0.3.1 orchestration migration.")
        for downstream in ("evidence_assessment", "report"):
            if phases.get(downstream, {}).get("status") in DONE_STATUSES:
                phases[downstream] = phase_template("Reset by v0.3.1: orchestration review must run first.")

    # v0.3.2 added delegated-review provenance. A v0.3.1 completed/waiting
    # review cannot be grandfathered in because it may have been written by the
    # lead after a child/provider failure. Preserve its files for audit but
    # require a fresh review round and reassessment.
    if data.get("schema_version") == "0.3.1":
        if phases.get("orchestration_review", {}).get("status") != "pending":
            phases["orchestration_review"] = phase_template("Reset by v0.3.2: provenance-tracked delegated reviews are required.")
        for downstream in ("evidence_assessment", "report"):
            if phases.get(downstream, {}).get("status") in DONE_STATUSES | {"waiting", "degraded", "blocked"}:
                phases[downstream] = phase_template("Reset by v0.3.2: a new provenance-tracked review must run first.")

    # v0.3.3 replaces open-ended reviewer browsing with bounded review packets.
    # Preserve old outputs for audit but require a new cost-bounded review round.
    if data.get("schema_version") == "0.3.2":
        if phases.get("orchestration_review", {}).get("status") != "pending":
            phases["orchestration_review"] = phase_template("Reset by v0.3.3: bounded delegated review packets are required.")
        for downstream in ("evidence_assessment", "report"):
            if phases.get(downstream, {}).get("status") in DONE_STATUSES | {"waiting", "degraded", "blocked"}:
                phases[downstream] = phase_template("Reset by v0.3.3: cost-bounded review must run first.")

    # v0.3.4 removes delegated review from the critical path. Preserve every
    # review artifact for audit, but never leave an upgraded case waiting on an
    # optional second opinion. Re-run only derived gates that were previously
    # blocked by orchestration; completed forensic parsing remains untouched.
    if data.get("schema_version") != "0.3.4":
        review = phases.get("orchestration_review", {})
        if review.get("status") in {"pending", "running", "waiting", "degraded", "blocked", "failed", "interrupted"}:
            phases["orchestration_review"] = {
                **phase_template("Optional second opinion disabled in the default v0.3.4 workflow."),
                "status": "skipped",
                "finished_utc": now_iso(),
            }
        assessment = phases.get("evidence_assessment", {})
        if assessment.get("status") in {"waiting", "degraded", "blocked", "failed", "interrupted"}:
            phases["evidence_assessment"] = phase_template("Reset by v0.3.4: reassess without delegated-review dependency.")
        report = phases.get("report", {})
        if report.get("status") in {"waiting", "degraded", "blocked", "failed", "interrupted"}:
            phases["report"] = phase_template("Reset by v0.3.4: report no longer depends on delegated review.")

    for phase in ALL_PHASES:
        phases.setdefault(phase, phase_template())

    # Preserve old keys for audit, but they are no longer part of the normal coordinator.
    inv["phase_order"] = list(DEFAULT_PHASE_ORDER)
    inv["optional_phases"] = list(OPTIONAL_PHASES)


def load_case(name: str) -> dict[str, Any]:
    path = case_json_path(name)
    if not path.exists():
        raise FileNotFoundError(f"Case does not exist: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    before = json.dumps(data, sort_keys=True)
    # Older web intake registered the upload directory and every primary image
    # inside it, making one uploaded E01 appear as two evidence sources. Remove
    # only container entries that contain no additional loose artifacts.
    evidence = data.get("evidence", {})
    for key, entry in list(evidence.items()):
        if not isinstance(entry, dict) or entry.get("kind") != "artifact_directory" or not entry.get("exclude_paths"):
            continue
        directory = Path(str(entry.get("path") or ""))
        if not directory.is_dir():
            continue
        excluded = {str(Path(value).resolve()).lower() for value in entry.get("exclude_paths", [])}
        try:
            has_loose = any(
                str(candidate.resolve()).lower() not in excluded
                for candidate in directory.rglob("*")
                if candidate.is_file() and not candidate.is_symlink()
            )
        except OSError:
            has_loose = True
        if not has_loose:
            evidence.pop(key, None)
    ensure_phase_state(data)
    data["schema_version"] = SCHEMA_VERSION
    after = json.dumps(data, sort_keys=True)
    if after != before:
        data["updated_utc"] = now_iso()
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


def save_case(name: str, data: dict[str, Any]) -> None:
    path = case_json_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    data["updated_utc"] = now_iso()
    data["schema_version"] = SCHEMA_VERSION
    ensure_phase_state(data)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def evidence_path(case: dict[str, Any], kind: str) -> Path | None:
    entry = case.get("evidence", {}).get(kind)
    if not entry:
        return None
    raw = entry.get("path")
    return Path(raw) if raw else None


def evidence_entries(case: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return registered sources in stable order, including legacy cases."""
    return [(key, value) for key, value in case.get("evidence", {}).items() if isinstance(value, dict)]


def evidence_capabilities(case: dict[str, Any]) -> set[str]:
    """Describe which investigation families the registered evidence can support.

    Artifact directories are intentionally treated as potentially containing
    EVTX and loose artifacts. Discovery will determine what is actually present.
    """
    caps: set[str] = set()
    for key, entry in evidence_entries(case):
        kind = str(entry.get("kind") or key).lower()
        if kind in {"e01", "disk_image"}:
            caps.update({"disk", "artifacts", "eventlogs"})
        elif kind == "memory":
            caps.add("memory")
        elif kind in {"artifact_directory", "artifact", "event_log", "registry_hive", "prefetch", "amcache", "srum", "mft", "usnjrnl", "lnk", "jumplist", "recycle_bin", "browser", "windows_timeline", "archive", "text_log", "unknown"}:
            caps.add("artifacts")
            if kind in {"artifact_directory", "artifact", "event_log", "unknown"}:
                caps.add("eventlogs")
    return caps


def ensure_phase_state(data: dict[str, Any]) -> None:
    migrate_phase_state(data)
    phases = data["investigation"]["phases"]
    caps = evidence_capabilities(data)

    def skip_pending(names: list[str], message: str) -> None:
        for phase in names:
            if phases[phase].get("status") == "pending":
                phases[phase]["status"] = "skipped"
                phases[phase]["message"] = message

    if "artifacts" not in caps:
        skip_pending(["artifact_discovery", "eventlog_baseline", "event_triage", "artifact_baseline", "artifact_triage"], "No disk or artifact evidence registered.")
    if "disk" not in caps:
        skip_pending(["disk_baseline", "disk_timeline"], "No supported disk image registered.")
    if "memory" not in caps and phases["memory_baseline"].get("status") == "pending":
        phases["memory_baseline"]["status"] = "skipped"
        phases["memory_baseline"]["message"] = "No memory evidence registered."


def mark_phase(
    case_name: str,
    phase: str,
    status: str,
    *,
    returncode: int | str | None = None,
    message: str = "",
    command: list[str] | None = None,
) -> dict[str, Any]:
    if phase not in ALL_PHASES:
        raise ValueError(f"Unknown phase: {phase}")
    if status not in PHASE_STATUSES:
        raise ValueError(f"Unknown phase status: {status}")
    data = load_case(case_name)
    state = data["investigation"]["phases"][phase]
    if status == "running":
        state["attempts"] = int(state.get("attempts") or 0) + 1
        state["started_utc"] = now_iso()
        state["finished_utc"] = None
    elif status in {"complete", "partial", "failed", "skipped", "interrupted"}:
        state["finished_utc"] = now_iso()
    state["status"] = status
    state["returncode"] = returncode
    state["message"] = message
    if command is not None:
        state["command"] = command
    save_case(case_name, data)
    return state


def reset_running_phases(case_name: str) -> list[str]:
    data = load_case(case_name)
    changed: list[str] = []
    for phase, state in data["investigation"]["phases"].items():
        if state.get("status") == "running":
            state["status"] = "interrupted"
            state["finished_utc"] = now_iso()
            state["message"] = "Previous run ended before this phase checkpointed completion. Safe to retry."
            changed.append(phase)
    if changed:
        save_case(case_name, data)
    return changed
