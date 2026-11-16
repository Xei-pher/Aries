from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import unquote

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from service import (
    ARIES_ROOT,
    activity_snapshot,
    ask_assistant,
    build_review_bundle,
    build_diagnostic_bundle,
    case_overview,
    case_root,
    create_draft_case,
    delete_case,
    list_cases,
    load_assistant_history,
    load_web_state,
    model_status,
    record_uploaded_file,
    register_case,
    report_text,
    save_web_state,
    start_investigation,
    stop_investigation,
    timeline_rows,
    upload_target,
    validate_case_name,
)


STATIC = Path(__file__).resolve().parent / "static"
MAX_UPLOAD_BYTES = int(float(__import__("os").environ.get("ARIES_WEB_MAX_UPLOAD_GB", "500")) * 1024**3)

app = FastAPI(title="Aries Forensics Console", version="0.5.0-dev", docs_url="/api/docs", redoc_url=None)


class CaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=2000)


class CaseRegister(BaseModel):
    description: str = Field(default="", max_length=2000)


class InvestigationStart(BaseModel):
    mode: str = "quick"
    instructions: str = Field(default="", max_length=12000)


class AssistantQuestion(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


class CaseDelete(BaseModel):
    confirmation: str = Field(min_length=1, max_length=80)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": "0.5.0-dev", "root": str(ARIES_ROOT), "ai": model_status()}


@app.get("/api/model")
def active_model() -> dict:
    return model_status()


@app.get("/api/cases")
def cases() -> dict:
    return {"cases": list_cases()}


@app.post("/api/cases", status_code=201)
def create_case(payload: CaseCreate) -> dict:
    try:
        return create_draft_case(payload.name, payload.description)
    except (ValueError, FileExistsError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/cases/{name}")
def get_case(name: str) -> dict:
    try:
        return case_overview(name)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.delete("/api/cases/{name}")
def remove_case(name: str, payload: CaseDelete) -> dict:
    try:
        delete_case(name, payload.confirmation)
        return {"deleted": True, "case": name}
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/cases/{name}/activity")
def case_activity(name: str) -> dict:
    try:
        return activity_snapshot(name)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/cases/{name}/artifacts", status_code=201)
async def upload_artifact(
    name: str,
    request: Request,
) -> dict:
    encoded_filename = request.headers.get("x-aries-filename", "")
    encoded_relative = request.headers.get("x-aries-relative-path", "")
    if not encoded_filename:
        raise HTTPException(status_code=400, detail="X-Aries-Filename header is required")
    filename = unquote(encoded_filename)
    relative_path = unquote(encoded_relative) if encoded_relative else filename
    expected_size_raw = request.headers.get("x-aries-size", "")
    try:
        expected_size = int(expected_size_raw) if expected_size_raw else None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid X-Aries-Size header") from exc
    if expected_size is not None and (expected_size < 0 or expected_size > MAX_UPLOAD_BYTES):
        raise HTTPException(status_code=413, detail="Artifact exceeds configured upload limit")
    try:
        name = validate_case_name(name)
        if not (case_root(name) / "web-state.json").is_file() and not (case_root(name) / "case.json").is_file():
            raise FileNotFoundError("Create the case before uploading artifacts")
        target = upload_target(name, filename or "artifact.bin", relative_path)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if target.exists():
        raise HTTPException(status_code=409, detail=f"Artifact already exists: {target.name}")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".uploading")
    if temporary.exists():
        raise HTTPException(status_code=409, detail=f"An incomplete upload already exists for {target.name}. Remove it or retry after restarting Aries.")
    digest = hashlib.sha256()
    size = 0
    try:
        with temporary.open("xb") as handle:
            async for chunk in request.stream():
                if not chunk:
                    continue
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Artifact exceeds configured upload limit")
                digest.update(chunk)
                handle.write(chunk)
        if expected_size is not None and size != expected_size:
            raise HTTPException(status_code=400, detail=f"Upload ended early: received {size} of {expected_size} bytes")
        temporary.replace(target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return record_uploaded_file(name, target, size, digest.hexdigest())


@app.post("/api/cases/{name}/register")
async def finalize_case(name: str, payload: CaseRegister) -> dict:
    try:
        case = await register_case(name, payload.description)
        return {"case": case, "web_state": load_web_state(name)}
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/cases/{name}/investigate", status_code=202)
def investigate(name: str, payload: InvestigationStart) -> dict:
    try:
        return start_investigation(name, payload.mode, payload.instructions)
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/cases/{name}/stop")
def stop_case_investigation(name: str) -> dict:
    try:
        return stop_investigation(name)
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/cases/{name}/timeline")
def timeline(name: str) -> dict:
    try:
        return {"rows": timeline_rows(name)}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/cases/{name}/report", response_class=PlainTextResponse)
def report(name: str) -> str:
    try:
        return report_text(name)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/cases/{name}/report/download")
def download_report(name: str) -> FileResponse:
    path = case_root(name) / "report" / "report.md"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Report is not ready")
    return FileResponse(path, filename=f"Aries-{name}-report.md", media_type="text/markdown")


@app.get("/api/cases/{name}/bundle")
def download_bundle(name: str) -> FileResponse:
    try:
        path = build_review_bundle(name)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return FileResponse(path, filename=path.name, media_type="application/zip")


@app.get("/api/cases/{name}/diagnostics")
def download_diagnostics(name: str) -> FileResponse:
    try:
        path = build_diagnostic_bundle(name)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return FileResponse(path, filename=path.name, media_type="application/zip")


@app.post("/api/cases/{name}/assistant")
async def assistant(name: str, payload: AssistantQuestion) -> dict:
    try:
        return await ask_assistant(name, payload.question)
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/cases/{name}/assistant/history")
def assistant_history(name: str) -> dict:
    try:
        overview = case_overview(name)
        return {"messages": load_assistant_history(name), "datalake": overview.get("datalake", {})}
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


app.mount("/assets", StaticFiles(directory=STATIC), name="assets")


@app.get("/{path:path}", response_class=HTMLResponse)
def frontend(path: str = "") -> HTMLResponse:
    return HTMLResponse((STATIC / "index.html").read_text(encoding="utf-8"))

