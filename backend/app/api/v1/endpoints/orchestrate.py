"""
Orchestration endpoints — the CEO's front door.

POST /orchestrate            submit an objective (+ optional file upload),
                              run the full plan -> delegate -> execute ->
                              verify -> synthesize pipeline, return the
                              final run. The uploaded file (if any) becomes
                              context["artifact"] for every specialist —
                              see agents/orchestration/pipeline.py.
GET  /orchestrate/{run_id}   check status / result of a run
GET  /orchestrate            list recent runs
GET  /orchestrate/events     Server-Sent Events stream of live orchestration
                              events, for the dashboard's Live Activity feed
"""

import asyncio
import json

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import StreamingResponse

from app.core.config import settings
from app.core.exceptions import AppException, NotFoundError
from app.schemas.common import APIResponse
from app.schemas.orchestration import RunRead, TaskRead

router = APIRouter()

# Files that are safe to also decode as UTF-8 text (source code, logs) so
# the Code Review / IOC Extraction agents can read them as text rather
# than raw bytes. Anything else (exe/dll/pcap/zip/...) stays binary-only.
_TEXT_DECODABLE_EXTENSIONS = (
    ".py",
    ".java",
    ".js",
    ".ts",
    ".go",
    ".rs",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".txt",
    ".log",
    ".md",
    ".json",
    ".yml",
    ".yaml",
)


def _run_to_schema(run) -> RunRead:
    tasks = []
    if run.plan:
        for t in run.plan.tasks:
            tasks.append(
                TaskRead(
                    id=t.id,
                    description=t.description,
                    assigned_agent=t.assigned_agent,
                    status=t.status,
                    attempts=t.attempts,
                    error=t.error,
                    result=t.result,
                )
            )
    return RunRead(
        id=run.id,
        objective=run.objective,
        status=run.status,
        started_at=run.started_at,
        finished_at=run.finished_at,
        final_report=run.final_report,
        error=run.error,
        tasks=tasks,
    )


@router.post("", response_model=APIResponse[RunRead])
async def submit_objective(
    request: Request,
    objective: str = Form(...),
    case_id: str | None = Form(None),
    file: UploadFile | None = File(None),
):
    orchestrator = request.app.state.orchestrator
    objective = objective.strip()
    if not objective:
        raise AppException(
            "objective is required", status_code=422, errors=["objective is required"]
        )

    artifact = None
    if file is not None and file.filename:
        content = await file.read()
        if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
            raise AppException(
                f"File exceeds MAX_UPLOAD_SIZE_MB ({settings.MAX_UPLOAD_SIZE_MB} MB)",
                status_code=413,
            )
        artifact = {"filename": file.filename, "content_bytes": content}
        if file.filename.lower().endswith(_TEXT_DECODABLE_EXTENSIONS):
            artifact["content_text"] = content.decode("utf-8", errors="ignore")

    run = await orchestrator.run_objective(
        objective, artifact=artifact, case_id=case_id
    )
    return APIResponse(
        data=_run_to_schema(run), message=f"Run finished with status '{run.status}'"
    )


@router.get("/events")
async def stream_events(request: Request):
    orchestrator = request.app.state.orchestrator
    queue = orchestrator.events.subscribe()

    async def event_generator():
        try:
            for event in orchestrator.events.recent(20):
                yield f"event: {event.type}\ndata: {json.dumps({**event.data, 'timestamp': event.timestamp})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                yield f"event: {event.type}\ndata: {json.dumps({**event.data, 'timestamp': event.timestamp})}\n\n"
        finally:
            orchestrator.events.unsubscribe(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("", response_model=APIResponse[list[RunRead]])
async def list_runs(request: Request):
    orchestrator = request.app.state.orchestrator
    runs = orchestrator.list_runs()
    return APIResponse(
        data=[_run_to_schema(r) for r in runs], message=f"{len(runs)} run(s)"
    )


@router.get("/{run_id}", response_model=APIResponse[RunRead])
async def get_run(run_id: str, request: Request):
    orchestrator = request.app.state.orchestrator
    run = orchestrator.get_run(run_id)
    if run is None:
        raise NotFoundError(f"No run with id '{run_id}'")
    return APIResponse(data=_run_to_schema(run), message="ok")
