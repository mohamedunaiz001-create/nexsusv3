"""
Battle API endpoints - Phase 5.

Handles cybersecurity battle sessions with AI Judge scoring.
"""

from datetime import datetime, timezone
import asyncio
import json
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import select, delete, update
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from app.core.exceptions import NotFoundError
from app.core.security import get_current_user_id_optional
from app.db.session import get_db
from app.schemas.common import APIResponse

router = APIRouter(prefix="/battle", tags=["battle"])


# ─── Schemas ──────────────────────────────────────────────────────────────


class BattleSessionCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    mission_type: str = Field(..., min_length=1, max_length=50)
    task_description: str
    model_configs: List[Dict[str, Any]] = Field(..., min_length=2, max_length=8)
    file_ids: List[str] = Field(default_factory=list)


class BattleSessionUpdate(BaseModel):
    name: Optional[str] = None
    task_description: Optional[str] = None
    model_configs: Optional[List[Dict[str, Any]]] = None


class BattleSessionResponse(BaseModel):
    id: str
    name: str
    mission_type: str
    task_description: str
    file_ids: List[str]
    model_configs: List[Dict[str, Any]]
    status: str
    winner_model: Optional[str] = None
    winner_score: Optional[float] = None
    judge_reasoning: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None


class BattleSessionListResponse(BaseModel):
    id: str
    name: str
    mission_type: str
    model_count: int
    status: str
    winner_model: Optional[str] = None
    winner_score: Optional[float] = None
    created_at: datetime
    updated_at: datetime


class BattleMissionResponse(BaseModel):
    id: str
    name: str
    description: str
    mission_type: str
    scoring_weights: Dict[str, float]
    is_active: bool
    created_at: datetime
    updated_at: datetime


class BattleScoreResponse(BaseModel):
    id: str
    battle_id: str
    provider: str
    model: str
    accuracy: Optional[float] = None
    depth: Optional[float] = None
    actionability: Optional[float] = None
    evidence: Optional[float] = None
    speed: Optional[float] = None
    total_score: Optional[float] = None
    ioc_precision: Optional[float] = None
    ioc_recall: Optional[float] = None
    mitre_accuracy: Optional[float] = None
    detection_accuracy: Optional[float] = None
    recommendation_quality: Optional[float] = None
    judge_reasoning: Optional[str] = None


# ─── Helper functions ───────────────────────────────────────────────────


async def _get_battle_or_404(db: AsyncSession, battle_id: str):
    from app.models.battle_session import BattleSession

    result = await db.execute(
        select(BattleSession).where(BattleSession.id == battle_id)
    )
    battle = result.scalar_one_or_none()
    if battle is None:
        raise NotFoundError(f"Battle session {battle_id} not found")
    return battle


async def _get_mission_or_404(db: AsyncSession, mission_type: str):
    from app.models.battle_mission import BattleMission

    result = await db.execute(
        select(BattleMission).where(
            BattleMission.mission_type == mission_type,
            BattleMission.is_active.is_(True),
        )
    )
    mission = result.scalar_one_or_none()
    if mission is None:
        raise NotFoundError(f"Mission {mission_type} not found or inactive")
    return mission


# ─── Battle CRUD ────────────────────────────────────────────────────────


@router.post(
    "",
    response_model=APIResponse[BattleSessionResponse],
    status_code=status.HTTP_201_CREATED,
)
async def create_battle(
    payload: BattleSessionCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Create a new battle session."""
    await _get_mission_or_404(db, payload.mission_type)

    from app.core.model_validation import validate_model_configs

    await validate_model_configs(
        request.app.state.orchestrator.ceo.router, payload.model_configs
    )

    from app.models.battle_session import BattleSession

    battle = BattleSession(
        name=payload.name,
        mission_type=payload.mission_type,
        task_description=payload.task_description,
        model_configs=payload.model_configs,
        file_ids=payload.file_ids,
        status="created",
    )
    db.add(battle)
    await db.commit()
    await db.refresh(battle)
    return APIResponse(data=battle, message="Battle session created")


@router.get("", response_model=APIResponse[List[BattleSessionListResponse]])
async def list_battles(
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
    offset: int = 0,
):
    """List all battle sessions."""
    from app.models.battle_session import BattleSession

    result = await db.execute(
        select(BattleSession)
        .order_by(BattleSession.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    battles = list(result.scalars().all())
    return APIResponse(
        data=[
            BattleSessionListResponse(
                id=b.id,
                name=b.name,
                mission_type=b.mission_type,
                model_count=len(b.model_configs),
                status=b.status,
                winner_model=b.winner_model,
                winner_score=b.winner_score,
                created_at=b.created_at,
                updated_at=b.updated_at,
            )
            for b in battles
        ],
        message=f"{len(battles)} battle(s)",
    )


@router.get("/{battle_id}", response_model=APIResponse[BattleSessionResponse])
async def get_battle(
    battle_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a single battle session with responses and scores."""
    battle = await _get_battle_or_404(db, battle_id)
    return APIResponse(data=battle, message="ok")


@router.patch("/{battle_id}", response_model=APIResponse[BattleSessionResponse])
async def update_battle(
    battle_id: str,
    payload: BattleSessionUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update a battle session."""
    battle = await _get_battle_or_404(db, battle_id)

    update_data = payload.model_dump(exclude_unset=True)
    if update_data.get("model_configs"):
        from app.core.model_validation import validate_model_configs

        await validate_model_configs(
            request.app.state.orchestrator.ceo.router, update_data["model_configs"]
        )
    for field, value in update_data.items():
        setattr(battle, field, value)

    await db.commit()
    await db.refresh(battle)
    return APIResponse(data=battle, message="Battle updated")


@router.delete("/{battle_id}", response_model=APIResponse[dict])
async def delete_battle(
    battle_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a battle session and all related data."""
    from app.models.battle_response import BattleResponse
    from app.models.battle_score import BattleScore

    battle = await _get_battle_or_404(db, battle_id)

    await db.execute(
        delete(BattleResponse).where(BattleResponse.battle_id == battle_id)
    )
    await db.execute(delete(BattleScore).where(BattleScore.battle_id == battle_id))
    await db.delete(battle)
    await db.commit()

    return APIResponse(data={"deleted": battle_id}, message="Battle deleted")


# ─── Battle Execution ───────────────────────────────────────────────────


@router.post("/{battle_id}/run", response_model=APIResponse[dict])
async def run_battle(
    battle_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user_id: str | None = Depends(get_current_user_id_optional),
):
    """Execute the battle session against all configured models."""
    battle = await _get_battle_or_404(db, battle_id)

    if battle.status in ("running", "completed"):
        return APIResponse(
            data={"error": "Battle already running or completed"},
            message="Cannot run battle",
            success=False,
        )

    battle.status = "running"
    await db.commit()

    from app.models.battle_response import BattleResponse

    responses = []
    for config in battle.model_configs:
        resp = BattleResponse(
            battle_id=battle.id,
            provider=config["provider"],
            model=config["model"],
            content="",
            status="streaming",
        )
        db.add(resp)
        responses.append(resp)

    await db.commit()

    from app.core.model_execution import execute_models
    from app.core.evidence import evidence_context

    mission = await _get_mission_or_404(db, battle.mission_type)
    from app.models.battle_session import BattleSession

    asyncio.create_task(
        execute_models(
            run_id=str(battle.id),
            response_model=BattleResponse,
            parent_model=BattleSession,
            parent_id_field="battle_id",
            configs=[
                {"provider": r.provider, "model": r.model, "response_id": str(r.id)}
                for r in responses
            ],
            prompt=f"{mission.system_prompt}\n\nMission: {mission.name}\n\nTask:\n{battle.task_description}"
            + await evidence_context(db, battle.file_ids, current_user_id),
            temperature=0.2,
            max_tokens=4096,
            router=request.app.state.orchestrator.ceo.router,
            agent_type="battle",
        )
    )

    return APIResponse(
        data={
            "battle_id": battle.id,
            "response_ids": [r.id for r in responses],
            "message": "Battle started, connect to SSE for streaming",
        },
        message="Battle running",
    )


@router.post("/{battle_id}/stop", response_model=APIResponse[dict])
async def stop_battle(
    battle_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Stop a running battle."""
    from app.models.battle_response import BattleResponse

    battle = await _get_battle_or_404(db, battle_id)

    await db.execute(
        update(BattleResponse)
        .where(
            BattleResponse.battle_id == battle_id, BattleResponse.status == "streaming"
        )
        .values(status="stopped", updated_at=datetime.now(timezone.utc))
    )

    battle.status = "stopped"
    battle.completed_at = datetime.now(timezone.utc)
    await db.commit()

    return APIResponse(data={"stopped": battle_id}, message="Battle stopped")


@router.get("/{battle_id}/stream")
async def stream_battle(battle_id: str, db: AsyncSession = Depends(get_db)):
    """Live per-model lifecycle events for a running battle."""
    from fastapi.responses import StreamingResponse
    from app.models.battle_response import BattleResponse

    await _get_battle_or_404(db, battle_id)

    async def event_generator():
        from app.core.model_execution import events, replay_snapshot

        snapshot = await replay_snapshot(BattleResponse, "battle_id", battle_id)
        async for event in events(battle_id, replay=snapshot):
            yield f"data: {json.dumps(event, default=str)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ─── Missions ───────────────────────────────────────────────────────────


@router.get("/missions", response_model=APIResponse[List[BattleMissionResponse]])
async def list_missions(
    db: AsyncSession = Depends(get_db),
    active_only: bool = True,
):
    """List all available battle missions."""
    from app.models.battle_mission import BattleMission

    query = select(BattleMission).order_by(BattleMission.name)
    if active_only:
        query = query.where(BattleMission.is_active.is_(True))
    result = await db.execute(query)
    missions = list(result.scalars().all())
    return APIResponse(data=missions, message=f"{len(missions)} mission(s)")


@router.get(
    "/missions/{mission_type}", response_model=APIResponse[BattleMissionResponse]
)
async def get_mission(
    mission_type: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific mission by type."""
    mission = await _get_mission_or_404(db, mission_type)
    return APIResponse(data=mission, message="ok")


# ─── AI Judge & Scoring ─────────────────────────────────────────────────


@router.post("/{battle_id}/judge", response_model=APIResponse[dict])
async def judge_battle(
    battle_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user_id: str | None = Depends(get_current_user_id_optional),
):
    """Run AI Judge to score all battle responses and determine winner."""
    battle = await _get_battle_or_404(db, battle_id)

    if battle.status != "completed":
        return APIResponse(
            data={"error": "Battle must be completed before judging"},
            message="Cannot judge incomplete battle",
            success=False,
        )

    mission = await _get_mission_or_404(db, battle.mission_type)

    from app.models.battle_response import BattleResponse

    resp_result = await db.execute(
        select(BattleResponse).where(
            BattleResponse.battle_id == battle_id, BattleResponse.status == "completed"
        )
    )
    responses = list(resp_result.scalars().all())

    if not responses:
        return APIResponse(
            data={"error": "No completed responses to judge"},
            message="Cannot judge battle with no responses",
            success=False,
        )

    from app.models.battle_score import BattleScore
    from agents.battle.judge import judge_responses

    weights = mission.scoring_weights
    from app.core.evidence import evidence_context

    # Judge model: use the live CEO's configured provider/model — the same
    # "smartest configured brain" every other cross-cutting evaluation in
    # this app defers to, rather than inventing a separate judge-config
    # surface (see docs/PHASE5_BATTLE_JUDGE.md for how to swap this for a
    # dedicated "battle_judge" AgentModelAssignment later).
    orchestrator = request.app.state.orchestrator
    judge_provider = orchestrator.ceo.provider
    judge_model = orchestrator.ceo.model

    judged = await judge_responses(
        router=orchestrator.ceo.router,
        judge_provider=judge_provider,
        judge_model=judge_model,
        objective=f"{mission.system_prompt}\n\nTask:\n{battle.task_description}"
        + await evidence_context(db, battle.file_ids, current_user_id),
        responses=[
            {
                "index": i,
                "provider": resp.provider,
                "model": resp.model,
                "content": resp.content or "",
                "latency_ms": resp.latency_ms,
            }
            for i, resp in enumerate(responses)
        ],
        weights=weights,
        mission_type=battle.mission_type,
    )

    scores = []
    for resp, result in zip(responses, judged):
        score = BattleScore(
            battle_id=battle.id,
            provider=resp.provider,
            model=resp.model,
            accuracy=result["accuracy"],
            depth=result["depth"],
            actionability=result["actionability"],
            evidence=result["evidence"],
            speed=result["speed"],
            total_score=result["total_score"],
            ioc_precision=result["ioc_precision"],
            ioc_recall=result["ioc_recall"],
            mitre_accuracy=result["mitre_accuracy"],
            detection_accuracy=result["detection_accuracy"],
            recommendation_quality=result["recommendation_quality"],
            judge_reasoning=(
                f"[{result['judge_method']}] {result['reasoning']}"
                if result["judge_method"] == "llm"
                else f"[heuristic fallback — judge unavailable: {result['judge_error']}] {result['reasoning']}"
            ),
        )
        db.add(score)
        scores.append(score)

    winner = max(scores, key=lambda s: s.total_score)
    battle.winner_model = f"{winner.provider}:{winner.model}"
    battle.winner_score = winner.total_score
    battle.judge_reasoning = f"Winner: {winner.provider}:{winner.model} with score {winner.total_score:.1f}. Judge reasoning: {winner.judge_reasoning}"
    battle.status = "judged"
    battle.completed_at = datetime.now(timezone.utc)

    await db.commit()

    return APIResponse(
        data={
            "battle_id": battle.id,
            "winner": {
                "model": battle.winner_model,
                "score": battle.winner_score,
            },
            "scores": [
                {
                    "provider": s.provider,
                    "model": s.model,
                    "total_score": s.total_score,
                    "accuracy": s.accuracy,
                    "depth": s.depth,
                    "actionability": s.actionability,
                    "evidence": s.evidence,
                    "speed": s.speed,
                    "ioc_precision": s.ioc_precision,
                    "ioc_recall": s.ioc_recall,
                    "mitre_accuracy": s.mitre_accuracy,
                    "detection_accuracy": s.detection_accuracy,
                    "recommendation_quality": s.recommendation_quality,
                }
                for s in scores
            ],
        },
        message="Battle judged successfully",
    )


@router.get(
    "/{battle_id}/scores", response_model=APIResponse[List[BattleScoreResponse]]
)
async def get_battle_scores(
    battle_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get all scores for a battle."""
    await _get_battle_or_404(db, battle_id)

    from app.models.battle_score import BattleScore

    result = await db.execute(
        select(BattleScore).where(BattleScore.battle_id == battle_id)
    )
    scores = list(result.scalars().all())
    return APIResponse(data=scores, message=f"{len(scores)} score(s)")


# ─── Battle History ─────────────────────────────────────────────────────


@router.get("/history", response_model=APIResponse[List[BattleSessionListResponse]])
async def list_battle_history(
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
    offset: int = 0,
):
    """List battle history."""
    from app.models.battle_session import BattleSession

    result = await db.execute(
        select(BattleSession)
        .where(BattleSession.status.in_(["completed", "judged"]))
        .order_by(BattleSession.completed_at.desc())
        .limit(limit)
        .offset(offset)
    )
    battles = list(result.scalars().all())
    return APIResponse(
        data=[
            BattleSessionListResponse(
                id=b.id,
                name=b.name,
                mission_type=b.mission_type,
                model_count=len(b.model_configs),
                status=b.status,
                winner_model=b.winner_model,
                winner_score=b.winner_score,
                created_at=b.created_at,
                updated_at=b.updated_at,
            )
            for b in battles
        ],
        message=f"{len(battles)} battle(s) in history",
    )


@router.post("/{battle_id}/rerun", response_model=APIResponse[BattleSessionResponse])
async def rerun_battle(
    battle_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Re-run a previous battle with same configuration."""
    battle = await _get_battle_or_404(db, battle_id)

    from app.models.battle_session import BattleSession

    new_battle = BattleSession(
        name=f"{battle.name} (rerun)",
        mission_type=battle.mission_type,
        task_description=battle.task_description,
        model_configs=battle.model_configs,
        file_ids=battle.file_ids,
        status="created",
    )
    db.add(new_battle)
    await db.commit()
    await db.refresh(new_battle)
    return APIResponse(data=new_battle, message="Battle re-created, ready to run")


@router.get("/{battle_id}/export")
async def export_battle(
    battle_id: str,
    format: str = "markdown",
    db: AsyncSession = Depends(get_db),
):
    """Export battle results as Markdown or TXT."""
    from fastapi.responses import Response

    battle = await _get_battle_or_404(db, battle_id)

    from app.models.battle_response import BattleResponse
    from app.models.battle_score import BattleScore

    resp_result = await db.execute(
        select(BattleResponse).where(BattleResponse.battle_id == battle_id)
    )
    responses = list(resp_result.scalars().all())

    score_result = await db.execute(
        select(BattleScore).where(BattleScore.battle_id == battle_id)
    )
    scores = {f"{s.provider}:{s.model}": s for s in score_result.scalars().all()}

    if format == "pdf":
        from app.core.pdf_report import battle_pdf

        return Response(
            content=battle_pdf(battle, responses, list(scores.values())),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{battle.name}.pdf"'
            },
        )

    if format == "json":
        payload = {
            "name": battle.name,
            "mission": battle.mission_type,
            "task": battle.task_description,
            "winner": {"model": battle.winner_model, "score": battle.winner_score},
            "responses": [
                {
                    "provider": r.provider,
                    "model": r.model,
                    "status": r.status,
                    "content": r.content,
                    "error": r.error,
                    "latency_ms": r.latency_ms,
                }
                for r in responses
            ],
            "scores": [
                {
                    "provider": s.provider,
                    "model": s.model,
                    "total_score": s.total_score,
                    "reasoning": s.judge_reasoning,
                }
                for s in scores.values()
            ],
        }
        return Response(
            content=json.dumps(payload, indent=2, default=str),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{battle.name}.json"'
            },
        )

    if format == "markdown":
        content = f"# {battle.name}\n\n"
        content += f"**Mission:** {battle.mission_type}\n\n"
        content += f"**Task:** {battle.task_description}\n\n"
        models_str = ", ".join(
            f'{c["provider"]}:{c["model"]}' for c in battle.model_configs
        )
        content += f"**Models:** {models_str}\n\n"
        content += f"**Winner:** {battle.winner_model or 'Not judged'} "
        if battle.winner_score:
            content += f"({battle.winner_score:.1f})"
        content += "\n\n---\n\n"

        for r in responses:
            content += f"## {r.provider}:{r.model}\n\n"
            content += f"{r.content}\n\n"
            key = f"{r.provider}:{r.model}"
            if key in scores:
                s = scores[key]
                content += f"**Score:** {s.total_score:.1f}/100\n\n"
                content += f"- Accuracy: {s.accuracy:.1f}\n"
                content += f"- Depth: {s.depth:.1f}\n"
                content += f"- Actionability: {s.actionability:.1f}\n"
                content += f"- Evidence: {s.evidence:.1f}\n"
                content += f"- Speed: {s.speed:.1f}\n\n"
            content += "---\n\n"

        return Response(
            content=content,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{battle.name}.md"'},
        )
    else:
        content = f"{battle.name}\n{'=' * len(battle.name)}\n\n"
        content += f"Mission: {battle.mission_type}\n"
        content += f"Task: {battle.task_description}\n\n"
        for r in responses:
            content += f"\n{r.provider}:{r.model}\n{'-' * 40}\n"
            content += f"{r.content}\n\n"

        return Response(
            content=content,
            media_type="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="{battle.name}.txt"'
            },
        )
