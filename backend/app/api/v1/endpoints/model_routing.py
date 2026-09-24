"""
Model routing endpoints — Phase 4.

Lets the frontend assign a provider/model (+ ordered fallback chain) to
each agent individually — the "every agent gets its own model
assignment" milestone from docs/PHASE4.md — and apply it to the *live*
running agent immediately, not just persist it for next restart.

Honesty note: not every registered agent actually calls an LLM. The
Phase 3 cybersecurity specialists (malware analysis, IOC extraction,
etc.) are deterministic static-analysis code with no `.provider`/`.model`
to route — see agents/specialists/malware/agent.py. Assigning them a
model is stored (for when/if they grow an LLM-backed mode) but reported
back as `applied_live: false` rather than silently pretending it changed
anything.
"""

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.db.session import get_db
from app.models.agent_model_assignment import AgentModelAssignment
from app.models.routing_policy import RoutingPolicy
from app.schemas.common import APIResponse
from app.schemas.model_routing import (
    AgentModelAssignmentBase,
    AgentModelAssignmentRead,
    AgentModelAssignmentUpdate,
    RoutingPolicyCreate,
    RoutingPolicyRead,
    RoutingPolicyUpdate,
)

router = APIRouter()


def _parse_chain(fallback_chain: list[str]) -> list[tuple[str, str]]:
    """ "provider:model" strings -> (provider, model) tuples, skipping any
    malformed entries rather than 500ing the whole request over one typo."""
    parsed = []
    for entry in fallback_chain:
        if ":" not in entry:
            continue
        provider, _, model = entry.partition(":")
        if provider and model:
            parsed.append((provider, model))
    return parsed


def _apply_live(
    request: Request, agent_type: str, provider: str, model: str, chain: list[str]
) -> bool:
    """Best-effort live application. Returns whether it actually changed a
    running agent's routing (see module docstring)."""
    orchestrator = request.app.state.orchestrator
    fallback_chain = _parse_chain(chain)

    if agent_type == "ceo":
        orchestrator.ceo.provider = provider
        orchestrator.ceo.model = model
        return True

    manager = orchestrator.ceo.agent_manager
    try:
        agent = manager.get(agent_type)
    except KeyError:
        return False

    apply_fn = getattr(agent, "apply_assignment", None)
    if callable(apply_fn):
        apply_fn(provider, model, fallback_chain)
        return True
    return False


async def _get_or_404(
    db: AsyncSession, assignment_id: uuid.UUID
) -> AgentModelAssignment:
    assignment = await db.get(AgentModelAssignment, assignment_id)
    if assignment is None:
        raise NotFoundError(f"No model assignment with id '{assignment_id}'")
    return assignment


@router.get("/assignments", response_model=APIResponse[list[AgentModelAssignmentRead]])
async def list_assignments(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AgentModelAssignment))
    rows = list(result.scalars().all())
    return APIResponse(
        data=[AgentModelAssignmentRead.model_validate(r) for r in rows],
        message=f"{len(rows)} assignment(s)",
    )


@router.put(
    "/assignments/{agent_type}", response_model=APIResponse[AgentModelAssignmentRead]
)
async def upsert_assignment(
    agent_type: str,
    payload: AgentModelAssignmentBase,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Create or replace the assignment for one agent_type (idempotent —
    this is what the model-routing UI's drag/drop or dropdown calls)."""
    result = await db.execute(
        select(AgentModelAssignment).where(
            AgentModelAssignment.agent_type == agent_type
        )
    )
    existing = result.scalar_one_or_none()

    if existing is None:
        existing = AgentModelAssignment(agent_type=agent_type)
        db.add(existing)

    existing.provider = payload.provider
    existing.model = payload.model
    existing.fallback_chain = payload.fallback_chain
    existing.priority = payload.priority
    await db.commit()
    await db.refresh(existing)

    applied_live = _apply_live(
        request, agent_type, payload.provider, payload.model, payload.fallback_chain
    )

    return APIResponse(
        data=AgentModelAssignmentRead.model_validate(existing),
        message=(
            "Assignment applied live"
            if applied_live
            else "Assignment saved (not LLM-routed live)"
        ),
    )


@router.patch(
    "/assignments/{assignment_id}", response_model=APIResponse[AgentModelAssignmentRead]
)
async def update_assignment(
    assignment_id: uuid.UUID,
    payload: AgentModelAssignmentUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    assignment = await _get_or_404(db, assignment_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(assignment, field, value)
    await db.commit()
    await db.refresh(assignment)

    applied_live = _apply_live(
        request,
        assignment.agent_type,
        assignment.provider,
        assignment.model,
        assignment.fallback_chain,
    )

    return APIResponse(
        data=AgentModelAssignmentRead.model_validate(assignment),
        message=(
            "Assignment applied live"
            if applied_live
            else "Assignment saved (not LLM-routed live)"
        ),
    )


@router.delete("/assignments/{assignment_id}", response_model=APIResponse[None])
async def delete_assignment(
    assignment_id: uuid.UUID, db: AsyncSession = Depends(get_db)
):
    assignment = await _get_or_404(db, assignment_id)
    await db.delete(assignment)
    await db.commit()
    return APIResponse(message="Assignment deleted")


# --- Routing policies (named, reusable rule sets) ------------------------------


@router.get("/policies", response_model=APIResponse[list[RoutingPolicyRead]])
async def list_policies(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RoutingPolicy))
    rows = list(result.scalars().all())
    return APIResponse(
        data=[RoutingPolicyRead.model_validate(r) for r in rows],
        message=f"{len(rows)} polic{'y' if len(rows) == 1 else 'ies'}",
    )


@router.post("/policies", response_model=APIResponse[RoutingPolicyRead])
async def create_policy(
    payload: RoutingPolicyCreate, db: AsyncSession = Depends(get_db)
):
    policy = RoutingPolicy(**payload.model_dump())
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return APIResponse(
        data=RoutingPolicyRead.model_validate(policy), message="Policy created"
    )


@router.patch("/policies/{policy_id}", response_model=APIResponse[RoutingPolicyRead])
async def update_policy(
    policy_id: uuid.UUID,
    payload: RoutingPolicyUpdate,
    db: AsyncSession = Depends(get_db),
):
    policy = await db.get(RoutingPolicy, policy_id)
    if policy is None:
        raise NotFoundError(f"No routing policy with id '{policy_id}'")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(policy, field, value)
    await db.commit()
    await db.refresh(policy)
    return APIResponse(
        data=RoutingPolicyRead.model_validate(policy), message="Policy updated"
    )


@router.delete("/policies/{policy_id}", response_model=APIResponse[None])
async def delete_policy(policy_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    policy = await db.get(RoutingPolicy, policy_id)
    if policy is None:
        raise NotFoundError(f"No routing policy with id '{policy_id}'")
    await db.delete(policy)
    await db.commit()
    return APIResponse(message="Policy deleted")
