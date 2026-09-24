"""
Agents endpoints — Phase 2: backed by the live AgentManager instead of a
placeholder. Lists registered specialist agents with real status, and
lets the frontend enable/disable them or trigger a health check.
"""

from fastapi import APIRouter, Request

from app.core.exceptions import NotFoundError
from app.schemas.common import APIResponse
from app.schemas.orchestration import AgentDetail, AgentSnapshot

router = APIRouter()


@router.get("", response_model=APIResponse[list[AgentSnapshot]])
async def list_agents(request: Request):
    manager = request.app.state.orchestrator.ceo.agent_manager
    snapshot = manager.snapshot()
    return APIResponse(data=snapshot, message=f"{len(snapshot)} agent(s) registered")


@router.get("/{agent_type}", response_model=APIResponse[AgentDetail])
async def agent_detail(agent_type: str, request: Request):
    """Full detail for one specialist's page: overview, current/last task,
    assigned model, status, last structured result, and run history."""
    manager = request.app.state.orchestrator.ceo.agent_manager
    try:
        detail = manager.detail(agent_type)
    except KeyError as exc:
        raise NotFoundError(str(exc)) from exc
    return APIResponse(data=detail, message="ok")


@router.get("/{agent_type}/health")
async def agent_health(agent_type: str, request: Request):
    manager = request.app.state.orchestrator.ceo.agent_manager
    try:
        result = await manager.health_check(agent_type)
    except KeyError as exc:
        raise NotFoundError(str(exc)) from exc
    return APIResponse(data=result, message="ok")


@router.post("/{agent_type}/enable", response_model=APIResponse[None])
async def enable_agent(agent_type: str, request: Request):
    manager = request.app.state.orchestrator.ceo.agent_manager
    try:
        manager.enable(agent_type)
    except KeyError as exc:
        raise NotFoundError(str(exc)) from exc
    return APIResponse(message=f"Agent '{agent_type}' enabled")


@router.post("/{agent_type}/disable", response_model=APIResponse[None])
async def disable_agent(agent_type: str, request: Request):
    manager = request.app.state.orchestrator.ceo.agent_manager
    try:
        manager.disable(agent_type)
    except KeyError as exc:
        raise NotFoundError(str(exc)) from exc
    return APIResponse(message=f"Agent '{agent_type}' disabled")


@router.post("/{agent_type}/test", response_model=APIResponse[dict])
async def test_agent(agent_type: str, request: Request):
    """Test an agent with a simple prompt, returning its assigned model response."""
    manager = request.app.state.orchestrator.ceo.agent_manager
    try:
        agent = manager.get(agent_type)
    except KeyError as exc:
        raise NotFoundError(str(exc)) from exc

    # Get agent's assigned model from assignment if available
    router = request.app.state.orchestrator.ceo.router

    # Use a simple test prompt
    from agents.providers.provider_router import ModelRequest

    test_prompt = (
        f"Test response from {agent_type} agent. Reply with 'OK' if you receive this."
    )

    # Try to get model assignment
    assigned_provider = getattr(agent, "provider", None)
    assigned_model = getattr(agent, "model", None)

    if not assigned_provider or not assigned_model:
        return APIResponse(
            data={
                "success": False,
                "agent_type": agent_type,
                "provider": "",
                "model": "",
                "latency_ms": 0,
                "tokens": {"prompt": None, "completion": None},
                "cost": None,
                "content": "",
                "error": "Agent has no model assigned",
            },
            message="Agent not configured with a model",
        )

    try:
        import time

        start = time.monotonic()

        request_obj = ModelRequest(
            provider=assigned_provider,
            model=assigned_model,
            messages=[{"role": "user", "content": test_prompt}],
            temperature=0.1,
            max_tokens=100,
        )

        response = await router.route(request_obj)
        latency_ms = (time.monotonic() - start) * 1000

        # Calculate cost
        from agents.providers.model_registry import calculate_estimated_cost

        usage = response.usage or {}
        cost = calculate_estimated_cost(
            provider=response.provider,
            model=response.model,
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
        )

        return APIResponse(
            data={
                "success": True,
                "agent_type": agent_type,
                "provider": response.provider,
                "model": response.model,
                "latency_ms": round(latency_ms, 1),
                "tokens": {
                    "prompt": usage.get("prompt_tokens"),
                    "completion": usage.get("completion_tokens"),
                },
                "cost": cost,
                "content": response.content,
                "error": None,
            },
            message="Test completed successfully",
        )
    except Exception as e:
        latency_ms = (time.monotonic() - start) * 1000
        return APIResponse(
            data={
                "success": False,
                "agent_type": agent_type,
                "provider": assigned_provider,
                "model": assigned_model,
                "latency_ms": round(latency_ms, 1),
                "tokens": {"prompt": None, "completion": None},
                "cost": None,
                "content": "",
                "error": str(e),
            },
            message=f"Test failed: {e}",
        )
