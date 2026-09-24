"""
Provider CRUD endpoints — Phase 4: Full provider management including
add, edit, delete, enable, disable, test connection, discover models,
rotate credentials, and health monitoring.
"""

from datetime import datetime, timezone
from typing import Optional, List, Dict
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status, Query
from sqlalchemy import select, delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError, ConflictError
from app.core.logging import get_logger
from app.db.session import get_db
from app.models.provider import Provider
from app.models.provider_credential import ProviderCredential
from app.models.provider_health import ProviderHealth
from app.schemas.common import APIResponse
from app.schemas.provider import (
    ProviderCreate,
    ProviderUpdate,
    ProviderResponse,
    ProviderWithHealth,
    ProviderCredentialCreate,
    ProviderCredentialUpdate,
    ProviderCredentialResponse,
    ProviderCredentialWithSecretRef,
    ModelInfoResponse,
    ProviderModelsResponse,
    TestConnectionRequest,
    TestConnectionResponse,
    RotateCredentialsRequest,
    RotateCredentialsResponse,
    BulkEnableDisableRequest,
    BulkEnableDisableResponse,
)

router = APIRouter()
logger = get_logger(__name__)


# ─── Helper functions ──────────────────────────────────────────────────


async def _get_provider_or_404(db: AsyncSession, provider_id: UUID) -> Provider:
    """Get provider by ID or raise 404."""
    result = await db.execute(select(Provider).where(Provider.id == provider_id))
    provider = result.scalar_one_or_none()
    if provider is None:
        raise NotFoundError(f"Provider with id {provider_id} not found")
    return provider


async def _get_provider_by_name_or_404(db: AsyncSession, name: str) -> Provider:
    """Get provider by name or raise 404."""
    result = await db.execute(select(Provider).where(Provider.name == name))
    provider = result.scalar_one_or_none()
    if provider is None:
        raise NotFoundError(f"Provider '{name}' not found")
    return provider


async def _get_credential_or_404(
    db: AsyncSession, provider_name: str, credential_id: UUID
) -> ProviderCredential:
    """Get credential by ID for a specific provider or raise 404."""
    result = await db.execute(
        select(ProviderCredential).where(
            ProviderCredential.id == credential_id,
            ProviderCredential.provider == provider_name,
        )
    )
    credential = result.scalar_one_or_none()
    if credential is None:
        raise NotFoundError(
            f"Credential {credential_id} not found for provider '{provider_name}'"
        )
    return credential


async def _probe_and_store(
    provider_name: str, request: Request, db: AsyncSession
) -> dict:
    """Probe a provider and store health result."""
    router_ = request.app.state.orchestrator.ceo.router
    client = router_.get_client(provider_name)
    if client is None:
        raise NotFoundError(f"No provider client registered for '{provider_name}'")

    import time

    start = time.monotonic()
    result = await client.test_connection()
    latency_ms = (time.monotonic() - start) * 1000

    row_result = await db.execute(
        select(ProviderHealth).where(ProviderHealth.provider == provider_name)
    )
    health = row_result.scalar_one_or_none()
    if health is None:
        health = ProviderHealth(provider=provider_name)
        db.add(health)

    health.status = "ok" if result.get("ok") else "error"
    health.latency_ms = latency_ms
    health.last_error = None if result.get("ok") else result.get("detail")
    health.last_checked_at = datetime.now(timezone.utc)
    await db.commit()

    return {
        "provider": provider_name,
        "ok": result.get("ok", False),
        "detail": result.get("detail"),
        "latency_ms": round(latency_ms, 1),
    }


@router.get("/health", response_model=APIResponse[List[dict]])
async def all_providers_health(request: Request, db: AsyncSession = Depends(get_db)):
    """Probe every registered provider and return current health."""
    router_ = request.app.state.orchestrator.ceo.router
    results = []
    for name in router_.available_providers():
        results.append(await _probe_and_store(name, request, db))
    return APIResponse(data=results, message=f"checked {len(results)} provider(s)")


@router.get("/health/cached", response_model=APIResponse[List[dict]])
async def cached_providers_health(db: AsyncSession = Depends(get_db)):
    """Last-known health without re-probing."""
    result = await db.execute(select(ProviderHealth))
    rows = list(result.scalars().all())
    return APIResponse(
        data=[
            {
                "provider": r.provider,
                "status": r.status,
                "latency_ms": r.latency_ms,
                "last_error": r.last_error,
                "last_checked_at": (
                    r.last_checked_at.isoformat() if r.last_checked_at else None
                ),
            }
            for r in rows
        ],
        message=f"{len(rows)} provider(s) with recorded health",
    )


# ─── Provider CRUD ─────────────────────────────────────────────────────


@router.get("", response_model=APIResponse[List[ProviderWithHealth]])
async def list_providers(
    request: Request,
    db: AsyncSession = Depends(get_db),
    include_health: bool = Query(True, description="Include cached health status"),
    enabled_only: bool = Query(False, description="Filter to enabled providers only"),
):
    """
    List all registered providers with optional health status.

    Shows which providers are registered on the ProviderRouter, which are
    configured in the database, and their live reachability status.
    """
    router_ = request.app.state.orchestrator.ceo.router
    configured_names = set(await router_.configured_providers())
    available_names = set(router_.available_providers())

    # Get DB providers
    query = select(Provider)
    if enabled_only:
        query = query.where(Provider.is_enabled.is_(True))
    result = await db.execute(query.order_by(Provider.name))
    db_providers = list(result.scalars().all())

    # Get health data if requested
    health_map: Dict[str, ProviderHealth] = {}
    if include_health:
        health_result = await db.execute(select(ProviderHealth))
        health_map = {h.provider: h for h in health_result.scalars().all()}

    data = []
    for p in db_providers:
        configured = p.name in configured_names
        health = health_map.get(p.name)

        data.append(
            ProviderWithHealth(
                id=p.id,
                name=p.name,
                provider_type=p.provider_type,
                base_url=p.base_url,
                is_enabled=p.is_enabled,
                created_at=p.created_at,
                updated_at=p.updated_at,
                health_status=health.status if health else "unknown",
                health_latency_ms=health.latency_ms if health else None,
                health_last_checked=health.last_checked_at if health else None,
                health_last_error=health.last_error if health else None,
                configured=configured,
            )
        )

    # Also include providers that are registered in router but not in DB
    for name in available_names:
        if not any(d.name == name for d in data):
            configured = name in configured_names
            health = health_map.get(name)
            data.append(
                ProviderWithHealth(
                    id=UUID("00000000-0000-0000-0000-000000000000"),  # placeholder
                    name=name,
                    provider_type="cloud" if name != "ollama" else "local",
                    base_url=None,
                    is_enabled=True,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                    health_status=health.status if health else "unknown",
                    health_latency_ms=health.latency_ms if health else None,
                    health_last_checked=health.last_checked_at if health else None,
                    health_last_error=health.last_error if health else None,
                    configured=configured,
                )
            )

    return APIResponse(data=data, message=f"{len(data)} provider(s) registered")


@router.post(
    "",
    response_model=APIResponse[ProviderResponse],
    status_code=status.HTTP_201_CREATED,
)
async def create_provider(
    payload: ProviderCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new provider entry."""
    # Check if name already exists
    existing = await db.execute(select(Provider).where(Provider.name == payload.name))
    if existing.scalar_one_or_none():
        raise ConflictError(f"Provider with name '{payload.name}' already exists")

    provider = Provider(
        name=payload.name,
        provider_type=payload.provider_type,
        base_url=str(payload.base_url) if payload.base_url else None,
        is_enabled=payload.is_enabled,
    )
    db.add(provider)
    await db.commit()
    await db.refresh(provider)

    return APIResponse(data=provider, message=f"Provider '{payload.name}' created")


@router.get("/{provider_id}", response_model=APIResponse[ProviderWithHealth])
async def get_provider(
    provider_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get a single provider by ID with health status."""
    provider = await _get_provider_or_404(db, provider_id)

    # Get health
    health_result = await db.execute(
        select(ProviderHealth).where(ProviderHealth.provider == provider.name)
    )
    health = health_result.scalar_one_or_none()

    router_ = request.app.state.orchestrator.ceo.router
    configured_names = set(await router_.configured_providers())
    configured = provider.name in configured_names

    return APIResponse(
        data=ProviderWithHealth(
            id=provider.id,
            name=provider.name,
            provider_type=provider.provider_type,
            base_url=provider.base_url,
            is_enabled=provider.is_enabled,
            created_at=provider.created_at,
            updated_at=provider.updated_at,
            health_status=health.status if health else "unknown",
            health_latency_ms=health.latency_ms if health else None,
            health_last_checked=health.last_checked_at if health else None,
            health_last_error=health.last_error if health else None,
            configured=configured,
        ),
        message="ok",
    )


@router.patch("/{provider_id}", response_model=APIResponse[ProviderResponse])
async def update_provider(
    provider_id: UUID,
    payload: ProviderUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update a provider's configuration."""
    provider = await _get_provider_or_404(db, provider_id)

    # Check name uniqueness if being changed
    if payload.name is not None and payload.name != provider.name:
        existing = await db.execute(
            select(Provider).where(Provider.name == payload.name)
        )
        if existing.scalar_one_or_none():
            raise ConflictError(f"Provider with name '{payload.name}' already exists")

    update_data = payload.model_dump(exclude_unset=True)
    if "base_url" in update_data and update_data["base_url"] is not None:
        update_data["base_url"] = str(update_data["base_url"])

    for field, value in update_data.items():
        setattr(provider, field, value)

    await db.commit()
    await db.refresh(provider)

    return APIResponse(data=provider, message=f"Provider '{provider.name}' updated")


@router.delete("/{provider_id}", response_model=APIResponse[dict])
async def delete_provider(
    provider_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete a provider and its credentials."""
    provider = await _get_provider_or_404(db, provider_id)
    name = provider.name

    # Delete credentials first
    await db.execute(
        delete(ProviderCredential).where(ProviderCredential.provider == name)
    )
    # Delete health record
    await db.execute(delete(ProviderHealth).where(ProviderHealth.provider == name))
    # Delete provider
    await db.delete(provider)
    await db.commit()

    return APIResponse(
        data={"deleted": name},
        message=f"Provider '{name}' and associated credentials deleted",
    )


@router.post("/{provider_id}/enable", response_model=APIResponse[ProviderResponse])
async def enable_provider(
    provider_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Enable a provider."""
    provider = await _get_provider_or_404(db, provider_id)
    if provider.is_enabled:
        return APIResponse(
            data=provider, message=f"Provider '{provider.name}' already enabled"
        )

    provider.is_enabled = True
    await db.commit()
    await db.refresh(provider)

    return APIResponse(data=provider, message=f"Provider '{provider.name}' enabled")


@router.post("/{provider_id}/disable", response_model=APIResponse[ProviderResponse])
async def disable_provider(
    provider_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Disable a provider."""
    provider = await _get_provider_or_404(db, provider_id)
    if not provider.is_enabled:
        return APIResponse(
            data=provider, message=f"Provider '{provider.name}' already disabled"
        )

    provider.is_enabled = False
    await db.commit()
    await db.refresh(provider)

    return APIResponse(data=provider, message=f"Provider '{provider.name}' disabled")


# ─── Bulk operations ───────────────────────────────────────────────────


@router.post(
    "/bulk/enable-disable", response_model=APIResponse[BulkEnableDisableResponse]
)
async def bulk_enable_disable(
    payload: BulkEnableDisableRequest,
    db: AsyncSession = Depends(get_db),
):
    """Enable or disable multiple providers at once."""
    updated = []
    failed = []

    for name in payload.provider_names:
        result = await db.execute(select(Provider).where(Provider.name == name))
        provider = result.scalar_one_or_none()
        if provider is None:
            failed.append({"provider": name, "reason": "not found"})
            continue

        provider.is_enabled = payload.is_enabled
        updated.append(name)

    await db.commit()

    return APIResponse(
        data=BulkEnableDisableResponse(
            success=len(failed) == 0,
            message=f"Updated {len(updated)} provider(s), {len(failed)} failed",
            updated=updated,
            failed=failed,
        ),
        message="ok",
    )


# ─── Provider Credentials ─────────────────────────────────────────────


@router.get(
    "/{provider_name}/credentials",
    response_model=APIResponse[List[ProviderCredentialResponse]],
)
async def list_credentials(
    provider_name: str,
    db: AsyncSession = Depends(get_db),
    active_only: bool = Query(True, description="Only return active credentials"),
):
    """List all credentials for a provider."""
    # Verify provider exists (either in DB or router)
    await _get_provider_by_name_or_404(db, provider_name)

    query = select(ProviderCredential).where(
        ProviderCredential.provider == provider_name
    )
    if active_only:
        query = query.where(ProviderCredential.is_active.is_(True))
    query = query.order_by(ProviderCredential.created_at.desc())

    result = await db.execute(query)
    credentials = list(result.scalars().all())

    return APIResponse(
        data=credentials,
        message=f"{len(credentials)} credential(s) for '{provider_name}'",
    )


@router.post(
    "/{provider_name}/credentials",
    response_model=APIResponse[ProviderCredentialWithSecretRef],
    status_code=status.HTTP_201_CREATED,
)
async def create_credential(
    provider_name: str,
    payload: ProviderCredentialCreate,
    db: AsyncSession = Depends(get_db),
):
    """Add a new credential for a provider."""
    # Verify provider exists
    await _get_provider_by_name_or_404(db, provider_name)

    credential = ProviderCredential(
        provider=provider_name,
        label=payload.label,
        secret_ref=payload.secret_ref,
        masked_preview=payload.masked_preview,
        is_active=payload.is_active,
    )
    db.add(credential)
    await db.commit()
    await db.refresh(credential)

    return APIResponse(
        data=credential,
        message=f"Credential '{payload.label}' added for '{provider_name}'",
    )


@router.patch(
    "/{provider_name}/credentials/{credential_id}",
    response_model=APIResponse[ProviderCredentialWithSecretRef],
)
async def update_credential(
    provider_name: str,
    credential_id: UUID,
    payload: ProviderCredentialUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update a credential."""
    credential = await _get_credential_or_404(db, provider_name, credential_id)

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(credential, field, value)

    await db.commit()
    await db.refresh(credential)

    return APIResponse(
        data=credential, message=f"Credential '{credential.label}' updated"
    )


@router.delete(
    "/{provider_name}/credentials/{credential_id}", response_model=APIResponse[dict]
)
async def delete_credential(
    provider_name: str,
    credential_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete a credential."""
    credential = await _get_credential_or_404(db, provider_name, credential_id)
    label = credential.label

    await db.delete(credential)
    await db.commit()

    return APIResponse(data={"deleted": label}, message=f"Credential '{label}' deleted")


@router.post(
    "/{provider_name}/credentials/{credential_id}/activate",
    response_model=APIResponse[ProviderCredentialWithSecretRef],
)
async def activate_credential(
    provider_name: str,
    credential_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Activate a credential (deactivates others for this provider)."""
    # Deactivate all credentials for this provider
    await db.execute(
        update(ProviderCredential)
        .where(ProviderCredential.provider == provider_name)
        .values(is_active=False)
    )

    # Activate the selected one
    credential = await _get_credential_or_404(db, provider_name, credential_id)
    credential.is_active = True
    await db.commit()
    await db.refresh(credential)

    return APIResponse(
        data=credential, message=f"Credential '{credential.label}' activated"
    )


@router.post(
    "/{provider_name}/credentials/{credential_id}/deactivate",
    response_model=APIResponse[ProviderCredentialWithSecretRef],
)
async def deactivate_credential(
    provider_name: str,
    credential_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Deactivate a credential."""
    credential = await _get_credential_or_404(db, provider_name, credential_id)
    credential.is_active = False
    await db.commit()
    await db.refresh(credential)

    return APIResponse(
        data=credential, message=f"Credential '{credential.label}' deactivated"
    )


# ─── Credential Rotation ──────────────────────────────────────────────


@router.post(
    "/{provider_name}/credentials/{credential_id}/rotate",
    response_model=APIResponse[RotateCredentialsResponse],
)
async def rotate_credential(
    provider_name: str,
    credential_id: UUID,
    payload: RotateCredentialsRequest,
    db: AsyncSession = Depends(get_db),
    request: Request = None,
):
    """Rotate credentials - update secret reference and optionally test connection."""
    credential = await _get_credential_or_404(db, provider_name, credential_id)

    # Update the credential
    credential.secret_ref = payload.secret_ref
    if payload.masked_preview is not None:
        credential.masked_preview = payload.masked_preview
    else:
        # Try to derive masked preview from new secret_ref
        if payload.secret_ref.startswith("env:"):
            # Can't mask env var value without reading it
            credential.masked_preview = "... (env var)"
        elif payload.secret_ref.startswith("vault:"):
            credential.masked_preview = "... (vault)"
        else:
            credential.masked_preview = "... (updated)"

    await db.commit()
    await db.refresh(credential)

    # Optionally test the new connection post-rotation, purely for
    # diagnostics — failures here don't roll back the rotation, and the
    # result isn't (yet) surfaced on the response, so at least log it
    # rather than silently computing and discarding it.
    if request:
        try:
            test_result = await _probe_and_store(provider_name, request, db)
            logger.info(
                "post_rotation_probe", provider=provider_name, result=test_result
            )
        except Exception as exc:
            logger.warning(
                "post_rotation_probe_failed", provider=provider_name, error=str(exc)
            )

    return APIResponse(
        data=RotateCredentialsResponse(
            success=True,
            message=f"Credential rotated for '{provider_name}'",
            credential_id=credential.id,
            new_masked_preview=credential.masked_preview,
        ),
        message="ok",
    )


# ─── Connection Testing ───────────────────────────────────────────────


@router.post(
    "/{provider_name}/test", response_model=APIResponse[TestConnectionResponse]
)
async def test_provider_connection(
    provider_name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    payload: Optional[TestConnectionRequest] = None,
):
    """Test connection to a provider (probes live)."""
    result = await _probe_and_store(provider_name, request, db)
    return APIResponse(
        data=TestConnectionResponse(**result), message="Connection test complete"
    )


@router.post("/test-all", response_model=APIResponse[List[TestConnectionResponse]])
async def test_all_providers(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Test connection to all configured providers."""
    router_ = request.app.state.orchestrator.ceo.router
    results = []
    for name in router_.available_providers():
        try:
            result = await _probe_and_store(name, request, db)
            results.append(TestConnectionResponse(**result))
        except Exception as exc:
            results.append(
                TestConnectionResponse(
                    provider=name,
                    ok=False,
                    detail=str(exc),
                    latency_ms=0,
                )
            )
    return APIResponse(data=results, message=f"Tested {len(results)} provider(s)")


# ─── Model Discovery ──────────────────────────────────────────────────


@router.get(
    "/{provider_name}/models", response_model=APIResponse[ProviderModelsResponse]
)
async def discover_models(
    provider_name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    use_cache: bool = Query(
        False, description="Use cached model registry instead of live call"
    ),
):
    """Discover models available from a provider (live call to provider's /models endpoint)."""
    router_ = request.app.state.orchestrator.ceo.router
    client = router_.get_client(provider_name)
    if client is None:
        raise NotFoundError(f"No provider client registered for '{provider_name}'")

    # Check if configured
    configured = set(await router_.configured_providers())
    if provider_name not in configured:
        return APIResponse(
            data=ProviderModelsResponse(
                provider=provider_name,
                models=[],
                unavailable_reason="not configured (missing credentials)",
            ),
            message=f"Provider '{provider_name}' not configured",
        )

    if use_cache:
        # Use static model registry
        from agents.providers.model_registry import all_known_models

        known = all_known_models()
        provider_models = [
            ModelInfoResponse(**m) for m in known if m.get("provider") == provider_name
        ]
        return APIResponse(
            data=ProviderModelsResponse(provider=provider_name, models=provider_models),
            message=f"{len(provider_models)} model(s) from registry",
        )

    # Live model discovery
    try:
        models = await client.list_models()
        model_responses = []
        for m in models:
            caps = await client.get_capabilities(m["id"])
            model_responses.append(
                ModelInfoResponse(
                    id=m["id"],
                    provider=provider_name,
                    context_window=caps.get("context_window"),
                    supports_tools=caps.get("supports_tools", False),
                    supports_vision=caps.get("supports_vision", False),
                    supports_streaming=caps.get("supports_streaming", True),
                    role=caps.get("role", "general"),
                    known=caps.get("known", True),
                )
            )
        return APIResponse(
            data=ProviderModelsResponse(provider=provider_name, models=model_responses),
            message=f"Discovered {len(model_responses)} model(s) from '{provider_name}'",
        )
    except Exception as exc:
        return APIResponse(
            data=ProviderModelsResponse(
                provider=provider_name,
                models=[],
                unavailable_reason=str(exc),
            ),
            message=f"Failed to discover models: {exc}",
        )


@router.get("/models/all", response_model=APIResponse[List[ProviderModelsResponse]])
async def discover_all_models(
    request: Request,
    db: AsyncSession = Depends(get_db),
    configured_only: bool = Query(
        True, description="Only discover from configured providers"
    ),
):
    """Discover models from all providers."""
    router_ = request.app.state.orchestrator.ceo.router
    configured = set(await router_.configured_providers())

    results = []
    for name in router_.available_providers():
        if configured_only and name not in configured:
            results.append(
                ProviderModelsResponse(
                    provider=name,
                    models=[],
                    unavailable_reason="not configured",
                )
            )
            continue

        client = router_.get_client(name)
        if client is None:
            results.append(
                ProviderModelsResponse(
                    provider=name,
                    models=[],
                    unavailable_reason="no client registered",
                )
            )
            continue

        try:
            models = await client.list_models()
            model_responses = []
            for m in models:
                caps = await client.get_capabilities(m["id"])
                model_responses.append(
                    ModelInfoResponse(
                        id=m["id"],
                        provider=name,
                        context_window=caps.get("context_window"),
                        supports_tools=caps.get("supports_tools", False),
                        supports_vision=caps.get("supports_vision", False),
                        supports_streaming=caps.get("supports_streaming", True),
                        role=caps.get("role", "general"),
                        known=caps.get("known", True),
                    )
                )
            results.append(
                ProviderModelsResponse(provider=name, models=model_responses)
            )
        except Exception as exc:
            results.append(
                ProviderModelsResponse(
                    provider=name, models=[], unavailable_reason=str(exc)
                )
            )

    return APIResponse(
        data=results,
        message=f"Discovered models from {len(results)} provider(s)",
    )


# ─── Health Endpoints (existing, kept for compatibility) ─────────────
