"""Writes to the immutable audit trail. Never pass secrets into metadata."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import redact
from app.models.audit_log import AuditLog


async def record_event(
    db: AsyncSession,
    action: str,
    actor_id=None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    metadata: dict | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        metadata_json=redact(metadata or {}),
        ip_address=ip_address,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry
