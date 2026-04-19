from __future__ import annotations

import json
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import SecurityAuditEvent, User
from ..mlops.logger import get_logger

logger = get_logger(__name__)


async def log_security_event(
    db: AsyncSession,
    event_type: str,
    severity: str = "INFO",
    user: User | None = None,
    tenant_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Write a security audit event without interrupting request flow on failures."""
    try:
        event = SecurityAuditEvent(
            user_id=user.id if user else None,
            tenant_id=tenant_id if tenant_id is not None else (user.tenant_id if user else None),
            event_type=event_type,
            severity=severity.upper(),
            ip_address=ip_address,
            user_agent=(user_agent or "")[:255] if user_agent else None,
            details_json=json.dumps(details or {}),
        )
        db.add(event)
        await db.flush()
    except Exception as exc:  # pragma: no cover - non-fatal logging path
        logger.warning(
            "Failed to persist security audit event",
            extra={"event_type": event_type, "error": str(exc)},
        )
