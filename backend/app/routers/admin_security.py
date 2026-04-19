from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.database import get_db
from ..db.models import SecurityAuditEvent, User
from ..dependencies import get_current_user
from ..models.schemas import AdminIncidentActionRequest, AdminLockUserRequest
from ..services.security_audit import log_security_event

router = APIRouter(prefix="/admin/security", tags=["admin-security"])
settings = get_settings()


def _require_admin(current_user: User) -> None:
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges are required for this operation.",
        )


@router.get("/incidents")
async def list_incidents(
    severity: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    _require_admin(current_user)

    base = select(SecurityAuditEvent)
    count_q = select(func.count()).select_from(SecurityAuditEvent)

    if severity:
        sev = severity.upper()
        base = base.where(SecurityAuditEvent.severity == sev)
        count_q = count_q.where(SecurityAuditEvent.severity == sev)
    if event_type:
        base = base.where(SecurityAuditEvent.event_type == event_type)
        count_q = count_q.where(SecurityAuditEvent.event_type == event_type)

    base = base.order_by(SecurityAuditEvent.created_at.desc()).offset((page - 1) * page_size).limit(page_size)

    rows = (await db.execute(base)).scalars().all()
    total = int((await db.execute(count_q)).scalar() or 0)

    items = []
    for row in rows:
        try:
            details = json.loads(row.details_json or "{}")
        except json.JSONDecodeError:
            details = {}
        items.append(
            {
                "id": row.id,
                "event_id": row.event_id,
                "user_id": row.user_id,
                "tenant_id": row.tenant_id,
                "event_type": row.event_type,
                "severity": row.severity,
                "ip_address": row.ip_address,
                "user_agent": row.user_agent,
                "details": details,
                "created_at": row.created_at,
            }
        )

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_more": page * page_size < total,
    }


@router.post("/respond/lock-user")
async def lock_user(
    payload: AdminLockUserRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    _require_admin(current_user)

    target = await db.get(User, payload.user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    target.locked_until = datetime.now(tz=timezone.utc) + timedelta(minutes=payload.lock_minutes)
    target.failed_login_attempts = settings.login_max_failures

    await log_security_event(
        db,
        event_type="account_locked_by_admin",
        severity="HIGH",
        user=target,
        details={"admin_id": current_user.id, "reason": payload.reason, "lock_minutes": payload.lock_minutes},
    )
    await db.flush()

    return {
        "success": True,
        "user_id": target.id,
        "locked_until": target.locked_until,
    }


@router.post("/respond/unlock-user")
async def unlock_user(
    payload: AdminIncidentActionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    _require_admin(current_user)

    target = await db.get(User, payload.user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    target.locked_until = None
    target.failed_login_attempts = 0

    await log_security_event(
        db,
        event_type="account_unlocked_by_admin",
        severity="MEDIUM",
        user=target,
        details={"admin_id": current_user.id, "reason": payload.reason},
    )
    await db.flush()

    return {
        "success": True,
        "user_id": target.id,
        "locked_until": None,
    }


@router.post("/respond/deactivate-user")
async def deactivate_user(
    payload: AdminIncidentActionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    _require_admin(current_user)

    target = await db.get(User, payload.user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    target.is_active = False
    target.locked_until = datetime.now(tz=timezone.utc) + timedelta(days=365)

    await log_security_event(
        db,
        event_type="account_deactivated_by_admin",
        severity="HIGH",
        user=target,
        details={"admin_id": current_user.id, "reason": payload.reason},
    )
    await db.flush()

    return {
        "success": True,
        "user_id": target.id,
        "is_active": False,
    }


@router.post("/respond/reactivate-user")
async def reactivate_user(
    payload: AdminIncidentActionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    _require_admin(current_user)

    target = await db.get(User, payload.user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    target.is_active = True
    target.locked_until = None
    target.failed_login_attempts = 0

    await log_security_event(
        db,
        event_type="account_reactivated_by_admin",
        severity="MEDIUM",
        user=target,
        details={"admin_id": current_user.id, "reason": payload.reason},
    )
    await db.flush()

    return {
        "success": True,
        "user_id": target.id,
        "is_active": True,
    }
