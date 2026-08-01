"""Audit log export endpoints for compliance review.

Exposes:
- GET /api/v1/admin/audit/export     — JSON export (paginated)
- GET /api/v1/admin/audit/export/csv — CSV export
- GET /api/v1/admin/audit/verify      — Chain integrity verification
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.models import User
from ..dependencies import get_current_user
from ..services.audit_log import export_audit_log, verify_chain

router = APIRouter(prefix="/admin/audit", tags=["audit"])

_ADMIN_ONLY = True


def _require_admin(current_user: User) -> None:
    if not current_user.is_admin and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges are required for this operation.",
        )


@router.get("/export", status_code=status.HTTP_200_OK)
async def export_audit(
    event_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    actor_id: Optional[int] = Query(default=None),
    start_date: Optional[datetime] = Query(default=None),
    end_date: Optional[datetime] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=200, ge=1, le=1000),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Export audit log entries as JSON (admin only, tenant-scoped)."""
    _require_admin(current_user)

    entries = await export_audit_log(
        db=db,
        tenant_id=current_user.tenant_id,
        event_type=event_type,
        severity=severity,
        actor_id=actor_id,
        start_date=start_date,
        end_date=end_date,
        page=page,
        page_size=page_size,
    )

    return {
        "total": len(entries),
        "page": page,
        "page_size": page_size,
        "tenant_id": current_user.tenant_id,
        "entries": entries,
    }


@router.get("/export/csv", status_code=status.HTTP_200_OK)
async def export_audit_csv(
    event_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    actor_id: Optional[int] = Query(default=None),
    start_date: Optional[datetime] = Query(default=None),
    end_date: Optional[datetime] = Query(default=None),
    limit: int = Query(default=5000, ge=1, le=50000),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Export audit log entries as CSV (admin only, tenant-scoped)."""
    _require_admin(current_user)

    entries = await export_audit_log(
        db=db,
        tenant_id=current_user.tenant_id,
        event_type=event_type,
        severity=severity,
        actor_id=actor_id,
        start_date=start_date,
        end_date=end_date,
        page=1,
        page_size=limit,
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "entry_id", "timestamp", "actor_id", "event_type", "resource_type",
        "resource_id", "action", "severity", "ip_address", "details",
        "previous_hash", "entry_hash", "key_version",
    ])
    for e in entries:
        writer.writerow([
            e["entry_id"],
            e["timestamp"],
            e["actor_id"],
            e["event_type"],
            e["resource_type"],
            e["resource_id"],
            e["action"],
            e["severity"],
            e["ip_address"],
            json.dumps(e["details"], default=str),
            e["previous_hash"],
            e["entry_hash"],
            e["key_version"],
        ])

    output.seek(0)
    filename = f"audit_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/verify", status_code=status.HTTP_200_OK)
async def verify_audit_chain(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Verify the cryptographic integrity of the audit log chain (admin only)."""
    _require_admin(current_user)

    result = await verify_chain(db, tenant_id=current_user.tenant_id)
    return result
