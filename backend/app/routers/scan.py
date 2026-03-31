from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.models import ScanRecord, User
from ..dependencies import check_plan_limit, get_current_user
from ..models.schemas import (
    PLAN_LIMITS,
    ScanFileRequest,
    ScanHistoryItem,
    ScanHistoryResponse,
    ScanNetworkRequest,
    ScanResponse,
    ScanTextRequest,
)
from ..services.alert_service import create_alert_if_needed
from ..services.scan_store import get_scan_by_id, get_scan_history, save_scan
from ..services import scanner as _scanner

router = APIRouter(prefix="/scan", tags=["scan"])


# ---------------------------------------------------------------------------
# Scan endpoints
# ---------------------------------------------------------------------------


@router.post("/text", response_model=ScanResponse, status_code=status.HTTP_200_OK)
async def scan_text(
    req: ScanTextRequest,
    current_user: User = Depends(check_plan_limit),
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    """Scan plain text for sensitive data and persist the result."""
    result = _scanner.scan_text(req)
    record = await save_scan(
        db=db,
        user=current_user,
        scan_response=result,
        scan_type="text",
        input_preview=req.text,
    )
    await create_alert_if_needed(db=db, user=current_user, scan_record=record, scan_response=result)
    return result


@router.post("/file", response_model=ScanResponse, status_code=status.HTTP_200_OK)
async def scan_file(
    req: ScanFileRequest,
    current_user: User = Depends(check_plan_limit),
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    """Decode a base64-encoded file and scan its contents for sensitive data."""
    try:
        result = _scanner.scan_file(req)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    record = await save_scan(
        db=db,
        user=current_user,
        scan_response=result,
        scan_type="file",
        filename=req.filename,
        input_preview=req.filename,
    )
    await create_alert_if_needed(db=db, user=current_user, scan_record=record, scan_response=result)
    return result


@router.post("/network", response_model=ScanResponse, status_code=status.HTTP_200_OK)
async def scan_network(
    req: ScanNetworkRequest,
    current_user: User = Depends(check_plan_limit),
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    """Scan a network payload for sensitive data."""
    result = _scanner.scan_network(req)
    record = await save_scan(
        db=db,
        user=current_user,
        scan_response=result,
        scan_type="network",
        input_preview=req.payload[:200],
        source_ip=req.source_ip,
    )
    await create_alert_if_needed(db=db, user=current_user, scan_record=record, scan_response=result)
    return result


# ---------------------------------------------------------------------------
# History & stats
# ---------------------------------------------------------------------------


@router.get("/history", response_model=ScanHistoryResponse)
async def scan_history(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    severity: Optional[str] = Query(default=None),
    scan_type: Optional[str] = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanHistoryResponse:
    """Return paginated scan history for the authenticated user's tenant."""
    return await get_scan_history(
        db=db,
        user=current_user,
        page=page,
        page_size=page_size,
        severity_filter=severity,
        scan_type_filter=scan_type,
    )


@router.get("/stats/summary")
async def scan_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return aggregate scan statistics for the authenticated user's tenant."""
    tenant_id = current_user.tenant_id

    async def _count(where_clauses) -> int:
        q = select(func.count(ScanRecord.id)).where(*where_clauses)
        result = await db.execute(q)
        return result.scalar_one()

    total_scans = await _count([ScanRecord.tenant_id == tenant_id])
    critical_scans = await _count(
        [ScanRecord.tenant_id == tenant_id, ScanRecord.severity == "CRITICAL"]
    )
    high_scans = await _count(
        [ScanRecord.tenant_id == tenant_id, ScanRecord.severity == "HIGH"]
    )
    safe_scans = await _count(
        [ScanRecord.tenant_id == tenant_id, ScanRecord.severity == "SAFE"]
    )

    return {
        "total_scans": total_scans,
        "critical_scans": critical_scans,
        "high_scans": high_scans,
        "safe_scans": safe_scans,
        "scans_this_month": current_user.scan_count_month,
        "plan_limit": PLAN_LIMITS.get(current_user.plan, PLAN_LIMITS["free"]),
        "plan": current_user.plan,
    }


@router.get("/models/info")
async def models_info() -> dict:
    """Return information about the loaded scan model (no auth required)."""
    return _scanner.get_model_info()


# ---------------------------------------------------------------------------
# Single scan lookup — must come AFTER named paths to avoid path conflicts
# ---------------------------------------------------------------------------


@router.get("/{scan_id}", response_model=ScanHistoryItem)
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanHistoryItem:
    """Fetch a single scan record by ID (tenant-isolated)."""
    record = await get_scan_by_id(db=db, user=current_user, scan_id=scan_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )
    return ScanHistoryItem.model_validate(record)
