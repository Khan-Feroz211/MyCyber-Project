from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.models import ScheduledScan, User
from ..dependencies import get_current_user
from ..models.schemas import (
    ScheduledScanCreate,
    ScheduledScanListResponse,
    ScheduledScanOut,
    ScanTextRequest,
)
from ..services import scanner as _scanner
from ..services.alert_service import create_alert_if_needed
from ..services.scan_store import save_scan
from ..mlops.logger import get_logger

router = APIRouter(prefix="/scheduled", tags=["scheduled"])
logger = get_logger(__name__)


@router.post("/jobs", response_model=ScheduledScanOut, status_code=status.HTTP_201_CREATED)
async def create_scheduled_scan(
    payload: ScheduledScanCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScheduledScanOut:
    """Create a new scheduled scan job."""
    job = ScheduledScan(
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        name=payload.name,
        scan_type=payload.scan_type,
        target=payload.target,
        schedule_cron=payload.schedule_cron,
        is_active=True,
    )
    db.add(job)
    await db.flush()
    return ScheduledScanOut.model_validate(job)


@router.get("/jobs", response_model=ScheduledScanListResponse)
async def list_scheduled_scans(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScheduledScanListResponse:
    """List all scheduled scans for the authenticated user."""
    result = await db.execute(
        select(ScheduledScan)
        .where(
            ScheduledScan.user_id == current_user.id,
            ScheduledScan.tenant_id == current_user.tenant_id,
        )
        .order_by(desc(ScheduledScan.created_at))
    )
    items = result.scalars().all()
    return ScheduledScanListResponse(
        items=[ScheduledScanOut.model_validate(i) for i in items],
        total=len(items),
    )


@router.delete("/jobs/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scheduled_scan(
    job_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a scheduled scan job."""
    result = await db.execute(
        select(ScheduledScan).where(
            ScheduledScan.job_id == job_id,
            ScheduledScan.user_id == current_user.id,
        )
    )
    job = result.scalar_one_or_none()
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled scan not found.",
        )
    await db.delete(job)
    await db.flush()


@router.post("/jobs/{job_id}/toggle", response_model=ScheduledScanOut)
async def toggle_scheduled_scan(
    job_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScheduledScanOut:
    """Toggle active/inactive state of a scheduled scan."""
    result = await db.execute(
        select(ScheduledScan).where(
            ScheduledScan.job_id == job_id,
            ScheduledScan.user_id == current_user.id,
        )
    )
    job = result.scalar_one_or_none()
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled scan not found.",
        )
    job.is_active = not job.is_active
    await db.flush()
    return ScheduledScanOut.model_validate(job)


@router.post("/jobs/{job_id}/run-now", response_model=dict)
async def run_scheduled_scan_now(
    job_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Manually trigger a scheduled scan immediately."""
    result = await db.execute(
        select(ScheduledScan).where(
            ScheduledScan.job_id == job_id,
            ScheduledScan.user_id == current_user.id,
        )
    )
    job = result.scalar_one_or_none()
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled scan not found.",
        )

    try:
        if job.scan_type == "text":
            scan_result = _scanner.scan_text(ScanTextRequest(text=job.target))
        elif job.scan_type == "file":
            scan_result = _scanner.scan_text(
                ScanTextRequest(text=job.target)
            )
        else:
            scan_result = _scanner.scan_text(
                ScanTextRequest(text=job.target)
            )

        record = await save_scan(
            db=db,
            user=current_user,
            scan_response=scan_result,
            scan_type=job.scan_type,
            input_preview=job.target[:200],
        )
        await create_alert_if_needed(
            db=db, user=current_user, scan_record=record, scan_response=scan_result
        )

        job.last_run_at = datetime.now(timezone.utc)
        await db.flush()

        return {
            "message": "Scan executed successfully.",
            "scan_id": scan_result.scan_id,
            "severity": scan_result.severity.value,
            "entities_found": scan_result.total_entities,
        }
    except Exception as exc:
        logger.error(
            "Scheduled scan execution failed",
            extra={"job_id": job_id, "error": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scheduled scan execution failed.",
        )
