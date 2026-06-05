from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.models import User
from ..dependencies import get_current_user
from ..models.schemas import AcknowledgeRequest, AlertOut, AlertsResponse
from ..models.schemas import FileDetail
from ..services.alert_service import (
    acknowledge_alert,
    acknowledge_all_alerts,
    delete_alert,
    get_alerts,
    update_review_status,
)
from ..services.scan_store import get_scan_by_id
from sqlalchemy.exc import NoResultFound
import json

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertsResponse)
async def list_alerts(
    include_acknowledged: bool = Query(default=False),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AlertsResponse:
    """Return a paginated list of alerts for the authenticated user's tenant."""
    return await get_alerts(
        db=db,
        user=current_user,
        include_acknowledged=include_acknowledged,
        page=page,
        page_size=page_size,
    )


@router.post("/acknowledge", response_model=AlertOut)
async def acknowledge(
    body: AcknowledgeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AlertOut:
    """Mark an alert as acknowledged."""
    alert = await acknowledge_alert(db=db, user=current_user, alert_id=body.alert_id)
    return AlertOut.model_validate(alert)


@router.get("/count")
async def alert_count(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return the number of unacknowledged alerts for the current tenant."""
    response = await get_alerts(
        db=db,
        user=current_user,
        include_acknowledged=False,
        page=1,
        page_size=1,
    )
    return {"unacknowledged": response.unacknowledged}


@router.post("/acknowledge-all")
async def acknowledge_all(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Acknowledge all unacknowledged alerts for the current tenant."""
    updated = await acknowledge_all_alerts(db=db, user=current_user)
    return {"updated": updated}


@router.delete("/{alert_id}")
async def delete_alert_endpoint(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete an alert by ID."""
    await delete_alert(db=db, user=current_user, alert_id=alert_id)
    return {"message": "Alert deleted"}


@router.patch("/{alert_id}/review-status")
async def update_review_status_endpoint(
    alert_id: str,
    status: str = Query(..., description="Review status: pending, reviewed, dismissed, resolved"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AlertOut:
    """Update the review status of an alert."""
    alert = await update_review_status(db=db, user=current_user, alert_id=alert_id, status=status)
    return AlertOut.model_validate(alert)



@router.get("/{alert_id}/file", response_model=FileDetail)
async def alert_file_details(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> FileDetail:
    """Return lightweight file/scan details for an alert's scan record.

    This endpoint returns filename, input preview, detected entities and timestamp.
    The service stores only a preview for many scan types; full original file
    content is not persisted by default.
    """
    # fetch the alert -> then the associated scan record
    # reuse existing get_alerts service via direct query for simplicity
    result = await db.execute(
        "SELECT scan_id FROM alerts WHERE alert_id = :aid AND tenant_id = :tid",
        {"aid": alert_id, "tid": current_user.tenant_id},
    )
    row = result.first()
    if not row:
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    scan_id = row[0]
    scan = await get_scan_by_id(db=db, user=current_user, scan_id=scan_id)
    if not scan:
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    # entities are stored as JSON text in scan.entities_json
    try:
        entities = json.loads(scan.entities_json) if scan.entities_json else []
    except Exception:
        entities = []

    return FileDetail(
        scan_id=scan.scan_id,
        filename=scan.filename,
        input_preview=scan.input_preview,
        entities=entities,
        created_at=scan.created_at,
    )
