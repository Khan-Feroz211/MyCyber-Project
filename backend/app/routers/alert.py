from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.models import User
from ..dependencies import get_current_user
from ..models.schemas import AcknowledgeRequest, AlertOut, AlertsResponse
from ..services.alert_service import (
    acknowledge_alert,
    acknowledge_all_alerts,
    delete_alert,
    get_alerts,
)

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
