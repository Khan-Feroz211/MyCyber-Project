from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Alert, ScanRecord, User
from ..models.schemas import AlertOut, AlertsResponse, ScanResponse

ALERT_SEVERITIES: set[str] = {"CRITICAL", "HIGH"}


async def create_alert_if_needed(
    db: AsyncSession,
    user: User,
    scan_record: ScanRecord,
    scan_response: ScanResponse,
) -> Alert | None:
    """Create an :class:`Alert` for CRITICAL or HIGH severity scans; return ``None`` otherwise."""
    severity = scan_response.severity.value
    if severity not in ALERT_SEVERITIES:
        return None

    title = (
        f"{severity}: Found {scan_response.total_entities} sensitive "
        f"entities in {scan_record.scan_type} scan"
    )
    description = scan_response.summary

    alert = Alert(
        user_id=user.id,
        tenant_id=user.tenant_id,
        scan_id=scan_record.scan_id,
        severity=severity,
        title=title,
        description=description,
    )
    db.add(alert)
    await db.flush()
    return alert


async def get_alerts(
    db: AsyncSession,
    user: User,
    include_acknowledged: bool = False,
    page: int = 1,
    page_size: int = 20,
) -> AlertsResponse:
    """Return a paginated :class:`AlertsResponse` scoped to *user*'s tenant."""
    base_query = select(Alert).where(Alert.tenant_id == user.tenant_id)

    if not include_acknowledged:
        base_query = base_query.where(Alert.is_acknowledged == False)  # noqa: E712

    count_result = await db.execute(
        select(func.count()).select_from(base_query.subquery())
    )
    total: int = count_result.scalar_one()

    offset = (page - 1) * page_size
    rows_result = await db.execute(
        base_query.order_by(Alert.created_at.desc()).offset(offset).limit(page_size)
    )
    alerts = rows_result.scalars().all()

    # Count unacknowledged separately (always reflects full tenant scope)
    unack_result = await db.execute(
        select(func.count()).where(
            Alert.tenant_id == user.tenant_id,
            Alert.is_acknowledged == False,  # noqa: E712
        )
    )
    unacknowledged: int = unack_result.scalar_one()

    return AlertsResponse(
        alerts=[AlertOut.model_validate(a) for a in alerts],
        total=total,
        unacknowledged=unacknowledged,
    )


async def acknowledge_alert(
    db: AsyncSession,
    user: User,
    alert_id: str,
) -> Alert:
    """Set ``is_acknowledged=True`` on the alert; raise 404 if not found or wrong tenant."""
    result = await db.execute(
        select(Alert).where(
            Alert.alert_id == alert_id,
            Alert.tenant_id == user.tenant_id,
        )
    )
    alert: Alert | None = result.scalars().first()

    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found",
        )

    alert.is_acknowledged = True
    alert.acknowledged_at = datetime.now(tz=timezone.utc)
    await db.flush()
    return alert


async def acknowledge_all_alerts(db: AsyncSession, user: User) -> int:
    """Acknowledge all unacknowledged alerts for the user's tenant.

    Returns the number of alerts updated.
    """
    result = await db.execute(
        select(Alert).where(
            Alert.tenant_id == user.tenant_id,
            Alert.is_acknowledged == False,  # noqa: E712
        )
    )
    alerts = result.scalars().all()

    now = datetime.now(tz=timezone.utc)
    for alert in alerts:
        alert.is_acknowledged = True
        alert.acknowledged_at = now

    await db.flush()
    return len(alerts)
