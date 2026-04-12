from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import ScanRecord, User
from ..models.schemas import ScanHistoryItem, ScanHistoryResponse, ScanResponse


async def save_scan(
    db: AsyncSession,
    user: User,
    scan_response: ScanResponse,
    scan_type: str,
    input_preview: str | None = None,
    filename: str | None = None,
    source_ip: str | None = None,
) -> ScanRecord:
    """Persist a :class:`ScanRecord` and increment the user's monthly scan counter."""
    import json

    record = ScanRecord(
        scan_id=scan_response.scan_id,
        user_id=user.id,
        tenant_id=user.tenant_id,
        scan_type=scan_type,
        severity=scan_response.severity.value,
        risk_score=scan_response.risk_score,
        total_entities=scan_response.total_entities,
        recommended_action=scan_response.recommended_action,
        summary=scan_response.summary,
        entities_json=json.dumps(
            [e.model_dump(mode="json") for e in scan_response.entities]
        ),
        input_preview=input_preview[:200] if input_preview else None,
        filename=filename,
        source_ip=source_ip,
        scan_duration_ms=scan_response.scan_duration_ms,
    )
    db.add(record)
    user.scan_count_month += 1
    await db.flush()
    return record


async def get_scan_history(
    db: AsyncSession,
    user: User,
    page: int = 1,
    page_size: int = 20,
    severity_filter: str | None = None,
    scan_type_filter: str | None = None,
) -> ScanHistoryResponse:
    """Return a paginated list of scan records scoped to *user*'s tenant."""
    base_query = select(ScanRecord).where(ScanRecord.tenant_id == user.tenant_id)

    if severity_filter:
        base_query = base_query.where(ScanRecord.severity == severity_filter.upper())
    if scan_type_filter:
        base_query = base_query.where(ScanRecord.scan_type == scan_type_filter.lower())

    count_result = await db.execute(
        select(func.count()).select_from(base_query.subquery())
    )
    total: int = count_result.scalar_one()

    offset = (page - 1) * page_size
    rows_result = await db.execute(
        base_query.order_by(ScanRecord.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    records = rows_result.scalars().all()

    items = [ScanHistoryItem.model_validate(r) for r in records]

    return ScanHistoryResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        has_more=(offset + len(items)) < total,
    )


async def get_scan_by_id(
    db: AsyncSession,
    user: User,
    scan_id: str,
) -> ScanRecord | None:
    """Return the :class:`ScanRecord` matching *scan_id* within *user*'s tenant, or ``None``."""
    result = await db.execute(
        select(ScanRecord).where(
            ScanRecord.scan_id == scan_id,
            ScanRecord.tenant_id == user.tenant_id,
        )
    )
    return result.scalars().first()
