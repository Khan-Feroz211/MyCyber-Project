"""Scan service: orchestrate scanning, persistence, alerts and audit logging.

Django port of ``backend/app/services/scanner.py`` + ``backend/app/services/scan_store.py``.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from apps.scans.models import ScanRecord

logger = logging.getLogger(__name__)

# Severity levels that warrant an alert (ported from ``alert_service.create_alert_if_needed``).
_ALERT_SEVERITIES = {"CRITICAL", "HIGH"}


def perform_scan(text: str, scan_id: str | None = None) -> dict:
    """Thin wrapper around the shared scanner engine (in ``mycyber.services.scanner``)."""
    from mycyber.services.scanner import perform_scan as _scan

    return _scan(text, scan_id=scan_id)


def scan_and_persist(
    user,
    scan_type: str,
    text: str,
    input_preview: str | None = None,
    filename: str | None = None,
    source_ip: str | None = None,
) -> tuple:
    """Run ``perform_scan`` over *text*, persist a :class:`ScanRecord`, fire an
    audit entry and (if warranted) an alert.  Returns ``(record, scan_response)``.
    """
    import uuid

    scan_id = str(uuid.uuid4())
    scan_response = perform_scan(text, scan_id=scan_id)
    record = save_scan(
        user=user,
        scan_response=scan_response,
        scan_type=scan_type,
        input_preview=input_preview,
        filename=filename,
        source_ip=source_ip,
    )

    if scan_response["severity"] in _ALERT_SEVERITIES:
        try:
            from apps.alerts.services import create_alert_if_needed

            create_alert_if_needed(
                user=user,
                scan_record=record,
                scan_response=scan_response,
            )
        except Exception as exc:  # noqa: BLE001 — alerting must never break scanning
            logger.exception("create_alert_if_needed failed: %s", exc)

    return record, scan_response


def save_scan(
    user,
    scan_response: dict[str, Any],
    scan_type: str,
    input_preview: str | None = None,
    filename: str | None = None,
    source_ip: str | None = None,
) -> ScanRecord:
    """Persist a scan response and append an ``scan_created`` audit entry."""
    from mycyber.services.audit_log import EVENT_SCAN, append_audit_log

    record = ScanRecord.objects.create(
        scan_id=scan_response["scan_id"],
        user=user,
        tenant_id=str(user.tenant_id),
        scan_type=scan_type,
        severity=scan_response["severity"],
        risk_score=scan_response["risk_score"],
        total_entities=scan_response["total_entities"],
        recommended_action=scan_response["recommended_action"],
        summary=scan_response["summary"],
        entities_json=json.dumps(scan_response["entities"]),
        input_preview=input_preview,
        filename=filename,
        source_ip=source_ip,
        scan_duration_ms=scan_response["scan_duration_ms"],
    )

    try:
        append_audit_log(
            event_type=EVENT_SCAN,
            resource_type="scan",
            action="create",
            tenant_id=str(user.tenant_id),
            actor=user,
            resource_id=str(record.scan_id),
            details={
                "scan_type": scan_type,
                "severity": scan_response["severity"],
                "risk_score": scan_response["risk_score"],
                "total_entities": scan_response["total_entities"],
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to append scan audit entry: %s", exc)

    # Increment monthly usage counter (best-effort — mirrors FastAPI behaviour).
    try:
        from apps.accounts.models import User  # noqa: F401  (typing clarity)

        if hasattr(user, "scan_count_month"):
            user.scan_count_month = (user.scan_count_month or 0) + 1
            user.save(update_fields=["scan_count_month"])
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to increment scan_count_month: %s", exc)

    return record


def get_scan_history(
    user,
    page: int = 1,
    page_size: int = 20,
    severity_filter: str | None = None,
    scan_type_filter: str | None = None,
) -> dict[str, Any]:
    """Return a paginated, tenant-scoped scan history dict."""
    qs = ScanRecord.objects.filter(user=user).order_by("-created_at")
    if severity_filter:
        qs = qs.filter(severity=severity_filter)
    if scan_type_filter:
        qs = qs.filter(scan_type=scan_type_filter)

    total = qs.count()
    offset = (page - 1) * page_size
    rows = list(qs[offset : offset + page_size])

    items = [_scan_record_to_dict(r) for r in rows]
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_more": (offset + len(items)) < total,
    }


def get_scan_by_id(user, scan_id: str) -> ScanRecord | None:
    """Fetch a single scan by its UUID, scoped to the requesting user's tenant."""
    try:
        return ScanRecord.objects.get(
            scan_id=scan_id,
            tenant_id=str(user.tenant_id),
        )
    except (ScanRecord.DoesNotExist, ValueError):
        return None


def get_scan_stats(user) -> dict[str, Any]:
    """Aggregate severity stats for the authenticated user's tenant."""
    from collections import Counter

    from django.db.models import Sum

    qs = ScanRecord.objects.filter(user=user)
    counts = dict(Counter(qs.values_list("severity", flat=True)))
    total_scans = qs.count()
    total_entities = qs.aggregate(total=Sum("total_entities"))["total"] or 0
    return {
        "total_scans": total_scans,
        "total_entities": total_entities,
        "severity_breakdown": counts,
    }


def _scan_record_to_dict(record: ScanRecord) -> dict[str, Any]:
    return {
        "scan_id": str(record.scan_id),
        "scan_type": record.scan_type,
        "severity": record.severity,
        "risk_score": record.risk_score,
        "total_entities": record.total_entities,
        "recommended_action": record.recommended_action,
        "summary": record.summary,
        "filename": record.filename,
        "source_ip": record.source_ip,
        "created_at": record.created_at.isoformat() if record.created_at else None,
    }
