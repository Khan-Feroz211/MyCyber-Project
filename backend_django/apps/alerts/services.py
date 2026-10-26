"""Alert service — create/acknowledge/review/delete DLP alerts.

Django port of ``backend/app/services/alert_service.py``.
"""
from __future__ import annotations

import logging
from typing import Any

from apps.alerts.models import Alert

logger = logging.getLogger(__name__)


def create_alert_if_needed(
    user,
    scan_record,
    scan_response: dict[str, Any],
) -> Alert | None:
    """Create an alert when the scan severity warrants one.

    Mirrors ``alert_service.create_alert_if_needed``: alerts are raised for
    ``CRITICAL`` and ``HIGH`` severity scans.  Returns the created ``Alert``
    (or ``None``).
    """
    severity = scan_response.get("severity", "")
    if severity not in ("CRITICAL", "HIGH"):
        return None

    from mycyber.services.audit_log import append_audit_log

    alert = Alert.objects.create(
        user=user,
        tenant_id=str(user.tenant_id),
        scan_id=str(scan_record.scan_id),
        severity=severity,
        title=f"{severity} severity DLP scan detected ({scan_response.get('total_entities', 0)} entities)",
        description=scan_response.get("summary", ""),
        review_status="pending",
    )

    try:
        append_audit_log(
            event_type="alert_created",
            resource_type="alert",
            action="create",
            tenant_id=str(user.tenant_id),
            actor=user,
            resource_id=str(alert.alert_id),
            details={
                "scan_id": str(scan_record.scan_id),
                "severity": severity,
                "title": alert.title,
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to append alert audit entry: %s", exc)

    # Best-effort notification (email/telegram) — never blocking.
    try:
        from mycyber.services.email_service import send_alert_notification

        send_alert_notification(alert)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Alert notification skipped: %s", exc)

    return alert


def get_alerts(
    user,
    page: int = 1,
    page_size: int = 20,
    severity: str | None = None,
    acknowledged: bool | None = None,
) -> dict[str, Any]:
    """Paginated list of alerts for the authenticated user."""
    qs = Alert.objects.filter(user=user).order_by("-created_at")
    if severity:
        qs = qs.filter(severity=severity)
    if acknowledged is not None:
        qs = qs.filter(is_acknowledged=acknowledged)

    total = qs.count()
    offset = (page - 1) * page_size
    rows = list(qs[offset : offset + page_size])
    items = [_alert_to_dict(a) for a in rows]
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_more": (offset + len(items)) < total,
    }


def acknowledge_alert(user, alert_id: str) -> Alert:
    """Mark a single alert as acknowledged."""
    from django.utils import timezone

    from mycyber.services.audit_log import EVENT_ALERT_ACKNOWLEDGED, append_audit_log

    alert = _get_user_alert(user, alert_id)
    if not alert.is_acknowledged:
        alert.is_acknowledged = True
        alert.acknowledged_at = timezone.now()
        alert.save(update_fields=["is_acknowledged", "acknowledged_at"])
        try:
            append_audit_log(
                event_type=EVENT_ALERT_ACKNOWLEDGED,
                resource_type="alert",
                action="acknowledge",
                tenant_id=str(user.tenant_id),
                actor=user,
                resource_id=str(alert.alert_id),
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to append ack audit entry: %s", exc)
    return alert


def acknowledge_all_alerts(user) -> int:
    """Mark every non-acknowledged alert for the user as acknowledged."""
    from django.utils import timezone

    qs = Alert.objects.filter(user=user, is_acknowledged=False)
    count = qs.count()
    if count:
        qs.update(is_acknowledged=True, acknowledged_at=timezone.now())
    return count


def delete_alert(user, alert_id: str) -> None:
    """Mark an alert as deleted (soft delete via review_status)."""
    from mycyber.services.audit_log import EVENT_ALERT_DELETED, append_audit_log

    alert = _get_user_alert(user, alert_id)
    alert.review_status = "deleted"
    alert.save(update_fields=["review_status"])
    try:
        append_audit_log(
            event_type=EVENT_ALERT_DELETED,
            resource_type="alert",
            action="delete",
            tenant_id=str(user.tenant_id),
            actor=user,
            resource_id=str(alert.alert_id),
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to append delete audit entry: %s", exc)


def update_review_status(user, alert_id: str, status: str, note: str | None = None) -> Alert:
    """Set the review status of an alert (e.g. investigated)."""
    from django.utils import timezone

    from mycyber.services.audit_log import EVENT_ALERT_REVIEWED, append_audit_log

    alert = _get_user_alert(user, alert_id)
    alert.review_status = status
    if status == "investigated":
        alert.reviewed_at = timezone.now()
    alert.save(update_fields=["review_status", "reviewed_at"])
    try:
        append_audit_log(
            event_type=EVENT_ALERT_REVIEWED,
            resource_type="alert",
            action=status,
            tenant_id=str(user.tenant_id),
            actor=user,
            resource_id=str(alert.alert_id),
            details={"note": note} if note else None,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to append review audit entry: %s", exc)
    return alert


def get_alert_counts(user) -> dict[str, int]:
    qs = Alert.objects.filter(user=user)
    return {
        "total": qs.count(),
        "pending": qs.filter(review_status="pending").count(),
        "investigated": qs.filter(review_status="investigated").count(),
        "acknowledged": qs.filter(is_acknowledged=True).count(),
        "critical": qs.filter(severity="CRITICAL").count(),
    }


def _get_user_alert(user, alert_id: str) -> Alert:
    try:
        return Alert.objects.get(alert_id=alert_id, tenant_id=str(user.tenant_id))
    except (Alert.DoesNotExist, ValueError):
        from rest_framework.exceptions import NotFound

        raise NotFound("Alert not found")


def _alert_to_dict(a: Alert) -> dict[str, Any]:
    return {
        "alert_id": str(a.alert_id),
        "scan_id": a.scan_id,
        "severity": a.severity,
        "title": a.title,
        "description": a.description,
        "is_acknowledged": a.is_acknowledged,
        "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        "review_status": a.review_status,
        "reviewed_at": a.reviewed_at.isoformat() if a.reviewed_at else None,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }
