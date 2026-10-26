"""Scheduled-scan service: CRUD for scheduled jobs + on-demand execution.

Django port of ``backend/app/routers/scheduled_scan.py`` + ``scans/tasks.py``.
"""
from __future__ import annotations

import logging
from typing import Any

from apps.scheduling.models import ScheduledScan

logger = logging.getLogger(__name__)


def create_scheduled_scan(user, name: str, scan_type: str, target: str, schedule_cron: str) -> ScheduledScan:
    return ScheduledScan.objects.create(
        user=user,
        tenant_id=str(user.tenant_id),
        name=name,
        scan_type=scan_type,
        target=target,
        schedule_cron=schedule_cron,
        is_active=True,
    )


def list_scheduled_scans(user) -> list[ScheduledScan]:
    return list(
        ScheduledScan.objects.filter(user=user, tenant_id=str(user.tenant_id))
        .order_by("-created_at")
    )


def get_scheduled_scan(user, job_id: str) -> ScheduledScan | None:
    try:
        return ScheduledScan.objects.get(job_id=job_id, user=user)
    except (ScheduledScan.DoesNotExist, ValueError):
        return None


def delete_scheduled_scan(user, job_id: str) -> bool:
    obj = get_scheduled_scan(user, job_id)
    if obj is None:
        return False
    obj.delete()
    return True


def toggle_scheduled_scan(user, job_id: str) -> ScheduledScan:
    obj = get_scheduled_scan(user, job_id)
    if obj is None:
        from rest_framework.exceptions import NotFound

        raise NotFound("Scheduled scan not found.")
    obj.is_active = not obj.is_active
    obj.save(update_fields=["is_active"])
    return obj


def run_scheduled_scan_now(user, job_id: str) -> dict[str, Any]:
    """Manually trigger a scheduled scan immediately."""
    obj = get_scheduled_scan(user, job_id)
    if obj is None:
        from rest_framework.exceptions import NotFound

        raise NotFound("Scheduled scan not found.")

    from apps.scans.services import scan_and_persist
    from django.utils import timezone

    try:
        record, scan_response = scan_and_persist(
            user=user,
            scan_type=obj.scan_type,
            text=obj.target,
            input_preview=obj.target[:200],
        )
        obj.last_run_at = timezone.now()
        obj.save(update_fields=["last_run_at"])
        return {
            "message": "Scan executed successfully.",
            "scan_id": scan_response["scan_id"],
            "severity": scan_response["severity"],
            "entities_found": scan_response["total_entities"],
        }
    except Exception as exc:  # noqa: BLE001
        logger.error("Scheduled scan execution failed", extra={"job_id": job_id, "error": str(exc)})
        from rest_framework.exceptions import APIException
        from rest_framework import status

        raise APIException({"detail": "Scheduled scan execution failed.", "status_code": status.HTTP_500}) from exc


def scheduled_scan_to_dict(obj: ScheduledScan) -> dict[str, Any]:
    return {
        "job_id": str(obj.job_id),
        "name": obj.name,
        "scan_type": obj.scan_type,
        "target": obj.target,
        "schedule_cron": obj.schedule_cron,
        "is_active": obj.is_active,
        "last_run_at": obj.last_run_at.isoformat() if obj.last_run_at else None,
        "next_run_at": obj.next_run_at.isoformat() if obj.next_run_at else None,
        "created_at": obj.created_at.isoformat() if obj.created_at else None,
    }
