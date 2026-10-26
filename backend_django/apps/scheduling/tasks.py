"""Celery tasks for scheduled scans."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from apps.scheduling.models import ScheduledScan
from mycyber.celery import app

logger = logging.getLogger(__name__)


@app.task(name="run_scheduled_scan")
def run_scheduled_scan_task(job_id: str) -> dict:
    """Execute a scheduled scan job (wired to django-celery-beat periodic tasks)."""
    try:
        job = ScheduledScan.objects.get(job_id=job_id, is_active=True)
    except ScheduledScan.DoesNotExist:
        logger.warning("Scheduled scan job not found or inactive: %s", job_id)
        return {"status": "skipped", "job_id": job_id}

    from apps.scans.services import scan_and_persist

    try:
        record, scan_response = scan_and_persist(
            user=job.user,
            scan_type=job.scan_type,
            text=job.target,
            input_preview=job.target[:200],
        )
        job.last_run_at = datetime.now(timezone.utc)
        job.save(update_fields=["last_run_at"])
        return {
            "status": "ok",
            "job_id": str(job.job_id),
            "scan_id": scan_response["scan_id"],
            "severity": scan_response["severity"],
            "entities_found": scan_response["total_entities"],
        }
    except Exception as exc:  # noqa: BLE001
        logger.error("run_scheduled_scan failed for %s: %s", job_id, exc)
        return {"status": "error", "job_id": str(job.job_id), "error": str(exc)}
