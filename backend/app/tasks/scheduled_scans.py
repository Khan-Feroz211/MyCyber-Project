"""Celery tasks for executing scheduled scans.

This module contains background tasks that run scheduled scans
based on the cron expressions stored in the database.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from celery import shared_task
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import AsyncSessionLocal
from ..db.models import ScheduledScan, User
from ..mlops.logger import get_logger
from ..models.schemas import ScanTextRequest
from ..services import scanner as _scanner
from ..services.alert_service import create_alert_if_needed
from ..services.scan_store import save_scan

logger = get_logger(__name__)


async def _execute_scheduled_scan_async(job_id: str) -> dict:
    """Async helper to execute a scheduled scan."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ScheduledScan).where(
                ScheduledScan.job_id == job_id,
                ScheduledScan.is_active == True,
            )
        )
        job = result.scalar_one_or_none()

        if not job:
            logger.warning("Scheduled job not found or inactive", extra={"job_id": job_id})
            return {"status": "error", "reason": "job_not_found"}

        # Get user
        user_result = await db.execute(select(User).where(User.id == job.user_id))
        user = user_result.scalar_one_or_none()

        if not user or not user.is_active:
            logger.warning("User not found or inactive", extra={"job_id": job_id, "user_id": job.user_id})
            return {"status": "error", "reason": "user_inactive"}

        try:
            # Execute scan based on type
            if job.scan_type == "text":
                scan_result = _scanner.scan_text(ScanTextRequest(text=job.target))
            elif job.scan_type == "file":
                # For file type, we treat target as content to scan
                scan_result = _scanner.scan_text(ScanTextRequest(text=job.target))
            else:
                # Network or other types
                scan_result = _scanner.scan_text(ScanTextRequest(text=job.target))

            # Save scan record
            record = await save_scan(
                db=db,
                user=user,
                scan_response=scan_result,
                scan_type=job.scan_type,
                input_preview=job.target[:200],
            )

            # Create alert if needed
            await create_alert_if_needed(
                db=db, user=user, scan_record=record, scan_response=scan_result
            )

            # Update job
            job.last_run_at = datetime.now(timezone.utc)
            await db.commit()

            logger.info(
                "Scheduled scan completed",
                extra={
                    "job_id": job_id,
                    "scan_id": scan_result.scan_id,
                    "severity": scan_result.severity.value,
                    "entities": scan_result.total_entities,
                },
            )

            return {
                "status": "success",
                "scan_id": scan_result.scan_id,
                "severity": scan_result.severity.value,
                "entities_found": scan_result.total_entities,
            }

        except Exception as exc:
            logger.error(
                "Scheduled scan failed",
                extra={"job_id": job_id, "error": str(exc)},
            )
            return {"status": "error", "reason": str(exc)}


@shared_task(bind=True, max_retries=3)
def execute_scheduled_scan(self, job_id: str) -> dict:
    """Execute a scheduled scan job.

    Args:
        job_id: The scheduled scan job ID to execute

    Returns:
        Dict with status and scan results
    """
    try:
        # Run async code in sync context
        result = asyncio.run(_execute_scheduled_scan_async(job_id))
        return result
    except Exception as exc:
        logger.error("Task failed", extra={"job_id": job_id, "error": str(exc)})
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task
def check_and_trigger_scheduled_scans() -> dict:
    """Periodic task to check for scheduled scans that need to run.

    This is called by Celery Beat on a schedule (e.g., every minute)
    and triggers individual scan tasks for due jobs.
    """
    async def _check():
        async with AsyncSessionLocal() as db:
            now = datetime.now(timezone.utc)

            # Get all active scheduled scans
            result = await db.execute(
                select(ScheduledScan).where(ScheduledScan.is_active == True)
            )
            jobs = result.scalars().all()

            triggered = 0
            for job in jobs:
                # Simple cron check: if minute matches and it's been at least 1 hour since last run
                # In production, use a proper cron parser like croniter
                should_run = False

                if not job.last_run_at:
                    should_run = True
                else:
                    # Check if enough time has passed (simplified cron logic)
                    # Parse cron: "0 9 * * *" = at 9:00 daily
                    parts = job.schedule_cron.split()
                    if len(parts) == 5:
                        minute, hour, day, month, weekday = parts
                        now_minute = now.minute
                        now_hour = now.hour

                        # Simple matching for common patterns
                        if minute == str(now_minute) or minute == "0" and now_minute == 0:
                            if hour == str(now_hour) or hour == "*":
                                hours_since_last = (now - job.last_run_at).total_seconds() / 3600
                                if hours_since_last >= 23:  # At least 23 hours between runs
                                    should_run = True

                if should_run:
                    # Trigger the scan task
                    execute_scheduled_scan.delay(job.job_id)
                    triggered += 1
                    logger.info("Triggered scheduled scan", extra={"job_id": job.job_id})

            return {"checked": len(jobs), "triggered": triggered}

    try:
        result = asyncio.run(_check())
        return result
    except Exception as exc:
        logger.error("Failed to check scheduled scans", extra={"error": str(exc)})
        return {"checked": 0, "triggered": 0, "error": str(exc)}
