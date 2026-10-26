"""Celery tasks for the scans app (migrated from backend/app/tasks/scheduled_scans.py)."""
from __future__ import annotations

from mycyber.celery import app as celery_app  # noqa: F401


@celery_app.task
def run_scheduled_scan(job_id: str) -> str:
    """Execute a scheduled scan. (Stub ported from FastAPI scheduled task.)"""
    # TODO: port backend/app/tasks/scheduled_scans.py run_scheduled_scan
    return f"scan:{job_id}:scheduled"
