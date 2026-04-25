"""Celery application configuration for background tasks.

Usage:
    # Start worker
    celery -A app.celery_app worker --loglevel=info

    # Start beat scheduler
    celery -A app.celery_app beat --loglevel=info
"""
from __future__ import annotations

import os

from celery import Celery

# Redis broker URL (default: local Redis)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "mycyber",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.tasks.scheduled_scans"],
)

celery_app.conf.update(
    # Task serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    # Timezone (use UTC)
    timezone="UTC",
    enable_utc=True,
    # Task execution
    task_track_started=True,
    task_time_limit=300,  # 5 minutes max per task
    # Result backend
    result_backend=REDIS_URL,
    result_expires=3600,  # Results expire after 1 hour
    # Beat scheduler - check for due scans every minute
    beat_schedule={
        "check-scheduled-scans": {
            "task": "app.tasks.scheduled_scans.check_and_trigger_scheduled_scans",
            "schedule": 60.0,  # Every 60 seconds
        },
    },
)

# Auto-discover tasks
celery_app.autodiscover_tasks()
