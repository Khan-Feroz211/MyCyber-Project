"""Celery application configuration for MyCyber DLP.

Usage:
    celery -A mycyber worker -l info
    celery -A mycyber beat -l info
"""
from __future__ import annotations

import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mycyber.settings.dev")

app = Celery("mycyber")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


# Import task modules so they register with Celery
from apps.scans import tasks as _scan_tasks  # noqa: F401, E402

__all__ = ["app"]
