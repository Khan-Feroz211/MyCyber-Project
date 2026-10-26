"""Scheduled-scan routes (migrated from backend/app/routers/scheduled_scan.py)."""
from __future__ import annotations

from django.urls import path

from apps.scheduling.views import (
    ScheduledScanDetailAPI,
    ScheduledScanListCreateAPI,
    ScheduledScanRunNowAPI,
    ScheduledScanToggleAPI,
)

app_name = "scheduling"

urlpatterns = [
    path("jobs", ScheduledScanListCreateAPI.as_view(), name="list-create"),
    path("jobs/<job_id>", ScheduledScanDetailAPI.as_view(), name="detail"),
    path("jobs/<job_id>/toggle", ScheduledScanToggleAPI.as_view(), name="toggle"),
    path("jobs/<job_id>/run-now", ScheduledScanRunNowAPI.as_view(), name="run-now"),
]
