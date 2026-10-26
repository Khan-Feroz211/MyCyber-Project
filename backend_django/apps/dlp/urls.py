"""DLP scan routes (migrated from backend/app/routers/scan.py)."""
from __future__ import annotations

from django.urls import path

from apps.dlp.views import (
    ScanDetailAPI,
    ScanFileAPI,
    ScanHistoryAPI,
    ScanModelsAPI,
    ScanModelsLoadAPI,
    ScanNetworkAPI,
    ScanStatsAPI,
    ScanTextAPI,
)

app_name = "dlp"

urlpatterns = [
    path("text", ScanTextAPI.as_view(), name="text"),
    path("file", ScanFileAPI.as_view(), name="file"),
    path("network", ScanNetworkAPI.as_view(), name="network"),
    path("history", ScanHistoryAPI.as_view(), name="history"),
    path("stats", ScanStatsAPI.as_view(), name="stats"),
    path("models", ScanModelsAPI.as_view(), name="models"),
    path("models/load", ScanModelsLoadAPI.as_view(), name="models-load"),
    path("<scan_id>", ScanDetailAPI.as_view(), name="detail"),
]
