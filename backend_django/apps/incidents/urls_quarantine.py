"""Quarantine admin routes (migrated from backend/app/routers/quarantine_admin.py)."""
from __future__ import annotations

from django.urls import path

from apps.incidents.views import (
    QuarantineDownloadAPI,
    QuarantineItemAPI,
    QuarantineListAPI,
    QuarantineReleaseAPI,
    QuarantineUploadAPI,
)

app_name = "incidents_quarantine"

urlpatterns = [
    path("list", QuarantineListAPI.as_view(), name="list"),
    path("quarantine", QuarantineUploadAPI.as_view(), name="upload"),
    path("item/<name>", QuarantineItemAPI.as_view(), name="item"),
    path("download/<name>", QuarantineDownloadAPI.as_view(), name="download"),
    path("release/<name>", QuarantineReleaseAPI.as_view(), name="release"),
    path("<name>", QuarantineItemAPI.as_view(), name="delete"),
]
