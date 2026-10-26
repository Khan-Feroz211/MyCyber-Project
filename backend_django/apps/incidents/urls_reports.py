"""Incident report export routes (migrated from backend/app/routers/reports.py)."""
from __future__ import annotations

from django.urls import path

from apps.incidents.views import (
    ReportExportCSVAPI,
    ReportExportHTMLAPI,
    ReportExportJSONAPI,
)

app_name = "incidents_reports"

urlpatterns = [
    path("export/csv", ReportExportCSVAPI.as_view(), name="export-csv"),
    path("export/html", ReportExportHTMLAPI.as_view(), name="export-html"),
    path("export/json", ReportExportJSONAPI.as_view(), name="export-json"),
]
