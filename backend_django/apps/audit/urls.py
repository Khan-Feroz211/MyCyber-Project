"""URL routes for the audit app (mirrors FastAPI ``routers/audit.py``)."""
from __future__ import annotations

from django.urls import path

from apps.audit.views import AuditCsvExportView, AuditExportView, AuditVerifyView

app_name = "audit"

urlpatterns = [
    path("export", AuditExportView.as_view(), name="export"),
    path("export/csv", AuditCsvExportView.as_view(), name="export-csv"),
    path("verify", AuditVerifyView.as_view(), name="verify"),
]
