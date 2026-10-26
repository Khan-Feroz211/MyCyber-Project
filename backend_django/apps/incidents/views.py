"""Incident report + quarantine HTTP views (DRF port of the FastAPI report and
quarantine routers).

Reports are mounted under ``/api/v1/reports/`` and quarantine admin endpoints
under ``/api/v1/admin/quarantine/``.
"""
from __future__ import annotations

from datetime import datetime, timezone

from django.http import FileResponse, HttpResponse
from rest_framework import permissions, views
from rest_framework.response import Response

from apps.accounts.permissions import IsAdminRole
from apps.incidents.services import (
    delete_quarantine_item,
    export_csv,
    export_html,
    export_json,
    get_quarantine_item,
    list_quarantine,
    quarantine_bytes,
    release_quarantine_item,
)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


class ReportExportCSVAPI(views.APIView):
    """GET /reports/export/csv."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        severity = request.query_params.get("severity")
        scan_type = request.query_params.get("scan_type")
        limit = min(int(request.query_params.get("limit", "500")), 5000)
        data = export_csv(request.user, severity=severity, scan_type=scan_type, limit=limit)
        now = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        resp = HttpResponse(data, content_type="text/csv; charset=utf-8")
        resp["Content-Disposition"] = f"attachment; filename=mycyber_scans_{now}.csv"
        return resp


class ReportExportHTMLAPI(views.APIView):
    """GET /reports/export/html."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        severity = request.query_params.get("severity")
        scan_type = request.query_params.get("scan_type")
        limit = min(int(request.query_params.get("limit", "200")), 2000)
        html = export_html(request.user, severity=severity, scan_type=scan_type, limit=limit)
        return HttpResponse(html, content_type="text/html; charset=utf-8")


class ReportExportJSONAPI(views.APIView):
    """GET /reports/export/json."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        severity = request.query_params.get("severity")
        scan_type = request.query_params.get("scan_type")
        limit = min(int(request.query_params.get("limit", "500")), 5000)
        data = export_json(request.user, severity=severity, scan_type=scan_type, limit=limit)
        now = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        resp = HttpResponse(data, content_type="application/json")
        resp["Content-Disposition"] = f"attachment; filename=mycyber_scans_{now}.json"
        return resp


# ---------------------------------------------------------------------------
# Quarantine (admin only)
# ---------------------------------------------------------------------------


class QuarantineListAPI(views.APIView):
    permission_classes = [IsAdminRole]

    def get(self, request):
        return Response({"items": list_quarantine()})


class QuarantineItemAPI(views.APIView):
    permission_classes = [IsAdminRole]

    def get(self, request, name):
        return Response(get_quarantine_item(name))

    def delete(self, request, name):
        return Response(delete_quarantine_item(name))


class QuarantineDownloadAPI(views.APIView):
    permission_classes = [IsAdminRole]

    def get(self, request, name):
        item = get_quarantine_item(name)
        from apps.incidents.services import quarantine_dir
        from pathlib import Path

        path = quarantine_dir() / name
        return FileResponse(Path(path), filename=name)


class QuarantineReleaseAPI(views.APIView):
    permission_classes = [IsAdminRole]

    def post(self, request, name):
        return Response(release_quarantine_item(name))


class QuarantineUploadAPI(views.APIView):
    """POST /admin/quarantine/quarantine — store a file into quarantine."""

    permission_classes = [IsAdminRole]

    def post(self, request):
        import base64

        filename = request.data.get("filename", "upload")
        content = request.data.get("content_base64")
        if not content:
            from rest_framework.exceptions import ValidationError

            raise ValidationError({"content_base64": "required"})
        data = base64.b64decode(content)
        path = quarantine_bytes(filename, data, meta={"uploaded_by": request.user.email})
        return Response({"quarantined_to": path})
