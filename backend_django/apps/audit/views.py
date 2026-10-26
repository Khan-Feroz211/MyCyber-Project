"""Audit log export/verify endpoints (admin only).

Port of ``backend/app/routers/audit.py``:

* GET /api/v1/admin/audit/export     — JSON export (paginated)
* GET /api/v1/admin/audit/export/csv — CSV export
* GET /api/v1/admin/audit/verify     — chain integrity verification
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from django.http import StreamingHttpResponse
from rest_framework import permissions, views
from rest_framework.response import Response

from apps.accounts.permissions import IsAdminRole
from mycyber.services.audit_log import export_audit_log, verify_chain


class AuditExportView(views.APIView):
    """JSON export of audit log entries (admin only, tenant-scoped)."""

    permission_classes = [permissions.IsAuthenticated, IsAdminRole]

    def get(self, request):
        event_type = request.query_params.get("event_type")
        severity = request.query_params.get("severity")
        actor_id = request.query_params.get("actor_id")
        start_date = request.query_params.get("start_date")
        end_date = request.query_params.get("end_date")
        page = int(request.query_params.get("page", 1))
        page_size = min(int(request.query_params.get("page_size", 200)), 1000)
        tenant_id = str(request.user.tenant_id)

        entries = export_audit_log(
            tenant_id=tenant_id,
            event_type=event_type,
            severity=severity,
            actor_id=int(actor_id) if actor_id else None,
            start_date=_parse_dt(start_date),
            end_date=_parse_dt(end_date),
            page=page,
            page_size=page_size,
        )

        return Response(
            {
                "total": len(entries),
                "page": page,
                "page_size": page_size,
                "tenant_id": tenant_id,
                "entries": entries,
            }
        )


class AuditCsvExportView(views.APIView):
    """CSV export of audit log entries (admin only, tenant-scoped)."""

    permission_classes = [permissions.IsAuthenticated, IsAdminRole]

    def get(self, request):
        event_type = request.query_params.get("event_type")
        severity = request.query_params.get("severity")
        actor_id = request.query_params.get("actor_id")
        start_date = request.query_params.get("start_date")
        end_date = request.query_params.get("end_date")
        limit = min(int(request.query_params.get("limit", 5000)), 50000)
        tenant_id = str(request.user.tenant_id)

        entries = export_audit_log(
            tenant_id=tenant_id,
            event_type=event_type,
            severity=severity,
            actor_id=int(actor_id) if actor_id else None,
            start_date=_parse_dt(start_date),
            end_date=_parse_dt(end_date),
            page=1,
            page_size=limit,
        )

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "entry_id", "timestamp", "actor_id", "event_type", "resource_type",
            "resource_id", "action", "severity", "ip_address", "details",
            "previous_hash", "entry_hash", "key_version",
        ])
        for e in entries:
            writer.writerow([
                e["entry_id"], e["timestamp"], e["actor_id"],
                e["event_type"], e["resource_type"], e["resource_id"],
                e["action"], e["severity"], e["ip_address"],
                json.dumps(e["details"], default=str),
                e["previous_hash"], e["entry_hash"], e["key_version"],
            ])

        output.seek(0)
        filename = f"audit_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        response = StreamingHttpResponse(
            iter([output.getvalue()]),
            content_type="text/csv; charset=utf-8",
        )
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


class AuditVerifyView(views.APIView):
    """Verify the cryptographic integrity of the audit log chain (admin only)."""

    permission_classes = [permissions.IsAuthenticated, IsAdminRole]

    def get(self, request):
        result = verify_chain(tenant_id=str(request.user.tenant_id))
        return Response(result)


def _parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
