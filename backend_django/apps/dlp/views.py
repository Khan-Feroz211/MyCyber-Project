"""DLP scan HTTP views (DRF port of ``backend/app/routers/scan.py``).

Mounted under ``/api/v1/scan/``.
"""
from __future__ import annotations

import json as _json

from rest_framework import permissions, status, views
from rest_framework.response import Response

from apps.accounts.plans import PLAN_LIMITS


def _check_plan_limit(user):
    """Raise a 429-style response if the user's monthly quota is exhausted."""
    limit = PLAN_LIMITS.get(getattr(user, "plan", "free"), PLAN_LIMITS["free"])
    used = getattr(user, "scan_count_month", 0) or 0
    if used >= limit:
        from rest_framework.exceptions import APIException

        class _PlanLimit(APIException):
            status_code = 429
            default_detail = (
                f"You have reached the {limit} scan limit for the '{user.plan}' plan this month."
            )

        raise _PlanLimit()


class ScanTextAPI(views.APIView):
    """POST /scan/text — scan a blob of text."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        _check_plan_limit(request.user)
        text = (request.data.get("text") or "").strip()
        if not text:
            return Response({"detail": "Field 'text' is required."}, status=status.HTTP_400_BAD_REQUEST)
        from apps.scans.services import scan_and_persist

        _scan_id = request.data.get("scan_id")
        record, scan_response = scan_and_persist(
            user=request.user,
            scan_type="text",
            text=text,
            input_preview=text[:200],
        )
        # Echo the caller-supplied scan_id if a collision-free match is not required.
        return Response(scan_response, status=status.HTTP_200_OK)


class ScanFileAPI(views.APIView):
    """POST /scan/file — scan an uploaded/base64 file."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        _check_plan_limit(request.user)
        from apps.scans.services import scan_and_persist

        raw = request.data.get("content_base64")
        if not raw:
            return Response({"detail": "Field 'content_base64' is required."}, status=status.HTTP_400_BAD_REQUEST)
        import base64

        data = base64.b64decode(raw)
        from mycyber.services.scanner import _extract_text_from_bytes

        text = _extract_text_from_bytes(data, request.data.get("filename", "file"))
        record, scan_response = scan_and_persist(
            user=request.user,
            scan_type="file",
            text=text,
            input_preview=raw[:200],
            filename=request.data.get("filename"),
        )
        return Response(scan_response, status=status.HTTP_200_OK)


class ScanNetworkAPI(views.APIView):
    """POST /scan/network — scan a network packet payload."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        _check_plan_limit(request.user)
        from apps.scans.services import scan_and_persist

        payload = (request.data.get("payload") or "")
        source_ip = request.data.get("source_ip")
        record, scan_response = scan_and_persist(
            user=request.user,
            scan_type="network",
            text=str(payload),
            input_preview=str(payload)[:200],
            source_ip=source_ip,
        )
        return Response(scan_response, status=status.HTTP_200_OK)


class ScanHistoryAPI(views.APIView):
    """GET /scan/history — paginated scan history."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        from apps.scans.services import get_scan_history

        page = int(request.query_params.get("page", "1"))
        page_size = int(request.query_params.get("page_size", "20"))
        severity = request.query_params.get("severity")
        scan_type = request.query_params.get("scan_type")
        return Response(
            get_scan_history(
                user=request.user,
                page=page,
                page_size=page_size,
                severity_filter=severity,
                scan_type_filter=scan_type,
            )
        )


class ScanDetailAPI(views.APIView):
    """GET /scan/{scan_id} — fetch a single scan."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, scan_id):
        from apps.scans.services import get_scan_by_id

        record = get_scan_by_id(request.user, scan_id)
        if record is None:
            return Response({"detail": "Scan not found."}, status=status.HTTP_404_NOT_FOUND)
        try:
            entities = _json.loads(record.entities_json or "[]")
        except ValueError:
            entities = []
        return Response(
            {
                "scan_id": str(record.scan_id),
                "scan_type": record.scan_type,
                "severity": record.severity,
                "risk_score": record.risk_score,
                "total_entities": record.total_entities,
                "recommended_action": record.recommended_action,
                "summary": record.summary,
                "entities": entities,
                "filename": record.filename,
                "source_ip": record.source_ip,
                "created_at": record.created_at.isoformat() if record.created_at else None,
            }
        )


class ScanStatsAPI(views.APIView):
    """GET /scan/stats — aggregate severity stats."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        from apps.scans.services import get_scan_stats

        return Response(get_scan_stats(request.user))


class ScanModelsAPI(views.APIView):
    """GET /scan/models — model/scanner info."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        from mycyber.services.scanner import get_model_info

        return Response(get_model_info())


class ScanModelsLoadAPI(views.APIView):
    """POST /scan/models/load — load the NER model (admin only)."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        from apps.accounts.permissions import IsAdminRole
        if not IsAdminRole().has_permission(request, self):
            return Response({"detail": "Admin privileges required."}, status=status.HTTP_403_FORBIDDEN)
        from mycyber.services.scanner import get_model_info, load_ner_model

        load_ner_model()
        return Response(get_model_info())
