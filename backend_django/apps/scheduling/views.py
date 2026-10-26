"""Scheduled-scan HTTP views (DRF port of ``backend/app/routers/scheduled_scan.py``).

Mounted under ``/api/v1/scheduled/``.
"""
from __future__ import annotations

from rest_framework import permissions, status, views
from rest_framework.response import Response

from apps.scheduling.services import (
    create_scheduled_scan,
    delete_scheduled_scan,
    get_scheduled_scan,
    list_scheduled_scans,
    run_scheduled_scan_now,
    scheduled_scan_to_dict,
    toggle_scheduled_scan,
)


class ScheduledScanListCreateAPI(views.APIView):
    """GET/POST /scheduled/jobs."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        items = [scheduled_scan_to_dict(j) for j in list_scheduled_scans(request.user)]
        return Response({"items": items, "total": len(items)})

    def post(self, request):
        name = request.data.get("name")
        scan_type = request.data.get("scan_type", "text")
        target = request.data.get("target", "")
        schedule_cron = request.data.get("schedule_cron", "0 * * * *")
        if not name or not schedule_cron:
            return Response(
                {"detail": "Fields 'name' and 'schedule_cron' are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        job = create_scheduled_scan(
            user=request.user, name=name, scan_type=scan_type, target=target, schedule_cron=schedule_cron
        )
        return Response(scheduled_scan_to_dict(job), status=status.HTTP_201_CREATED)


class ScheduledScanDetailAPI(views.APIView):
    """DELETE /scheduled/jobs/{job_id}."""

    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, job_id):
        ok = delete_scheduled_scan(request.user, job_id)
        if not ok:
            return Response({"detail": "Scheduled scan not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response({"deleted": job_id}, status=status.HTTP_200_OK)


class ScheduledScanToggleAPI(views.APIView):
    """POST /scheduled/jobs/{job_id}/toggle."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, job_id):
        job = toggle_scheduled_scan(request.user, job_id)
        return Response(scheduled_scan_to_dict(job))


class ScheduledScanRunNowAPI(views.APIView):
    """POST /scheduled/jobs/{job_id}/run-now."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, job_id):
        result = run_scheduled_scan_now(request.user, job_id)
        return Response(result, status=status.HTTP_200_OK)
