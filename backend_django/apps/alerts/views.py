"""Alert HTTP views (DRF port of ``backend/app/routers/alert.py``).

Mounted under ``/api/v1/alerts/``.
"""
from __future__ import annotations

from rest_framework import permissions, status, views
from rest_framework.response import Response

from apps.accounts.permissions import IsAdminRole


class AlertListAPI(views.APIView):
    """GET /alerts — list the authenticated user's alerts."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        from apps.alerts.services import get_alerts

        page = int(request.query_params.get("page", "1"))
        page_size = int(request.query_params.get("page_size", "20"))
        severity = request.query_params.get("severity")
        acknowledged = request.query_params.get("acknowledged")
        acknowledged_bool = None
        if acknowledged is not None:
            acknowledged_bool = acknowledged.lower() in ("1", "true", "yes")
        return Response(
            get_alerts(
                user=request.user,
                page=page,
                page_size=page_size,
                severity=severity,
                acknowledged=acknowledged_bool,
            )
        )


class AlertDetailAPI(views.APIView):
    """GET/DELETE /alerts/{alert_id}."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, alert_id):
        from apps.alerts.services import _get_user_alert

        alert = _get_user_alert(request.user, alert_id)
        from apps.alerts.services import _alert_to_dict

        return Response(_alert_to_dict(alert))

    def delete(self, request, alert_id):
        from apps.alerts.services import delete_alert

        delete_alert(request.user, alert_id)
        return Response({"deleted": alert_id}, status=status.HTTP_200_OK)


class AcknowledgeAlertAPI(views.APIView):
    """POST /alerts/{alert_id}/acknowledge."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, alert_id):
        from apps.alerts.services import acknowledge_alert, _alert_to_dict

        return Response(_alert_to_dict(acknowledge_alert(request.user, alert_id)))


class AcknowledgeAllAlertsAPI(views.APIView):
    """POST /alerts/acknowledge-all."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        from apps.alerts.services import acknowledge_all_alerts

        count = acknowledge_all_alerts(request.user)
        return Response({"acknowledged": count})


class AlertCountAPI(views.APIView):
    """GET /alerts/count."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        from apps.alerts.services import get_alert_counts

        return Response(get_alert_counts(request.user))


class AlertReviewAPI(views.APIView):
    """POST /alerts/{alert_id}/review."""

    permission_classes = [IsAdminRole]

    def post(self, request, alert_id):
        from apps.alerts.services import update_review_status, _alert_to_dict

        status_val = request.data.get("status", "investigated")
        note = request.data.get("note")
        return Response(_alert_to_dict(update_review_status(request.user, alert_id, status_val, note)))
