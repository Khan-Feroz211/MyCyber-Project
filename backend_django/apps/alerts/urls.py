"""Alert routes (migrated from backend/app/routers/alert.py)."""
from __future__ import annotations

from django.urls import path

from apps.alerts.views import (
    AcknowledgeAllAlertsAPI,
    AcknowledgeAlertAPI,
    AlertCountAPI,
    AlertDetailAPI,
    AlertListAPI,
    AlertReviewAPI,
)

app_name = "alerts"

urlpatterns = [
    path("", AlertListAPI.as_view(), name="list"),
    path("count", AlertCountAPI.as_view(), name="count"),
    path("acknowledge-all", AcknowledgeAllAlertsAPI.as_view(), name="acknowledge-all"),
    path("<alert_id>", AlertDetailAPI.as_view(), name="detail"),
    path("<alert_id>/acknowledge", AcknowledgeAlertAPI.as_view(), name="acknowledge"),
    path("<alert_id>/review", AlertReviewAPI.as_view(), name="review"),
]
