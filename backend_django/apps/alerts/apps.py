from __future__ import annotations

from django.apps import AppConfig


class AlertsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.alerts"
    verbose_name = "Alerts"


# WebSocket routing surface (extended when real-time alerts are built).
websocket_urlpatterns = []
