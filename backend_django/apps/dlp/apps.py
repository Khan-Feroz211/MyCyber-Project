from __future__ import annotations

from django.apps import AppConfig


class DlpConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.dlp"
    verbose_name = "DLP"
