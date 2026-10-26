"""Admin security URL routes (mounted at ``/api/v1/admin/security/``)."""
from __future__ import annotations

from django.urls import path

from apps.accounts.views.security_views import (
    DeactivateUserView,
    EncryptionStatusView,
    IncidentListView,
    LockUserView,
    ReactivateUserView,
    RotateEncryptionKeyView,
    UnlockUserView,
)

app_name = "accounts_admin"

urlpatterns = [
    path("incidents", IncidentListView.as_view(), name="incidents"),
    path("respond/lock-user", LockUserView.as_view(), name="lock-user"),
    path("respond/unlock-user", UnlockUserView.as_view(), name="unlock-user"),
    path("respond/deactivate-user", DeactivateUserView.as_view(), name="deactivate-user"),
    path("respond/reactivate-user", ReactivateUserView.as_view(), name="reactivate-user"),
    path("encryption/status", EncryptionStatusView.as_view(), name="encryption-status"),
    path("encryption/rotate", RotateEncryptionKeyView.as_view(), name="encryption-rotate"),
]
