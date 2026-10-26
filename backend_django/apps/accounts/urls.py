"""URL routes for auth (mounted at ``/api/v1/auth/`` by the project URL conf)."""
from __future__ import annotations

from django.urls import path

from apps.accounts.views.auth_views import (
    LoginView,
    MFADisableView,
    MFASetupView,
    MFAStatusView,
    MFAVerifyView,
    MeFullView,
    MeView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
    RegisterView,
    SessionView,
)

app_name = "accounts"

urlpatterns = [
    path("register", RegisterView.as_view(), name="register"),
    path("login", LoginView.as_view(), name="login"),
    path("me", MeView.as_view(), name="me"),
    path("me/full", MeFullView.as_view(), name="me-full"),
    path("session", SessionView.as_view(), name="session"),
    path("mfa/status", MFAStatusView.as_view(), name="mfa-status"),
    path("mfa/setup", MFASetupView.as_view(), name="mfa-setup"),
    path("mfa/verify", MFAVerifyView.as_view(), name="mfa-verify"),
    path("mfa/disable", MFADisableView.as_view(), name="mfa-disable"),
    path("password/reset/request", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("password/reset/confirm", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
]
