"""URL configuration for the MyCyber DLP Django project.

All API endpoints live under ``/api/v1/`` (matching the existing FastAPI
routes so the React frontend requires **no** changes beyond
``VITE_API_URL``).  A lightweight ``/healthz`` health-check and OpenAPI
schema endpoint are also exposed at the root.
"""
from __future__ import annotations

from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

# Custom health check view
from apps.accounts.views.health import healthz  # noqa: E402

urlpatterns = [
    # Django admin (with two-factor-auth)
    path("admin/", include("mycyber.admin_urls")),  # noqa: F821 — defined at bottom

    # Health check
    path("healthz", healthz, name="healthz"),
    path("health", healthz, name="health"),

    # OpenAPI schema
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("api/docs/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),

    # API v1 — all app URL includes
    path("api/v1/auth/", include("apps.accounts.urls")),
    path("api/v1/scan/", include("apps.dlp.urls")),
    path("api/v1/llm-dlp/", include("apps.llm.urls")),
    path("api/v1/alerts/", include("apps.alerts.urls")),
    path("api/v1/billing/", include("apps.billing.urls")),
    path("api/v1/admin/security/", include("apps.accounts.urls_admin")),
    path("api/v1/admin/audit/", include("apps.audit.urls")),
    path("api/v1/scheduled/", include("apps.scheduling.urls")),
    path("api/v1/reports/", include("apps.incidents.urls_reports")),
    path("api/v1/admin/quarantine/", include("apps.incidents.urls_quarantine")),
]
