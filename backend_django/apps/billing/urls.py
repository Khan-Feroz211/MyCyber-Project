"""Billing / subscription routes (migrated from backend/app/routers/billing.py)."""
from __future__ import annotations

from django.urls import path

from apps.billing.views import (
    BillingCancelAPI,
    BillingHistoryAPI,
    BillingPlansAPI,
    BillingSubscriptionAPI,
    BillingUpgradeAPI,
    BillingUsageAPI,
    SafepayWebhookAPI,
)

app_name = "billing"

urlpatterns = [
    path("plans", BillingPlansAPI.as_view(), name="plans"),
    path("usage", BillingUsageAPI.as_view(), name="usage"),
    path("subscription", BillingSubscriptionAPI.as_view(), name="subscription"),
    path("upgrade", BillingUpgradeAPI.as_view(), name="upgrade"),
    path("cancel", BillingCancelAPI.as_view(), name="cancel"),
    path("history", BillingHistoryAPI.as_view(), name="history"),
    path("webhook", SafepayWebhookAPI.as_view(), name="webhook"),
]
