"""Billing models (port of ``backend/app/db/models.py`` Subscription + BillingEvent)."""
from __future__ import annotations

import uuid

from django.db import models


class Subscription(models.Model):
    """A user's subscription (one per user; created on payment success)."""

    sub_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        "accounts.User",
        on_delete=models.CASCADE,
        related_name="subscription",
    )
    tenant_id = models.CharField(max_length=36, db_index=True)
    plan = models.CharField(max_length=20, default="free")
    status = models.CharField(max_length=20, default="active")
    scan_limit = models.IntegerField()
    price_pkr = models.IntegerField()
    billing_cycle = models.CharField(max_length=20, default="monthly")
    current_period_start = models.DateTimeField(blank=True, null=True)
    current_period_end = models.DateTimeField(blank=True, null=True)
    # Sensitive fields — encrypted at rest via the KMS field helpers.
    safepay_token = models.CharField(max_length=255, blank=True, null=True)
    safepay_tracker = models.CharField(max_length=255, blank=True, null=True)
    cancelled_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "subscriptions"
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["tenant_id"])]

    def __str__(self) -> str:
        return f"Subscription {self.sub_id} ({self.plan}/{self.status})"


class BillingEvent(models.Model):
    """An immutable record of a billing lifecycle event."""

    event_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
        related_name="billing_events",
    )
    tenant_id = models.CharField(max_length=36, db_index=True)
    event_type = models.CharField(max_length=50)
    plan = models.CharField(max_length=20, blank=True, null=True)
    amount_pkr = models.IntegerField(default=0)
    safepay_data = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "billing_events"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["tenant_id"]),
            models.Index(fields=["event_type"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self) -> str:
        return f"BillingEvent {self.event_id} ({self.event_type})"
