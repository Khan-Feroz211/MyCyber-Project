"""Alert model (port of ``backend/app/db/models.py`` Alert)."""
from __future__ import annotations

import uuid

from django.db import models


class Alert(models.Model):
    """A DLP alert raised for CRITICAL/HIGH severity scans."""

    alert_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
        related_name="alerts",
    )
    tenant_id = models.CharField(max_length=36, db_index=True)
    # References ScanRecord.scan_id (or LLMInteraction.interaction_id) — kept as a
    # plain string so the LLM leak-alert case (interaction id) is supported.
    scan_id = models.CharField(max_length=36, blank=True, null=True)
    severity = models.CharField(max_length=20)
    title = models.CharField(max_length=255)
    description = models.TextField()
    is_acknowledged = models.BooleanField(default=False)
    acknowledged_at = models.DateTimeField(blank=True, null=True)
    review_status = models.CharField(max_length=20, default="pending")
    reviewed_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "alerts"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["tenant_id"]),
            models.Index(fields=["is_acknowledged"]),
            models.Index(fields=["review_status"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self) -> str:
        return f"Alert {self.alert_id} ({self.severity})"
