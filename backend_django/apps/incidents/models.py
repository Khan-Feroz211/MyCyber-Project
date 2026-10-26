"""Incident + quarantine tracking models."""
from __future__ import annotations

import uuid

from django.db import models


class Incident(models.Model):
    """A DLP/security incident."""

    incident_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        "accounts.User", on_delete=models.CASCADE, related_name="incidents"
    )
    tenant_id = models.CharField(max_length=36, db_index=True)
    severity = models.CharField(max_length=20)
    title = models.CharField(max_length=255)
    description = models.TextField()
    status = models.CharField(max_length=20, default="open")
    details_json = models.TextField(default="{}")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "incidents"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["tenant_id"]),
            models.Index(fields=["status"]),
            models.Index(fields=["severity"]),
        ]

    def __str__(self) -> str:
        return f"Incident {self.incident_id} ({self.status})"


class QuarantineItem(models.Model):
    """Registry entry for a quarantined file (actual bytes live on disk)."""

    item_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    size = models.IntegerField()
    meta_json = models.TextField(default="{}")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "quarantine_items"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"QuarantineItem {self.name}"
