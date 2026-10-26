"""ScheduledScan model (port of ``backend/app/db/models.py`` ScheduledScan)."""
from __future__ import annotations

import uuid

from django.db import models


class ScheduledScan(models.Model):
    """A recurring scan job owned by a user."""

    job_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
        related_name="scheduled_scans",
    )
    tenant_id = models.CharField(max_length=36, db_index=True)
    name = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=20)
    target = models.TextField()
    schedule_cron = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)
    last_run_at = models.DateTimeField(blank=True, null=True)
    next_run_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "scheduled_scans"
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["tenant_id"]), models.Index(fields=["user"])]

    def __str__(self) -> str:
        return f"ScheduledScan {self.job_id} ({self.name})"
