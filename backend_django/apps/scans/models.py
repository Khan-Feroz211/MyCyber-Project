"""ScanRecord model (port of ``backend/app/db/models.py`` ScanRecord)."""
from __future__ import annotations

import uuid

from django.db import models


class ScanRecord(models.Model):
    """A persisted DLP scan result."""

    scan_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
        related_name="scans",
    )
    tenant_id = models.CharField(max_length=36, db_index=True)
    scan_type = models.CharField(max_length=20)
    severity = models.CharField(max_length=20)
    risk_score = models.FloatField()
    total_entities = models.IntegerField(default=0)
    recommended_action = models.CharField(max_length=10)
    summary = models.TextField()
    entities_json = models.TextField()
    input_preview = models.CharField(max_length=200, blank=True, null=True)
    filename = models.CharField(max_length=255, blank=True, null=True)
    source_ip = models.CharField(max_length=50, blank=True, null=True)
    scan_duration_ms = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "scan_records"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["tenant_id"]),
            models.Index(fields=["severity"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.get_severity_display() if hasattr(self, 'get_severity_display') else self.severity} / {self.scan_id}"
