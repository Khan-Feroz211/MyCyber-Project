"""Security & audit models for MyCyber DLP.

Ported from ``backend/app/db/models.py``:

* ``AuditLogEntry`` — append-only, hash-chained audit log (tamper-evident).
* ``SecurityAuditEvent`` — operational security event log (non-fatal logging).
"""
from __future__ import annotations

import json
import uuid

from django.db import models

#: Sentinel previous_hash for the first entry in the table.
GENESIS_HASH = "GENESIS"


class SecurityAuditEvent(models.Model):
    """Operational security event log.

    Used by :func:`mycyber.services.security_audit.log_security_event`.  This
    table is *not* hash-chained; it is best-effort operational logging.  For
    tamper-evident, append-only records see :class:`AuditLogEntry`.
    """

    event_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="security_events",
    )
    tenant_id = models.CharField(max_length=36, blank=True, null=True, db_index=True)
    event_type = models.CharField(max_length=64)
    severity = models.CharField(max_length=16, default="INFO")
    ip_address = models.CharField(max_length=64, blank=True, null=True)
    user_agent = models.CharField(max_length=255, blank=True, null=True)
    details_json = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "security_audit_events"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["tenant_id"]),
            models.Index(fields=["event_type"]),
            models.Index(fields=["severity"], name="sev_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.event_type} ({self.severity})"

    def details(self) -> dict:
        try:
            return json.loads(self.details_json or "{}")
        except (ValueError, TypeError):
            return {}


class AuditLogEntry(models.Model):
    """Append-only, tamper-evident audit log.

    Each entry is cryptographically chained to the previous one via a
    SHA-256 HMAC digest (see :mod:`mycyber.services.audit_log`).
    """

    entry_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    tenant_id = models.CharField(max_length=36, db_index=True)
    actor = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_entries",
    )
    event_type = models.CharField(max_length=64, db_index=True)
    resource_type = models.CharField(max_length=64)
    resource_id = models.CharField(max_length=36, blank=True, null=True)
    action = models.CharField(max_length=32)
    severity = models.CharField(max_length=16, default="INFO")
    ip_address = models.CharField(max_length=64, blank=True, null=True)
    user_agent = models.CharField(max_length=255, blank=True, null=True)
    details_json = models.TextField(default="{}")

    # Hash chaining
    previous_hash = models.CharField(max_length=64, default=GENESIS_HASH)
    entry_hash = models.CharField(max_length=64, default="")
    # Key version used for hashing (for rotation auditing)
    key_version = models.IntegerField(default=1)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "audit_log_entries"
        ordering = ["created_at", "id"]
        indexes = [
            models.Index(fields=["tenant_id"]),
            models.Index(fields=["actor"]),
            models.Index(fields=["event_type"]),
            models.Index(fields=["created_at"], name="created_at_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.event_type}/{self.action} [{self.entry_id}]"

    def details(self) -> dict:
        try:
            return json.loads(self.details_json or "{}")
        except (ValueError, TypeError):
            return {}
