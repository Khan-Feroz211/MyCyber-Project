"""LLMInteraction model (port of ``backend/app/db/models.py`` LLMInteraction)."""
from __future__ import annotations

import uuid

from django.db import models


class LLMInteraction(models.Model):
    """A record of an LLM-DLP pipeline run."""

    interaction_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
        related_name="llm_interactions",
    )
    tenant_id = models.CharField(max_length=36, db_index=True)
    original_prompt = models.TextField()
    redacted_prompt = models.TextField(blank=True, null=True)
    llm_response = models.TextField(blank=True, null=True)
    post_scan_summary = models.TextField(blank=True, null=True)
    pre_entities_json = models.TextField(default="[]")
    post_entities_json = models.TextField(default="[]")
    exposed_keys_json = models.TextField(default="[]")
    auto_deactivated = models.BooleanField(default=False)
    status = models.CharField(max_length=20, default="allowed")
    llm_provider = models.CharField(max_length=50, blank=True, null=True)
    model_used = models.CharField(max_length=50, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "llm_interactions"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["tenant_id"]),
            models.Index(fields=["status"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self) -> str:
        return f"LLMInteraction {self.interaction_id} ({self.status})"
