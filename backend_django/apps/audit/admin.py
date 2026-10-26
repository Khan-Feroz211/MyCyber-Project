"""Django admin registration for audit models."""
from __future__ import annotations

from django.contrib import admin

from apps.audit.models import AuditLogEntry, SecurityAuditEvent


@admin.register(SecurityAuditEvent)
class SecurityAuditEventAdmin(admin.ModelAdmin):
    list_display = ("event_type", "severity", "user", "tenant_id", "ip_address", "created_at")
    list_filter = ("severity", "event_type", "created_at")
    search_fields = ("event_type", "ip_address", "tenant_id")
    readonly_fields = ("event_id", "created_at")
    date_hierarchy = "created_at"


@admin.register(AuditLogEntry)
class AuditLogEntryAdmin(admin.ModelAdmin):
    list_display = (
        "event_type", "action", "severity", "actor", "tenant_id",
        "created_at", "entry_hash",
    )
    list_filter = ("event_type", "severity", "created_at")
    search_fields = ("event_type", "action", "tenant_id", "entry_hash", "previous_hash")
    readonly_fields = (
        "entry_id", "tenant_id", "actor", "event_type", "resource_type", "resource_id",
        "action", "severity", "ip_address", "user_agent", "details_json",
        "previous_hash", "entry_hash", "key_version", "created_at",
    )
    date_hierarchy = "created_at"

    # The audit log is append-only — prevent mutation from the admin.
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
