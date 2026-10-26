"""Django admin registration for the accounts app."""
from __future__ import annotations

from django.contrib import admin

from apps.accounts.models import User


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = (
        "email", "full_name", "role", "plan", "is_active", "is_admin", "is_staff",
        "mfa_enabled", "created_at", "last_login",
    )
    list_filter = ("role", "plan", "is_active", "is_admin", "mfa_enabled", "created_at")
    search_fields = ("email", "full_name")
    ordering = ("-created_at",)
    readonly_fields = ("created_at", "tenant_id")
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Profile", {"fields": ("full_name", "role", "plan", "tenant_id")}),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "is_admin")}),
        ("MFA", {"fields": ("mfa_enabled", "mfa_secret")}),
        ("Usage", {"fields": ("scan_count_month", "failed_login_attempts", "locked_until")}),
        ("Audit", {"fields": ("last_login_ip", "last_login", "created_at")}),
    )
    add_fieldsets = (
        (None, {"fields": ("email", "password1", "password2")}),
    )
