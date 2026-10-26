"""DRF serializers (ported from ``backend/app/models/schemas.py``)."""
from __future__ import annotations

from rest_framework import serializers

from apps.accounts.models import User


class UserCreateSerializer(serializers.Serializer):
    """Registration payload: email, password (>=8 chars), full_name."""

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8, max_length=100)
    full_name = serializers.CharField(required=False, allow_blank=True, default="")


class UserOutSerializer(serializers.ModelSerializer):
    """Public user profile — never exposes ``hashed_password``."""

    class Meta:
        model = User
        fields = [
            "id", "email", "full_name", "is_active", "is_admin", "role",
            "plan", "tenant_id", "scan_count_month", "mfa_enabled", "created_at",
        ]
        read_only_fields = fields


class TokenSerializer(serializers.Serializer):
    access_token = serializers.CharField()
    token_type = serializers.CharField(default="bearer")
    user = UserOutSerializer()


class MFASetupResponseSerializer(serializers.Serializer):
    secret = serializers.CharField()
    provisioning_uri = serializers.CharField()
    issuer = serializers.CharField(default="MyCyber")
    account_name = serializers.CharField()


class MFAVerifySerializer(serializers.Serializer):
    code = serializers.CharField(min_length=6, max_length=6)


class MFAStatusResponseSerializer(serializers.Serializer):
    enabled = serializers.BooleanField()
    rollout_mode = serializers.CharField()


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, min_length=8, max_length=100)


# ── Admin security action payloads ──────────────────────────────────────


class AdminIncidentActionSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    reason = serializers.CharField(default="Admin response action")


class AdminLockUserSerializer(AdminIncidentActionSerializer):
    lock_minutes = serializers.IntegerField(default=60, min_value=1, max_value=10080)
