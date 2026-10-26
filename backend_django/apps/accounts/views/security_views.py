"""Admin security endpoints (DRF port of ``backend/app/routers/admin_security.py``).

Mounted at ``/api/v1/admin/security/`` via ``apps.accounts.urls_admin``.

* GET  /incidents                              — list security audit events
* POST /respond/lock-user                      — lock a user account
* POST /respond/unlock-user                    — unlock a user account
* POST /respond/deactivate-user                 — deactivate a user
* POST /respond/reactivate-user                 — reactivate a user
* GET  /encryption/status                      — KMS status report
* POST /encryption/rotate                       — key rotation + re-encryption
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from rest_framework import permissions, status, views
from rest_framework.response import Response

from apps.accounts.permissions import IsAdminRole
from apps.accounts.serializers import AdminIncidentActionSerializer, AdminLockUserSerializer
from apps.accounts.models import User

from mycyber.services.audit_log import EVENT_ADMIN_ACTION, append_audit_log
from mycyber.services.field_encryption import reencrypt_all_sensitive_fields
from mycyber.services.kms import get_encryption_status
from mycyber.services.security_audit import log_security_event


def _require_admin(user) -> None:
    from mycyber.services.auth import resolve_role

    if not resolve_role(user) == "admin":
        from rest_framework.exceptions import PermissionDenied

        raise PermissionDenied(
            "Admin privileges are required for this operation."
        )


class IncidentListView(views.APIView):
    """List security audit events (admin only)."""

    permission_classes = [permissions.IsAuthenticated, IsAdminRole]

    def get(self, request):
        from apps.audit.models import SecurityAuditEvent

        qs = SecurityAuditEvent.objects.all()
        severity = request.query_params.get("severity")
        event_type = request.query_params.get("event_type")
        if severity:
            qs = qs.filter(severity=severity.upper())
        if event_type:
            qs = qs.filter(event_type=event_type)

        page = max(int(request.query_params.get("page", 1)), 1)
        page_size = min(max(int(request.query_params.get("page_size", 25)), 1), 200)
        total = qs.count()
        qs = qs.order_by("-created_at")[(page - 1) * page_size : page * page_size]

        items = []
        for row in qs:
            try:
                details = json.loads(row.details_json or "{}")
            except (ValueError, TypeError):
                details = {}
            items.append(
                {
                    "id": row.pk,
                    "event_id": str(row.event_id),
                    "user_id": row.user_id,
                    "tenant_id": row.tenant_id,
                    "event_type": row.event_type,
                    "severity": row.severity,
                    "ip_address": row.ip_address,
                    "user_agent": row.user_agent,
                    "details": details,
                    "created_at": row.created_at,
                }
            )

        return Response(
            {
                "items": items,
                "total": total,
                "page": page,
                "page_size": page_size,
                "has_more": page * page_size < total,
            }
        )


class LockUserView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdminRole]

    def post(self, request):
        serializer = AdminLockUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        lock_minutes = serializer.validated_data["lock_minutes"]
        reason = serializer.validated_data["reason"]
        admin = request.user

        target = User.objects.filter(id=serializer.validated_data["user_id"]).first()
        if not target:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        target.locked_until = datetime.now(tz=timezone.utc) + timedelta(minutes=lock_minutes)
        target.failed_login_attempts = 999
        target.save(update_fields=["locked_until", "failed_login_attempts"])

        log_security_event(
            event_type="account_locked_by_admin",
            severity="HIGH",
            user=target,
            ip_address=None,
            details={"admin_id": admin.id, "reason": reason, "lock_minutes": lock_minutes},
        )
        try:
            append_audit_log(
                event_type=EVENT_ADMIN_ACTION,
                resource_type="user",
                resource_id=str(target.id),
                action="lock_user",
                tenant_id=str(admin.tenant_id),
                actor=admin,
                details={"target_user_id": target.id, "lock_minutes": lock_minutes, "reason": reason},
            )
        except Exception:
            pass

        return Response({"success": True, "user_id": target.id, "locked_until": target.locked_until})


class _UnlockReactivateMixin:
    """Shared logic for unlocking / reactivating a user."""

    def _do(self, request, *, activate: bool):
        serializer = AdminIncidentActionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        reason = serializer.validated_data["reason"]
        admin = request.user

        target = User.objects.filter(id=serializer.validated_data["user_id"]).first()
        if not target:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        target.failed_login_attempts = 0
        if activate:
            target.is_active = True
            event_type = "account_reactivated_by_admin"
            action = "reactivate_user"
            severity = "MEDIUM"
        else:
            target.locked_until = None
            event_type = "account_unlocked_by_admin"
            action = "unlock_user"
            severity = "MEDIUM"
        target.save(update_fields=["failed_login_attempts", "locked_until", "is_active"])

        log_security_event(
            event_type=event_type,
            severity=severity,
            user=target,
            ip_address=None,
            details={"admin_id": admin.id, "reason": reason},
        )
        try:
            append_audit_log(
                event_type=EVENT_ADMIN_ACTION,
                resource_type="user",
                resource_id=str(target.id),
                action=action,
                tenant_id=str(admin.tenant_id),
                actor=admin,
                details={"target_user_id": target.id, "reason": reason},
            )
        except Exception:
            pass

        return Response(
            {
                "success": True,
                "user_id": target.id,
                "is_active": target.is_active,
                "locked_until": target.locked_until,
            }
        )


class UnlockUserView(views.APIView, _UnlockReactivateMixin):
    permission_classes = [permissions.IsAuthenticated, IsAdminRole]

    def post(self, request):
        return self._do(request, activate=False)


class DeactivateUserView(views.APIView, _UnlockReactivateMixin):
    permission_classes = [permissions.IsAuthenticated, IsAdminRole]

    def post(self, request):
        serializer = AdminIncidentActionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        reason = serializer.validated_data["reason"]
        admin = request.user

        target = User.objects.filter(id=serializer.validated_data["user_id"]).first()
        if not target:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        target.is_active = False
        target.locked_until = datetime.now(tz=timezone.utc) + timedelta(days=365)
        target.save(update_fields=["is_active", "locked_until"])

        log_security_event(
            event_type="account_deactivated_by_admin",
            severity="HIGH",
            user=target,
            ip_address=None,
            details={"admin_id": admin.id, "reason": reason},
        )
        try:
            append_audit_log(
                event_type=EVENT_ADMIN_ACTION,
                resource_type="user",
                resource_id=str(target.id),
                action="deactivate_user",
                tenant_id=str(admin.tenant_id),
                actor=admin,
            )
        except Exception:
            pass

        return Response({"success": True, "user_id": target.id, "is_active": False})


class ReactivateUserView(views.APIView, _UnlockReactivateMixin):
    permission_classes = [permissions.IsAuthenticated, IsAdminRole]

    def post(self, request):
        return self._do(request, activate=True)


class EncryptionStatusView(views.APIView):
    """Return the current encryption-at-rest configuration (admin only)."""

    permission_classes = [permissions.IsAuthenticated, IsAdminRole]

    def get(self, request):
        return Response(get_encryption_status())


class RotateEncryptionKeyView(views.APIView):
    """Trigger a key rotation and re-encryption of all sensitive fields."""

    permission_classes = [permissions.IsAuthenticated, IsAdminRole]

    def post(self, request):
        summary = reencrypt_all_sensitive_fields()
        admin = request.user
        try:
            append_audit_log(
                event_type=EVENT_ADMIN_ACTION,
                resource_type="encryption",
                action="key_rotation",
                tenant_id=str(admin.tenant_id),
                actor=admin,
                details={"reencrypted": summary},
            )
        except Exception:
            pass

        return Response(
            {
                "success": True,
                "message": "Key rotation and re-encryption completed.",
                "reencrypted": summary,
            }
        )
