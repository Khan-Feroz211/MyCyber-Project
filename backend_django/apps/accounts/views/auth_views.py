"""Auth API views (DRF port of ``backend/app/routers/auth.py``).

Endpoints (mounted under ``/api/v1/auth/``):

* ``POST /register``              — create account
* ``POST /login``                 — e-mail + password → JWT (form-encoded)
* ``GET  /me``                    — current profile
* ``GET  /me/full``               — profile + subscription + usage
* ``GET  /session``              — session metadata
* ``GET  /mfa/status``            — MFA status
* ``POST /mfa/setup``             — initiate TOTP setup
* ``POST /mfa/verify``            — confirm TOTP (enable MFA)
* ``POST /mfa/disable``           — disable MFA
* ``POST /password/reset/request``
* ``POST /password/reset/confirm``
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from rest_framework import permissions, status, views
from rest_framework.response import Response

from apps.accounts.models import User
from apps.accounts.serializers import (
    MFASetupResponseSerializer,
    MFAStatusResponseSerializer,
    MFAVerifySerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    TokenSerializer,
    UserCreateSerializer,
    UserOutSerializer,
)
from apps.accounts.plans import get_usage
from mycyber.services.auth import (
    AuthError,
    create_access_token,
    create_reset_token,
    decode_reset_token,
    hash_password,
    resolve_role,
    verify_password,
)
from mycyber.services.audit_log import (
    EVENT_LOGIN_FAILED,
    EVENT_LOGIN_SUCCESS,
    EVENT_MFA_TOGGLE,
    EVENT_PASSWORD_RESET,
    append_audit_log,
)
from mycyber.services.email_service import send_password_reset_email
from mycyber.services import conf as _conf
from mycyber.services.mfa import build_otpauth_uri, generate_totp_secret, verify_totp_code
from mycyber.services.security_audit import log_security_event


def _client_ip(request) -> str | None:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class RegisterView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = UserCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        if User.objects.filter(email=email).exists():
            return Response(
                {"detail": "An account with this email address already exists."},
                status=status.HTTP_409_CONFLICT,
            )

        user = User(
            email=email,
            full_name=serializer.validated_data.get("full_name") or None,
        )
        user.set_password(serializer.validated_data["password"])
        user.tenant_id = uuid.uuid4()
        user.save()

        return Response(UserOutSerializer(user).data, status=status.HTTP_201_CREATED)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


class LoginView(views.APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []  # login must be reachable without a token

    def post(self, request):
        email = request.data.get("username") or request.data.get("email")
        password = request.data.get("password")
        mfa_code = request.headers.get("X-MFA-CODE")
        client_ip = _client_ip(request)
        user_agent = request.headers.get("user-agent")
        now = _utcnow()

        user = User.objects.filter(email=email).first() if email else None

        if user and user.locked_until and user.locked_until > now:
            log_security_event(
                event_type="login_blocked_locked_account",
                severity="MEDIUM",
                user=user,
                ip_address=client_ip,
                user_agent=user_agent,
                details={"locked_until": user.locked_until.isoformat()},
            )
            return Response(
                {"detail": "Account is temporarily locked due to repeated failed sign-in attempts."},
                status=status.HTTP_423_LOCKED,
            )

        if user is None or not verify_password(password or "", user.password):
            if user is not None:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= _conf.login_max_failures():
                    user.locked_until = now + timedelta(minutes=_conf.login_lock_minutes())
                user.save(update_fields=["failed_login_attempts", "locked_until"])

                log_security_event(
                    event_type="login_failed",
                    severity="MEDIUM",
                    user=user,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    details={
                        "failed_login_attempts": user.failed_login_attempts,
                        "lock_threshold": _conf.login_max_failures(),
                    },
                )
                try:
                    append_audit_log(
                        event_type=EVENT_LOGIN_FAILED,
                        resource_type="session",
                        action="login_failed",
                        tenant_id=str(user.tenant_id),
                        actor=user,
                        ip_address=client_ip,
                        user_agent=user_agent,
                    )
                except Exception:
                    pass

            return Response(
                {"detail": "Incorrect email or password."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if not user.is_active:
            log_security_event(
                event_type="login_blocked_inactive",
                severity="LOW",
                user=user,
                ip_address=client_ip,
                user_agent=user_agent,
                details={"reason": "login_attempt_inactive"},
            )
            return Response({"detail": "Account is inactive."}, status=status.HTTP_403_FORBIDDEN)

        # --- MFA ---
        mfa_required = _conf.mfa_rollout_mode() == "enforced" or (
            _conf.mfa_rollout_mode() == "opt_in" and user.mfa_enabled
        )
        if mfa_required:
            if not user.mfa_secret:
                return Response(
                    {"detail": "MFA is required for this account but no authenticator setup is available. Contact an administrator."},
                    status=status.HTTP_403_FORBIDDEN,
                )
            if not mfa_code:
                return Response(
                    {"error": "mfa_required", "message": "Multi-factor code is required.", "mfa_required": True},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            if not verify_totp_code(user.mfa_secret, mfa_code):
                log_security_event(
                    event_type="mfa_failed",
                    severity="HIGH",
                    user=user,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    details={"reason": "invalid_code"},
                )
                return Response({"detail": "Invalid multi-factor code."}, status=status.HTTP_401_UNAUTHORIZED)

        # --- Success ---
        previous_ip = user.last_login_ip
        suspicious_login = bool(previous_ip and client_ip and previous_ip != client_ip)
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login = _utcnow()
        user.last_login_ip = client_ip

        if suspicious_login:
            log_security_event(
                event_type="suspicious_login_new_ip",
                severity="HIGH",
                user=user,
                ip_address=client_ip,
                user_agent=user_agent,
                details={"previous_ip": previous_ip, "current_ip": client_ip},
            )

        log_security_event(
            event_type="login_success",
            severity="INFO",
            user=user,
            ip_address=client_ip,
            user_agent=user_agent,
            details={"mfa_used": bool(mfa_required and mfa_code)},
        )

        try:
            append_audit_log(
                event_type=EVENT_LOGIN_SUCCESS,
                resource_type="session",
                action="login",
                tenant_id=str(user.tenant_id),
                actor=user,
                ip_address=client_ip,
                user_agent=user_agent,
            )
        except Exception:
            pass

        user.save(update_fields=["failed_login_attempts", "locked_until", "last_login", "last_login_ip"])

        access_token = create_access_token(user.id, user.email, str(user.tenant_id))
        return Response(
            {
                "access_token": access_token,
                "token_type": "bearer",
                "user": UserOutSerializer(user).data,
            }
        )


# ---------------------------------------------------------------------------
# Profile / session
# ---------------------------------------------------------------------------


class MeView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response(UserOutSerializer(request.user).data)


class MeFullView(views.APIView):
    """Return user profile, subscription snapshot, and usage in one call."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response(
            {
                "user": UserOutSerializer(request.user).data,
                "subscription": {
                    "plan": request.user.plan,
                    "status": "active",
                    "scan_limit": None,
                },
                "usage": get_usage(request.user),
            }
        )


class SessionView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response(
            {
                "ip_address": _client_ip(request),
                "user_agent": request.headers.get("user-agent", "Unknown"),
                "login_time": request.user.last_login,
                "last_login_ip": request.user.last_login_ip,
                "is_active": request.user.is_active,
                "role": resolve_role(request.user),
            }
        )


# ---------------------------------------------------------------------------
# MFA
# ---------------------------------------------------------------------------


class MFAStatusView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response(
            {
                "enabled": bool(request.user.mfa_enabled),
                "rollout_mode": _conf.mfa_rollout_mode(),
            }
        )


class MFASetupView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        secret = generate_totp_secret()
        request.user.mfa_secret = secret
        request.user.save(update_fields=["mfa_secret"])

        issuer = "MyCyber"
        provisioning_uri = build_otpauth_uri(secret=secret, account_name=request.user.email, issuer=issuer)

        log_security_event(
            event_type="mfa_setup_started",
            severity="INFO",
            user=request.user,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )

        return Response(
            {
                "secret": secret,
                "provisioning_uri": provisioning_uri,
                "issuer": issuer,
                "account_name": request.user.email,
            }
        )


class MFAVerifyView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = MFAVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        code = serializer.validated_data["code"]

        if not request.user.mfa_secret:
            return Response(
                {"detail": "MFA setup was not initialized for this account."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not verify_totp_code(request.user.mfa_secret, code):
            log_security_event(
                event_type="mfa_verify_failed",
                severity="MEDIUM",
                user=request.user,
                ip_address=_client_ip(request),
                user_agent=request.headers.get("user-agent"),
            )
            return Response({"detail": "Invalid multi-factor code."}, status=status.HTTP_401_UNAUTHORIZED)

        request.user.mfa_enabled = True
        request.user.save(update_fields=["mfa_enabled"])

        log_security_event(
            event_type="mfa_enabled",
            severity="INFO",
            user=request.user,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        try:
            append_audit_log(
                event_type=EVENT_MFA_TOGGLE,
                resource_type="user_mfa",
                action="enable",
                tenant_id=str(request.user.tenant_id),
                actor=request.user,
            )
        except Exception:
            pass

        return Response(
            {"enabled": True, "rollout_mode": _conf.mfa_rollout_mode()}
        )


class MFADisableView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = MFAVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        code = serializer.validated_data["code"]

        if not request.user.mfa_secret or not request.user.mfa_enabled:
            return Response(
                {"enabled": False, "rollout_mode": _conf.mfa_rollout_mode()}
            )

        if not verify_totp_code(request.user.mfa_secret, code):
            return Response({"detail": "Invalid multi-factor code."}, status=status.HTTP_401_UNAUTHORIZED)

        request.user.mfa_enabled = False
        request.user.mfa_secret = None
        request.user.save(update_fields=["mfa_enabled", "mfa_secret"])

        log_security_event(
            event_type="mfa_disabled",
            severity="MEDIUM",
            user=request.user,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        try:
            append_audit_log(
                event_type=EVENT_MFA_TOGGLE,
                resource_type="user_mfa",
                action="disable",
                tenant_id=str(request.user.tenant_id),
                actor=request.user,
            )
        except Exception:
            pass

        return Response({"enabled": False, "rollout_mode": _conf.mfa_rollout_mode()})


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------


class PasswordResetRequestView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        user = User.objects.filter(email=email, is_active=True).first()
        if user is None:
            # Prevent email enumeration.
            return Response(
                {"message": "If an account exists with this email, a reset link has been sent."},
                status=status.HTTP_202_ACCEPTED,
            )

        reset_token = create_reset_token(user.id, user.email)
        log_security_event(
            event_type="password_reset_requested",
            severity="INFO",
            user=user,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )

        email_sent = send_password_reset_email(user.email, reset_token)
        if email_sent:
            return Response(
                {"message": "If an account exists with this email, a reset link has been sent."},
                status=status.HTTP_202_ACCEPTED,
            )
        # Development fallback: return the token directly.
        return Response(
            {
                "message": "If an account exists with this email, a reset link has been sent.",
                "reset_token": reset_token,
            },
            status=status.HTTP_202_ACCEPTED,
        )


class PasswordResetConfirmView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]
        new_password = serializer.validated_data["new_password"]

        # decode_reset_token raises AuthError (→ 401/419 via exception handler).
        token_data = decode_reset_token(token)

        user = User.objects.filter(id=token_data.user_id).first()
        if user is None or not user.is_active:
            raise AuthError("Invalid or expired reset token", status_code=401)

        user.set_password(new_password)
        user.save(update_fields=["password"])

        try:
            append_audit_log(
                event_type=EVENT_PASSWORD_RESET,
                resource_type="user",
                action="password_reset",
                tenant_id=str(user.tenant_id),
                actor=user,
            )
        except Exception:
            pass

        return Response({"message": "Password has been reset successfully."})
