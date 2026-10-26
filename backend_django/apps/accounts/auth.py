"""Custom JWT authentication for the MyCyber Django API.

DRF ``Authentication`` class referenced from ``REST_FRAMEWORK`` settings as
``apps.accounts.auth.MFATokenAuthentication``.

Behaviour matches the FastAPI backend (``backend/app/services/auth.py`` +
``backend/app/dependencies.py``):

* Tokens are signed with **PyJWT** (HS256) and carry ``sub``/``email``/
  ``tenant_id``/``iat``/``exp`` claims — identical to the FastAPI API so the
  frontend's ``VITE_API_URL`` token contract is unchanged.
* Expired-signature → 419 (re-authenticate).
* Invalid token → 401.
* User must be active, else 403.
* Session-timeout (``iat`` older than ``SESSION_TIMEOUT_HOURS``) → 419, after
  recording an ``session_expired`` audit entry.
"""
from __future__ import annotations

from datetime import datetime, timezone

import jwt
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied

from mycyber.services.audit_log import EVENT_SESSION_EXPIRED, append_audit_log
from mycyber.services.auth import AuthError, decode_access_token, session_is_expired


class SessionExpired(AuthenticationFailed):
    """419 response telling the client to re-authenticate."""

    status_code = 419
    default_detail = "Session has expired. Please re-authenticate."
    default_code = "session_expired"


class MFATokenAuthentication(authentication.BaseAuthentication):
    """Validate a ``Bearer`` JWT and return the authenticated user."""

    keyword = "Bearer"

    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None  # No auth header → leave to permission classes (401).

        token = self.get_raw_token(header)
        if token is None:
            return None

        # decode_access_token raises AuthError (419/401) on bad/expired tokens.
        try:
            token_data = decode_access_token(token)
        except AuthError as exc:
            raise self._to_drf(exc)

        from django.contrib.auth import get_user_model

        User = get_user_model()
        try:
            user = User.objects.get(id=token_data.user_id)
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found")

        if not user.is_active:
            raise PermissionDenied("Account is inactive")

        # Session-timeout: token still valid but issued too long ago → 419.
        if session_is_expired(token):
            try:
                append_audit_log(
                    event_type=EVENT_SESSION_EXPIRED,
                    resource_type="session",
                    action="expired",
                    tenant_id=str(user.tenant_id),
                    actor=user,
                )
            except Exception:
                pass
            raise SessionExpired()

        return (user, token)

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _to_drf(exc: AuthError):
        """Translate an :class:`AuthError` into a DRF exception with status."""
        from rest_framework.exceptions import AuthenticationFailed, PermissionDenied

        if exc.status_code == 419:
            return SessionExpired(detail=exc.message)
        if exc.status_code == 403:
            return PermissionDenied(detail=exc.message)
        return AuthenticationFailed(detail=exc.message)

    def get_header(self, request) -> str | None:
        """Extract the raw ``Authorization`` header value."""
        header = request.META.get("HTTP_AUTHORIZATION")
        if not header:
            return None
        parts = header.split()
        if len(parts) < 2 or parts[0].lower() != "bearer":
            return None
        return header

    def get_raw_token(self, header: str) -> str | None:
        # ``header`` already validated as ``Bearer <token>`` in get_header.
        parts = header.split()
        if len(parts) != 2:
            return None
        token = parts[1].strip()
        return token or None

    def authenticate_header(self, request):
        return self.keyword
