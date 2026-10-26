"""Authentication helpers: password hashing + JWT tokens.

Ported from ``backend/app/services/auth.py``.  Password hashing delegates to
Django's configured password hashers (BCrypt 12 rounds in prod, fast hasher in
tests) so hashes are verified consistently across the admin and the API.

JWT tokens are issued/verified with **PyJWT** (not simplejwt) so the claim set
(``sub``, ``email``, ``tenant_id``, ``iat``, ``exp``) matches the FastAPI API
exactly — keeping the API contract and the test suite compatible.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from django.contrib.auth.hashers import check_password, make_password

from . import conf

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24
RESET_TOKEN_EXPIRE_HOURS = 1


def _secret_key() -> str:
    return conf.jwt_secret()


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    """Return a Django-hashed password string for *password*."""
    return make_password(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Return ``True`` if *plain* matches *hashed*."""
    return check_password(plain, hashed)


# Alias used by some routers / scripts
get_password_hash = hash_password


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def create_access_token(user_id: int, email: str, tenant_id: str) -> str:
    """Encode a signed JWT containing identity claims and an expiry timestamp."""
    now = _now()
    payload: dict = {
        "sub": str(user_id),
        "email": email,
        "tenant_id": tenant_id,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, _secret_key(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> "TokenData":
    """Decode and validate *token*, raising ``AuthError`` on any failure."""
    try:
        payload = jwt.decode(token, _secret_key(), algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Token has expired", status_code=419) from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("Could not validate credentials", status_code=401) from exc

    return _payload_to_token_data(payload)


def create_refresh_token(user_id: int, email: str, tenant_id: str) -> str:
    """Create a long-lived refresh token (7 days) for *user*."""
    now = _now()
    payload = {
        "sub": str(user_id),
        "email": email,
        "tenant_id": tenant_id,
        "type": "refresh",
        "iat": now,
        "exp": now + timedelta(days=7),
    }
    return jwt.encode(payload, _secret_key(), algorithm=ALGORITHM)


def decode_refresh_token(token: str) -> "TokenData":
    """Decode a refresh token, raising ``AuthError`` on any failure."""
    try:
        payload = jwt.decode(token, _secret_key(), algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Refresh token has expired. Please log in again.", status_code=419) from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("Invalid or expired refresh token", status_code=401) from exc

    if payload.get("type") != "refresh":
        raise AuthError("Invalid or expired refresh token", status_code=401)
    return _payload_to_token_data(payload)


def create_reset_token(user_id: int, email: str) -> str:
    """Create a short-lived JWT for password reset."""
    now = _now()
    payload = {
        "sub": str(user_id),
        "email": email,
        "type": "password_reset",
        "iat": now,
        "exp": now + timedelta(hours=RESET_TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, _secret_key(), algorithm=ALGORITHM)


def decode_reset_token(token: str) -> "TokenData":
    """Decode a password reset token, raising ``AuthError`` on failure."""
    try:
        payload = jwt.decode(token, _secret_key(), algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Reset token has expired. Please request a new one.", status_code=419) from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("Invalid or expired reset token", status_code=401) from exc

    if payload.get("type") != "password_reset":
        raise AuthError("Invalid or expired reset token", status_code=401)
    return _payload_to_token_data(payload)


def _payload_to_token_data(payload: dict) -> "TokenData":
    user_id_raw = payload.get("sub")
    email = payload.get("email")
    tenant_id = payload.get("tenant_id")
    if user_id_raw is None or email is None or tenant_id is None:
        raise AuthError("Could not validate credentials", status_code=401)
    return TokenData(user_id=int(user_id_raw), email=email, tenant_id=tenant_id)


# ---------------------------------------------------------------------------
# RBAC role helpers (mirrors backend/app/dependencies.py)
# ---------------------------------------------------------------------------

#: Roles sorted by privilege level (lowest -> highest).
_ROLE_HIERARCHY = {
    "viewer": 0,
    "analyst": 1,
    "admin": 2,
}


def resolve_role(user) -> str:
    """Return the effective role: ``admin`` if ``is_admin`` else ``role``."""
    if getattr(user, "is_admin", False):
        return "admin"
    role = getattr(user, "role", None)
    return role or "viewer"


def role_level(role: str) -> int:
    return _ROLE_HIERARCHY.get(role, 0)


# ---------------------------------------------------------------------------
# Token-data container + auth error
# ---------------------------------------------------------------------------


class TokenData:
    """Lightweight container for decoded JWT claims (replaces pydantic TokenData)."""

    def __init__(self, user_id: int, email: str, tenant_id: str):
        self.user_id = user_id
        self.email = email
        self.tenant_id = tenant_id


class AuthError(Exception):
    """Raised when a token is invalid/expired or credentials fail.

    ``status_code`` mirrors the FastAPI HTTP status that the corresponding
    FastAPI exception used, so DRF views can translate it 1:1.
    """

    def __init__(self, message: str, status_code: int = 401):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def session_is_expired(token: str) -> bool:
    """Return True when a *valid* token's ``iat`` predates the session timeout."""
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except jwt.InvalidTokenError:
        return False
    iat = unverified.get("iat")
    if iat is None:
        return False
    issued_at = datetime.fromtimestamp(iat, tz=timezone.utc)
    now = _now()
    from datetime import timedelta as _td

    return (now - issued_at) > _td(hours=conf.session_timeout_hours())
