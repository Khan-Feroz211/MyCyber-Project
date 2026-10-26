"""Shared test helpers (port of the FastAPI ``backend/tests/conftest.py`` fixtures).

Uses Django's ``APIClient`` (synchronous) instead of httpx's ``AsyncClient``.
"""
from __future__ import annotations

import json

from rest_framework.test import APIClient  # noqa: F401  (re-exported for type users)


def parse_json(resp) -> dict:
    """Parse a JSON response body."""
    return json.loads(resp.content.decode("utf-8"))


# ---------------------------------------------------------------------------
# HTTP-level helpers
# ---------------------------------------------------------------------------

_AUTH_PATHS = {
    "register": "/api/v1/auth/register",
    "login": "/api/v1/auth/login",
}


def register_user(client, email: str, password: str = "password123", full_name: str = "Test User"):
    """POST /api/v1/auth/register and return the response."""
    return client.post(
        _AUTH_PATHS["register"],
        data={"email": email, "password": password, "full_name": full_name},
    )


def login_user(client, email: str, password: str = "password123"):
    """POST /api/v1/auth/login (form-encoded) and return the response."""
    return client.post(
        _AUTH_PATHS["login"],
        data={"username": email, "password": password},
    )


def get_auth_headers(
    client,
    email: str = "user@test.com",
    password: str = "password123",
    full_name: str = "Test User",
) -> dict:
    """Register + login a user and return ``{"Authorization": "Bearer ..."}``.

    Mirrors the FastAPI ``auth_headers`` fixture.
    """
    register_user(client, email, password, full_name)
    resp = login_user(client, email, password)
    assert resp.status_code == 200, resp.content
    token = parse_json(resp)["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Direct-model helpers (mirror FastAPI ``_create_*`` fixtures)
# ---------------------------------------------------------------------------

def create_user(
    email: str,
    *,
    role: str = "viewer",
    plan: str = "free",
    is_admin: bool = False,
    password: str = "password123",
    full_name: str = "User",
    tenant_id=None,
):
    """Create a ``User`` row directly via the ORM (bypasses the register API)."""
    from apps.accounts.models import User

    user = User(
        email=email,
        full_name=full_name,
        role=role,
        plan=plan,
        is_admin=is_admin,
        is_active=True,
        is_staff=bool(is_admin),
        is_superuser=bool(is_admin),
    )
    if tenant_id is not None:
        user.tenant_id = tenant_id
    user.set_password(password)
    user.save()
    return user


def login_as(client, email: str, password: str = "password123") -> dict:
    """Login a DB-created user and return auth headers."""
    resp = login_user(client, email, password)
    assert resp.status_code == 200, resp.content
    token = parse_json(resp)["access_token"]
    return {"Authorization": f"Bearer {token}"}
