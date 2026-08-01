"""Tests for RBAC hardening — fine-grained roles, session timeout, forced re-auth.

Run with:  pytest backend/tests/test_rbac.py -v
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import User
from app.models.schemas import UserRole
from app.services.auth import hash_password
from app.config import get_settings


async def _create_admin(db_session: AsyncSession) -> User:
    admin = User(
        email="adminrbac@test.com",
        hashed_password=hash_password("password123"),
        full_name="Admin RBAC",
        tenant_id="rbac-admin-tenant",
        plan="enterprise",
        role="admin",
        is_admin=True,
    )
    db_session.add(admin)
    await db_session.commit()
    await db_session.refresh(admin)
    return admin


async def _create_analyst(db_session: AsyncSession) -> User:
    analyst = User(
        email="analyst@test.com",
        hashed_password=hash_password("password123"),
        full_name="Analyst User",
        tenant_id="rbac-analyst-tenant",
        plan="pro",
        role="analyst",
        is_admin=False,
    )
    db_session.add(analyst)
    await db_session.commit()
    await db_session.refresh(analyst)
    return analyst


async def _create_viewer(db_session: AsyncSession) -> User:
    viewer = User(
        email="viewer@test.com",
        hashed_password=hash_password("password123"),
        full_name="Viewer User",
        tenant_id="rbac-viewer-tenant",
        plan="free",
        role="viewer",
        is_admin=False,
    )
    db_session.add(viewer)
    await db_session.commit()
    await db_session.refresh(viewer)
    return viewer


async def _login(client: AsyncClient, email: str) -> dict:
    resp = await client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": "password123"},
    )
    assert resp.status_code == 200
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


# ---------------------------------------------------------------------------
# Role field tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_assigns_viewer_role(client: AsyncClient) -> None:
    """New users default to the 'viewer' role."""
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": "roleuser@test.com", "password": "password123", "full_name": "Role"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["role"] == "viewer"
    assert data["is_admin"] is False


@pytest.mark.asyncio
async def test_admin_can_access_audit_export(client: AsyncClient, db_session: AsyncSession) -> None:
    """Admin role can access audit export endpoint."""
    await _create_admin(db_session)
    headers = await _login(client, "adminrbac@test.com")

    resp = await client.get("/api/v1/admin/audit/export", headers=headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_analyst_cannot_access_admin_audit(client: AsyncClient, db_session: AsyncSession) -> None:
    """Analyst role cannot access admin-only audit export."""
    await _create_analyst(db_session)
    headers = await _login(client, "analyst@test.com")

    resp = await client.get("/api/v1/admin/audit/export", headers=headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_access_admin_audit(client: AsyncClient, db_session: AsyncSession) -> None:
    """Viewer role cannot access admin-only audit export."""
    await _create_viewer(db_session)
    headers = await _login(client, "viewer@test.com")

    resp = await client.get("/api/v1/admin/audit/export", headers=headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_can_access_admin_security(client: AsyncClient, db_session: AsyncSession) -> None:
    """Admin can access admin security incident list."""
    await _create_admin(db_session)
    headers = await _login(client, "adminrbac@test.com")

    resp = await client.get("/api/v1/admin/security/incidents", headers=headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_analyst_cannot_access_admin_security(client: AsyncClient, db_session: AsyncSession) -> None:
    """Analyst role cannot access admin security endpoints."""
    await _create_analyst(db_session)
    headers = await _login(client, "analyst@test.com")

    resp = await client.get("/api/v1/admin/security/incidents", headers=headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# UserOut exposes role
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_me_endpoint_returns_role(client: AsyncClient, auth_headers: dict) -> None:
    """GET /me returns the role field."""
    resp = await client.get("/api/v1/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "role" in data
    assert data["role"] in ("viewer", "analyst", "admin")


# ---------------------------------------------------------------------------
# Session timeout (forced re-auth)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_session_timeout_forces_reauth(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """A token issued more than SESSION_TIMEOUT_HOURS ago triggers 419."""
    from app.services.auth import create_access_token

    admin = await _create_admin(db_session)

    # Create a token with an old iat (simulate 25h-old session)
    from datetime import datetime, timedelta, timezone
    from jose import jwt

    settings = get_settings()
    now = datetime.now(tz=timezone.utc)
    old_time = now - timedelta(hours=25)
    payload = {
        "sub": str(admin.id),
        "email": admin.email,
        "tenant_id": admin.tenant_id,
        "iat": old_time,
        "exp": now + timedelta(hours=1),
    }
    old_token = jwt.encode(payload, settings.jwt_secret, algorithm="HS256")
    headers = {"Authorization": f"Bearer {old_token}"}

    # The health endpoint doesn't require auth, so use scan which does
    resp = await client.post(
        "/api/v1/scan/text",
        json={"text": "hello"},
        headers=headers,
    )
    assert resp.status_code == 419


@pytest.mark.asyncio
async def test_recent_token_passes_session_timeout(
    client: AsyncClient,
    auth_headers: dict,
) -> None:
    """A token issued recently passes the session timeout check."""
    # auth_headers fixture logs in fresh, so the token is recent
    from unittest.mock import patch

    def _mock_run_ner(text: str) -> list:
        return []

    with patch("app.services.ner_model.run_ner", side_effect=_mock_run_ner):
        resp = await client.post(
            "/api/v1/scan/text",
            json={"text": "hello world"},
            headers=auth_headers,
        )
    assert resp.status_code == 200
