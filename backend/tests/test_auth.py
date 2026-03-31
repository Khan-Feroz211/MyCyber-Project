from __future__ import annotations

"""Tests for authentication endpoints.

Run with:  pytest backend/tests/test_auth.py -v
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_success(client: AsyncClient) -> None:
    """POST /register with valid data returns 201 and correct fields."""
    resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@example.com",
            "password": "securepass",
            "full_name": "Alice Smith",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "alice@example.com"
    assert data["plan"] == "free"
    assert "tenant_id" in data
    assert len(data["tenant_id"]) == 36  # UUID format
    assert data["is_active"] is True
    # Password must never be exposed
    assert "hashed_password" not in data
    assert "password" not in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient) -> None:
    """Registering the same email twice returns 409 Conflict."""
    payload = {
        "email": "bob@example.com",
        "password": "securepass",
        "full_name": "Bob",
    }
    first = await client.post("/api/v1/auth/register", json=payload)
    assert first.status_code == 201

    second = await client.post("/api/v1/auth/register", json=payload)
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_register_weak_password(client: AsyncClient) -> None:
    """Passwords shorter than 8 characters are rejected with 422."""
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": "weak@example.com", "password": "short", "full_name": "Weak"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient) -> None:
    """Valid credentials return 200 with access_token and embedded UserOut."""
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "carol@example.com",
            "password": "goodpassword",
            "full_name": "Carol",
        },
    )
    resp = await client.post(
        "/api/v1/auth/login",
        data={"username": "carol@example.com", "password": "goodpassword"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == "carol@example.com"


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient) -> None:
    """Wrong password returns 401 Unauthorized."""
    await client.post(
        "/api/v1/auth/register",
        json={"email": "dave@example.com", "password": "correct123", "full_name": "Dave"},
    )
    resp = await client.post(
        "/api/v1/auth/login",
        data={"username": "dave@example.com", "password": "wrongpassword"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_me_endpoint(client: AsyncClient, auth_headers: dict) -> None:
    """GET /me returns the authenticated user's profile."""
    resp = await client.get("/api/v1/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "user@test.com"
    assert "tenant_id" in data
    assert "hashed_password" not in data


@pytest.mark.asyncio
async def test_protected_without_token(client: AsyncClient) -> None:
    """Scan endpoint returns 401 when no Bearer token is provided."""
    resp = await client.post(
        "/api/v1/scan/text",
        json={"text": "hello world"},
    )
    assert resp.status_code == 401
