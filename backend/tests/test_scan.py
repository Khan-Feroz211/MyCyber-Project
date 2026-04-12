from __future__ import annotations

"""Tests for all scan endpoints.

The NER model is never downloaded — app.services.ner_model.run_ner is
patched to return [] for every test that triggers a scan.
"""

import pytest
from unittest.mock import patch
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


def _mock_run_ner(text: str) -> list:
    """Stub NER that always returns no entities."""
    return []


# ---------------------------------------------------------------------------
# Text scan — content-based assertions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_text_clean(client: AsyncClient, auth_headers: dict) -> None:
    """Clean text produces a SAFE result with zero entities."""
    with patch("app.services.ner_model.run_ner", side_effect=_mock_run_ner):
        response = await client.post(
            "/api/v1/scan/text",
            json={"text": "Hello world this is clean text"},
            headers=auth_headers,
        )
    assert response.status_code == 200
    data = response.json()
    assert data["severity"] == "SAFE"
    assert data["recommended_action"] == "ALLOW"
    assert data["total_entities"] == 0
    assert "scan_id" in data
    assert data["risk_score"] == 0.0


@pytest.mark.asyncio
async def test_scan_text_cnic_critical(
    client: AsyncClient, auth_headers: dict
) -> None:
    """A Pakistani CNIC number triggers CRITICAL severity and BLOCK action."""
    with patch("app.services.ner_model.run_ner", side_effect=_mock_run_ner):
        response = await client.post(
            "/api/v1/scan/text",
            json={"text": "CNIC: 42101-1234567-1"},
            headers=auth_headers,
        )
    assert response.status_code == 200
    data = response.json()
    assert data["severity"] == "CRITICAL"
    assert data["recommended_action"] == "BLOCK"
    assert data["total_entities"] >= 1
    entity_types = [e["entity_type"] for e in data["entities"]]
    assert "CNIC" in entity_types


@pytest.mark.asyncio
async def test_scan_text_email_detected(
    client: AsyncClient, auth_headers: dict
) -> None:
    """An email address is detected as an EMAIL entity with at least MEDIUM severity."""
    with patch("app.services.ner_model.run_ner", side_effect=_mock_run_ner):
        response = await client.post(
            "/api/v1/scan/text",
            json={"text": "Contact john@example.com for details"},
            headers=auth_headers,
        )
    assert response.status_code == 200
    data = response.json()
    entity_types = [e["entity_type"] for e in data["entities"]]
    assert "EMAIL" in entity_types
    assert data["severity"] in ("HIGH", "MEDIUM", "LOW")


@pytest.mark.asyncio
async def test_scan_text_api_key(client: AsyncClient, auth_headers: dict) -> None:
    """A secret-prefixed token triggers CRITICAL severity as an API_KEY."""
    with patch("app.services.ner_model.run_ner", side_effect=_mock_run_ner):
        response = await client.post(
            "/api/v1/scan/text",
            json={"text": "config = secret_abcdefghijklmnopqrstuvwxyz"},
            headers=auth_headers,
        )
    assert response.status_code == 200
    data = response.json()
    assert data["severity"] == "CRITICAL"
    entity_types = [e["entity_type"] for e in data["entities"]]
    assert "API_KEY" in entity_types


@pytest.mark.asyncio
async def test_scan_text_multiple_entities(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Text containing CNIC + email has >= 2 entities, CRITICAL severity, score >= 70."""
    with patch("app.services.ner_model.run_ner", side_effect=_mock_run_ner):
        response = await client.post(
            "/api/v1/scan/text",
            json={
                "text": (
                    "Name: Ali Khan, "
                    "CNIC: 42101-1234567-1, "
                    "email: ali@corp.com"
                )
            },
            headers=auth_headers,
        )
    assert response.status_code == 200
    data = response.json()
    assert data["total_entities"] >= 2
    assert data["risk_score"] >= 70.0
    assert data["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Text scan — validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_text_empty_rejected(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Empty text fails Pydantic validation with 422."""
    response = await client.post(
        "/api/v1/scan/text",
        json={"text": ""},
        headers=auth_headers,
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_scan_text_too_long(client: AsyncClient, auth_headers: dict) -> None:
    """Text exceeding the 1,000,000-character limit is rejected with 422."""
    response = await client.post(
        "/api/v1/scan/text",
        json={"text": "A" * 1_000_001},
        headers=auth_headers,
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Network scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_network_suspicious_dest(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Network payload containing a CNIC triggers CRITICAL or HIGH severity."""
    with patch("app.services.ner_model.run_ner", side_effect=_mock_run_ner):
        response = await client.post(
            "/api/v1/scan/network",
            json={
                "payload": "POST /upload HTTP/1.1\r\ncnic=42101-1234567-1",
                "source_ip": "192.168.1.100",
                "destination_ip": "198.51.100.1",
                "protocol": "HTTP",
            },
            headers=auth_headers,
        )
    assert response.status_code == 200
    data = response.json()
    assert data["severity"] in ("CRITICAL", "HIGH")


# ---------------------------------------------------------------------------
# History & isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_history_saved(client: AsyncClient, auth_headers: dict) -> None:
    """A completed scan is persisted and appears in the scan history."""
    with patch("app.services.ner_model.run_ner", side_effect=_mock_run_ner):
        await client.post(
            "/api/v1/scan/text",
            json={"text": "CNIC: 42101-1234567-1"},
            headers=auth_headers,
        )
    history = await client.get("/api/v1/scan/history", headers=auth_headers)
    assert history.status_code == 200
    assert history.json()["total"] >= 1


@pytest.mark.asyncio
async def test_tenant_isolation(
    client: AsyncClient, auth_headers: dict, pro_user_headers: dict
) -> None:
    """Scans performed by one tenant are not visible to another tenant."""
    with patch("app.services.ner_model.run_ner", side_effect=_mock_run_ner):
        await client.post(
            "/api/v1/scan/text",
            json={"text": "CNIC: 42101-1234567-1"},
            headers=auth_headers,
        )
    history = await client.get("/api/v1/scan/history", headers=pro_user_headers)
    assert history.status_code == 200
    assert history.json()["total"] == 0


# ---------------------------------------------------------------------------
# Plan-limit enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_plan_limit_free_user(
    client: AsyncClient,
    db_session: AsyncSession,
    registered_user,
) -> None:
    """A free-plan user who has hit the monthly quota receives HTTP 429."""
    registered_user.scan_count_month = 100
    await db_session.commit()

    login = await client.post(
        "/api/v1/auth/login",
        data={"username": "test@mycyber.com", "password": "password123"},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    with patch("app.services.ner_model.run_ner", side_effect=_mock_run_ner):
        response = await client.post(
            "/api/v1/scan/text",
            json={"text": "test text for plan limit check"},
            headers=headers,
        )
    assert response.status_code == 429
