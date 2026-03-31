from __future__ import annotations

"""Tests for scan history, alerts, tenant isolation, and plan limits.

Run with:  pytest backend/tests/test_scan_history.py -v
"""

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import User

# ---------------------------------------------------------------------------
# Test payloads
# ---------------------------------------------------------------------------

# Contains no sensitive data → SAFE severity
_SAFE_TEXT = "The quick brown fox jumps over the lazy dog."

# Contains an API key pattern → CRITICAL severity (API_KEY entity type)
_CRITICAL_TEXT = "sk_" + "a" * 30


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _do_scan(client: AsyncClient, headers: dict, text: str = _SAFE_TEXT) -> None:
    resp = await client.post(
        "/api/v1/scan/text",
        json={"text": text},
        headers=headers,
    )
    assert resp.status_code == 200, f"Scan failed: {resp.text}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_saved_after_scan(
    client: AsyncClient,
    auth_headers: dict,
) -> None:
    """After one scan the history endpoint returns exactly 1 item."""
    await _do_scan(client, auth_headers)

    resp = await client.get("/api/v1/scan/history", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert len(data["items"]) == 1
    assert "scan_id" in data["items"][0]


@pytest.mark.asyncio
async def test_history_pagination(
    client: AsyncClient,
    auth_headers: dict,
) -> None:
    """5 scans with page_size=3 gives has_more=True on page 1."""
    for _ in range(5):
        await _do_scan(client, auth_headers)

    resp = await client.get(
        "/api/v1/scan/history?page=1&page_size=3",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 3
    assert data["has_more"] is True
    assert data["total"] == 5


@pytest.mark.asyncio
async def test_history_severity_filter(
    client: AsyncClient,
    auth_headers: dict,
) -> None:
    """Filtering history by CRITICAL returns only CRITICAL-severity items."""
    await _do_scan(client, auth_headers, _SAFE_TEXT)
    await _do_scan(client, auth_headers, _CRITICAL_TEXT)

    resp = await client.get(
        "/api/v1/scan/history?severity=CRITICAL",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    for item in data["items"]:
        assert item["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_tenant_isolation(
    client: AsyncClient,
    auth_headers: dict,
) -> None:
    """user_b cannot see scan records created by user_a."""
    # user_a (auth_headers) performs a scan
    await _do_scan(client, auth_headers)

    # Register and login user_b
    await client.post(
        "/api/v1/auth/register",
        json={"email": "userb@tenant-iso.com", "password": "password123", "full_name": "B"},
    )
    resp_b = await client.post(
        "/api/v1/auth/login",
        data={"username": "userb@tenant-iso.com", "password": "password123"},
    )
    headers_b = {"Authorization": f"Bearer {resp_b.json()['access_token']}"}

    resp = await client.get("/api/v1/scan/history", headers=headers_b)
    assert resp.status_code == 200
    assert resp.json()["total"] == 0


@pytest.mark.asyncio
async def test_critical_creates_alert(
    client: AsyncClient,
    auth_headers: dict,
) -> None:
    """Scanning text with an API key pattern creates a CRITICAL alert."""
    await _do_scan(client, auth_headers, _CRITICAL_TEXT)

    resp = await client.get("/api/v1/alerts", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    severities = {a["severity"] for a in data["alerts"]}
    assert "CRITICAL" in severities


@pytest.mark.asyncio
async def test_acknowledge_alert(
    client: AsyncClient,
    auth_headers: dict,
) -> None:
    """An alert can be acknowledged; the response reflects is_acknowledged=True."""
    await _do_scan(client, auth_headers, _CRITICAL_TEXT)

    alerts_resp = await client.get("/api/v1/alerts", headers=auth_headers)
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()["alerts"]
    assert len(alerts) >= 1
    alert_id = alerts[0]["alert_id"]

    ack_resp = await client.post(
        "/api/v1/alerts/acknowledge",
        json={"alert_id": alert_id},
        headers=auth_headers,
    )
    assert ack_resp.status_code == 200
    assert ack_resp.json()["is_acknowledged"] is True

    # Unacknowledged count should now be 0
    count_resp = await client.get("/api/v1/alerts/count", headers=auth_headers)
    assert count_resp.status_code == 200
    assert count_resp.json()["unacknowledged"] == 0


@pytest.mark.asyncio
async def test_plan_limit_enforcement(
    client: AsyncClient,
    auth_headers: dict,
    db_session: AsyncSession,
) -> None:
    """When scan_count_month equals the plan limit the next scan returns 429."""
    # Directly set the user's monthly scan count to the free-plan limit (100)
    result = await db_session.execute(
        select(User).where(User.email == "user@test.com")
    )
    user = result.scalars().first()
    assert user is not None
    user.scan_count_month = 100
    await db_session.commit()

    resp = await client.post(
        "/api/v1/scan/text",
        json={"text": _SAFE_TEXT},
        headers=auth_headers,
    )
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_stats_summary(
    client: AsyncClient,
    auth_headers: dict,
) -> None:
    """Stats summary returns correct aggregate counts and plan info."""
    await _do_scan(client, auth_headers, _SAFE_TEXT)
    await _do_scan(client, auth_headers, _CRITICAL_TEXT)

    resp = await client.get("/api/v1/scan/stats/summary", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["total_scans"] >= 2
    assert data["critical_scans"] >= 1
    assert data["plan"] == "free"
    assert data["plan_limit"] == 100
    assert "scans_this_month" in data
    assert "safe_scans" in data
    assert "high_scans" in data
