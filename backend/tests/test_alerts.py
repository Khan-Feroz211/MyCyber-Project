from __future__ import annotations

"""Tests for alert creation, listing, acknowledgement, and counting.

NER is stubbed out so no model weights are downloaded.
"""

import pytest
from unittest.mock import patch
from httpx import AsyncClient


def _mock_run_ner(text: str) -> list:
    """Stub NER that always returns no entities."""
    return []


# ---------------------------------------------------------------------------
# Alert creation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_critical_scan_creates_alert(
    client: AsyncClient, auth_headers: dict
) -> None:
    """A CRITICAL scan auto-generates an unacknowledged alert."""
    with patch("app.services.ner_model.run_ner", side_effect=_mock_run_ner):
        scan_resp = await client.post(
            "/api/v1/scan/text",
            json={"text": "CNIC: 42101-1234567-1"},
            headers=auth_headers,
        )
    assert scan_resp.status_code == 200

    alerts = await client.get("/api/v1/alerts", headers=auth_headers)
    assert alerts.status_code == 200
    data = alerts.json()
    assert data["unacknowledged"] >= 1
    assert data["alerts"][0]["severity"] in ("CRITICAL", "HIGH")


@pytest.mark.asyncio
async def test_safe_scan_no_alert(
    client: AsyncClient, auth_headers: dict
) -> None:
    """A SAFE scan does not create any alerts."""
    with patch("app.services.ner_model.run_ner", side_effect=_mock_run_ner):
        await client.post(
            "/api/v1/scan/text",
            json={"text": "Hello world, nothing sensitive here."},
            headers=auth_headers,
        )
    alerts = await client.get("/api/v1/alerts", headers=auth_headers)
    assert alerts.status_code == 200
    assert alerts.json()["unacknowledged"] == 0


# ---------------------------------------------------------------------------
# Alert acknowledgement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_acknowledge_alert(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Acknowledging an alert marks it as acknowledged and removes it from the unack count."""
    with patch("app.services.ner_model.run_ner", side_effect=_mock_run_ner):
        await client.post(
            "/api/v1/scan/text",
            json={"text": "CNIC: 42101-1234567-1"},
            headers=auth_headers,
        )

    alerts_resp = await client.get("/api/v1/alerts", headers=auth_headers)
    assert alerts_resp.status_code == 200
    alert_id = alerts_resp.json()["alerts"][0]["alert_id"]

    ack = await client.post(
        "/api/v1/alerts/acknowledge",
        json={"alert_id": alert_id},
        headers=auth_headers,
    )
    assert ack.status_code == 200
    assert ack.json()["is_acknowledged"] is True

    alerts_after = await client.get("/api/v1/alerts", headers=auth_headers)
    assert alerts_after.status_code == 200
    assert alerts_after.json()["unacknowledged"] == 0


# ---------------------------------------------------------------------------
# Alert count
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alert_count_endpoint(
    client: AsyncClient, auth_headers: dict
) -> None:
    """GET /api/v1/alerts/count returns a JSON object with an 'unacknowledged' key."""
    response = await client.get("/api/v1/alerts/count", headers=auth_headers)
    assert response.status_code == 200
    assert "unacknowledged" in response.json()
