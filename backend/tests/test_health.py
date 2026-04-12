"""Tests for health, metrics, and model-info endpoints."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_ok(client: AsyncClient) -> None:
    """GET /health returns 200 with required fields."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("ok", "degraded")
    assert "uptime_seconds" in data
    assert "scanners_loaded" in data
    # "text" is always present in the scanner registry
    assert "text" in data["scanners_loaded"]


@pytest.mark.asyncio
async def test_metrics_endpoint(client: AsyncClient) -> None:
    """GET /metrics returns Prometheus text output with expected metric names."""
    response = await client.get("/metrics")
    assert response.status_code == 200
    assert b"mycyber_scan_requests_total" in response.content


@pytest.mark.asyncio
async def test_model_info(client: AsyncClient) -> None:
    """GET /api/v1/scan/models/info returns scanner metadata (no auth required)."""
    response = await client.get("/api/v1/scan/models/info")
    assert response.status_code == 200
    data = response.json()
    assert "ner_model" in data
    assert "regex_patterns_count" in data
