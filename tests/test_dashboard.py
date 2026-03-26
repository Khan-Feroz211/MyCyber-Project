"""Tests for dashboard-api auth and routes."""
import os
import pytest

os.environ.setdefault("JWT_SECRET", "test-secret-key-for-testing-only")

from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    import sys
    sys.modules.setdefault("opentelemetry.exporter.otlp.proto.grpc.trace_exporter", MagicMock())
    sys.modules.setdefault("opentelemetry.instrumentation.fastapi", MagicMock())
    with patch("redis.asyncio.from_url", return_value=AsyncMock()):
        from services.dashboard_api.main import app
        app.state.redis = AsyncMock()
        with TestClient(app) as c:
            yield c


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200


def test_login_returns_token(client):
    resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "test"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_scans_requires_auth(client):
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 403


def test_scans_with_token(client):
    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "test"})
    token = login.json()["access_token"]
    resp = client.get("/api/v1/scans", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
