"""Tests for ingestion service."""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch, MagicMock


@pytest.fixture()
def client():
    import sys
    sys.modules.setdefault("opentelemetry.exporter.otlp.proto.grpc.trace_exporter", MagicMock())
    sys.modules.setdefault("opentelemetry.instrumentation.fastapi", MagicMock())
    with patch("redis.asyncio.from_url", return_value=AsyncMock()):
        from services.ingestion.main import app
        app.state.redis = AsyncMock()
        app.state.redis.lpush = AsyncMock(return_value=1)
        with TestClient(app) as c:
            yield c


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_receive_event_queued(client):
    payload = {
        "tenant_id": "tenant-1",
        "endpoint_id": "host-1",
        "file_path": "/tmp/test.txt",
        "file_content": "Hello world",
        "file_size_bytes": 11,
    }
    resp = client.post("/events", json=payload)
    assert resp.status_code == 202
    assert "scan_id" in resp.json()
    assert resp.json()["status"] == "queued"
