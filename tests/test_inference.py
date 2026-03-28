"""Tests for ML inference service."""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch


@pytest.fixture()
def client():
    import sys
    sys.modules.setdefault("opentelemetry.exporter.otlp.proto.grpc.trace_exporter", MagicMock())
    sys.modules.setdefault("opentelemetry.instrumentation.fastapi", MagicMock())
    with patch("services.ml-inference.main.joblib", MagicMock()):
        from services.ml_inference.main import app
        app.state.model = None
        with TestClient(app) as c:
            yield c


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200


def test_scan_clean(client):
    resp = client.post("/scan", json={
        "scan_id": "test-001",
        "tenant_id": "t1",
        "content": "The quick brown fox jumped over the lazy dog.",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["label"] == "CLEAN"
    assert data["confidence"] > 0.9


def test_scan_pii_email(client):
    resp = client.post("/scan", json={
        "scan_id": "test-002",
        "tenant_id": "t1",
        "content": "Contact John at john.doe@example.com for details.",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["label"] != "CLEAN"
    assert "email" in data["pii_types"]
