"""Tests for the health endpoint."""
import sys
import os

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _get_app():
    from unittest.mock import MagicMock, patch
    from app.services import ner_model as ner_module

    ner_module._pipeline = MagicMock()
    from app.main import app

    return app


def test_health_endpoint():
    app = _get_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"


def test_root_endpoint():
    app = _get_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.json()["service"] == "MyCyber DLP"
