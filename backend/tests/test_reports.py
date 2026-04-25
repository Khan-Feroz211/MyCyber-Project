"""Tests for reports API (CSV and HTML export)."""
from __future__ import annotations

import csv
import io

import pytest
from fastapi import status
from httpx import AsyncClient

from app.db.models import ScanRecord, User


class TestCSVExport:
    """Test CSV report export."""

    @pytest.mark.asyncio
    async def test_export_csv_empty(self, client: AsyncClient, auth_headers):
        """Can export empty CSV when no scans."""
        response = await client.get(
            "/api/v1/reports/export/csv",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.headers["content-type"] == "text/csv; charset=utf-8"
        assert "attachment" in response.headers["content-disposition"]

        # Parse CSV
        content = response.content.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)

        # Should have header row
        assert len(rows) >= 1
        assert rows[0][0] == "scan_id"

    @pytest.mark.asyncio
    async def test_export_csv_with_data(self, client: AsyncClient, auth_headers, db_session, test_user):
        """CSV export includes scan data."""
        # Create a scan record
        scan = ScanRecord(
            user_id=test_user.id,
            tenant_id=test_user.tenant_id,
            scan_id="test-scan-123",
            scan_type="text",
            severity="CRITICAL",
            risk_score=85.0,
            total_entities=3,
            recommended_action="REVIEW",
            summary="Test scan with CNIC",
            entities_json="[]",
            input_preview="test content",
            scan_duration_ms=150.0,
        )
        db_session.add(scan)
        await db_session.commit()

        response = await client.get(
            "/api/v1/reports/export/csv",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_200_OK
        content = response.content.decode("utf-8-sig")
        assert "test-scan-123" in content
        assert "CRITICAL" in content

    @pytest.mark.asyncio
    async def test_export_csv_with_severity_filter(self, client: AsyncClient, auth_headers):
        """Can filter CSV export by severity."""
        response = await client.get(
            "/api/v1/reports/export/csv?severity=CRITICAL",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_export_csv_with_scan_type_filter(self, client: AsyncClient, auth_headers):
        """Can filter CSV export by scan type."""
        response = await client.get(
            "/api/v1/reports/export/csv?scan_type=text",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_export_csv_requires_auth(self, client: AsyncClient):
        """CSV export requires authentication."""
        response = await client.get("/api/v1/reports/export/csv")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestHTMLExport:
    """Test HTML report export."""

    @pytest.mark.asyncio
    async def test_export_html(self, client: AsyncClient, auth_headers):
        """Can export HTML report."""
        response = await client.get(
            "/api/v1/reports/export/html",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.headers["content-type"] == "text/html; charset=utf-8"

        content = response.text
        assert "<!DOCTYPE html>" in content
        assert "MyCyber DLP" in content
        assert "Scan Report" in content

    @pytest.mark.asyncio
    async def test_export_html_with_filters(self, client: AsyncClient, auth_headers):
        """Can filter HTML export."""
        response = await client.get(
            "/api/v1/reports/export/html?severity=HIGH&scan_type=file",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_200_OK
        assert "<!DOCTYPE html>" in response.text

    @pytest.mark.asyncio
    async def test_export_html_requires_auth(self, client: AsyncClient):
        """HTML export requires authentication."""
        response = await client.get("/api/v1/reports/export/html")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestReportPagination:
    """Test report export limits."""

    @pytest.mark.asyncio
    async def test_csv_respects_limit_parameter(self, client: AsyncClient, auth_headers):
        """CSV export respects the limit parameter."""
        response = await client.get(
            "/api/v1/reports/export/csv?limit=5",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_csv_limit_validation(self, client: AsyncClient, auth_headers):
        """CSV export validates limit parameter."""
        # Limit too high
        response = await client.get(
            "/api/v1/reports/export/csv?limit=10000",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Limit too low
        response = await client.get(
            "/api/v1/reports/export/csv?limit=0",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
