"""Tests for scheduled scans API and tasks."""
from __future__ import annotations

import pytest
from fastapi import status
from httpx import AsyncClient

from app.db.models import ScheduledScan, User


@pytest.fixture
async def scheduled_scan(db_session, test_user):
    """Create a scheduled scan for testing."""
    job = ScheduledScan(
        user_id=test_user.id,
        tenant_id=test_user.tenant_id,
        name="Test Scheduled Scan",
        scan_type="text",
        target="Test content with 42101-1234567-1 CNIC",
        schedule_cron="0 9 * * *",
        is_active=True,
    )
    db_session.add(job)
    await db_session.commit()
    await db_session.refresh(job)
    return job


class TestScheduledScanAPI:
    """Test scheduled scan CRUD API."""

    @pytest.mark.asyncio
    async def test_create_scheduled_scan(self, client: AsyncClient, auth_headers):
        """Can create a scheduled scan."""
        payload = {
            "name": "Daily CNIC Check",
            "scan_type": "text",
            "target": "Test content with CNIC 42101-1234567-1",
            "schedule_cron": "0 9 * * *",
        }

        response = await client.post(
            "/api/v1/scheduled/jobs",
            json=payload,
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["name"] == payload["name"]
        assert data["scan_type"] == payload["scan_type"]
        assert data["schedule_cron"] == payload["schedule_cron"]
        assert data["is_active"] is True
        assert "job_id" in data

    @pytest.mark.asyncio
    async def test_list_scheduled_scans(self, client: AsyncClient, auth_headers, scheduled_scan):
        """Can list scheduled scans."""
        response = await client.get(
            "/api/v1/scheduled/jobs",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total"] >= 1
        assert len(data["items"]) >= 1
        assert data["items"][0]["name"] == scheduled_scan.name

    @pytest.mark.asyncio
    async def test_delete_scheduled_scan(self, client: AsyncClient, auth_headers, scheduled_scan):
        """Can delete a scheduled scan."""
        response = await client.delete(
            f"/api/v1/scheduled/jobs/{scheduled_scan.job_id}",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT

    @pytest.mark.asyncio
    async def test_toggle_scheduled_scan(self, client: AsyncClient, auth_headers, scheduled_scan):
        """Can toggle scheduled scan active state."""
        # Toggle off
        response = await client.post(
            f"/api/v1/scheduled/jobs/{scheduled_scan.job_id}/toggle",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["is_active"] is False

        # Toggle back on
        response = await client.post(
            f"/api/v1/scheduled/jobs/{scheduled_scan.job_id}/toggle",
            headers=auth_headers,
        )

        data = response.json()
        assert data["is_active"] is True

    @pytest.mark.asyncio
    async def test_run_now_scheduled_scan(self, client: AsyncClient, auth_headers, scheduled_scan):
        """Can manually trigger a scheduled scan."""
        response = await client.post(
            f"/api/v1/scheduled/jobs/{scheduled_scan.job_id}/run-now",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "Scan executed successfully."
        assert "scan_id" in data
        assert "severity" in data

    @pytest.mark.asyncio
    async def test_cannot_access_other_users_scheduled_scan(
        self, client: AsyncClient, auth_headers, db_session
    ):
        """Cannot access scheduled scans of other users."""
        # Create another user and their scan
        other_user = User(
            email="other@test.com",
            hashed_password="hashed",
            tenant_id="other-tenant",
        )
        db_session.add(other_user)
        await db_session.flush()

        other_scan = ScheduledScan(
            user_id=other_user.id,
            tenant_id=other_user.tenant_id,
            name="Other User Scan",
            scan_type="text",
            target="test",
            schedule_cron="0 9 * * *",
        )
        db_session.add(other_scan)
        await db_session.commit()
        await db_session.refresh(other_scan)

        # Try to delete other user's scan
        response = await client.delete(
            f"/api/v1/scheduled/jobs/{other_scan.job_id}",
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestScheduledScanValidation:
    """Test scheduled scan input validation."""

    @pytest.mark.asyncio
    async def test_invalid_scan_type_rejected(self, client: AsyncClient, auth_headers):
        """Invalid scan type is rejected."""
        payload = {
            "name": "Test",
            "scan_type": "invalid_type",
            "target": "test",
            "schedule_cron": "0 9 * * *",
        }

        response = await client.post(
            "/api/v1/scheduled/jobs",
            json=payload,
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_missing_name_rejected(self, client: AsyncClient, auth_headers):
        """Missing name is rejected."""
        payload = {
            "scan_type": "text",
            "target": "test",
            "schedule_cron": "0 9 * * *",
        }

        response = await client.post(
            "/api/v1/scheduled/jobs",
            json=payload,
            headers=auth_headers,
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
