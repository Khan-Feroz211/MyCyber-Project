"""Tests for the immutable, hash-chained audit log service and router.

Run with:  pytest backend/tests/test_audit_log.py -v
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient


# ---------------------------------------------------------------------------
# Service-layer tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_append_audit_log_creates_entry(db_session, registered_user) -> None:
    """append_audit_log writes a single entry with hash chaining."""
    from app.services.audit_log import append_audit_log, EVENT_SCAN

    entry = await append_audit_log(
        db=db_session,
        event_type=EVENT_SCAN,
        resource_type="scan_record",
        resource_id="test-scan-001",
        action="create",
        tenant_id=registered_user.tenant_id,
        actor=registered_user,
        details={"scan_type": "text", "severity": "SAFE"},
    )
    await db_session.commit()

    assert entry.entry_id is not None
    assert entry.event_type == EVENT_SCAN
    assert entry.resource_type == "scan_record"
    assert entry.action == "create"
    assert entry.tenant_id == registered_user.tenant_id
    assert entry.actor_id == registered_user.id
    assert entry.severity == "INFO"
    # First entry has GENESIS as previous_hash
    assert entry.previous_hash == "GENESIS"
    # entry_hash is a 64-char hex string
    assert len(entry.entry_hash) == 64
    assert entry.key_version == 1


@pytest.mark.asyncio
async def test_hash_chaining_between_entries(db_session, registered_user) -> None:
    """The second entry's previous_hash must equal the first entry's entry_hash."""
    from app.services.audit_log import append_audit_log, EVENT_SCAN

    entry1 = await append_audit_log(
        db=db_session,
        event_type=EVENT_SCAN,
        resource_type="scan_record",
        action="create",
        tenant_id=registered_user.tenant_id,
        actor=registered_user,
    )
    entry2 = await append_audit_log(
        db=db_session,
        event_type=EVENT_SCAN,
        resource_type="scan_record",
        action="create",
        tenant_id=registered_user.tenant_id,
        actor=registered_user,
    )
    await db_session.commit()

    assert entry2.previous_hash == entry1.entry_hash


@pytest.mark.asyncio
async def test_verify_chain_valid(db_session, registered_user) -> None:
    """verify_chain returns valid=True for an unbroken chain."""
    from app.services.audit_log import append_audit_log, verify_chain, EVENT_SCAN

    for i in range(3):
        await append_audit_log(
            db=db_session,
            event_type=EVENT_SCAN,
            resource_type="scan_record",
            action="create",
            tenant_id=registered_user.tenant_id,
            actor=registered_user,
            details={"seq": i},
        )
    await db_session.commit()

    result = await verify_chain(db_session, tenant_id=registered_user.tenant_id)
    assert result["valid"] is True
    assert result["entries_checked"] == 3
    assert result["details"] == []


@pytest.mark.asyncio
async def test_verify_chain_detects_tampering(db_session, registered_user) -> None:
    """verify_chain detects a corrupted entry_hash."""
    from app.services.audit_log import append_audit_log, verify_chain, EVENT_SCAN

    e1 = await append_audit_log(
        db=db_session,
        event_type=EVENT_SCAN,
        resource_type="scan_record",
        action="create",
        tenant_id=registered_user.tenant_id,
        actor=registered_user,
    )
    await db_session.flush()

    # Tamper with the entry hash
    e1.entry_hash = "tampered" + "a" * 56
    await db_session.flush()

    result = await verify_chain(db_session, tenant_id=registered_user.tenant_id)
    assert result["valid"] is False
    assert len(result["details"]) >= 1


@pytest.mark.asyncio
async def test_export_audit_log(db_session, registered_user) -> None:
    """export_audit_log returns entries as plain dicts."""
    from app.services.audit_log import append_audit_log, export_audit_log, EVENT_SCAN

    await append_audit_log(
        db=db_session,
        event_type=EVENT_SCAN,
        resource_type="scan_record",
        action="create",
        tenant_id=registered_user.tenant_id,
        actor=registered_user,
        details={"test": True},
    )
    await db_session.commit()

    entries = await export_audit_log(
        db=db_session,
        tenant_id=registered_user.tenant_id,
        page=1,
        page_size=100,
    )
    assert len(entries) == 1
    assert entries[0]["event_type"] == EVENT_SCAN
    assert entries[0]["action"] == "create"
    assert entries[0]["actor_id"] == registered_user.id
    assert "details" in entries[0]
    assert entries[0]["details"]["test"] is True


# ---------------------------------------------------------------------------
# Router-level tests (integration via HTTP)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_export_requires_admin(client: AsyncClient, auth_headers: dict) -> None:
    """Non-admin users get 403 on audit export."""
    resp = await client.get("/api/v1/admin/audit/export", headers=auth_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_audit_export_admin_ok(client: AsyncClient, db_session) -> None:
    """An admin user can export audit logs as JSON."""
    from app.db.models import User
    from app.services.auth import hash_password

    admin = User(
        email="admin@test.com",
        hashed_password=hash_password("password123"),
        full_name="Admin",
        tenant_id="admin-tenant-001",
        plan="enterprise",
        role="admin",
        is_admin=True,
    )
    db_session.add(admin)
    await db_session.commit()
    await db_session.refresh(admin)

    resp = await client.post(
        "/api/v1/auth/login",
        data={"username": "admin@test.com", "password": "password123"},
    )
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.get("/api/v1/admin/audit/export", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "entries" in data
    assert "total" in data
    assert "page" in data


@pytest.mark.asyncio
async def test_audit_export_csv_admin(client: AsyncClient, db_session) -> None:
    """Admin can download CSV export."""
    from app.db.models import User
    from app.services.auth import hash_password

    admin = User(
        email="admincsv@test.com",
        hashed_password=hash_password("password123"),
        full_name="Admin CSV",
        tenant_id="admin-tenant-002",
        plan="enterprise",
        role="admin",
        is_admin=True,
    )
    db_session.add(admin)
    await db_session.commit()
    await db_session.refresh(admin)

    resp = await client.post(
        "/api/v1/auth/login",
        data={"username": "admincsv@test.com", "password": "password123"},
    )
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.get("/api/v1/admin/audit/export/csv", headers=headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")


@pytest.mark.asyncio
async def test_audit_verify_chain(client: AsyncClient, db_session) -> None:
    """Admin can verify the audit chain integrity."""
    from app.db.models import User
    from app.services.auth import hash_password

    admin = User(
        email="adminverify@test.com",
        hashed_password=hash_password("password123"),
        full_name="Admin Verify",
        tenant_id="admin-tenant-003",
        plan="enterprise",
        role="admin",
        is_admin=True,
    )
    db_session.add(admin)
    await db_session.commit()
    await db_session.refresh(admin)

    resp = await client.post(
        "/api/v1/auth/login",
        data={"username": "adminverify@test.com", "password": "password123"},
    )
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.get("/api/v1/admin/audit/verify", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "valid" in data
    assert "entries_checked" in data


@pytest.mark.asyncio
async def test_scan_creates_audit_entry(client: AsyncClient, auth_headers: dict, db_session) -> None:
    """A successful scan writes an audit log entry."""
    from unittest.mock import patch
    from sqlalchemy import select
    from app.db.models import AuditLogEntry

    def _mock_run_ner(text: str) -> list:
        return []

    with patch("app.services.ner_model.run_ner", side_effect=_mock_run_ner):
        scan_resp = await client.post(
            "/api/v1/scan/text",
            json={"text": "Hello world, this is clean"},
            headers=auth_headers,
        )
    assert scan_resp.status_code == 200

    # Check audit log was written
    result = await db_session.execute(
        select(AuditLogEntry).where(AuditLogEntry.event_type == "scan_created")
    )
    entries = result.scalars().all()
    assert len(entries) >= 1
    assert entries[0].action == "create"
    assert entries[0].resource_type == "scan_record"
    assert entries[0].previous_hash == "GENESIS" or len(entries[0].previous_hash) == 64
