"""Tests for the immutable, hash-chained audit log service and admin router.

Django port of ``backend/tests/test_audit_log.py``.

Run with::

    backend_django/manage.py test tests.test_audit_log --settings=mycyber.settings.test -v2
"""
from __future__ import annotations

from django.test import TestCase
from rest_framework.test import APIClient

from mycyber.services.audit_log import (
    EVENT_LOGIN_FAILED,
    EVENT_LOGIN_SUCCESS,
    EVENT_MFA_TOGGLE,
    EVENT_PASSWORD_RESET,
    EVENT_SCAN,
    append_audit_log,
    export_audit_log,
    verify_chain,
)

from tests.helpers import create_user, get_auth_headers, login_as, parse_json


# ---------------------------------------------------------------------------
# Service-layer tests
# ---------------------------------------------------------------------------


class AuditLogServiceTests(TestCase):
    def setUp(self):
        self.user = create_user("user@test.com", full_name="Audit User")

    def test_append_audit_log_creates_entry(self):
        """append_audit_log writes a single entry with hash chaining."""
        entry = append_audit_log(
            event_type=EVENT_SCAN,
            resource_type="scan_record",
            resource_id="test-scan-001",
            action="create",
            tenant_id=str(self.user.tenant_id),
            actor=self.user,
            details={"scan_type": "text", "severity": "SAFE"},
        )

        self.assertIsNotNone(entry.entry_id)
        self.assertEqual(entry.event_type, EVENT_SCAN)
        self.assertEqual(entry.resource_type, "scan_record")
        self.assertEqual(entry.action, "create")
        self.assertEqual(entry.tenant_id, str(self.user.tenant_id))
        self.assertEqual(entry.actor_id, self.user.id)
        self.assertEqual(entry.severity, "INFO")
        # First entry has GENESIS as previous_hash
        self.assertEqual(entry.previous_hash, "GENESIS")
        # entry_hash is a 64-char hex string
        self.assertEqual(len(entry.entry_hash), 64)
        self.assertEqual(entry.key_version, 1)

    def test_hash_chaining_between_entries(self):
        """The second entry's previous_hash must equal the first entry's entry_hash."""
        entry1 = append_audit_log(
            event_type=EVENT_SCAN,
            resource_type="scan_record",
            action="create",
            tenant_id=str(self.user.tenant_id),
            actor=self.user,
        )
        entry2 = append_audit_log(
            event_type=EVENT_SCAN,
            resource_type="scan_record",
            action="create",
            tenant_id=str(self.user.tenant_id),
            actor=self.user,
        )
        self.assertEqual(entry2.previous_hash, entry1.entry_hash)

    def test_verify_chain_valid(self):
        """verify_chain returns valid=True for an unbroken chain."""
        for i in range(3):
            append_audit_log(
                event_type=EVENT_SCAN,
                resource_type="scan_record",
                action="create",
                tenant_id=str(self.user.tenant_id),
                actor=self.user,
                details={"seq": i},
            )

        result = verify_chain(tenant_id=str(self.user.tenant_id))
        self.assertTrue(result["valid"])
        self.assertEqual(result["entries_checked"], 3)
        self.assertEqual(result["details"], [])

    def test_verify_chain_detects_tampering(self):
        """verify_chain detects a corrupted entry_hash."""
        entry = append_audit_log(
            event_type=EVENT_SCAN,
            resource_type="scan_record",
            action="create",
            tenant_id=str(self.user.tenant_id),
            actor=self.user,
        )

        # Tamper with the entry hash
        entry.entry_hash = "tampered" + "a" * 56  # 64 chars
        entry.save(update_fields=["entry_hash"])

        result = verify_chain(tenant_id=str(self.user.tenant_id))
        self.assertFalse(result["valid"])
        self.assertGreaterEqual(len(result["details"]), 1)

    def test_export_audit_log(self):
        """export_audit_log returns entries as plain dicts."""
        append_audit_log(
            event_type=EVENT_SCAN,
            resource_type="scan_record",
            action="create",
            tenant_id=str(self.user.tenant_id),
            actor=self.user,
            details={"test": True},
        )

        entries = export_audit_log(
            tenant_id=str(self.user.tenant_id),
            page=1,
            page_size=100,
        )
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["event_type"], EVENT_SCAN)
        self.assertEqual(entries[0]["action"], "create")
        self.assertEqual(entries[0]["actor_id"], self.user.id)
        self.assertIn("details", entries[0])
        self.assertTrue(entries[0]["details"]["test"] is True)


# ---------------------------------------------------------------------------
# Router-level tests (integration via HTTP)
# ---------------------------------------------------------------------------


class AuditExportHTTPTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_audit_export_requires_admin(self):
        """Non-admin users get 403 on audit export."""
        headers = get_auth_headers(self.client, email="viewer@test.com")
        resp = self.client.get(
            "/api/v1/admin/audit/export",
            HTTP_AUTHORIZATION=headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 403)

    def test_audit_export_admin_ok(self):
        """An admin user can export audit logs as JSON."""
        admin = create_user(
            "admin@test.com", role="admin", plan="enterprise", is_admin=True
        )
        headers = login_as(self.client, "admin@test.com")

        resp = self.client.get("/api/v1/admin/audit/export", HTTP_AUTHORIZATION=headers["Authorization"])
        self.assertEqual(resp.status_code, 200)
        data = parse_json(resp)
        self.assertIn("entries", data)
        self.assertIn("total", data)
        self.assertIn("page", data)

    def test_audit_export_csv_admin(self):
        """Admin can download CSV export."""
        create_user("admincsv@test.com", role="admin", plan="enterprise", is_admin=True)
        headers = login_as(self.client, "admincsv@test.com")

        resp = self.client.get("/api/v1/admin/audit/export/csv", HTTP_AUTHORIZATION=headers["Authorization"])
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp["Content-Type"].startswith("text/csv"))

    def test_audit_verify_chain(self):
        """Admin can verify the audit chain integrity."""
        create_user("adminverify@test.com", role="admin", plan="enterprise", is_admin=True)
        headers = login_as(self.client, "adminverify@test.com")

        resp = self.client.get("/api/v1/admin/audit/verify", HTTP_AUTHORIZATION=headers["Authorization"])
        self.assertEqual(resp.status_code, 200)
        data = parse_json(resp)
        self.assertIn("valid", data)
        self.assertIn("entries_checked", data)
