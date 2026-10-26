"""End-to-end tests for the ported DLP scan engine (Phase 5).

Covers the product core: ``POST /api/v1/scan/text`` → scan response +
``EVENT_SCAN`` audit entry → alert creation for high-risk scans, plus
history/stats/list endpoints and auth enforcement.  No network or LLM
calls are made.

Run with::

    backend_django/manage.py test tests.test_scan --settings=mycyber.settings.test -v2
"""
from __future__ import annotations

from django.test import TestCase
from rest_framework.test import APIClient

from apps.alerts.models import Alert
from apps.scans.models import ScanRecord
from mycyber.services.audit_log import EVENT_SCAN, verify_chain

from tests.helpers import create_user, login_as, parse_json


class ScanEngineTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        create_user("scanuser@test.com", role="viewer", plan="free", is_admin=False)
        self.headers = login_as(self.client, "scanuser@test.com")

    def _post_scan(self, text: str):
        return self.client.post(
            "/api/v1/scan/text",
            data={"text": text},
            HTTP_AUTHORIZATION=self.headers["Authorization"],
        )

    def test_scan_text_safe_response(self):
        resp = self._post_scan("Just a regular message with no secrets.")
        self.assertEqual(resp.status_code, 200, resp.content)
        data = parse_json(resp)
        self.assertEqual(data["severity"], "SAFE")
        self.assertEqual(data["total_entities"], 0)
        self.assertEqual(data["recommended_action"], "ALLOW")
        self.assertEqual(data["risk_score"], 0)
        self.assertIn("scan_id", data)

    def test_scan_with_credit_card_creates_alert_and_audit(self):
        resp = self._post_scan("My card number is 4111111111111111 please don't leak it.")
        self.assertEqual(resp.status_code, 200, resp.content)
        data = parse_json(resp)
        self.assertIn(data["severity"], {"CRITICAL", "HIGH"})
        self.assertGreater(data["total_entities"], 0)

        # A ScanRecord persisted.
        self.assertTrue(ScanRecord.objects.filter(scan_id=data["scan_id"]).exists())

        # A high-risk alert was created.
        self.assertTrue(
            Alert.objects.filter(scan_id=data["scan_id"], severity=data["severity"]).exists()
        )

    def test_scan_creates_audit_entry_and_chain_valid(self):
        self._post_scan("4111111111111111")
        from apps.audit.models import AuditLogEntry

        scans = AuditLogEntry.objects.filter(event_type=EVENT_SCAN)
        self.assertEqual(scans.count(), 1)
        result = verify_chain()
        self.assertTrue(result["valid"], result["details"])
        self.assertGreaterEqual(result["entries_checked"], 1)

    def test_scan_history_paginated(self):
        self._post_scan("4111111111111111")
        self._post_scan("nothing sensitive here")
        resp = self.client.get(
            "/api/v1/scan/history",
            HTTP_AUTHORIZATION=self.headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 200)
        data = parse_json(resp)
        self.assertEqual(data["total"], 2)
        self.assertEqual(len(data["items"]), 2)

    def test_scan_stats_aggregate(self):
        self._post_scan("4111111111111111")
        resp = self.client.get(
            "/api/v1/scan/stats",
            HTTP_AUTHORIZATION=self.headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 200)
        data = parse_json(resp)
        self.assertGreaterEqual(data["total_scans"], 1)
        self.assertIn("HIGH", data["severity_breakdown"])

    def test_scan_requires_auth(self):
        resp = self.client.post("/api/v1/scan/text", data={"text": "hello"})
        self.assertEqual(resp.status_code, 401)

    def test_scan_detail(self):
        resp = self._post_scan("contact a@b.com")
        data = parse_json(resp)
        scan_id = data["scan_id"]
        resp2 = self.client.get(
            f"/api/v1/scan/{scan_id}",
            HTTP_AUTHORIZATION=self.headers["Authorization"],
        )
        self.assertEqual(resp2.status_code, 200)
        detail = parse_json(resp2)
        self.assertEqual(detail["scan_id"], scan_id)
        self.assertGreaterEqual(detail["total_entities"], 1)
        self.assertEqual(detail["entities"][0]["entity_type"], "EMAIL")


class AlertListTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        create_user("alertuser@test.com", role="viewer", plan="free", is_admin=False)
        self.headers = login_as(self.client, "alertuser@test.com")

    def test_alert_list_and_acknowledge(self):
        # Create a high-risk scan that yields an alert.
        resp = self.client.post(
            "/api/v1/scan/text",
            data={"text": "card 4111111111111111"},
            HTTP_AUTHORIZATION=self.headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        scan_id = parse_json(resp)["scan_id"]

        # Alert list
        resp = self.client.get(
            "/api/v1/alerts/",
            HTTP_AUTHORIZATION=self.headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 200)
        data = parse_json(resp)
        self.assertGreaterEqual(data["total"], 1)
        alert_id = data["items"][0]["alert_id"]

        # Acknowledge
        resp = self.client.post(
            f"/api/v1/alerts/{alert_id}/acknowledge",
            HTTP_AUTHORIZATION=self.headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(parse_json(resp)["is_acknowledged"])

        # Counts
        resp = self.client.get(
            "/api/v1/alerts/count",
            HTTP_AUTHORIZATION=self.headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(parse_json(resp)["acknowledged"], 1)


class BillingPlansTests(TestCase):
    def test_plans_list_is_public(self):
        resp = APIClient().get("/api/v1/billing/plans")
        self.assertEqual(resp.status_code, 200)
        data = parse_json(resp)
        self.assertEqual(len(data), 3)
        self.assertEqual({c["plan_id"] for c in data}, {"free", "pro", "enterprise"})


class LLMHistoryTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        create_user("llmuser@test.com", role="viewer", plan="free", is_admin=False)
        self.headers = login_as(self.client, "llmuser@test.com")

    def test_llm_history_empty(self):
        resp = self.client.get(
            "/api/v1/llm-dlp/history",
            HTTP_AUTHORIZATION=self.headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 200)
        data = parse_json(resp)
        self.assertEqual(data["total"], 0)

    def test_llm_stats_empty(self):
        resp = self.client.get(
            "/api/v1/llm-dlp/stats",
            HTTP_AUTHORIZATION=self.headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(parse_json(resp)["total_interactions"], 0)


class SchedulingTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        create_user("scheduser@test.com", role="analyst", plan="pro", is_admin=False)
        self.headers = login_as(self.client, "scheduser@test.com")

    def test_schedule_create_list_delete(self):
        resp = self.client.post(
            "/api/v1/scheduled/jobs",
            data={"name": "daily scan", "scan_type": "text", "target": "hello world", "schedule_cron": "0 1 * * *"},
            HTTP_AUTHORIZATION=self.headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 201, resp.content)
        job_id = parse_json(resp)["job_id"]

        resp = self.client.get(
            "/api/v1/scheduled/jobs",
            HTTP_AUTHORIZATION=self.headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(parse_json(resp)["total"], 1)

        resp = self.client.delete(
            f"/api/v1/scheduled/jobs/{job_id}",
            HTTP_AUTHORIZATION=self.headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 200)


class SQLInjectionDetectionTests(TestCase):
    """Verify the regex DLP engine flags SQL-injection payloads (SQL_INJECTION)."""

    def setUp(self):
        self.client = APIClient()

    def _scan(self, text):
        from mycyber.services.scanner import perform_scan

        return perform_scan(text, scan_id="t")

    def test_classic_drop_table_detected(self):
        r = self._scan("'; DROP TABLE users; --")
        self.assertEqual(r["severity"], "CRITICAL")
        self.assertTrue(any(e["entity_type"] == "SQL_INJECTION" for e in r["entities"]))

    def test_union_select_detected(self):
        r = self._scan("1 UNION SELECT password FROM users")
        self.assertEqual(r["severity"], "CRITICAL")
        self.assertTrue(any(e["entity_type"] == "SQL_INJECTION" for e in r["entities"]))

    def test_tautology_or_detected(self):
        r = self._scan("password = ' OR '1'='1")
        self.assertEqual(r["severity"], "CRITICAL")
        self.assertTrue(any(e["entity_type"] == "SQL_INJECTION" for e in r["entities"]))

    def test_safe_text_not_flagged(self):
        r = self._scan("Quarterly headcount and roadmap briefing for Q4.")
        self.assertEqual(r["severity"], "SAFE")
        self.assertEqual(r["total_entities"], 0)

    def test_case_insensitive_sqli(self):
        r = self._scan("1 union select name from users; drop table sessions")
        self.assertEqual(r["severity"], "CRITICAL")
        self.assertTrue(any(e["entity_type"] == "SQL_INJECTION" for e in r["entities"]))


class DataRetentionTests(TestCase):
    """The purge_old_data command deletes stale non-audit artefacts only."""

    def setUp(self):
        self.client = APIClient()
        create_user("retention@test.com", role="viewer", plan="free", is_admin=False)
        self.headers = login_as(self.client, "retention@test.com")

    def test_purge_removes_old_scans_preserves_audit_and_recent(self):
        from datetime import timedelta
        from uuid import uuid4

        from django.core.management import call_command
        from django.utils import timezone

        from apps.audit.models import AuditLogEntry
        from apps.scans.models import ScanRecord
        from mycyber.services.audit_log import EVENT_SENSITIVE_ACTION, verify_chain

        from apps.accounts.models import User
        user = User.objects.get(email="retention@test.com")
        tenant = str(user.tenant_id)

        old = timezone.now() - timedelta(days=40)
        recent = timezone.now() - timedelta(days=1)

        old_rec = ScanRecord.objects.create(
            scan_id=uuid4(), user=user, tenant_id=tenant,
            scan_type="text", severity="SAFE", risk_score=0.0, total_entities=0,
            recommended_action="ALLOW", summary="old", entities_json="[]",
            scan_duration_ms=0.0,
        )
        ScanRecord.objects.filter(pk=old_rec.pk).update(created_at=old)

        recent_rec = ScanRecord.objects.create(
            scan_id=uuid4(), user=user, tenant_id=tenant,
            scan_type="text", severity="SAFE", risk_score=0.0, total_entities=0,
            recommended_action="ALLOW", summary="recent", entities_json="[]",
            scan_duration_ms=0.0,
        )
        ScanRecord.objects.filter(pk=recent_rec.pk).update(created_at=recent)

        call_command("purge_old_data", "--days", "30", "--tenant", tenant)

        self.assertFalse(ScanRecord.objects.filter(scan_id=old_rec.scan_id).exists())
        self.assertTrue(ScanRecord.objects.filter(scan_id=recent_rec.scan_id).exists())
        self.assertTrue(
            AuditLogEntry.objects.filter(event_type=EVENT_SENSITIVE_ACTION, action="purge_old_data").exists()
        )
        self.assertTrue(verify_chain(tenant_id=tenant)["valid"])
