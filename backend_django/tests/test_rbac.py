"""Tests for RBAC hardening — fine-grained roles, session timeout, forced re-auth.

Django port of ``backend/tests/test_rbac.py``.

Run with::

    backend_django/manage.py test tests.test_rbac --settings=mycyber.settings.test -v2
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import jwt
from django.test import TestCase
from rest_framework.test import APIClient

from mycyber.services import conf
from mycyber.services.auth import ALGORITHM

from tests.helpers import (
    create_user,
    get_auth_headers,
    login_as,
    parse_json,
    register_user,
)


class RBACRoleTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_register_assigns_viewer_role(self):
        """New users default to the 'viewer' role."""
        resp = register_user(
            self.client, "roleuser@test.com", "securepass", "Role"
        )
        self.assertEqual(resp.status_code, 201)
        data = parse_json(resp)
        self.assertEqual(data["role"], "viewer")
        self.assertFalse(data["is_admin"])

    def test_admin_can_access_audit_export(self):
        """Admin role can access audit export endpoint."""
        create_user(
            "adminrbac@test.com", role="admin", plan="enterprise", is_admin=True
        )
        headers = login_as(self.client, "adminrbac@test.com")
        resp = self.client.get(
            "/api/v1/admin/audit/export",
            HTTP_AUTHORIZATION=headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 200)

    def test_analyst_cannot_access_admin_audit(self):
        """Analyst role cannot access admin-only audit export."""
        create_user(
            "analyst@test.com", role="analyst", plan="pro", is_admin=False
        )
        headers = login_as(self.client, "analyst@test.com")
        resp = self.client.get(
            "/api/v1/admin/audit/export",
            HTTP_AUTHORIZATION=headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 403)

    def test_viewer_cannot_access_admin_audit(self):
        """Viewer role cannot access admin-only audit export."""
        create_user(
            "viewer@test.com", role="viewer", plan="free", is_admin=False
        )
        headers = login_as(self.client, "viewer@test.com")
        resp = self.client.get(
            "/api/v1/admin/audit/export",
            HTTP_AUTHORIZATION=headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_access_admin_security(self):
        """Admin can access admin security incident list."""
        create_user(
            "adminsec@test.com", role="admin", plan="enterprise", is_admin=True
        )
        headers = login_as(self.client, "adminsec@test.com")
        resp = self.client.get(
            "/api/v1/admin/security/incidents",
            HTTP_AUTHORIZATION=headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 200)

    def test_analyst_cannot_access_admin_security(self):
        """Analyst role cannot access admin security endpoints."""
        create_user(
            "analystsec@test.com", role="analyst", plan="pro", is_admin=False
        )
        headers = login_as(self.client, "analystsec@test.com")
        resp = self.client.get(
            "/api/v1/admin/security/incidents",
            HTTP_AUTHORIZATION=headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 403)

    def test_me_endpoint_returns_role(self):
        """GET /me returns the role field."""
        headers = get_auth_headers(self.client, email="me@test.com")
        resp = self.client.get(
            "/api/v1/auth/me",
            HTTP_AUTHORIZATION=headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 200)
        data = parse_json(resp)
        self.assertIn("role", data)
        self.assertIn(data["role"], ("viewer", "analyst", "admin"))


class SessionTimeoutTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin = create_user(
            "adminsto@test.com",
            role="admin",
            plan="enterprise",
            is_admin=True,
        )

    def test_session_timeout_forces_reauth(self):
        """A token issued more than SESSION_TIMEOUT_HOURS ago triggers 419."""
        now = datetime.now(tz=timezone.utc)
        old_time = now - timedelta(hours=25)
        payload = {
            "sub": str(self.admin.id),
            "email": self.admin.email,
            "tenant_id": str(self.admin.tenant_id),
            "type": "access",
            "iat": old_time,
            "exp": now + timedelta(hours=1),
        }
        old_token = jwt.encode(payload, conf.jwt_secret(), algorithm=ALGORITHM)

        resp = self.client.get(
            "/api/v1/auth/me",
            HTTP_AUTHORIZATION=f"Bearer {old_token}",
        )
        self.assertEqual(resp.status_code, 419)

    def test_recent_token_passes_session_timeout(self):
        """A token issued recently passes the session timeout check."""
        headers = login_as(self.client, "adminsto@test.com")
        resp = self.client.get(
            "/api/v1/auth/me",
            HTTP_AUTHORIZATION=headers["Authorization"],
        )
        self.assertEqual(resp.status_code, 200)
