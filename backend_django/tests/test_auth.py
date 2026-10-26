"""Tests for authentication endpoints.

Django port of ``backend/tests/test_auth.py``.

Run with::

    backend_django/manage.py test tests.test_auth --settings=mycyber.settings.test -v2
"""
from __future__ import annotations

from django.test import TestCase
from rest_framework.test import APIClient

from tests.helpers import get_auth_headers, parse_json, register_user


class AuthTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_register_success(self):
        """POST /register with valid data returns 201 and correct fields."""
        resp = register_user(
            self.client, "alice@example.com", "securepass", "Alice Smith"
        )
        self.assertEqual(resp.status_code, 201)
        data = parse_json(resp)
        self.assertEqual(data["email"], "alice@example.com")
        self.assertEqual(data["plan"], "free")
        self.assertIn("tenant_id", data)
        self.assertEqual(len(data["tenant_id"]), 36)  # UUID format
        self.assertTrue(data["is_active"])
        # Password must never be exposed
        self.assertNotIn("hashed_password", data)
        self.assertNotIn("password", data)

    def test_register_duplicate_email(self):
        """Registering the same email twice returns 409 Conflict."""
        payload = {
            "email": "bob@example.com",
            "password": "securepass",
            "full_name": "Bob",
        }
        first = register_user(self.client, "bob@example.com", "securepass", "Bob")
        self.assertEqual(first.status_code, 201)

        second = self.client.post("/api/v1/auth/register", data=payload)
        self.assertEqual(second.status_code, 409)

    def test_register_weak_password(self):
        """Passwords shorter than 8 characters are rejected.

        FastAPI returns 422; DRF returns 400 for serializer validation errors.
        """
        resp = register_user(
            self.client, "weak@example.com", "short", "Weak"
        )
        self.assertEqual(resp.status_code, 400)

    def test_login_success(self):
        """Valid credentials return 200 with access_token and embedded user."""
        register_user(self.client, "carol@example.com", "goodpassword", "Carol")
        resp = self.client.post(
            "/api/v1/auth/login",
            data={"username": "carol@example.com", "password": "goodpassword"},
        )
        self.assertEqual(resp.status_code, 200)
        data = parse_json(resp)
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["user"]["email"], "carol@example.com")

    def test_login_wrong_password(self):
        """Wrong password returns 401 Unauthorized."""
        register_user(self.client, "dave@example.com", "correct123", "Dave")
        resp = self.client.post(
            "/api/v1/auth/login",
            data={"username": "dave@example.com", "password": "wrongpassword"},
        )
        self.assertEqual(resp.status_code, 401)

    def test_me_endpoint(self):
        """GET /me returns the authenticated user's profile."""
        headers = get_auth_headers(self.client, email="user@test.com")
        resp = self.client.get("/api/v1/auth/me", HTTP_AUTHORIZATION=headers["Authorization"])
        self.assertEqual(resp.status_code, 200)
        data = parse_json(resp)
        self.assertEqual(data["email"], "user@test.com")
        self.assertIn("tenant_id", data)
        self.assertNotIn("hashed_password", data)

    def test_protected_without_token(self):
        """A protected endpoint returns 401 when no Bearer token is provided."""
        resp = self.client.get("/api/v1/auth/me")
        self.assertEqual(resp.status_code, 401)
