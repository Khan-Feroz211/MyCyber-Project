"""Tests for email service."""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.email_service import (
    _is_development,
    _sendgrid_configured,
    _smtp_configured,
    build_password_reset_email,
    send_email,
    send_password_reset_email,
)


class TestEmailConfiguration:
    """Test email configuration detection."""

    def test_smtp_configured_all_set(self):
        """SMTP is configured when all vars are set."""
        with patch.dict(os.environ, {
            "SMTP_HOST": "smtp.gmail.com",
            "SMTP_USERNAME": "user",
            "SMTP_PASSWORD": "pass",
        }):
            assert _smtp_configured() is True

    def test_smtp_configured_missing_host(self):
        """SMTP is not configured when host is missing."""
        with patch.dict(os.environ, {
            "SMTP_HOST": "",
            "SMTP_USERNAME": "user",
            "SMTP_PASSWORD": "pass",
        }, clear=True):
            assert _smtp_configured() is False

    def test_sendgrid_configured(self):
        """SendGrid is configured when API key is set."""
        with patch.dict(os.environ, {"SENDGRID_API_KEY": "SG.test"}):
            assert _sendgrid_configured() is True

    def test_sendgrid_not_configured(self):
        """SendGrid is not configured when API key is empty."""
        with patch.dict(os.environ, {"SENDGRID_API_KEY": ""}, clear=True):
            assert _sendgrid_configured() is False

    def test_is_development_true(self):
        """Development mode detected correctly."""
        with patch.dict(os.environ, {"APP_ENV": "development"}):
            assert _is_development() is True

    def test_is_development_false(self):
        """Production mode detected correctly."""
        with patch.dict(os.environ, {"APP_ENV": "production"}):
            assert _is_development() is False


class TestPasswordResetEmail:
    """Test password reset email building."""

    def test_build_password_reset_email_contains_token(self):
        """Email contains the reset token in the URL."""
        html, text = build_password_reset_email("test-token-123", "user@test.com")

        assert "test-token-123" in html
        assert "test-token-123" in text
        assert "user@test.com" in html
        assert "user@test.com" in text

    def test_build_password_reset_email_has_reset_link(self):
        """Email contains reset link."""
        with patch.dict(os.environ, {"FRONTEND_URL": "https://mycyber.pk"}):
            html, text = build_password_reset_email("token123", "user@test.com")

            assert "https://mycyber.pk/reset-password" in html
            assert "https://mycyber.pk/reset-password" in text


class TestSendPasswordResetEmail:
    """Test sending password reset email."""

    @pytest.mark.asyncio
    async def test_sends_email_in_production(self):
        """Email is sent in production with SMTP configured."""
        with patch.dict(os.environ, {
            "APP_ENV": "production",
            "SMTP_HOST": "smtp.gmail.com",
            "SMTP_USERNAME": "user",
            "SMTP_PASSWORD": "pass",
        }):
            with patch("app.services.email_service.send_email_smtp", new_callable=AsyncMock) as mock_send:
                mock_send.return_value = True

                result = await send_password_reset_email("user@test.com", "token123")

                assert result is True
                mock_send.assert_called_once()

    @pytest.mark.asyncio
    async def test_returns_false_in_development(self):
        """Returns False in development (token shown in UI)."""
        with patch.dict(os.environ, {
            "APP_ENV": "development",
            "SMTP_HOST": "",
        }, clear=True):
            result = await send_password_reset_email("user@test.com", "token123")

            assert result is False

    @pytest.mark.asyncio
    async def test_uses_sendgrid_when_smtp_not_configured(self):
        """Uses SendGrid when SMTP not configured but SendGrid is."""
        with patch.dict(os.environ, {
            "APP_ENV": "production",
            "SMTP_HOST": "",
            "SENDGRID_API_KEY": "SG.test",
        }):
            with patch("app.services.email_service.send_email_sendgrid", new_callable=AsyncMock) as mock_send:
                mock_send.return_value = True

                result = await send_password_reset_email("user@test.com", "token123")

                assert result is True
                mock_send.assert_called_once()
