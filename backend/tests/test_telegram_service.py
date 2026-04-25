"""Tests for Telegram alert service."""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest

from app.services.telegram_service import (
    _enabled,
    format_alert_message,
    notify_scan_alert,
    send_telegram_alert,
)


class TestTelegramConfiguration:
    """Test Telegram configuration detection."""

    def test_enabled_when_both_vars_set(self):
        """Service is enabled when both token and chat ID are set."""
        with patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": "123456:ABC-DEF",
            "TELEGRAM_DEFAULT_CHAT_ID": "123456789",
        }):
            assert _enabled() is True

    def test_disabled_when_token_missing(self):
        """Service is disabled when token is missing."""
        with patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": "",
            "TELEGRAM_DEFAULT_CHAT_ID": "123456789",
        }, clear=True):
            assert _enabled() is False

    def test_disabled_when_chat_id_missing(self):
        """Service is disabled when chat ID is missing."""
        with patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": "123456:ABC-DEF",
            "TELEGRAM_DEFAULT_CHAT_ID": "",
        }, clear=True):
            assert _enabled() is False


class TestAlertFormatting:
    """Test alert message formatting."""

    def test_format_alert_message_includes_severity(self):
        """Message includes severity level."""
        msg = format_alert_message(
            severity="CRITICAL",
            scan_type="text",
            entity_count=5,
            summary="Found CNIC numbers",
            user_email="user@test.com",
            scan_id="scan-123",
        )

        assert "CRITICAL" in msg
        assert "scan-123" in msg
        assert "user@test.com" in msg
        assert "Found CNIC numbers" in msg

    def test_format_alert_message_uses_correct_icon(self):
        """Message uses correct emoji for severity."""
        critical = format_alert_message("CRITICAL", "text", 1, "test", "user@test.com", "scan-1")
        high = format_alert_message("HIGH", "text", 1, "test", "user@test.com", "scan-1")
        medium = format_alert_message("MEDIUM", "text", 1, "test", "user@test.com", "scan-1")
        safe = format_alert_message("SAFE", "text", 0, "test", "user@test.com", "scan-1")

        assert "🔴" in critical
        assert "🟠" in high
        assert "🟡" in medium
        assert "🟢" in safe


class TestSendTelegramAlert:
    """Test sending Telegram alerts."""

    @pytest.mark.asyncio
    async def test_returns_false_when_not_configured(self):
        """Returns False when Telegram not configured."""
        with patch.dict(os.environ, {}, clear=True):
            result = await send_telegram_alert("test message")
            assert result is False

    @pytest.mark.asyncio
    async def test_sends_message_when_configured(self):
        """Sends message when configured."""
        with patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": "123456:ABC-DEF",
            "TELEGRAM_DEFAULT_CHAT_ID": "123456789",
        }):
            with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
                mock_post.return_value.json.return_value = {"ok": True}
                mock_post.return_value.status_code = 200

                result = await send_telegram_alert("test message")

                assert result is True
                mock_post.assert_called_once()

    @pytest.mark.asyncio
    async def test_returns_false_on_api_error(self):
        """Returns False when Telegram API returns error."""
        with patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": "123456:ABC-DEF",
            "TELEGRAM_DEFAULT_CHAT_ID": "123456789",
        }):
            with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
                mock_post.return_value.json.return_value = {
                    "ok": False,
                    "description": "Bad Request: chat not found",
                }
                mock_post.return_value.status_code = 400

                result = await send_telegram_alert("test message")

                assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_on_exception(self):
        """Returns False on network exception."""
        with patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": "123456:ABC-DEF",
            "TELEGRAM_DEFAULT_CHAT_ID": "123456789",
        }):
            with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
                mock_post.side_effect = Exception("Network error")

                result = await send_telegram_alert("test message")

                assert result is False


class TestNotifyScanAlert:
    """Test scan alert notification wrapper."""

    @pytest.mark.asyncio
    async def test_notifies_scan_alert(self):
        """Wrapper correctly formats and sends scan alert."""
        with patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": "123456:ABC-DEF",
            "TELEGRAM_DEFAULT_CHAT_ID": "123456789",
        }):
            with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
                mock_post.return_value.json.return_value = {"ok": True}
                mock_post.return_value.status_code = 200

                result = await notify_scan_alert(
                    severity="CRITICAL",
                    scan_type="text",
                    entity_count=5,
                    summary="Found sensitive data",
                    user_email="admin@company.com",
                    scan_id="scan-12345",
                )

                assert result is True
                # Verify the message was formatted and sent
                call_args = mock_post.call_args
                assert "admin@company.com" in str(call_args)
                assert "scan-12345" in str(call_args)
