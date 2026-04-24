"""Telegram alerting service for MyCyber DLP.

Sends alert notifications via Telegram Bot API when high-severity
entities are detected during scans.  The bot token and default chat
ID are read from environment variables; per-user overrides can be
stored in the database later.
"""

from __future__ import annotations

import os
from typing import Optional

import httpx

from ..mlops.logger import get_logger

logger = get_logger(__name__)

_TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
_TELEGRAM_DEFAULT_CHAT_ID = os.environ.get("TELEGRAM_DEFAULT_CHAT_ID", "")
_TELEGRAM_API_BASE = "https://api.telegram.org"


def _enabled() -> bool:
    return bool(_TELEGRAM_BOT_TOKEN and _TELEGRAM_DEFAULT_CHAT_ID)


def format_alert_message(
    severity: str,
    scan_type: str,
    entity_count: int,
    summary: str,
    user_email: str,
    scan_id: str,
) -> str:
    icon = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "SAFE": "🟢",
    }.get(severity.upper(), "⚪")

    return (
        f"{icon} *MyCyber DLP Alert*\n"
        f"Severity: *{severity}*\n"
        f"Scan type: {scan_type}\n"
        f"Entities found: {entity_count}\n"
        f"User: {user_email}\n"
        f"Scan ID: `{scan_id}`\n\n"
        f"Summary:\n{summary[:400]}"
    )


async def send_telegram_alert(
    message: str,
    chat_id: Optional[str] = None,
    parse_mode: str = "Markdown",
) -> bool:
    """Send a message via the Telegram Bot API.

    Returns *True* if the request succeeds, *False* otherwise.
    Errors are logged but never raised so that alert delivery
    failures do not break the scan pipeline.
    """
    if not _enabled():
        logger.debug("Telegram alerting is disabled (missing TELEGRAM_BOT_TOKEN or TELEGRAM_DEFAULT_CHAT_ID).")
        return False

    token = _TELEGRAM_BOT_TOKEN
    target_chat = chat_id or _TELEGRAM_DEFAULT_CHAT_ID
    url = f"{_TELEGRAM_API_BASE}/bot{token}/sendMessage"

    payload = {
        "chat_id": target_chat,
        "text": message,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=payload)
            data = response.json()
            if not data.get("ok"):
                logger.warning(
                    "Telegram API returned error",
                    extra={"error": data.get("description"), "chat_id": target_chat},
                )
                return False
            logger.info("Telegram alert sent", extra={"chat_id": target_chat})
            return True
    except Exception as exc:
        logger.error("Failed to send Telegram alert", extra={"error": str(exc)})
        return False


async def notify_scan_alert(
    severity: str,
    scan_type: str,
    entity_count: int,
    summary: str,
    user_email: str,
    scan_id: str,
    chat_id: Optional[str] = None,
) -> bool:
    """Convenience wrapper that formats and sends a scan alert."""
    message = format_alert_message(severity, scan_type, entity_count, summary, user_email, scan_id)
    return await send_telegram_alert(message, chat_id=chat_id)
