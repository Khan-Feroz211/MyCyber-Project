"""Email service for MyCyber DLP.

Supports SMTP (Gmail, AWS SES, etc.) and SendGrid.
Configuration via environment variables.
"""

from __future__ import annotations

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import httpx

from ..mlops.logger import get_logger

logger = get_logger(__name__)

# Environment configuration
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"
EMAIL_FROM = os.environ.get("EMAIL_FROM", "noreply@mycyber.pk")
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://mycyber.pk")


def _smtp_configured() -> bool:
    return all([SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD])


def _sendgrid_configured() -> bool:
    return bool(SENDGRID_API_KEY)


def _is_development() -> bool:
    return os.environ.get("APP_ENV", "development").lower() == "development"


async def send_email_smtp(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: Optional[str] = None,
) -> bool:
    """Send email via SMTP (Gmail, AWS SES, etc.)."""
    if not _smtp_configured():
        logger.warning("SMTP not configured")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = EMAIL_FROM
        msg["To"] = to_email

        # Plain text version
        if text_body:
            msg.attach(MIMEText(text_body, "plain"))

        # HTML version
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            if SMTP_USE_TLS:
                server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, [to_email], msg.as_string())

        logger.info("Email sent via SMTP", extra={"to": to_email, "subject": subject})
        return True

    except Exception as exc:
        logger.error("Failed to send email via SMTP", extra={"error": str(exc), "to": to_email})
        return False


async def send_email_sendgrid(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: Optional[str] = None,
) -> bool:
    """Send email via SendGrid API."""
    if not _sendgrid_configured():
        logger.warning("SendGrid not configured")
        return False

    try:
        url = "https://api.sendgrid.com/v3/mail/send"
        headers = {
            "Authorization": f"Bearer {SENDGRID_API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "personalizations": [{"to": [{"email": to_email}]}],
            "from": {"email": EMAIL_FROM, "name": "MyCyber DLP"},
            "subject": subject,
            "content": [],
        }

        if text_body:
            payload["content"].append({"type": "text/plain", "value": text_body})

        payload["content"].append({"type": "text/html", "value": html_body})

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(url, headers=headers, json=payload)
            if response.status_code in (200, 202):
                logger.info("Email sent via SendGrid", extra={"to": to_email, "subject": subject})
                return True
            else:
                logger.warning(
                    "SendGrid API error",
                    extra={"status": response.status_code, "body": response.text},
                )
                return False

    except Exception as exc:
        logger.error("Failed to send email via SendGrid", extra={"error": str(exc), "to": to_email})
        return False


async def send_email(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: Optional[str] = None,
) -> bool:
    """Send email using available provider (SMTP preferred, fallback to SendGrid)."""
    # Try SMTP first
    if _smtp_configured():
        return await send_email_smtp(to_email, subject, html_body, text_body)

    # Fallback to SendGrid
    if _sendgrid_configured():
        return await send_email_sendgrid(to_email, subject, html_body, text_body)

    logger.error("No email provider configured")
    return False


def build_password_reset_email(reset_token: str, user_email: str) -> tuple[str, str]:
    """Build password reset email content.

    Returns: (html_body, text_body)
    """
    reset_url = f"{FRONTEND_URL}/reset-password?token={reset_token}"

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Reset - MyCyber DLP</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #0f172a; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; background: #f8fafc; }}
        .button {{ display: inline-block; background: #0891b2; color: white; padding: 12px 24px;
                   text-decoration: none; border-radius: 6px; margin: 20px 0; }}
        .footer {{ text-align: center; font-size: 12px; color: #64748b; padding: 20px; }}
        .warning {{ background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>MyCyber DLP</h1>
            <p>Password Reset Request</p>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>We received a request to reset your password for <strong>{user_email}</strong>.</p>
            <p>Click the button below to reset your password:</p>
            <center>
                <a href="{reset_url}" class="button">Reset Password</a>
            </center>
            <p>Or copy and paste this link into your browser:</p>
            <p><code>{reset_url}</code></p>
            <div class="warning">
                <strong>Important:</strong> This link expires in 1 hour. If you didn't request this reset,
                please ignore this email or contact support if you're concerned.
            </div>
        </div>
        <div class="footer">
            <p>MyCyber DLP — AI-powered Data Leakage Prevention for Pakistan</p>
            <p>If you need help, contact us at support@mycyber.pk</p>
        </div>
    </div>
</body>
</html>
"""

    text_body = f"""MyCyber DLP - Password Reset Request

Hello,

We received a request to reset your password for {user_email}.

Click the link below to reset your password:
{reset_url}

This link expires in 1 hour.

If you didn't request this reset, please ignore this email or contact support@mycyber.pk.

---
MyCyber DLP — AI-powered Data Leakage Prevention for Pakistan
"""

    return html_body, text_body


async def send_password_reset_email(user_email: str, reset_token: str) -> bool:
    """Send password reset email to user.

    In development mode, returns False so the token can be returned in API response.
    In production, sends actual email and returns True on success.
    """
    if _is_development() and not (_smtp_configured() or _sendgrid_configured()):
        logger.info("Development mode: skipping email, will return token in response")
        return False

    html_body, text_body = build_password_reset_email(reset_token, user_email)

    success = await send_email(
        to_email=user_email,
        subject="Password Reset - MyCyber DLP",
        html_body=html_body,
        text_body=text_body,
    )

    return success
