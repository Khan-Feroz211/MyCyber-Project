"""Email service for MyCyber DLP.

Port of ``backend/app/services/email_service.py``.  SMTP and SendGrid are
wired via env vars; in development (no provider configured) the password-reset
flow returns the token directly instead of sending mail.

SendGrid uses ``httpx`` which is optional — the import is guarded so the service
degrades gracefully when only SMTP is configured (or neither).
"""
from __future__ import annotations

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from . import conf


def _smtp_configured() -> bool:
    return all([conf.smtp_host(), conf.smtp_username(), conf.smtp_password()])


def _sendgrid_configured() -> bool:
    return bool(conf.sendgrid_api_key())


def _is_development() -> bool:
    return conf.app_env().lower() == "development"


def _send_email_sendgrid(
    to_email: str, subject: str, html_body: str, text_body: Optional[str] = None
) -> bool:
    """Send email via SendGrid API (httpx is optional)."""
    if not _sendgrid_configured():
        return False

    try:
        import httpx  # local import — optional dependency
    except ImportError:  # pragma: no cover
        return False

    url = "https://api.sendgrid.com/v3/mail/send"
    headers = {
        "Authorization": f"Bearer {conf.sendgrid_api_key()}",
        "Content-Type": "application/json",
    }
    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": conf.email_from(), "name": "MyCyber DLP"},
        "subject": subject,
        "content": [],
    }
    if text_body:
        payload["content"].append({"type": "text/plain", "value": text_body})
    payload["content"].append({"type": "text/html", "value": html_body})

    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(url, headers=headers, json=payload)
            if response.status_code in (200, 202):
                return True
            return False
    except Exception:
        return False


def send_email_smtp(
    to_email: str, subject: str, html_body: str, text_body: Optional[str] = None
) -> bool:
    """Send email via SMTP (Gmail, AWS SES, etc.)."""
    if not _smtp_configured():
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = conf.email_from()
        msg["To"] = to_email

        if text_body:
            msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(conf.smtp_host(), conf.smtp_port()) as server:
            if conf.smtp_use_tls():
                server.starttls()
            if conf.smtp_username() and conf.smtp_password():
                server.login(conf.smtp_username(), conf.smtp_password())
            server.sendmail(conf.email_from(), [to_email], msg.as_string())
        return True
    except Exception:
        return False


def send_email(
    to_email: str, subject: str, html_body: str, text_body: Optional[str] = None
) -> bool:
    """Send email using the first available provider (SMTP preferred)."""
    if _smtp_configured():
        return send_email_smtp(to_email, subject, html_body, text_body)
    if _sendgrid_configured():
        return _send_email_sendgrid(to_email, subject, html_body, text_body)
    return False


def build_password_reset_email(reset_token: str, user_email: str) -> tuple[str, str]:
    """Build password reset email content.  Returns ``(html_body, text_body)``."""
    reset_url = f"{conf.frontend_url()}/reset-password?token={reset_token}"

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
            <p>If you need help, contact us at www.ferozkhan@outlook.com</p>
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

If you didn't request this reset, please ignore this email or contact www.ferozkhan@outlook.com.

---
MyCyber DLP — AI-powered Data Leakage Prevention for Pakistan
"""

    return html_body, text_body


def send_password_reset_email(user_email: str, reset_token: str) -> bool:
    """Send password-reset email.

    In development mode (no provider configured) returns ``False`` so the token
    can be returned in the API response.  In production, sends the real email
    and returns ``True`` on success.
    """
    if _is_development() and not (_smtp_configured() or _sendgrid_configured()):
        return False

    html_body, text_body = build_password_reset_email(reset_token, user_email)
    return send_email(
        to_email=user_email,
        subject="Password Reset - MyCyber DLP",
        html_body=html_body,
        text_body=text_body,
    )
