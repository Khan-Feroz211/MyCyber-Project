"""Security audit event logging (non-fatal).

Port of ``backend/app/services/security_audit.py``.  Writes
``SecurityAuditEvent`` rows (the *operational* security log) without ever
interrupting request flow.  The *immutable hash-chained* audit log lives in
``apps.audit.services`` — see that module for tamper-evident logging.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from . import conf

_logger = logging.getLogger(__name__)


def _hmac_key() -> bytes:
    """Return the HMAC key for audit log hashing.

    Uses ``SAFEPAY_SECRET_KEY`` if set, otherwise the JWT secret.  Falls back
    to a non-secret dev sentinel (mirrors the FastAPI behaviour).
    """
    import hashlib
    import hmac

    key = conf.safepay_secret_key() or conf.jwt_secret()
    if not key:
        key = "dev-audit-hmac-key-please-rotate"
    return hmac.new(key.encode("utf-8"), b"", hashlib.sha256).digest()[:32]


def log_security_event(
    event_type: str,
    severity: str = "INFO",
    user=None,
    tenant_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Write a security audit event without interrupting request flow on failures."""
    from apps.audit.models import SecurityAuditEvent

    try:
        event = SecurityAuditEvent(
            user=user,
            tenant_id=tenant_id if tenant_id is not None else (getattr(user, "tenant_id", None) if user else None),
            event_type=event_type,
            severity=severity.upper(),
            ip_address=ip_address,
            user_agent=(user_agent or "")[:255] if user_agent else None,
            details_json=json.dumps(details or {}),
        )
        event.save()
    except Exception as exc:  # pragma: no cover - non-fatal logging path
        _logger.warning(
            "Failed to persist security audit event",
            extra={"event_type": event_type, "error": str(exc)},
        )


# Expose the hmac key for the audit-log chaining service (kept for parity).
GENESIS_HASH = "GENESIS"
HMAC_KEY = _hmac_key
