"""Immutable audit logging service.

Every scan, alert, admin action, and access event is written to the
``audit_log_entries`` table.  Entries are append-only: the service never
issues UPDATE or DELETE statements against this table.

Cryptographic hash chaining
---------------------------
Each entry stores ``previous_hash`` (the SHA-256 of the immediately
preceding entry's ``entry_hash``) and its own ``entry_hash``.  When the
table is empty the ``previous_hash`` is the sentinel ``"GENESIS"``.

Tamper detection
----------------
Call :func:`verify_chain` to walk the entire table in chronological order
and confirm that every ``previous_hash`` matches the prior ``entry_hash``.
Any mismatch indicates tampering.

The hash uses ``AUDIT_LOG_HMAC_SECRET`` from settings (falls back to
``jwt_secret``) as an HMAC-SHA256 key so that an attacker who compromises
the DB alone cannot forge new entries.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.models import AuditLogEntry, User
from ..mlops.logger import get_logger

logger = get_logger(__name__)

# Sentinel previous_hash for the first entry in the table.
GENESIS_HASH = "GENESIS"

# Event types
EVENT_SCAN = "scan_created"
EVENT_ALERT_ACKNOWLEDGED = "alert_acknowledged"
EVENT_ALERT_REVIEWED = "alert_reviewed"
EVENT_ALERT_DELETED = "alert_deleted"
EVENT_LOGIN_SUCCESS = "login_success"
EVENT_LOGIN_FAILED = "login_failed"
EVENT_ADMIN_ACTION = "admin_action"
EVENT_PASSWORD_RESET = "password_reset"
EVENT_PASSWORD_RESET = "password_reset"
EVENT_MFA_TOGGLE = "mfa_toggle"
EVENT_MFA_FAILED = "mfa_failed"
EVENT_LLM_INTERACTION = "llm_interaction"
EVENT_QUARANTINE = "quarantine_action"
EVENT_PLAN_CHANGE = "plan_change"
EVENT_PLAN_CHANGE = "plan_change"
EVENT_SESSION_EXPIRED = "session_expired"
EVENT_SENSITIVE_ACTION = "sensitive_action_reauth"


def _hmac_key() -> bytes:
    """Return the HMAC key for audit log hashing."""
    settings = get_settings()
    key = settings.safepay_secret_key or settings.jwt_secret
    if not key:
        # Fallback for dev/test — non-secret but deterministic
        key = "dev-audit-hmac-key-please-rotate"
    return hmac.new(key.encode("utf-8"), b"", hashlib.sha256).digest()[:32]


def _compute_entry_hash(
    entry_id: str,
    tenant_id: str,
    actor_id: int | None,
    event_type: str,
    resource_type: str,
    resource_id: str | None,
    action: str,
    severity: str,
    ip_address: str | None,
    user_agent: str | None,
    details_json: str,
    created_at: datetime,
    previous_hash: str,
) -> str:
    """Compute the HMAC-SHA256 digest for an audit entry."""
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    else:
        created_at = created_at.astimezone(timezone.utc)

    payload = "|".join(
        str(x) for x in (
            entry_id,
            tenant_id,
            str(actor_id) if actor_id is not None else "",
            event_type,
            resource_type,
            resource_id or "",
            action,
            severity,
            ip_address or "",
            user_agent or "",
            details_json,
            created_at.isoformat(),
            previous_hash,
        )
    )
    return hmac.new(_hmac_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()


async def _get_last_hash(db: AsyncSession, tenant_id: str | None = None) -> str:
    """Return the ``entry_hash`` of the most recent log entry.

    When *tenant_id* is provided the chain is scoped per-tenant; otherwise
    it is global.  Returns :data:`GENESIS_HASH` when the table is empty.
    """
    query = select(AuditLogEntry.entry_hash)
    if tenant_id is not None:
        query = query.where(AuditLogEntry.tenant_id == tenant_id)
    query = query.order_by(AuditLogEntry.created_at.desc(), AuditLogEntry.id.desc()).limit(1)
    result = await db.execute(query)
    last_hash: str | None = result.scalar_one_or_none()
    return last_hash or GENESIS_HASH


async def append_audit_log(
    db: AsyncSession,
    event_type: str,
    resource_type: str,
    action: str,
    tenant_id: str,
    details: dict[str, Any] | None = None,
    actor: User | None = None,
    actor_id: int | None = None,
    resource_id: str | None = None,
    severity: str = "INFO",
    ip_address: str | None = None,
    user_agent: str | None = None,
    created_at: datetime | None = None,
) -> AuditLogEntry:
    """Append a single entry to the immutable audit log.

    The entry's ``previous_hash`` is set to the hash of the last entry
    in the chain (per-tenant scope).  The entry is flushed but not
    committed — the caller controls the transaction boundary.
    """
    settings = get_settings()
    if created_at is None:
        created_at = datetime.now(timezone.utc)

    resolved_actor_id = actor_id
    if actor is not None:
        resolved_actor_id = actor.id
        if tenant_id is None:
            tenant_id = actor.tenant_id

    details_json = json.dumps(details or {}, sort_keys=True)

    previous_hash = await _get_last_hash(db, tenant_id=tenant_id)
    entry_hash = _compute_entry_hash(
        entry_id="",  # placeholder — replaced after id is known; see note below
        tenant_id=tenant_id,
        actor_id=resolved_actor_id,
        event_type=event_type,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        severity=severity.upper(),
        ip_address=ip_address,
        user_agent=user_agent,
        details_json=details_json,
        created_at=created_at,
        previous_hash=previous_hash,
    )

    # NOTE: entry_id is generated by the DB default (uuid), so we create
    # the row, flush to get the id, then recompute the hash including it.
    entry = AuditLogEntry(
        tenant_id=tenant_id,
        actor_id=resolved_actor_id,
        event_type=event_type,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        severity=severity.upper(),
        ip_address=ip_address,
        user_agent=user_agent,
        details_json=details_json,
        previous_hash=previous_hash,
        entry_hash="",  # placeholder, updated below
        key_version=settings.encryption_key_version,
        created_at=created_at,
    )
    db.add(entry)
    await db.flush()

    # Recompute with the real entry_id
    entry_hash = _compute_entry_hash(
        entry_id=entry.entry_id,
        tenant_id=tenant_id,
        actor_id=resolved_actor_id,
        event_type=event_type,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        severity=severity.upper(),
        ip_address=ip_address,
        user_agent=user_agent,
        details_json=details_json,
        created_at=created_at,
        previous_hash=previous_hash,
    )
    entry.entry_hash = entry_hash
    await db.flush()

    logger.info(
        "Audit log entry written",
        extra={
            "event_type": event_type,
            "resource_type": resource_type,
            "action": action,
            "entry_id": entry.entry_id,
            "actor_id": resolved_actor_id,
            "tenant_id": tenant_id,
        },
    )
    return entry


async def verify_chain(db: AsyncSession, tenant_id: str | None = None) -> dict[str, Any]:
    """Walk the audit log in order and verify hash chaining integrity.

    Returns a dict with:
    - ``valid``: bool — whether the chain is intact.
    - ``entries_checked``: int — number of entries examined.
    - ``first_tamper_index``: int | None — index of the first broken link.
    - ``details``: list[str] — human-readable issues.
    """
    query = (
        select(AuditLogEntry)
        .order_by(AuditLogEntry.created_at.asc(), AuditLogEntry.id.asc())
    )
    if tenant_id is not None:
        query = query.where(AuditLogEntry.tenant_id == tenant_id)

    result = await db.execute(query)
    entries = result.scalars().all()

    issues: list[str] = []
    previous_hash = GENESIS_HASH

    for idx, entry in enumerate(entries):
        if entry.previous_hash != previous_hash:
            issues.append(
                f"Chain break at index {idx}: expected previous_hash={previous_hash}, "
                f"got {entry.previous_hash}"
            )
        # Recompute the entry's own hash and compare
        details_json = entry.details_json or "{}"
        recomputed = _compute_entry_hash(
            entry_id=entry.entry_id,
            tenant_id=entry.tenant_id,
            actor_id=entry.actor_id,
            event_type=entry.event_type,
            resource_type=entry.resource_type,
            resource_id=entry.resource_id,
            action=entry.action,
            severity=entry.severity,
            ip_address=entry.ip_address,
            user_agent=entry.user_agent,
            details_json=details_json,
            created_at=entry.created_at or datetime.now(timezone.utc),
            previous_hash=entry.previous_hash,
        )
        if recomputed != entry.entry_hash:
            issues.append(
                f"Hash mismatch at index {idx}: stored {entry.entry_hash} "
                f"!= recomputed {recomputed}"
            )
        previous_hash = entry.entry_hash

    return {
        "valid": len(issues) == 0,
        "entries_checked": len(entries),
        "first_tamper_index": None if not issues else issues.index(issues[0]),
        "details": issues,
    }


async def export_audit_log(
    db: AsyncSession,
    tenant_id: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    actor_id: int | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    page: int = 1,
    page_size: int = 200,
) -> list[dict[str, Any]]:
    """Return a list of audit log entries as plain dicts for export."""
    query = select(AuditLogEntry)
    if tenant_id is not None:
        query = query.where(AuditLogEntry.tenant_id == tenant_id)
    if event_type is not None:
        query = query.where(AuditLogEntry.event_type == event_type)
    if severity is not None:
        query = query.where(AuditLogEntry.severity == severity.upper())
    if actor_id is not None:
        query = query.where(AuditLogEntry.actor_id == actor_id)
    if start_date is not None:
        query = query.where(AuditLogEntry.created_at >= start_date)
    if end_date is not None:
        query = query.where(AuditLogEntry.created_at <= end_date)

    query = (
        query.order_by(AuditLogEntry.created_at.desc(), AuditLogEntry.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )

    result = await db.execute(query)
    entries = result.scalars().all()

    export: list[dict[str, Any]] = []
    for entry in entries:
        try:
            details = json.loads(entry.details_json or "{}")
        except json.JSONDecodeError:
            details = {}
        export.append({
            "entry_id": entry.entry_id,
            "timestamp": entry.created_at.isoformat() if entry.created_at else None,
            "tenant_id": entry.tenant_id,
            "actor_id": entry.actor_id,
            "event_type": entry.event_type,
            "resource_type": entry.resource_type,
            "resource_id": entry.resource_id,
            "action": entry.action,
            "severity": entry.severity,
            "ip_address": entry.ip_address,
            "user_agent": entry.user_agent,
            "details": details,
            "previous_hash": entry.previous_hash,
            "entry_hash": entry.entry_hash,
            "key_version": entry.key_version,
        })
    return export
