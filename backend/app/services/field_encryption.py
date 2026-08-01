"""Service-layer helpers for encrypting/decrypting sensitive PII fields at rest.

These helpers wrap the KMS encryption service and are called at the point
where data enters or leaves the persistence layer.  They encrypt:

* ``User.mfa_secret``            — TOTP shared secret (PII-adjacent credential)
* ``Subscription.safepay_token`` — payment gateway token
* ``Subscription.safepay_tracker`` — payment gateway tracker
* ``BillingEvent.safepay_data``  — raw Safepay webhook payload (may contain PII)
* ``LLMInteraction.original_prompt`` / ``llm_response`` — raw user prompts/responses
"""

from __future__ import annotations

from .kms import decrypt_field, encrypt_field, reencrypt_field

# ---------------------------------------------------------------------------
# Field-level encryption/decryption wrappers
# ---------------------------------------------------------------------------


def encrypt_mfa_secret(secret: str | None) -> str | None:
    """Encrypt a TOTP secret before storing in the DB."""
    if secret is None:
        return None
    return encrypt_field(secret)


def decrypt_mfa_secret(encrypted: str | None) -> str | None:
    """Decrypt a TOTP secret read from the DB."""
    if encrypted is None:
        return None
    return decrypt_field(encrypted)


def encrypt_payment_token(token: str | None) -> str | None:
    """Encrypt a Safepay token before storing."""
    if token is None:
        return None
    return encrypt_field(token)


def decrypt_payment_token(encrypted: str | None) -> str | None:
    """Decrypt a Safepay token."""
    if encrypted is None:
        return None
    return decrypt_field(encrypted)


def encrypt_payment_tracker(tracker: str | None) -> str | None:
    """Encrypt a Safepay tracker before storing."""
    if tracker is None:
        return None
    return encrypt_field(tracker)


def decrypt_payment_tracker(encrypted: str | None) -> str | None:
    """Decrypt a Safepay tracker."""
    if encrypted is None:
        return None
    return decrypt_field(encrypted)


def encrypt_safepay_data(data: str | None) -> str | None:
    """Encrypt raw Safepay webhook data before storing."""
    if data is None:
        return None
    return encrypt_field(data)


def decrypt_safepay_data(encrypted: str | None) -> str | None:
    """Decrypt stored Safepay webhook data."""
    if encrypted is None:
        return None
    return decrypt_field(encrypted)


def encrypt_llm_prompt(prompt: str | None) -> str | None:
    """Encrypt a raw LLM prompt/response before storing (PII at rest protection)."""
    if prompt is None:
        return None
    return encrypt_field(prompt)


def decrypt_llm_prompt(encrypted: str | None) -> str | None:
    """Decrypt a stored LLM prompt/response."""
    if encrypted is None:
        return None
    return decrypt_field(encrypted)


# ---------------------------------------------------------------------------
# Key rotation / re-encryption jobs
# ---------------------------------------------------------------------------


async def reencrypt_all_sensitive_fields(db) -> dict:
    """Re-encrypt all sensitive fields across models under the current key version.

    This is the background job invoked during key rotation.  It iterates
    over every row in the relevant tables, decrypts any versioned ciphertext
    with an old key, and re-encrypts with the current key version.

    Returns a summary dict with counts per table.
    """
    from sqlalchemy import select, update

    from ..db.models import BillingEvent, LLMInteraction, Subscription, User
    from ..mlops.logger import get_logger

    _log = get_logger(__name__)
    summary: dict[str, int] = {}

    # --- User.mfa_secret ---
    try:
        result = await db.execute(select(User))
        users = result.scalars().all()
        count = 0
        for u in users:
            if u.mfa_secret:
                u.mfa_secret = reencrypt_field(u.mfa_secret)
                count += 1
        await db.flush()
        summary["users"] = count
    except Exception as exc:
        _log.error("Failed re-encrypting users: %s", exc)

    # --- Subscription payment tokens ---
    try:
        result = await db.execute(select(Subscription))
        subs = result.scalars().all()
        count = 0
        for s in subs:
            if s.safepay_token:
                s.safepay_token = reencrypt_field(s.safepay_token)
                count += 1
            if s.safepay_tracker:
                s.safepay_tracker = reencrypt_field(s.safepay_tracker)
                count += 1
        await db.flush()
        summary["subscriptions"] = count
    except Exception as exc:
        _log.error("Failed re-encrypting subscriptions: %s", exc)

    # --- BillingEvent.safepay_data ---
    try:
        result = await db.execute(select(BillingEvent))
        events = result.scalars().all()
        count = 0
        for e in events:
            if e.safepay_data:
                e.safepay_data = reencrypt_field(e.safepay_data)
                count += 1
        await db.flush()
        summary["billing_events"] = count
    except Exception as exc:
        _log.error("Failed re-encrypting billing events: %s", exc)

    # --- LLMInteraction prompts/response ---
    try:
        result = await db.execute(select(LLMInteraction))
        interactions = result.scalars().all()
        count = 0
        for i in interactions:
            if i.original_prompt:
                i.original_prompt = reencrypt_field(i.original_prompt)
                count += 1
            if i.llm_response:
                i.llm_response = reencrypt_field(i.llm_response)
                count += 1
        await db.flush()
        summary["llm_interactions"] = count
    except Exception as exc:
        _log.error("Failed re-encrypting LLM interactions: %s", exc)

    return summary
