"""Service-layer helpers for encrypting/decrypting sensitive PII fields at rest.

Ported from ``backend/app/services/field_encryption.py``.  The
:func:`reencrypt_all_sensitive_fields` job walks a registry of
``(model, field_name)`` pairs so that as each Django app is ported it can
register its own sensitive columns (e.g. ``Subscription.safepay_token``)
without modifying this module.
"""
from __future__ import annotations

from typing import List, Tuple, Type

from django.db import models as dj_models

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
# Sensitive-field registry & key-rotation job
# ---------------------------------------------------------------------------

# Apps register their encrypted columns here as ``(model_class, field_name)``.
# Populated dynamically so importing this module never triggers model imports.
SENSITIVE_FIELDS: List[Tuple[Type[dj_models.Model], str]] = []


def register_sensitive_field(model: Type[dj_models.Model], field_name: str) -> None:
    """Register a model+field pair for the key-rotation re-encryption job."""
    SENSITIVE_FIELDS.append((model, field_name))


def reencrypt_all_sensitive_fields() -> dict:
    """Re-encrypt all sensitive fields under the current key version.

    Iterates every registered ``(model, field)`` pair, decrypts any versioned
    ciphertext with an old key and re-encrypts with the current master key.

    Returns a summary dict with counts per ``app_label.model``.
    """
    from mycyber.services.kms import get_kms_backend  # noqa: F811
    from mycyber.services.kms import reencrypt_field as _reencrypt

    kms = get_kms_backend()
    summary: dict[str, int] = {}

    for model, field_name in SENSITIVE_FIELDS:
        key = f"{model._meta.app_label}.{model.__name__}"
        count = 0
        try:
            for instance in model._default_manager.all():
                value = getattr(instance, field_name, None)
                if value:
                    reencrypted = _reencrypt(value, kms)
                    if reencrypted != value:
                        setattr(instance, field_name, reencrypted)
                        instance.save(update_fields=[field_name])
                        count += 1
            summary[key] = count
        except Exception as exc:  # pragma: no cover - non-fatal, like FastAPI
            from mycyber.services.kms import _logger as _kms_logger

            _kms_logger.error("Failed re-encrypting %s: %s", key, exc)

    return summary
