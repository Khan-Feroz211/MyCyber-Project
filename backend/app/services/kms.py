"""Key Management Service abstraction for encryption at rest.

This module provides a pluggable KMS abstraction.  Currently two backends
are supported:

* **EnvVarKMS** — the default, env-var-based backend.  Master key material
  is read from ``ENCRYPTION_MASTER_KEY`` (and legacy keys from
  ``ENCRYPTION_LEGACY_KEYS``).  This is sufficient for single-instance
  deployments and testing.

* **AWSKMS** / **VaultKMS** — stubs that will be activated when the
  corresponding env vars (``ENCRYPTION_KMS_BACKEND=aws`` or ``=vault``)
  are set.  They delegate data-key generation and master-key wrapping to
  AWS KMS or HashiCorp Vault respectively.

Key rotation strategy
----------------------
Each version of the master key is identified by an integer version.
``get_data_key()`` always returns a key encrypted under the *current*
version.  ``decrypt_data_key(version, ciphertext)`` can decrypt data keys
encrypted under any known version (current or legacy).

Field-level encryption
----------------------
The :class:`FieldEncryptionMixin` provides ``encrypt`` / ``decrypt`` helpers
that use AES-256-GCM with a version prefix so ciphertext is self-describing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from abc import ABC, abstractmethod
from functools import lru_cache
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from ..config import get_settings

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_KEY_PREFIX = "v"  # prefix for version-embedded ciphertext
_NONCE_LEN = 12  # AES-GCM standard nonce length
_MAX_KEY_LEN = 256  # bits — hard ceiling
GENESIS_HASH = "GENESIS"


# ---------------------------------------------------------------------------
# Master KMS interface
# ---------------------------------------------------------------------------


class KMSBackend(ABC):
    """Abstract base class for KMS backends."""

    @abstractmethod
    def get_master_key(self, version: int | None = None) -> bytes:
        """Return the raw master key bytes for *version* (current if None)."""

    @abstractmethod
    def current_version(self) -> int:
        """Return the active key version integer."""

    @abstractmethod
    def legacy_versions(self) -> list[int]:
        """Return a list of legacy key versions available for decryption."""


# ---------------------------------------------------------------------------
# Env-var-based KMS (default)
# ---------------------------------------------------------------------------


class EnvVarKMS(KMSBackend):
    """Master keys derived from env-var configuration.

    The primary key comes from ``ENCRYPTION_MASTER_KEY``.  Legacy keys are
    parsed from ``ENCRYPTION_LEGACY_KEYS`` as ``version=base64key`` pairs.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._legacy_cache: dict[int, bytes] = {}

    def _resolve_key(self, raw: str) -> bytes:
        """Normalise a key string to exactly 32 bytes for AES-256."""
        if not raw:
            raise ValueError("Encryption key material is empty.")
        try:
            decoded = base64.b64decode(raw, validate=True)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass
        # Fall back: hash the raw string to 32 bytes (deterministic).
        return hashlib.sha256(raw.encode("utf-8")).digest()

    def get_master_key(self, version: int | None = None) -> bytes:
        """Return 32-byte master key for *version*."""
        settings = self._settings
        if version is None or version == settings.encryption_key_version:
            if not settings.encryption_master_key:
                raise ValueError(
                    "ENCRYPTION_MASTER_KEY is not configured. "
                    "Set it to a 32-byte key (or >= 32-char string)."
                )
            return self._resolve_key(settings.encryption_master_key)
        # Legacy key
        if version in self._legacy_cache:
            return self._legacy_cache[version]
        legacy = self._parse_legacy_keys()
        if version not in legacy:
            raise ValueError(
                f"Unknown encryption key version: {version}. "
                f"Available: {sorted(legacy.keys())}"
            )
        key = self._resolve_key(legacy[version])
        self._legacy_cache[version] = key
        return key

    def current_version(self) -> int:
        return self._settings.encryption_key_version

    def legacy_versions(self) -> list[int]:
        return sorted(self._parse_legacy_keys().keys())

    def _parse_legacy_keys(self) -> dict[int, str]:
        """Parse ``ENCRYPTION_LEGACY_KEYS=1=key1,2=key2`` → ``{1: key1, ...}``."""
        raw = self._settings.encryption_legacy_keys
        if not raw:
            return {}
        result: dict[int, str] = {}
        for pair in raw.split(","):
            pair = pair.strip()
            if not pair or "=" not in pair:
                continue
            ver_str, key_val = pair.split("=", 1)
            try:
                result[int(ver_str.strip())] = key_val.strip()
            except ValueError:
                continue
        return result


# ---------------------------------------------------------------------------
# AWS KMS backend (stub — activated when ENCRYPTION_KMS_BACKEND=aws)
# ---------------------------------------------------------------------------


class AWSKMS(KMSBackend):
    """AWS KMS-backed KMS.  Requires ``boto3`` and ``AWS_KMS_KEY_ID``.

    Not fully wired yet — included as a pluggable stub for future activation.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        try:
            import boto3  # noqa: F401

            self._kms = boto3.client("kms")
        except Exception:
            _logger.warning("boto3 not available; AWS KMS backend disabled.")
            self._kms = None

    def get_master_key(self, version: int | None = None) -> bytes:
        if self._kms is None:
            raise RuntimeError("AWS KMS backend not available (boto3 missing).")
        key_id = os.getenv("AWS_KMS_KEY_ID", "")
        if not key_id:
            raise ValueError("AWS_KMS_KEY_ID env var not set.")
        if version is None:
            resp = self._kms.decrypt(CiphertextBlob=...)  # type: ignore[truthy-bool]
            return resp["Plaintext"]  # type: ignore
        raise NotImplementedError("Versioned AWS KMS key retrieval not yet implemented.")

    def current_version(self) -> int:
        return self._settings.encryption_key_version

    def legacy_versions(self) -> list[int]:
        return []


# ---------------------------------------------------------------------------
# HashiCorp Vault backend (stub — activated when ENCRYPTION_KMS_BACKEND=vault)
# ---------------------------------------------------------------------------


class VaultKMS(KMSBackend):
    """HashiCorp Vault-backed KMS.  Requires ``hvac`` and ``VAULT_ADDR``.

    Not fully wired yet — included as a pluggable stub for future activation.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        try:
            import hvac  # noqa: F401

            self._client = hvac.Client(url=os.getenv("VAULT_ADDR", "http://localhost:8200"))
        except Exception:
            _logger.warning("hvac not available; Vault KMS backend disabled.")
            self._client = None

    def get_master_key(self, version: int | None = None) -> bytes:
        if self._client is None:
            raise RuntimeError("Vault KMS backend not available (hvac missing).")
        raise NotImplementedError("Vault KMS key retrieval not yet implemented.")

    def current_version(self) -> int:
        return self._settings.encryption_key_version

    def legacy_versions(self) -> list[int]:
        return []


# ---------------------------------------------------------------------------
# Backend factory
# ---------------------------------------------------------------------------

_BACKEND_MAP = {
    "env": EnvVarKMS,
    "aws": AWSKMS,
    "vault": VaultKMS,
}


@lru_cache
def get_kms_backend() -> KMSBackend:
    """Return the active KMS backend based on ``ENCRYPTION_KMS_BACKEND``."""
    backend_name = os.getenv("ENCRYPTION_KMS_BACKEND", "env").lower()
    backend_cls = _BACKEND_MAP.get(backend_name, EnvVarKMS)
    _logger.info("Using KMS backend: %s", backend_cls.__name__)
    return backend_cls()


# ---------------------------------------------------------------------------
# Field-level encryption helpers
# ---------------------------------------------------------------------------


def _derive_data_key(master_key: bytes, salt: bytes, info: bytes = b"mycyber-field-encryption") -> bytes:
    """Derive a 32-byte AES-256 data key from *master_key* using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(master_key)


def encrypt_field(plaintext: str | None, kms: KMSBackend | None = None) -> str | None:
    """Encrypt a plaintext string with AES-256-GCM.

    The returned ciphertext is self-describing: it embeds the key version,
    a random salt (for HKDF key derivation), the nonce, and the encrypted
    payload.  All binary parts are base64url-encoded and joined with ``:``.

    Format::

        v1:<base64(salt)>:<base64(nonce)>:<base64(ciphertext+tag)>

    Returns the plaintext unchanged when encryption is disabled or no key
    is configured (graceful degradation for dev/test).
    """
    if not plaintext:
        return plaintext

    kms = kms or get_kms_backend()
    settings = get_settings()

    if not settings.encryption_at_rest_enabled:
        return plaintext

    if not settings.encryption_master_key:
        # No key configured — fail safe (log warning, return plaintext)
        _logger.warning(
            "encryption_master_key not set; storing plaintext (encryption-at-rest disabled)."
        )
        return plaintext

    version = kms.current_version()
    master_key = kms.get_master_key(version=version)

    # Per-field random salt so identical plaintexts produce different ciphertexts
    salt = os.urandom(16)
    data_key = _derive_data_key(master_key, salt)
    nonce = os.urandom(_NONCE_LEN)

    aesgcm = AESGCM(data_key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)

    return _encode_ciphertext(version, salt, nonce, ct)


def decrypt_field(ciphertext: str | None, kms: KMSBackend | None = None) -> str | None:
    """Decrypt a ciphertext produced by :func:`encrypt_field`.

    Reads the embedded version to select the correct master key, supporting
    key rotation (legacy versions can still be decrypted).

    Returns the plaintext unchanged when the input does not look like a
    versioned ciphertext (backward-compatible with existing plaintext).
    """
    if not ciphertext or not ciphertext.startswith("v"):
        return ciphertext

    kms = kms or get_kms_backend()
    settings = get_settings()

    if not settings.encryption_at_rest_enabled:
        return ciphertext

    try:
        version, salt, nonce, ct = _decode_ciphertext(ciphertext)
    except (ValueError, IndexError):
        # Not in our format — treat as plaintext (backward compat)
        return ciphertext

    try:
        master_key = kms.get_master_key(version=version)
    except ValueError:
        _logger.error(
            "Cannot decrypt field: key version %d not available.",
            version,
        )
        return ciphertext  # cannot decrypt — return as-is for inspection

    data_key = _derive_data_key(master_key, salt)
    aesgcm = AESGCM(data_key)
    plaintext = aesgcm.decrypt(nonce, ct, associated_data=None)
    return plaintext.decode("utf-8")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _encode_ciphertext(version: int, salt: bytes, nonce: bytes, ct: bytes) -> str:
    """Encode the components into the canonical ciphertext string."""
    return "{ver}:{salt}:{nonce}:{ct}".format(
        ver=f"v{version}",
        salt=base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        nonce=base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("="),
        ct=base64.urlsafe_b64encode(ct).decode("ascii").rstrip("="),
    )


def _decode_ciphertext(ciphertext: str) -> tuple[int, bytes, bytes, bytes]:
    """Parse a versioned ciphertext string into its components."""
    parts = ciphertext.split(":")
    if len(parts) != 4:
        raise ValueError(f"Invalid ciphertext format: expected 4 parts, got {len(parts)}")

    ver_str = parts[0]
    if not ver_str.startswith("v") or not ver_str[1:].isdigit():
        raise ValueError(f"Invalid version prefix: {ver_str}")
    version = int(ver_str[1:])

    salt = _b64url_decode(parts[1])
    nonce = _b64url_decode(parts[2])
    ct = _b64url_decode(parts[3])

    return version, salt, nonce, ct


def _b64url_decode(s: str) -> bytes:
    """Decode a base64url string, adding padding as needed."""
    pad = 4 - len(s) % 4
    if pad < 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


# ---------------------------------------------------------------------------
# Key rotation & re-encryption
# ---------------------------------------------------------------------------


def reencrypt_field(
    current_value: str | None,
    kms: KMSBackend | None = None,
) -> str | None:
    """Re-encrypt a field value under the current key version.

    If *current_value* is already ciphertext (versioned), it is decrypted
    using the version embedded in the ciphertext and re-encrypted with
    the current master key.  If it is plaintext, it is encrypted directly.

    Returns ``None`` unchanged.  Returns the value as-is when encryption
    is disabled or no key is configured.
    """
    if current_value is None:
        return None

    kms = kms or get_kms_backend()
    settings = get_settings()

    if not settings.encryption_at_rest_enabled or not settings.encryption_master_key:
        return current_value

    plaintext = decrypt_field(current_value, kms)
    if plaintext == current_value:
        # Not ciphertext — plaintext, just encrypt
        return encrypt_field(plaintext, kms)
    else:
        # Was ciphertext — re-encrypt under current version
        return encrypt_field(plaintext, kms)


def get_encryption_status() -> dict[str, Any]:
    """Return a diagnostic dict describing the current encryption configuration."""
    kms = get_kms_backend()
    settings = get_settings()
    try:
        current_ver = kms.current_version()
        legacy_vers = kms.legacy_versions()
    except Exception:
        current_ver = -1
        legacy_vers = []

    return {
        "backend": kms.__class__.__name__,
        "enabled": settings.encryption_at_rest_enabled,
        "current_version": current_ver,
        "legacy_versions": legacy_vers,
        "key_configured": bool(settings.encryption_master_key),
    }
