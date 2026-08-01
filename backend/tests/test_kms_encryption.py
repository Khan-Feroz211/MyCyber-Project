"""Tests for the KMS encryption-at-rest module and field encryption helpers.

Run with:  pytest backend/tests/test_kms_encryption.py -v
"""

from __future__ import annotations

import base64
import os

import pytest

from app.services import kms
from app.services.field_encryption import (
    decrypt_llm_prompt,
    decrypt_mfa_secret,
    encrypt_llm_prompt,
    encrypt_mfa_secret,
    reencrypt_all_sensitive_fields,
)
from app.services.kms import (
    AESGCM,
    GENESIS_HASH,
    EnvVarKMS,
    decrypt_field,
    encrypt_field,
    get_encryption_status,
    reencrypt_field,
)


# ---------------------------------------------------------------------------
# KMS backend
# ---------------------------------------------------------------------------


class TestEnvVarKMS:
    def test_current_version(self):
        backend = EnvVarKMS()
        assert backend.current_version() == 1

    def test_legacy_versions_empty(self):
        backend = EnvVarKMS()
        assert backend.legacy_versions() == []

    def test_get_master_key(self):
        backend = EnvVarKMS()
        key = backend.get_master_key()
        assert len(key) == 32

    def test_get_master_key_raises_without_config(self, monkeypatch):
        """When no key is configured, get_master_key should raise."""
        monkeypatch.delenv("ENCRYPTION_MASTER_KEY", raising=False)
        from app.config import Settings

        class TestSettings(Settings):
            encryption_master_key: str = ""
            encryption_key_version: int = 1
            encryption_legacy_keys: str = ""
            encryption_at_rest_enabled: bool = True

            model_config = {"env_prefix": "", "extra": "allow"}

        import app.services.kms as kms_mod

        original = kms_mod.get_settings
        kms_mod.get_settings = lambda: TestSettings()
        try:
            backend = EnvVarKMS()
            with pytest.raises(ValueError, match="not configured"):
                backend.get_master_key()
        finally:
            kms_mod.get_settings = original

    def test_legacy_key_parsing(self):
        """Legacy keys are parsed from comma-separated version=key pairs."""
        from app.config import Settings

        class TestSettings(Settings):
            encryption_master_key: str = "0" * 32
            encryption_key_version: int = 2
            encryption_legacy_keys: str = "1=aaaa,2=bbbb"
            encryption_at_rest_enabled: bool = True

            model_config = {"env_prefix": ""}

        backend = EnvVarKMS.__new__(EnvVarKMS)
        backend._settings = TestSettings()
        assert sorted(backend.legacy_versions()) == [1, 2]


# ---------------------------------------------------------------------------
# Field encryption / decryption round-trip
# ---------------------------------------------------------------------------


class TestFieldEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        plaintext = "my-secret-totp-code"
        encrypted = encrypt_field(plaintext)
        assert encrypted != plaintext
        assert encrypted.startswith("v1:")
        decrypted = decrypt_field(encrypted)
        assert decrypted == plaintext

    def test_encrypt_empty_string(self):
        assert encrypt_field("") == ""

    def test_encrypt_none(self):
        assert encrypt_field(None) is None

    def test_decrypt_plaintext_passes_through(self):
        """Existing plaintext (no version prefix) is returned unchanged."""
        plaintext = "not-encrypted-yet"
        assert decrypt_field(plaintext) == plaintext

    def test_decrypt_none(self):
        assert decrypt_field(None) is None

    def test_encryption_produces_different_ciphertext(self):
        """Same plaintext → different ciphertext (random salt/nonce)."""
        a = encrypt_field("secret")
        b = encrypt_field("secret")
        assert a != b
        assert decrypt_field(a) == "secret"
        assert decrypt_field(b) == "secret"


# ---------------------------------------------------------------------------
# Field encryption helpers
# ---------------------------------------------------------------------------


class TestFieldEncryptionHelpers:
    def test_mfa_secret_roundtrip(self):
        secret = "JBSWY3DPEHPK3PXP"
        enc = encrypt_mfa_secret(secret)
        dec = decrypt_mfa_secret(enc)
        assert dec == secret

    def test_mfa_secret_none(self):
        assert encrypt_mfa_secret(None) is None
        assert decrypt_mfa_secret(None) is None

    def test_llm_prompt_roundtrip(self):
        prompt = "My API key is sk-abc123def456"
        enc = encrypt_llm_prompt(prompt)
        dec = decrypt_llm_prompt(enc)
        assert dec == prompt


# ---------------------------------------------------------------------------
# Key rotation (re-encrypt under new version)
# ---------------------------------------------------------------------------


class TestKeyRotation:
    def test_reencrypt_field_reencrypts_plaintext(self):
        plaintext = "legacy-data"
        result = reencrypt_field(plaintext)
        assert result.startswith("v1:")
        assert decrypt_field(result) == plaintext

    def test_reencrypt_field_reencrypts_existing_ciphertext(self):
        plaintext = "sensitive-value"
        encrypted_v1 = encrypt_field(plaintext)
        # Simulate rotation: re-encrypt should decrypt and re-encrypt
        result = reencrypt_field(encrypted_v1)
        assert result.startswith("v1:")
        assert decrypt_field(result) == plaintext
        # The result should differ from the original (new salt)
        assert result != encrypted_v1

    def test_reencrypt_field_none(self):
        assert reencrypt_field(None) is None


# ---------------------------------------------------------------------------
# Encryption status
# ---------------------------------------------------------------------------


class TestEncryptionStatus:
    def test_status_report(self):
        status = get_encryption_status()
        assert status["backend"] == "EnvVarKMS"
        assert status["enabled"] is True
        assert status["current_version"] == 1
        assert status["legacy_versions"] == []
        assert status["key_configured"] is True


# ---------------------------------------------------------------------------
# Re-encryption job (integration with SQLite DB)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reencrypt_all_sensitive_fields(client, db_session) -> None:
    """The re-encryption job should process rows and return a summary dict."""
    from app.db.models import BillingEvent, LLMInteraction, Subscription, User
    from app.services.auth import hash_password

    user = User(
        email="reencrypt@test.com",
        hashed_password=hash_password("password123"),
        full_name="Test",
        tenant_id="reencrypt-tenant",
        plan="free",
        role="user",
        is_admin=False,
    )
    db_session.add(user)
    await db_session.flush()

    sub = Subscription(
        user_id=user.id,
        tenant_id=user.tenant_id,
        plan="pro",
        status="active",
        scan_limit=100,
        price_pkr=4500,
        safepay_token="tok_abc123",
        safepay_tracker="trk_xyz789",
    )
    db_session.add(sub)
    await db_session.flush()

    event = BillingEvent(
        user_id=user.id,
        tenant_id=user.tenant_id,
        event_type="subscription_created",
        plan="pro",
        amount_pkr=4500,
        safepay_data='{"order_id": "test-123"}',
    )
    db_session.add(event)
    await db_session.flush()

    interaction = LLMInteraction(
        user_id=user.id,
        tenant_id=user.tenant_id,
        original_prompt="My SSN is 123-45-6789",
        llm_response="Here is your data",
        pre_entities_json="[]",
        post_entities_json="[]",
        exposed_keys_json="[]",
        status="allowed",
        llm_provider="openai",
        model_used="gpt-4o-mini",
    )
    db_session.add(interaction)
    await db_session.flush()

    summary = await reencrypt_all_sensitive_fields(db_session)
    await db_session.commit()

    assert isinstance(summary, dict)
    # Tokens and data should now be encrypted (versioned ciphertext)
    assert summary.get("subscriptions", 0) >= 2
    assert summary.get("billing_events", 0) >= 1
    assert summary.get("llm_interactions", 0) >= 2
