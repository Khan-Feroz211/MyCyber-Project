"""Tests for the KMS encryption-at-rest module and field encryption helpers.

Django port of ``backend/tests/test_kms_encryption.py``.  The service-layer
logic is identical; the only adaptation is the re-encryption job which walks
the Django ``SENSITIVE_FIELDS`` registry (currently ``User.mfa_secret``)
instead of the FastAPI ORM models.

Run with::

    backend_django/manage.py test tests.test_kms_encryption --settings=mycyber.settings.test -v2
"""
from __future__ import annotations

import os
from unittest import mock

from django.test import SimpleTestCase, TestCase

from mycyber.services.kms import (
    AESGCM,
    GENESIS_HASH,
    EnvVarKMS,
    decrypt_field,
    encrypt_field,
    get_encryption_status,
    reencrypt_field,
)
from mycyber.services.field_encryption import (
    decrypt_llm_prompt,
    decrypt_mfa_secret,
    encrypt_llm_prompt,
    encrypt_mfa_secret,
    reencrypt_all_sensitive_fields,
    SENSITIVE_FIELDS,
)


# ---------------------------------------------------------------------------
# KMS backend
# ---------------------------------------------------------------------------


class EnvVarKMSTests(SimpleTestCase):
    def test_current_version(self):
        backend = EnvVarKMS()
        self.assertEqual(backend.current_version(), 1)

    def test_legacy_versions_empty(self):
        backend = EnvVarKMS()
        self.assertEqual(backend.legacy_versions(), [])

    def test_get_master_key(self):
        backend = EnvVarKMS()
        key = backend.get_master_key()
        self.assertEqual(len(key), 32)

    def test_get_master_key_raises_without_config(self):
        """When no key is configured, get_master_key should raise."""
        env = {"ENCRYPTION_MASTER_KEY": ""}
        with mock.patch.dict(os.environ, env, clear=False):
            backend = EnvVarKMS()
            with self.assertRaises(ValueError, msg="not configured"):
                backend.get_master_key()

    def test_legacy_key_parsing(self):
        """Legacy keys are parsed from comma-separated version=key pairs."""
        env = {"ENCRYPTION_LEGACY_KEYS": "1=aaaa,2=bbbb"}
        with mock.patch.dict(os.environ, env, clear=False):
            backend = EnvVarKMS()
            self.assertEqual(sorted(backend.legacy_versions()), [1, 2])

    def test_genesis_hash_constant(self):
        self.assertEqual(GENESIS_HASH, "GENESIS")


# ---------------------------------------------------------------------------
# Field encryption / decryption round-trip
# ---------------------------------------------------------------------------


class FieldEncryptionTests(SimpleTestCase):
    def test_encrypt_decrypt_roundtrip(self):
        plaintext = "my-secret-totp-code"
        encrypted = encrypt_field(plaintext)
        self.assertNotEqual(encrypted, plaintext)
        self.assertTrue(encrypted.startswith("v1:"))
        decrypted = decrypt_field(encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_empty_string(self):
        self.assertEqual(encrypt_field(""), "")

    def test_encrypt_none(self):
        self.assertIsNone(encrypt_field(None))

    def test_decrypt_plaintext_passes_through(self):
        """Existing plaintext (no version prefix) is returned unchanged."""
        plaintext = "not-encrypted-yet"
        self.assertEqual(decrypt_field(plaintext), plaintext)

    def test_decrypt_none(self):
        self.assertIsNone(decrypt_field(None))

    def test_encryption_produces_different_ciphertext(self):
        """Same plaintext -> different ciphertext (random salt/nonce)."""
        a = encrypt_field("secret")
        b = encrypt_field("secret")
        self.assertNotEqual(a, b)
        self.assertEqual(decrypt_field(a), "secret")
        self.assertEqual(decrypt_field(b), "secret")


# ---------------------------------------------------------------------------
# Field encryption helpers
# ---------------------------------------------------------------------------


class FieldEncryptionHelperTests(SimpleTestCase):
    def test_mfa_secret_roundtrip(self):
        secret = "JBSWY3DPEHPK3PXP"
        enc = encrypt_mfa_secret(secret)
        dec = decrypt_mfa_secret(enc)
        self.assertEqual(dec, secret)

    def test_mfa_secret_none(self):
        self.assertIsNone(encrypt_mfa_secret(None))
        self.assertIsNone(decrypt_mfa_secret(None))

    def test_llm_prompt_roundtrip(self):
        prompt = "My API key is sk-abc123def456"
        enc = encrypt_llm_prompt(prompt)
        dec = decrypt_llm_prompt(enc)
        self.assertEqual(dec, prompt)


# ---------------------------------------------------------------------------
# Key rotation (re-encrypt under new version)
# ---------------------------------------------------------------------------


class KeyRotationTests(SimpleTestCase):
    def test_reencrypt_field_reencrypts_plaintext(self):
        plaintext = "legacy-data"
        result = reencrypt_field(plaintext)
        self.assertTrue(result.startswith("v1:"))
        self.assertEqual(decrypt_field(result), plaintext)

    def test_reencrypt_field_reencrypts_existing_ciphertext(self):
        plaintext = "sensitive-value"
        encrypted_v1 = encrypt_field(plaintext)
        result = reencrypt_field(encrypted_v1)
        self.assertTrue(result.startswith("v1:"))
        self.assertEqual(decrypt_field(result), plaintext)
        # Re-encrypted ciphertext differs (new random salt/nonce)
        self.assertNotEqual(result, encrypted_v1)

    def test_reencrypt_field_none(self):
        self.assertIsNone(reencrypt_field(None))


# ---------------------------------------------------------------------------
# Encryption status
# ---------------------------------------------------------------------------


class EncryptionStatusTests(SimpleTestCase):
    def test_status_report(self):
        status = get_encryption_status()
        self.assertEqual(status["backend"], "EnvVarKMS")
        self.assertTrue(status["enabled"] is True)
        self.assertEqual(status["current_version"], 1)
        self.assertEqual(status["legacy_versions"], [])
        self.assertTrue(status["key_configured"] is True)


# ---------------------------------------------------------------------------
# Re-encryption job (integration with the Django test DB)
# ---------------------------------------------------------------------------


class ReencryptAllTests(TestCase):
    """The rotation job walks the SENSITIVE_FIELDS registry (User.mfa_secret)."""

    def test_reencrypt_all_sensitive_fields(self) -> None:
        from django.db import transaction

        from apps.accounts.models import User

        # The accounts app config registers (User, "mfa_secret") in ready().
        registered = any(
            m is User and f == "mfa_secret" for m, f in SENSITIVE_FIELDS
        )
        self.assertTrue(registered, "User.mfa_secret must be registered as sensitive")

        user = User.objects.create(
            email="reencrypt@test.com",
            full_name="Reencrypt",
            role="viewer",
            plan="free",
            is_admin=False,
            mfa_secret="JBSWY3DPEHPK3PXP",  # plaintext — should be encrypted
        )
        user.set_password("password123")
        user.save()

        with transaction.atomic():
            summary = reencrypt_all_sensitive_fields()

        # The job should have encrypted the plaintext mfa_secret.
        key = "accounts.User"
        self.assertIn(key, summary)
        self.assertGreaterEqual(summary[key], 1)

        # Reload from DB and confirm the value is now versioned ciphertext.
        user.refresh_from_db()
        self.assertTrue(user.mfa_secret.startswith("v1:"))
        self.assertNotEqual(user.mfa_secret, "JBSWY3DPEHPK3PXP")

        # And it must still decrypt back to the original secret.
        from mycyber.services.field_encryption import decrypt_mfa_secret

        self.assertEqual(decrypt_mfa_secret(user.mfa_secret), "JBSWY3DPEHPK3PXP")
