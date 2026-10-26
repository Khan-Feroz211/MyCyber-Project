"""Lazy, env-backed configuration access for MyCyber Django services.

This replaces the FastAPI ``pydantic`` ``Settings`` object.  Every accessor
reads ``os.environ`` directly so values are honoured at call-time (critical for
tests that set env vars after the settings module is imported).
"""
from __future__ import annotations

import os


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


# ── Application ───────────────────────────────────────────────────────────
def app_env() -> str:
    return _env("APP_ENV", "development")


def frontend_url() -> str:
    return _env("FRONTEND_URL", "http://localhost:5173")


# ── Auth / JWT ────────────────────────────────────────────────────────────
def jwt_secret() -> str:
    """JWT signing secret. Falls back to Django SECRET_KEY when unset."""
    return _env("JWT_SECRET_KEY") or _django_secret_key()


def _django_secret_key() -> str:
    from django.conf import settings

    return getattr(settings, "SECRET_KEY", "")


def jwt_access_token_lifetime_hours() -> int:
    return int(_env("JWT_EXPIRE_HOURS", "24"))


# ── MFA ───────────────────────────────────────────────────────────────────
def mfa_rollout_mode() -> str:
    """``off`` | ``opt_in`` | ``enforced``."""
    return _env("MFA_ROLLOUT_MODE", "opt_in")


def login_max_failures() -> int:
    return int(_env("LOGIN_MAX_FAILURES", "5"))


def login_lock_minutes() -> int:
    return int(_env("LOGIN_LOCK_MINUTES", "15"))


def session_timeout_hours() -> int:
    return int(_env("SESSION_TIMEOUT_HOURS", "24"))


# ── Data residency / sovereignty ─�─────────────────────────────────────────
def deployment_region() -> str:
    return _env("DEPLOYMENT_REGION", "")


# ── Encryption at rest (KMS abstraction) ──────────────────────────────────
def encryption_master_key() -> str:
    return _env("ENCRYPTION_MASTER_KEY", "")


def encryption_key_version() -> int:
    return int(_env("ENCRYPTION_KEY_VERSION", "1"))


def encryption_legacy_keys() -> str:
    """Comma-separated ``version=base64key`` pairs for key rotation."""
    return _env("ENCRYPTION_LEGACY_KEYS", "")


def encryption_at_rest_enabled() -> bool:
    return _env("ENCRYPTION_AT_REST_ENABLED", "true").lower() == "true"


def kms_backend_name() -> str:
    return _env("ENCRYPTION_KMS_BACKEND", "env").lower()


# ── Billing / Safepay ─────────────────────────────────────────────────────
def safepay_secret_key() -> str:
    return _env("SAFEPAY_SECRET_KEY", "")


def safepay_webhook_secret() -> str:
    return _env("SAFEPAY_WEBHOOK_SECRET", "")


# ── LLM DLP ───────────────────────────────────────────────────────────────
def llm_api_key() -> str:
    return _env("LLM_API_KEY", "")


def llm_base_url() -> str:
    return _env("LLM_BASE_URL", "https://api.openai.com/v1")


def llm_model() -> str:
    return _env("LLM_MODEL", "gpt-4o-mini")


def llm_dlp_enabled() -> bool:
    return _env("LLM_DLP_ENABLED", "true").lower() == "true"


def llm_auto_deactivate() -> bool:
    return _env("LLM_AUTO_DEACTIVATE", "true").lower() == "true"


def llm_urdu_preprocess() -> bool:
    return _env("URDU_PREPROCESS", "true").lower() == "true"


# ── Email ─────────────────────────────────────────────────────────────────
def email_from() -> str:
    return _env("EMAIL_FROM", "noreply@mycyber.pk")


def smtp_host() -> str:
    return _env("SMTP_HOST", "")


def smtp_port() -> int:
    return int(_env("SMTP_PORT", "587"))


def smtp_use_tls() -> bool:
    return _env("SMTP_USE_TLS", "true").lower() == "true"


def smtp_username() -> str:
    return _env("SMTP_USERNAME", "")


def smtp_password() -> str:
    return _env("SMTP_PASSWORD", "")


def sendgrid_api_key() -> str:
    return _env("SENDGRID_API_KEY", "")


# ── Limits ────────────────────────────────────────────────────────────────
def max_file_size_mb() -> float:
    return float(_env("MAX_FILE_SIZE_MB", "25.0"))


def max_text_length() -> int:
    return int(_env("MAX_TEXT_LENGTH", "50000"))


def rate_limit_per_min() -> int:
    return int(_env("RATE_LIMIT_PER_MIN", "60"))
