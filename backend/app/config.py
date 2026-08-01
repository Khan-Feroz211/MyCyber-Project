from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Application
    app_env: str = Field(default="development", validation_alias="APP_ENV")
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")

    # CORS
    cors_origins: str = Field(
        default="http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173",
        validation_alias="CORS_ORIGINS",
    )

    # Limits
    max_file_size_mb: float = Field(default=25.0, validation_alias="MAX_FILE_SIZE_MB")
    max_text_length: int = Field(default=50_000, validation_alias="MAX_TEXT_LENGTH")
    rate_limit_per_min: int = Field(default=60, validation_alias="RATE_LIMIT_PER_MIN")

    # NER / ML model
    ner_model_name: str = Field(default="dslim/bert-base-NER", validation_alias="NER_MODEL_NAME")
    ner_min_confidence: float = Field(default=0.85, validation_alias="NER_MIN_CONFIDENCE")
    use_transformer: bool = Field(default=True, validation_alias="USE_TRANSFORMER")
    model_cache_dir: str = Field(default="/tmp/hf_models", validation_alias="MODEL_CACHE_DIR")  # nosec B108

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/mycyber_dlp",
        validation_alias="DATABASE_URL",
    )

    # Auth / JWT
    jwt_secret: str = Field(default="", validation_alias="JWT_SECRET_KEY")
    jwt_expire_hours: int = Field(default=24, validation_alias="JWT_EXPIRE_HOURS")
    mfa_rollout_mode: str = Field(default="opt_in", validation_alias="MFA_ROLLOUT_MODE")  # off | opt_in | enforced
    login_max_failures: int = Field(default=5, validation_alias="LOGIN_MAX_FAILURES")
    login_lock_minutes: int = Field(default=15, validation_alias="LOGIN_LOCK_MINUTES")
    # Session inactivity timeout — sessions older than this require re-auth
    session_timeout_hours: int = 24

    # MLflow
    mlflow_tracking_uri: str = Field(default="http://mlflow:5001", validation_alias="MLFLOW_TRACKING_URI")

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0", validation_alias="REDIS_URL")

    # Billing / Safepay
    safepay_secret_key: str = Field(default="", validation_alias="SAFEPAY_SECRET_KEY")
    safepay_webhook_secret: str = Field(default="", validation_alias="SAFEPAY_WEBHOOK_SECRET")
    frontend_url: str = Field(default="http://localhost:5173", validation_alias="FRONTEND_URL")

    # ── Data residency / sovereignty ─────────────────────────────────────
    # When set to "PK", all outbound LLM and external API calls are blocked
    # and payloads are quarantined locally.
    deployment_region: str = Field(default="", validation_alias="DEPLOYMENT_REGION")

    # ── Encryption at rest (KMS abstraction) ─────────────────────────────
    # Master key material (env-var-based). In production this should be
    # provisioned by an external KMS (AWS KMS / HashiCorp Vault) via a
    # pluggable backend.  The default below is for local development only.
    encryption_master_key: str = Field(default="", validation_alias="ENCRYPTION_MASTER_KEY")
    # Current key version (integer).  Bumped on rotation; older versions
    # are retained so legacy ciphertext can still be decrypted.
    encryption_key_version: int = Field(default=1, validation_alias="ENCRYPTION_KEY_VERSION")
    # Comma-separated list of older key versions for decryption of legacy
    # ciphertext, e.g. "1=base64key1,2=base64key2"
    encryption_legacy_keys: str = Field(default="", validation_alias="ENCRYPTION_LEGACY_KEYS")
    # When True, sensitive fields at rest are AES-256-GCM encrypted.
    encryption_at_rest_enabled: bool = Field(default=True, validation_alias="ENCRYPTION_AT_REST_ENABLED")

    # Email
    email_from: str = Field(default="noreply@mycyber.pk", validation_alias="EMAIL_FROM")
    smtp_host: str = Field(default="", validation_alias="SMTP_HOST")
    smtp_port: int = Field(default=587, validation_alias="SMTP_PORT")
    smtp_use_tls: bool = Field(default=True, validation_alias="SMTP_USE_TLS")
    smtp_username: str = Field(default="", validation_alias="SMTP_USERNAME")
    smtp_password: str = Field(default="", validation_alias="SMTP_PASSWORD")
    sendgrid_api_key: str = Field(default="", validation_alias="SENDGRID_API_KEY")

    @field_validator("jwt_secret")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        if not v or len(v) < 32:
            raise ValueError(
                "JWT_SECRET_KEY environment variable must be set to a string "
                "with at least 32 characters for production security."
            )
        return v

    @field_validator("encryption_master_key")
    @classmethod
    def validate_encryption_key(cls, v: str) -> str:
        """Validate the encryption master key length (32 bytes for AES-256)."""
        if not v:
            # Allow empty — encryption-at-rest is a no-op in dev/test.
            return v
        # Accept raw strings of >= 32 chars or base64-encoded 32-byte keys.
        import base64

        try:
            raw = base64.b64decode(v)
            if len(raw) == 32:
                return v
        except Exception:
            pass
        if len(v) >= 32:
            return v
        raise ValueError(
            "ENCRYPTION_MASTER_KEY must be at least 32 characters (or a base64-encoded 32-byte key)."
        )

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "populate_by_name": True,
        "protected_namespaces": ("settings_",),
    }


@lru_cache
def get_settings() -> Settings:
    return Settings()
