from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Application
    app_env: str = "development"
    log_level: str = "INFO"

    # CORS
    cors_origins: str = (
        "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"
    )

    # Limits
    max_file_size_mb: float = 10.0
    max_text_length: int = 50_000
    rate_limit_per_min: int = 60

    # NER / ML model
    ner_model_name: str = "dslim/bert-base-NER"
    ner_min_confidence: float = 0.85
    use_transformer: bool = True
    model_cache_dir: str = "/tmp/hf_models"  # nosec B108

    # Database
    database_url: str = (
        "postgresql+asyncpg://postgres:postgres@localhost:5432/mycyber_dlp"
    )

    # Auth / JWT
    jwt_secret: str = "change-this-in-production"
    jwt_expire_hours: int = 24

    # MLflow
    mlflow_tracking_uri: str = "http://mlflow:5001"

    # Billing / Safepay
    safepay_secret_key: str = ""
    safepay_webhook_secret: str = ""
    frontend_url: str = "http://localhost:5173"

    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()
