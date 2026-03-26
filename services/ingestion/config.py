"""Ingestion service configuration."""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    REDIS_URL: str = "redis://redis:6379/0"
    SCAN_QUEUE_KEY: str = "dlp:scan_queue"
    OTLP_ENDPOINT: str = "http://otel-collector:4317"

    class Config:
        env_file = ".env"


settings = Settings()
