"""Django settings for MyCyber DLP — development."""
from __future__ import annotations

from .base import *  # noqa: F401, F403


DEBUG = True

# In dev, skip HTTPS redirect so http://localhost works
SECURE_SSL_REDIRECT = False

# Use localhost DB by default in dev (override via DATABASE_URL env-var)
# The base settings already default to postgresql://postgres@127.0.0.1:5432

# CORS — allow local dev origins
CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
]

# Allow plaintext localhost for dev convenience
SECURE_PROXY_SSL_HEADER = None

# Email backend — console in dev
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# Celery — eager in dev for synchronous task execution
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
        },
    },
    "formatters": {
        "json": {
            "()": "mycyber.logging.JSONFormatter",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
}
