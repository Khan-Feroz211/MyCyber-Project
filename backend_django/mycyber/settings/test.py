"""Django settings for running the test suite.

Hermetic: SQLite (in-memory), locmem email, MD5 password hashing (fast),
no request throttling, eager Celery.  All secrets are test-only values.

Run with::

    backend_django/manage.py test --settings=mycyber.settings.test
"""
from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Test-only env vars — set BEFORE importing anything that reads them.
# Mirrors backend/tests/conftest.py so the Django suite is self-contained.
# ---------------------------------------------------------------------------
os.environ.setdefault("DJANGO_SECRET_KEY", "test-django-secret-key-for-pytest-only-32ch!")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-for-pytest-only-32chars!")
os.environ.setdefault("ENCRYPTION_MASTER_KEY", "test-encryption-key-32-bytes-long!!!")
os.environ.setdefault("SAFEPAY_SECRET_KEY", "test-safepay-secret-key-32-chars-long!!")  # noqa: S105 — test only
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_mycyber_django_db")
os.environ.setdefault("FRONTEND_URL", "http://localhost:5173")
os.environ.setdefault("MFA_ROLLOUT_MODE", "opt_in")

BASE_DIR = Path(__file__).resolve().parent.parent.parent

from .dev import *  # noqa: E402,F401,F403

# ---------------------------------------------------------------------------
# Database — SQLite in-memory (hermetic, fast, no Postgres required)
# ---------------------------------------------------------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
        "OPTIONS": {"timeout": 20},
    }
}

# ---------------------------------------------------------------------------
# Caching — locmem (no redis required for tests)
# ---------------------------------------------------------------------------
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "test-mycyber-locmem",
    }
}

# ---------------------------------------------------------------------------
# Email — in-memory
# ---------------------------------------------------------------------------
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"

# ---------------------------------------------------------------------------
# Password hashing — MD5 for speed (tests only, never production)
# ---------------------------------------------------------------------------
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]
HASHING_HASHER = "MD5"

AUTH_PASSWORD_VALIDATORS = []  # relaxed in tests; serialised validation still applies

# ---------------------------------------------------------------------------
# DRF — no throttling in tests
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["apps.accounts.auth.MFATokenAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_EXCEPTION_HANDLER": "apps.accounts.exceptions.drf_exception_handler",
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_CLASSES": [],
    "DEFAULT_THROTTLE_RATES": {},
}

# ---------------------------------------------------------------------------
# Celery — eager
# ---------------------------------------------------------------------------
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_BROKER_URL = "memory://"
CELERY_RESULT_BACKEND = "cache"
CELERY_CACHE_BACKEND = "default"

# ---------------------------------------------------------------------------
# OpenAPI schema — do not require auth for the schema endpoint
# ---------------------------------------------------------------------------
SPECTACULAR_SETTINGS = {
    "TITLE": "MyCyber DLP API",
    "DESCRIPTION": "Django port of the MyCyber DLP service",
    "VERSION": "5.0.0",
}

DEBUG = False
