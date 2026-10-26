"""Django settings for running the test suite.

Inherits from dev and swaps in SQLite + test-only env vars so the suite is
fully hermetic (no PostgreSQL / Redis / email required).
"""
from __future__ import annotations

import os

from .dev import *  # noqa: F401, F403

# --- Hermetic env vars (must be set before services read them) ---
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-for-pytest-only-32chars!")
os.environ.setdefault("DJANGO_SECRET_KEY", "test-django-secret-key-for-pytest-only-32ch!")
os.environ.setdefault(
    "DATABASE_URL",
    "sqlite:///./test_mycyber_django.db",
)
os.environ.setdefault("ENCRYPTION_MASTER_KEY", "test-encryption-key-32-bytes-long!!!")
os.environ.setdefault("FRONTEND_URL", "http://localhost:5173")

# --- Database: SQLite so tests run without PostgreSQL ---
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "test_mycyber_django_db",
        "OPTIONS": {"timeout": 20},
    }
}

# Don't let test throttling / rate-limiting interfere with the suite.
REST_FRAMEWORK = {  # noqa: F811  (override inherited)
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "apps.accounts.auth.MFATokenAuthentication",
    ],
    "DEFAULT_THROTTLE_CLASSES": [],
    "DEFAULT_THROTTLE_RATES": {},
}

# Celery runs eagerly in tests.
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True

# Speed up password hashing in tests.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

# Use the console email backend so password-reset "emails" are captured.
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
