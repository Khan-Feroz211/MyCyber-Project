"""Base Django settings for MyCyber DLP.

Shared by all environments (dev, prod).  Environment-specific
overrides live in ``dev.py`` and ``prod.py``.
"""
from __future__ import annotations

import os
import socket
from datetime import timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent.parent
APPS_DIR = BASE_DIR / "apps"

# ---------------------------------------------------------------------------
# Core Django settings
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY", "dev-insecure-secret-key-change-in-production-32ch!"
)

DEBUG = os.environ.get("DJANGO_DEBUG", "true").lower() == "true"

ALLOWED_HOSTS = os.environ.get(
    "DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,0.0.0.0"
).split(",")

AUTH_USER_MODEL = "accounts.User"

ROOT_URLCONF = "mycyber.urls"

# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------
INSTALLED_APPS = [
    # Django defaults
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third-party API / infra
    "rest_framework",
    "drf_spectacular",
    "corsheaders",
    "django_celery_beat",
    "auditlog",
    "django_otp",
    "two_factor",
    "django_prometheus",
    "import_export",
    "channels",
    # Local apps
    "apps.accounts",
    "apps.dlp",
    "apps.llm",
    "apps.scans",
    "apps.alerts",
    "apps.incidents",
    "apps.audit",
    "apps.scheduling",
    "apps.billing",
]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

MIDDLEWARE = [
    "django_prometheus.middleware.PrometheusBeforeMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_otp.middleware.OTPMiddleware",
    "two_factor.middleware.threadlocals.ThreadLocals",  # noqa
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "mycyber.middleware.request_id.RequestIdMiddleware",
    "mycyber.middleware.audit.ActorMiddleware",
    "django_prometheus.middleware.PrometheusAfterMiddleware",
]

# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ---------------------------------------------------------------------------
# Database  (PostgreSQL in prod; SQLite fallback for dev/test)
# ---------------------------------------------------------------------------
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/mycyber_dlp",
)

from urllib.parse import urlparse  # noqa: E402

_db_parsed = urlparse(DATABASE_URL)
if _db_parsed.scheme in ("sqlite", "sqlite+aiosqlite"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": _db_parsed.path[1:] if _db_parsed.path.startswith("/") else _db_parsed.path,
            "OPTIONS": {"timeout": 20},
        }
    }
else:
    _db_user = _db_parsed.username or "postgres"
    _db_pass = _db_parsed.password or ""
    _db_host = _db_parsed.hostname or "localhost"
    _db_port = str(_db_parsed.port) if _db_parsed.port else "5432"
    _db_name = _db_parsed.path.lstrip("/") or "mycyber_dlp"
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": _db_name,
            "USER": _db_user,
            "PASSWORD": _db_pass,
            "HOST": _db_host,
            "PORT": _db_port,
            "CONN_MAX_AGE": 0,
            "OPTIONS": {"sslmode": os.environ.get("DB_SSLMODE", "prefer")},
        }
    }

# ---------------------------------------------------------------------------
# Caching / Redis
# ---------------------------------------------------------------------------
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "mycyber-locmem",
    }
}

# ---------------------------------------------------------------------------
# Channels / ASGI
# ---------------------------------------------------------------------------
ASGI_APPLICATION = "mycyber.asgi.application"

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [REDIS_URL],
        },
    },
}

# ---------------------------------------------------------------------------
# Celery
# ---------------------------------------------------------------------------
CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = "rpc"  # TODO: switch to django-celery-results once installed
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = "UTC"
CELERY_ENABLE_UTC = True
CELERY_BEAT_SCHEDULER = "django_celery_beat.schedulers:DatabaseScheduler"
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 300

# ---------------------------------------------------------------------------
# Password validation (matches FastAPI behaviour — bcrypt 12 rounds)
# ---------------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.BCryptPasswordHasher",
]

# ---------------------------------------------------------------------------
# DRF + JWT (djangorestframework-simplejwt)
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["apps.accounts.auth.MFATokenAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_EXCEPTION_HANDLER": "apps.accounts.exceptions.drf_exception_handler",
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.AnonRateThrottle", "rest_framework.throttles.UserRateThrottle"],  # noqa: E501
    "DEFAULT_THROTTLE_RATES": {"anon": "1000/hour", "user": "5000/hour"},
}

SPECTACULAR_SETTINGS = {
    "TITLE": "MyCyber DLP API",
    "DESCRIPTION": "Django port of the MyCyber DLP service",
    "VERSION": "5.0.0",
}
REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "apps.accounts.auth.MFATokenAuthentication",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "100/hour",
        "user": "1000/hour",
    },
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=24),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": os.environ.get("JWT_SECRET_KEY", SECRET_KEY),
    "VERIFYING_KEY": None,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "TOKEN_TYPE_CLAIM": "token_type",
    "JTI_CLAIM": "jti",
}

# ---------------------------------------------------------------------------
# django-two-factor-auth
# ---------------------------------------------------------------------------
# Uses two_factor's built-in TOTPDevice model (MFA for the Django admin UI).
# API-level MFA is handled by apps.accounts.auth.MFATokenAuthentication +
# mycyber.services.mfa instead.
TWO_FACTOR_PATCH_ADMIN = True

# ---------------------------------------------------------------------------
# CORS (Vite frontend)
# ---------------------------------------------------------------------------
CORS_ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "CORS_ORIGINS",
        "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://localhost:8000",
    ).split(",")
    if o.strip()
]
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
CORS_ALLOWED_HEADERS = ["*"]

# ---------------------------------------------------------------------------
# drf-spectacular
# ---------------------------------------------------------------------------
SPECTACULAR_SETTINGS = {
    "TITLE": "MyCyber DLP API",
    "DESCRIPTION": "Data Loss Prevention API — scan text, files, and network payloads for sensitive entities.",
    "VERSION": "5.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
}

# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

DEFAULT_FROM_EMAIL = os.environ.get("EMAIL_FROM", "noreply@mycyber.pk")

# ---------------------------------------------------------------------------
# Application config mirrors FastAPI config.py
# ---------------------------------------------------------------------------
APP_ENV = os.environ.get("APP_ENV", "development")
MFA_ROLLOUT_MODE = os.environ.get("MFA_ROLLOUT_MODE", "opt_in")  # off | opt_in | enforced
LOGIN_MAX_FAILURES = int(os.environ.get("LOGIN_MAX_FAILURES", "5"))
LOGIN_LOCK_MINUTES = int(os.environ.get("LOGIN_LOCK_MINUTES", "15"))
SESSION_TIMEOUT_HOURS = int(os.environ.get("SESSION_TIMEOUT_HOURS", "24"))
DEPLOYMENT_REGION = os.environ.get("DEPLOYMENT_REGION", "")
ENCRYPTION_MASTER_KEY = os.environ.get("ENCRYPTION_MASTER_KEY", "")
ENCRYPTION_KEY_VERSION = int(os.environ.get("ENCRYPTION_KEY_VERSION", "1"))
ENCRYPTION_AT_REST_ENABLED = os.environ.get("ENCRYPTION_AT_REST_ENABLED", "true").lower() == "true"

# Sentry / error reporting
SENTRY_DSN = os.environ.get("SENTRY_DSN", "")

# ---------------------------------------------------------------------------
# django-import-export
# ---------------------------------------------------------------------------
IMPORT_EXPORT_USE_TRANSACTIONS = True
IMPORT_EXPORT_IMPORT_PERMISSION_CODE = None  # allow all authenticated users

# ---------------------------------------------------------------------------
# Session settings
# ---------------------------------------------------------------------------
SESSION_COOKIE_AGE = timedelta(hours=SESSION_TIMEOUT_HOURS).total_seconds()
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# ---------------------------------------------------------------------------
# Internal: hostname for metrics
# ---------------------------------------------------------------------------
HOSTNAME = socket.gethostname()
