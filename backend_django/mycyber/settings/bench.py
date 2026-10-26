"""Benchmark settings — dev behaviour (file SQLite) with the MFA-only auth
contract so PyJWT tokens issued by the auth service are accepted.

Run the load test against this::

    manage.py runserver 127.0.0.1:8123 --noreload --settings=mycyber.settings.bench
    python tests/load/bench_scan.py http://127.0.0.1:8123
"""
from __future__ import annotations

from .dev import *  # noqa: F401,F403

# MFA-only auth (PyJWT HS256 tokens); skip simplejwt.
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["apps.accounts.auth.MFATokenAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_EXCEPTION_HANDLER": "apps.accounts.exceptions.drf_exception_handler",
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_CLASSES": [],
    "DEFAULT_THROTTLE_RATES": {},
}

# Locmem cache + email (no Redis/SendGrid needed for the load test).
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "bench-locmem",
    }
}
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
DEBUG = True
