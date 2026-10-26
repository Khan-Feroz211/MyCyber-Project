"""Health-check view (port of ``backend/app/routers/health.py``).

Exposed at ``/healthz`` and ``/health`` by the project URL conf.
"""
from __future__ import annotations

import time

from django.http import JsonResponse

_START_TIME: float = time.time()

_VERSION = "5.0.0"


def healthz(request):
    """Return service health information including DB connectivity and KMS status."""
    db_status = "ok"
    try:
        from django.db import connection

        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
    except Exception:
        db_status = "error"

    overall = "ok" if db_status == "ok" else "degraded"
    uptime = int(time.time() - _START_TIME)

    from mycyber.services.kms import get_encryption_status

    return JsonResponse(
        {
            "status": overall,
            "uptime_seconds": uptime,
            "version": _VERSION,
            "database": db_status,
            "encryption_at_rest": get_encryption_status(),
        }
    )
