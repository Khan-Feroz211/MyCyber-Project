"""DRF exception handling for MyCyber auth errors.

Maps :class:`mycyber.services.auth.AuthError` (raised by JWT decode / session
checks) to DRF ``Response`` objects preserving the original status code
(notably **419** for session expiry, which DRF has no built-in exception for).
"""
from __future__ import annotations

from rest_framework.response import Response
from rest_framework.views import exception_handler


def drf_exception_handler(exc, context):
    # Imported lazily to avoid importing auth models at settings load time.
    from mycyber.services.auth import AuthError

    if isinstance(exc, AuthError):
        return Response({"detail": exc.message}, status=exc.status_code)

    # Fall back to DRF's default handling (APIException -> Response).
    return exception_handler(exc, context)
