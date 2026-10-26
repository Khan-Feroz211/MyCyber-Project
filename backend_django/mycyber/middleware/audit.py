"""Actor / request-metadata capture for the audit & security layers.

Mirrors the FastAPI ``ActorMiddleware`` concept: it stashes the authenticated
actor, client IP and user-agent on a thread-local so the audit-log service can
attribute *automatic* events (e.g. session expiry) to the correct principal
without every view passing them explicitly.
"""
from __future__ import annotations

import threading

_local = threading.local()


def get_current_actor():
    """Return the actor model instance for the current request, or ``None``."""
    return getattr(_local, "actor", None)


def get_current_request_meta() -> dict:
    """Return ``{"ip_address": ..., "user_agent": ...}`` for the current request."""
    return {
        "ip_address": getattr(_local, "ip_address", None),
        "user_agent": getattr(_local, "user_agent", None),
    }


class ActorMiddleware:
    """Populate the thread-local actor context from the Django request."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        _local.actor = getattr(request, "user", None)
        if getattr(request, "user", None) and not getattr(request.user, "is_authenticated", False):
            _local.actor = None

        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
        else:
            meta = request.META
            ip = meta.get("HTTP_X_REAL_IP") or meta.get("REMOTE_ADDR")
        _local.ip_address = ip
        _local.user_agent = request.headers.get("user-agent")

        try:
            response = self.get_response(request)
        finally:
            # Clear thread-local state so the next request starts clean.
            _local.actor = None
            _local.ip_address = None
            _local.user_agent = None
        return response
