"""Generate (and propagate) a per-request ``X-Request-Id``."""
from __future__ import annotations

import uuid

HEADER = "X-Request-Id"


class RequestIdMiddleware:
    """Attach a unique request id to every request/response cycle.

    * Reads an incoming ``X-Request-Id`` header if present (for trace
      continuity across proxies), otherwise generates a new one.
    * Stores it on ``request.request_id`` for downstream use.
    * Echoes it back in the response headers.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = request.headers.get(HEADER) or uuid.uuid4().hex[:16]
        request.request_id = request_id
        response = self.get_response(request)
        response[HEADER] = request_id
        return response
