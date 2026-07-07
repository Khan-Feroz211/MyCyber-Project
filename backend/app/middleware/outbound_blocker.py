from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
import json
import logging

from ..services.quarantine import quarantine_bytes
from ..config import get_settings

_logger = logging.getLogger(__name__)


class OutboundBlockerMiddleware(BaseHTTPMiddleware):
    """Blocks outbound-sensitive routes (LLM) when DEPLOYMENT_REGION enforces local-only mode.

    When blocking, saves the raw request body to quarantine and returns 403/503.
    """

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        path = request.url.path or ""

        # If sovereign mode (PK) is set, block LLM DLP interactions from reaching external LLMs
        if settings.deployment_region and settings.deployment_region.upper() == "PK":
            # Target LLM DLP endpoints
            if path.startswith("/api/v1/llm-dlp"):
                try:
                    body = await request.body()
                    meta = {
                        "method": request.method,
                        "path": path,
                        "client": request.client.host if request.client else None,
                    }
                    quarantine_bytes("llm-prompt.txt", body, meta=meta)
                except Exception as exc:
                    _logger.exception("Error quarantining blocked LLM payload: %s", exc)

                return JSONResponse(
                    status_code=503,
                    content={
                        "error": "External LLM calls are disabled in this deployment (DEPLOYMENT_REGION=PK). The request has been quarantined.",
                    },
                )

        # Otherwise pass through
        return await call_next(request)
