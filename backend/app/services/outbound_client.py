from __future__ import annotations

import os
import logging
from typing import Any, Dict, Optional

import httpx

from .quarantine import quarantine_bytes
from ..config import get_settings

_logger = logging.getLogger(__name__)


class OutboundClient:
    def __init__(self, timeout: float = 30.0):
        self._timeout = timeout
        self._settings = get_settings()

    async def post(self, url: str, data: bytes | str, headers: Optional[Dict[str, str]] = None, service_name: Optional[str] = None) -> httpx.Response:
        """Central outbound POST helper. In sovereign mode it will quarantine sensitive payloads instead of sending."""
        # If in PK sovereign mode and service flagged sensitive, quarantine and raise
        if self._settings.deployment_region and self._settings.deployment_region.upper() == "PK":
            # For now, block all external hosts — more granular allowlist can be added
            _logger.warning("Outbound POST blocked by sovereign policy: %s", url)
            # Ensure bytes
            if isinstance(data, str):
                data_bytes = data.encode("utf-8")
            else:
                data_bytes = data
            meta = {"url": url, "service": service_name}
            quarantine_bytes("outbound-payload.bin", data_bytes, meta=meta)
            raise RuntimeError("Outbound calls disabled in sovereign DEPLOYMENT_REGION=PK")

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(url, content=data, headers=headers or {})
            return resp


outbound_client = OutboundClient()
