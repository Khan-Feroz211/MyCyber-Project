from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from ..mlops.metrics import REGISTRY

router = APIRouter(tags=["monitoring"])


@router.get("/metrics")
async def metrics() -> Response:
    """
    Prometheus metrics endpoint.
    Prometheus scrapes this every 15 seconds.
    Returns metrics in Prometheus text exposition format.
    Do not add JWT protection —
    restrict via nginx allow/deny in production instead.
    """
    data = generate_latest(REGISTRY)
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
