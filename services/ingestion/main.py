"""Ingestion Service — receives file events, normalises payloads, pushes to Redis."""

from __future__ import annotations

import uuid
from typing import Any

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Request, status
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import Counter, make_asgi_app
from pydantic import BaseModel, Field

from .config import settings
from .logger import get_logger

# ── OpenTelemetry setup ────────────────────────────────────────────────────────
resource = Resource(attributes={"service.name": "ingestion-service"})
provider = TracerProvider(resource=resource)
provider.add_span_processor(
    BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.OTLP_ENDPOINT))
)
trace.set_tracer_provider(provider)
tracer = trace.get_tracer(__name__)

# ── Prometheus metrics ─────────────────────────────────────────────────────────
EVENTS_RECEIVED = Counter(
    "ingestion_events_total",
    "Total file events received",
    ["tenant_id"],
)

log = get_logger()

app = FastAPI(title="DLP Ingestion Service", version="1.0.0")
FastAPIInstrumentor.instrument_app(app)
app.mount("/metrics", make_asgi_app())


class FileEvent(BaseModel):
    tenant_id: str = Field(..., description="Tenant identifier")
    endpoint_id: str = Field(..., description="Source endpoint/host")
    file_path: str
    file_content: str = Field(..., description="Base-64 encoded or plain text content")
    file_size_bytes: int
    mime_type: str = "application/octet-stream"
    metadata: dict[str, Any] = Field(default_factory=dict)


class NormalisedEvent(BaseModel):
    scan_id: str
    tenant_id: str
    endpoint_id: str
    file_path: str
    content: str
    mime_type: str
    file_size_bytes: int
    metadata: dict[str, Any]


@app.on_event("startup")
async def startup() -> None:
    app.state.redis = aioredis.from_url(
        settings.REDIS_URL, encoding="utf-8", decode_responses=True
    )
    log.info("ingestion_service_started", redis_url=settings.REDIS_URL)


@app.on_event("shutdown")
async def shutdown() -> None:
    await app.state.redis.aclose()


@app.post("/events", status_code=status.HTTP_202_ACCEPTED)
async def receive_event(event: FileEvent, request: Request) -> dict[str, str]:
    with tracer.start_as_current_span("receive_event") as span:
        scan_id = str(uuid.uuid4())
        span.set_attribute("scan_id", scan_id)
        span.set_attribute("tenant_id", event.tenant_id)

        normalised = NormalisedEvent(
            scan_id=scan_id,
            tenant_id=event.tenant_id,
            endpoint_id=event.endpoint_id,
            file_path=event.file_path,
            content=event.file_content,
            mime_type=event.mime_type,
            file_size_bytes=event.file_size_bytes,
            metadata=event.metadata,
        )

        try:
            await request.app.state.redis.lpush(
                settings.SCAN_QUEUE_KEY,
                normalised.model_dump_json(),
            )
        except Exception as exc:
            log.error("redis_push_failed", error=str(exc), scan_id=scan_id)
            raise HTTPException(status_code=503, detail="Queue unavailable") from exc

        EVENTS_RECEIVED.labels(tenant_id=event.tenant_id).inc()
        log.info(
            "event_queued",
            scan_id=scan_id,
            tenant_id=event.tenant_id,
            file_path=event.file_path,
        )
        return {"scan_id": scan_id, "status": "queued"}


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}
