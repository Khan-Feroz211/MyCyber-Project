"""Alert Service — sends Slack/email/REST callbacks on WARN/BLOCK decisions."""

from __future__ import annotations

import asyncio
import json
import os

import httpx
import structlog
from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import Counter, make_asgi_app
import redis.asyncio as aioredis

_resource = Resource(attributes={"service.name": "alert-service"})
_provider = TracerProvider(resource=_resource)
_provider.add_span_processor(
    BatchSpanProcessor(
        OTLPSpanExporter(
            endpoint=os.getenv("OTLP_ENDPOINT", "http://otel-collector:4317")
        )
    )
)
trace.set_tracer_provider(_provider)
tracer = trace.get_tracer(__name__)

ALERTS_SENT = Counter(
    "dlp_alerts_total",
    "Total alerts dispatched",
    ["channel", "decision"],
)

log = structlog.get_logger()
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
ALERT_QUEUE_KEY = os.getenv("ALERT_QUEUE_KEY", "dlp:alert_queue")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

app = FastAPI(title="DLP Alert Service", version="1.0.0")
FastAPIInstrumentor.instrument_app(app)
app.mount("/metrics", make_asgi_app())


async def send_slack(payload: dict) -> None:
    if not SLACK_WEBHOOK_URL:
        log.warning("slack_webhook_not_configured")
        return
    message = {
        "text": (
            f"*DLP Alert* [{payload['decision']}]\n"
            f"Tenant: `{payload['tenant_id']}`\n"
            f"Scan: `{payload['scan_id']}`\n"
            f"Reason: {payload['reason']}"
        )
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(SLACK_WEBHOOK_URL, json=message)
        resp.raise_for_status()
    ALERTS_SENT.labels(channel="slack", decision=payload["decision"]).inc()
    log.info(
        "slack_alert_sent", scan_id=payload["scan_id"], decision=payload["decision"]
    )


async def process_alerts(redis_client: aioredis.Redis) -> None:
    while True:
        try:
            item = await redis_client.brpop(ALERT_QUEUE_KEY, timeout=5)
            if not item:
                continue
            _, payload_str = item
            payload = json.loads(payload_str)
            with tracer.start_as_current_span("dispatch_alert"):
                await send_slack(payload)
        except Exception as exc:
            log.error("alert_dispatch_error", error=str(exc))
            await asyncio.sleep(1)


@app.on_event("startup")
async def startup() -> None:
    app.state.redis = aioredis.from_url(
        REDIS_URL, encoding="utf-8", decode_responses=True
    )
    asyncio.create_task(process_alerts(app.state.redis))
    log.info("alert_service_started")


@app.on_event("shutdown")
async def shutdown() -> None:
    await app.state.redis.aclose()


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}
