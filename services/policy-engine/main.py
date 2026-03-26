"""Policy Engine — consumes inference results, applies DLP policies."""
from __future__ import annotations

import asyncio
import json
import os
import re
from enum import Enum
from typing import Any

import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI, Request
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import Counter, make_asgi_app
from pydantic import BaseModel, Field

_resource = Resource(attributes={"service.name": "policy-engine"})
_provider = TracerProvider(resource=_resource)
_provider.add_span_processor(
    BatchSpanProcessor(
        OTLPSpanExporter(endpoint=os.getenv("OTLP_ENDPOINT", "http://otel-collector:4317"))
    )
)
trace.set_tracer_provider(_provider)
tracer = trace.get_tracer(__name__)

POLICY_DECISIONS = Counter(
    "policy_decisions_total",
    "Policy engine decisions",
    ["decision", "tenant_id"],
)

log = structlog.get_logger()
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
RESULTS_QUEUE_KEY = os.getenv("RESULTS_QUEUE_KEY", "dlp:results_queue")
ALERT_QUEUE_KEY = os.getenv("ALERT_QUEUE_KEY", "dlp:alert_queue")

app = FastAPI(title="DLP Policy Engine", version="1.0.0")
FastAPIInstrumentor.instrument_app(app)
app.mount("/metrics", make_asgi_app())


class Decision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


class PolicyResult(BaseModel):
    scan_id: str
    tenant_id: str
    label: str
    confidence: float
    pii_types: list[str]
    decision: Decision
    reason: str


# ── Default policies ───────────────────────────────────────────────────────────
HIGH_RISK_LABELS = {"SENSITIVE_HIGH"}
LOW_RISK_LABELS = {"SENSITIVE_LOW"}
CONFIDENCE_BLOCK_THRESHOLD = float(os.getenv("CONFIDENCE_BLOCK_THRESHOLD", "0.85"))
CONFIDENCE_WARN_THRESHOLD = float(os.getenv("CONFIDENCE_WARN_THRESHOLD", "0.60"))


def evaluate_policy(inference: dict[str, Any]) -> PolicyResult:
    label: str = inference["label"]
    confidence: float = float(inference["confidence"])
    pii_types: list[str] = inference.get("pii_types", [])

    if label in HIGH_RISK_LABELS and confidence >= CONFIDENCE_BLOCK_THRESHOLD:
        decision = Decision.BLOCK
        reason = f"High-risk PII detected ({', '.join(pii_types)}) with confidence {confidence:.2f}"
    elif label in LOW_RISK_LABELS or (
        label in HIGH_RISK_LABELS and confidence < CONFIDENCE_BLOCK_THRESHOLD
    ):
        decision = Decision.WARN
        reason = f"Potential PII detected ({', '.join(pii_types)}) with confidence {confidence:.2f}"
    else:
        decision = Decision.ALLOW
        reason = "No sensitive data detected"

    return PolicyResult(
        scan_id=inference["scan_id"],
        tenant_id=inference["tenant_id"],
        label=label,
        confidence=confidence,
        pii_types=pii_types,
        decision=decision,
        reason=reason,
    )


async def process_results(redis_client: aioredis.Redis) -> None:
    """Background task: consume inference results queue and emit decisions."""
    while True:
        try:
            item = await redis_client.brpop(RESULTS_QUEUE_KEY, timeout=5)
            if not item:
                continue
            _, payload = item
            inference = json.loads(payload)

            with tracer.start_as_current_span("evaluate_policy") as span:
                span.set_attribute("scan_id", inference.get("scan_id", ""))
                result = evaluate_policy(inference)

            POLICY_DECISIONS.labels(
                decision=result.decision.value, tenant_id=result.tenant_id
            ).inc()

            if result.decision in (Decision.WARN, Decision.BLOCK):
                await redis_client.lpush(ALERT_QUEUE_KEY, result.model_dump_json())

            log.info(
                "policy_decision",
                scan_id=result.scan_id,
                tenant_id=result.tenant_id,
                decision=result.decision.value,
                reason=result.reason,
            )
        except Exception as exc:
            log.error("policy_processing_error", error=str(exc))
            await asyncio.sleep(1)


@app.on_event("startup")
async def startup() -> None:
    app.state.redis = aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    asyncio.create_task(process_results(app.state.redis))
    log.info("policy_engine_started")


@app.on_event("shutdown")
async def shutdown() -> None:
    await app.state.redis.aclose()


@app.post("/evaluate", response_model=PolicyResult)
async def evaluate(inference: dict) -> PolicyResult:
    return evaluate_policy(inference)


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}
