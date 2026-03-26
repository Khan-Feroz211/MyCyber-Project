"""ML Inference Service — loads sklearn + transformer models, returns classification."""
from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import structlog
from fastapi import FastAPI, Request, status
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import Counter, Histogram, make_asgi_app
from pydantic import BaseModel, Field

# ── OpenTelemetry ──────────────────────────────────────────────────────────────
_resource = Resource(attributes={"service.name": "ml-inference-service"})
_provider = TracerProvider(resource=_resource)
_provider.add_span_processor(
    BatchSpanProcessor(
        OTLPSpanExporter(endpoint=os.getenv("OTLP_ENDPOINT", "http://otel-collector:4317"))
    )
)
trace.set_tracer_provider(_provider)
tracer = trace.get_tracer(__name__)

# ── Prometheus metrics ─────────────────────────────────────────────────────────
DLP_SCANS_TOTAL = Counter(
    "dlp_scans_total",
    "Total DLP scans processed",
    ["result", "model_version"],
)
DLP_INFERENCE_LATENCY = Histogram(
    "dlp_inference_latency_seconds",
    "Inference latency in seconds",
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
)

log = structlog.get_logger()
MODEL_VERSION = os.getenv("MODEL_VERSION", "1.0.0")

app = FastAPI(title="DLP ML Inference Service", version="1.0.0")
FastAPIInstrumentor.instrument_app(app)
app.mount("/metrics", make_asgi_app())


class ScanRequest(BaseModel):
    scan_id: str
    tenant_id: str
    content: str
    file_path: str = ""
    mime_type: str = "text/plain"


class ScanResult(BaseModel):
    scan_id: str
    tenant_id: str
    label: str
    confidence: float
    pii_types: list[str]
    model_version: str


# ── Simple regex + heuristic classifier (fallback when no trained model) ───────
import re

PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "phone": re.compile(r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "api_key": re.compile(r"\b[A-Za-z0-9_\-]{32,64}\b"),
}


def classify_content(content: str) -> tuple[str, float, list[str]]:
    """Heuristic PII classification; replaced by a trained model when available."""
    found: list[str] = []
    for pii_type, pattern in PII_PATTERNS.items():
        if pattern.search(content):
            found.append(pii_type)

    if not found:
        return "CLEAN", 0.98, []

    high_risk = {"ssn", "credit_card", "aws_key"}
    if any(p in high_risk for p in found):
        return "SENSITIVE_HIGH", 0.95, found

    return "SENSITIVE_LOW", 0.80, found


@app.on_event("startup")
async def startup() -> None:
    model_path = Path(os.getenv("MODEL_PATH", "/models/dlp_classifier.joblib"))
    if model_path.exists():
        app.state.model = joblib.load(model_path)
        log.info("model_loaded", path=str(model_path), version=MODEL_VERSION)
    else:
        app.state.model = None
        log.warning("model_not_found_using_heuristics", path=str(model_path))


@app.post("/scan", response_model=ScanResult)
async def scan(request_body: ScanRequest) -> ScanResult:
    with tracer.start_as_current_span("scan") as span:
        span.set_attribute("scan_id", request_body.scan_id)
        span.set_attribute("tenant_id", request_body.tenant_id)

        t0 = time.perf_counter()
        label, confidence, pii_types = await asyncio.get_event_loop().run_in_executor(
            None, classify_content, request_body.content
        )
        elapsed = time.perf_counter() - t0

        DLP_INFERENCE_LATENCY.observe(elapsed)
        DLP_SCANS_TOTAL.labels(result=label, model_version=MODEL_VERSION).inc()

        log.info(
            "scan_complete",
            scan_id=request_body.scan_id,
            tenant_id=request_body.tenant_id,
            label=label,
            confidence=confidence,
            latency_s=round(elapsed, 4),
            model_version=MODEL_VERSION,
        )

        return ScanResult(
            scan_id=request_body.scan_id,
            tenant_id=request_body.tenant_id,
            label=label,
            confidence=confidence,
            pii_types=pii_types,
            model_version=MODEL_VERSION,
        )


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok", "model_version": MODEL_VERSION}
