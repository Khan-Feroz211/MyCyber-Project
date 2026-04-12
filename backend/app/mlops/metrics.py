from __future__ import annotations

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
)

REGISTRY = CollectorRegistry()

scan_requests_total = Counter(
    "mycyber_scan_requests_total",
    "Total number of scan requests",
    ["scan_type", "severity", "status"],
    registry=REGISTRY,
)

scan_latency_seconds = Histogram(
    "mycyber_scan_latency_seconds",
    "Scan processing latency in seconds",
    ["scan_type"],
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
    registry=REGISTRY,
)

entities_detected_total = Counter(
    "mycyber_entities_detected_total",
    "Total PII entities detected",
    ["entity_type", "severity"],
    registry=REGISTRY,
)

active_users_gauge = Gauge(
    "mycyber_active_users",
    "Approximate active users (last 5 min)",
    registry=REGISTRY,
)

ner_inference_latency = Histogram(
    "mycyber_ner_inference_latency_seconds",
    "HuggingFace NER model inference latency",
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0],
    registry=REGISTRY,
)

risk_score_histogram = Histogram(
    "mycyber_risk_score",
    "Distribution of scan risk scores",
    buckets=[0, 10, 20, 40, 60, 70, 80, 90, 100],
    registry=REGISTRY,
)

alerts_created_total = Counter(
    "mycyber_alerts_created_total",
    "Total security alerts created",
    ["severity"],
    registry=REGISTRY,
)

plan_limit_exceeded_total = Counter(
    "mycyber_plan_limit_exceeded_total",
    "Total times plan scan limit was exceeded",
    ["plan"],
    registry=REGISTRY,
)


def record_scan(
    scan_type: str,
    severity: str,
    status: str,
    latency_seconds: float,
    risk_score: float,
    entities: list,
) -> None:
    """
    Records all Prometheus metrics for one completed scan.
    Call this at the end of every scan endpoint.
    Increments scan_requests_total counter.
    Observes latency in scan_latency_seconds histogram.
    Observes risk_score in risk_score_histogram.
    Increments entities_detected_total for each entity.
    """
    scan_requests_total.labels(
        scan_type=scan_type,
        severity=severity,
        status=status,
    ).inc()
    scan_latency_seconds.labels(scan_type=scan_type).observe(latency_seconds)
    risk_score_histogram.observe(risk_score)
    for entity in entities:
        entities_detected_total.labels(
            entity_type=entity.entity_type.value,
            severity=severity,
        ).inc()
