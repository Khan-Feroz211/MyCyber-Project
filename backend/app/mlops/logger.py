from __future__ import annotations

import json
import logging
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """
    Formats every log record as a single JSON line.
    Base fields in every line:
      timestamp  — ISO 8601 UTC string
      level      — INFO / WARNING / ERROR / CRITICAL
      message    — the log message string
      service    — always "mycyber-dlp"
    Extra fields merged in when passed via extra={}:
      user_id, tenant_id, scan_id, scan_type,
      severity, risk_score, latency_ms,
      entity_count, model_version, endpoint,
      request_id, status
    Exception info appended as "exception" key if present.
    """

    _EXTRA_FIELDS = (
        "user_id",
        "tenant_id",
        "scan_id",
        "scan_type",
        "severity",
        "risk_score",
        "latency_ms",
        "entity_count",
        "model_version",
        "endpoint",
        "request_id",
        "status",
    )

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "service": "mycyber-dlp",
        }
        for field in self._EXTRA_FIELDS:
            if hasattr(record, field):
                log_data[field] = getattr(record, field)
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)


def get_logger(name: str) -> logging.Logger:
    """
    Returns a JSON-formatted logger.
    Usage:
        from app.mlops.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Scan completed", extra={
            "user_id":    1,
            "scan_type":  "text",
            "severity":   "CRITICAL",
            "latency_ms": 234.5,
        })
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
