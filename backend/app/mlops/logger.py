from __future__ import annotations

import json
import logging
import re
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
        "plan",
        "amount_pkr",
        "error",
    )

    def format(self, record: logging.LogRecord) -> str:
        # Redact sensitive tokens from message and extra fields
        def _redact_text(s: str) -> str:
            if not isinstance(s, str):
                return s
            # mask bearer tokens and long-looking secrets
            s = re.sub(r"Bearer\s+[A-Za-z0-9\-\._~\+/=]{10,}", "Bearer [REDACTED]", s)
            s = re.sub(r"(?i)(?:api[_\- ]?key|anthropic_api_key|llm_api_key|authorization)\s*[:=]\s*['\"]?[A-Za-z0-9\-\._~\+/=]{4,}['\"]?", "[REDACTED]", s)
            s = re.sub(r"(?i)(?:password|pwd|passwd)\s*[:=]\s*['\"][^'\"]{2,}['\"]", "[REDACTED]", s)
            return s

        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": _redact_text(record.getMessage()),
            "service": "mycyber-dlp",
        }
        for field in self._EXTRA_FIELDS:
            if hasattr(record, field):
                val = getattr(record, field)
                if isinstance(val, str):
                    log_data[field] = _redact_text(val)
                else:
                    log_data[field] = val
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
        # Attach a simple filter to remove sensitive keys from record.args if present
        class RedactingFilter(logging.Filter):
            def filter(self, record: logging.LogRecord) -> bool:
                try:
                    if hasattr(record, "args") and isinstance(record.args, dict):
                        for k in list(record.args.keys()):
                            if any(t in k.lower() for t in ("authorization", "api_key", "anthropic", "llm_api_key", "password")):
                                record.args[k] = "[REDACTED]"
                except Exception:
                    pass
                return True

        handler.addFilter(RedactingFilter())
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
