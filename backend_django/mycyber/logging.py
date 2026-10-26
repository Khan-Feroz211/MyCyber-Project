"""JSON logging formatter for MyCyber DLP.

Emits one JSON object per log record so container log collectors (Stackdriver,
Loki, Datadog, ...) can parse structured fields.  Falls back to the message
itself when an exception occurs during formatting.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Formatter that serialises each record to a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        try:
            payload: dict = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
            # Merge any structured ``extra`` fields the caller provided.
            for key, value in record.__dict__.items():
                if key in {
                    "args", "asctime", "created", "exc_info", "exc_text",
                    "filename", "funcName", "levelname", "levelno", "lineno",
                    "message", "module", "msecs", "msg", "name", "pathname",
                    "process", "processName", "relativeCreated", "stack_info",
                    "thread", "threadName", "taskName", "timestamp",
                }:
                    continue
                payload[key] = value
            if record.exc_info:
                payload["exception"] = self.formatException(record.exc_info)
            return json.dumps(payload, default=str)
        except Exception:  # pragma: no cover - never raise from handler
            return super().format(record)
