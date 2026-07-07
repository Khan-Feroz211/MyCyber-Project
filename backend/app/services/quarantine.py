from __future__ import annotations

import os
import json
from datetime import datetime
from pathlib import Path
import logging

_logger = logging.getLogger(__name__)

QUARANTINE_DIR = Path(os.getenv("QUARANTINE_DIR", "quarantine"))
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


def quarantine_bytes(filename: str, data: bytes, meta: dict | None = None) -> str:
    """Store bytes into the quarantine store (local filesystem). Returns path."""
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe_name = f"{ts}-{Path(filename).name}"
    dest = QUARANTINE_DIR / safe_name
    try:
        with open(dest, "wb") as fh:
            fh.write(data)
        if meta is None:
            meta = {}
        meta_path = dest.with_suffix(dest.suffix + ".json")
        with open(meta_path, "w", encoding="utf-8") as mh:
            json.dump({"created_at": ts, **meta}, mh, ensure_ascii=False, indent=2)
        _logger.info("Quarantined file %s to %s", filename, dest)
        return str(dest)
    except Exception as exc:
        _logger.exception("Failed to quarantine file %s: %s", filename, exc)
        raise
