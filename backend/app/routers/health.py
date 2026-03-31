from __future__ import annotations

import time

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..services.scanner import SCANNER_NAMES, _model_name

router = APIRouter(tags=["health"])

_START_TIME: float = time.time()


@router.get("/health")
async def health(db: AsyncSession = Depends(get_db)) -> dict:
    """Return service health information including DB connectivity."""
    db_status = "ok"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "error"

    overall = "ok" if db_status == "ok" else "degraded"
    uptime = int(time.time() - _START_TIME)

    return {
        "status": overall,
        "uptime_seconds": uptime,
        "version": "0.3.0",
        "scanners_loaded": SCANNER_NAMES,
        "database": db_status,
        "ner_model": _model_name,
    }
