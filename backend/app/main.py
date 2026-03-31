from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .db.database import init_db
from .routers import alert, auth, health, scan
from .services.scanner import load_ner_model

_logger = logging.getLogger(__name__)
_settings = get_settings()
_ALLOWED_ORIGINS = [o.strip() for o in _settings.cors_origins.split(",") if o.strip()]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: load model, initialise DB, then yield."""
    _logger.info("Starting MyCyber DLP backend …")

    # Load NER model in a thread to avoid blocking the event loop
    await asyncio.to_thread(load_ner_model)

    # Ensure all ORM tables exist
    await init_db()

    print(
        "\n"
        "╔══════════════════════════════════════╗\n"
        "║   MyCyber DLP  v0.3.0  is ready 🛡   ║\n"
        "╚══════════════════════════════════════╝\n"
    )

    yield

    _logger.info("MyCyber DLP backend shutting down.")


app = FastAPI(
    title="MyCyber DLP API",
    description=(
        "Data Loss Prevention API — scan text, files, and network payloads "
        "for sensitive entities using regex and optional NER."
    ),
    version="0.3.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(health.router)                        # /health
app.include_router(auth.router,  prefix="/api/v1")      # /api/v1/auth/…
app.include_router(scan.router,  prefix="/api/v1")      # /api/v1/scan/…
app.include_router(alert.router, prefix="/api/v1")      # /api/v1/alerts/…
