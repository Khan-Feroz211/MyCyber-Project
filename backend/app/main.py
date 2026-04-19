from __future__ import annotations

import asyncio
import time as time_module
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.middleware.error_handler import (
    http_exception_handler,
    validation_exception_handler,
)

from .config import get_settings
from .db.database import init_db
from .middleware.security import SecurityHeadersMiddleware
from .mlops.logger import get_logger
from .mlops.tracker import setup_mlflow
from .routers import (
    admin_security,
    alert,
    auth,
    billing,
    health,
    metrics_router,
    scan,
)
from .services.scanner import load_ner_model

logger = get_logger(__name__)
_settings = get_settings()
_ALLOWED_ORIGINS = [o.strip() for o in _settings.cors_origins.split(",") if o.strip()]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: load model, initialise DB, configure MLflow, then yield."""
    logger.info("Starting MyCyber DLP backend …")

    # Load NER model in a thread to avoid blocking the event loop
    await asyncio.to_thread(load_ner_model)

    # Ensure all ORM tables exist
    await init_db()

    # Configure MLflow (non-fatal if server is unreachable)
    setup_mlflow()

    logger.info(
        "Application started",
        extra={
            "status": "startup",
            "version": "0.5.0",
        },
    )

    print(
        "\n"
        "╔══════════════════════════════════════╗\n"
        "║   MyCyber DLP  v0.5.0  is ready 🛡   ║\n"
        "╚══════════════════════════════════════╝\n"
    )

    yield

    logger.info("MyCyber DLP backend shutting down.")


app = FastAPI(
    title="MyCyber DLP API",
    description=(
        "Data Loss Prevention API — scan text, files, and network payloads "
        "for sensitive entities using regex and optional NER."
    ),
    version="0.5.0",
    lifespan=lifespan,
)

app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)

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
# Request logging middleware
# ---------------------------------------------------------------------------


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())[:8]
        start = time_module.time()
        response = await call_next(request)

        if _settings.app_env == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"

        latency_ms = round((time_module.time() - start) * 1000, 1)
        logger.info(
            "HTTP request",
            extra={
                "endpoint": request.url.path,
                "method": request.method,
                "status": response.status_code,
                "latency_ms": latency_ms,
                "request_id": request_id,
            },
        )
        return response


app.add_middleware(RequestLoggingMiddleware)

# ---------------------------------------------------------------------------
# Security headers (production only)
# ---------------------------------------------------------------------------
if _settings.app_env == "production":
    app.add_middleware(SecurityHeadersMiddleware)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(health.router)  # /health
app.include_router(metrics_router.router)  # /metrics
app.include_router(auth.router, prefix="/api/v1")  # /api/v1/auth/…
app.include_router(scan.router, prefix="/api/v1")  # /api/v1/scan/…
app.include_router(alert.router, prefix="/api/v1")  # /api/v1/alerts/…
app.include_router(billing.router, prefix="/api/v1")  # /api/v1/billing/…
app.include_router(admin_security.router, prefix="/api/v1")  # /api/v1/admin/security/…


@app.get("/")
async def root():
    return RedirectResponse(url="/health")
