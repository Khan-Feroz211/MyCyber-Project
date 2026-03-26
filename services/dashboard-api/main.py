"""Dashboard API — JWT auth, RBAC, REST + WebSocket, rate limiting."""
from __future__ import annotations

import asyncio
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from typing import Any, Callable

import structlog
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from prometheus_client import Counter, make_asgi_app
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
import redis.asyncio as aioredis

log = structlog.get_logger()

# ── Config ─────────────────────────────────────────────────────────────────────
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://dlp:dlp@postgres:5432/dlp")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

# ── Crypto ─────────────────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

# ── Rate limiter ───────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

# ── Prometheus metrics ─────────────────────────────────────────────────────────
API_REQUESTS = Counter("dashboard_api_requests_total", "API requests", ["route", "method"])

app = FastAPI(
    title="MyCyber DLP Dashboard API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.mount("/metrics", make_asgi_app())

# ── WebSocket connection manager ───────────────────────────────────────────────
class ConnectionManager:
    def __init__(self) -> None:
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.active.remove(ws)

    async def broadcast(self, message: dict) -> None:
        for ws in list(self.active):
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(ws)


manager = ConnectionManager()


# ── Auth helpers ───────────────────────────────────────────────────────────────
class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class TokenData(BaseModel):
    sub: str
    role: Role
    tenant_id: str


def create_access_token(data: dict[str, Any]) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> TokenData:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return TokenData(
            sub=payload["sub"],
            role=Role(payload["role"]),
            tenant_id=payload["tenant_id"],
        )
    except (JWTError, KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def require_role(*roles: Role) -> Callable:
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            user: TokenData = kwargs.get("current_user") or args[-1]
            if user.role not in roles:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# ── Schemas ────────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ScanSummary(BaseModel):
    scan_id: str
    tenant_id: str
    label: str
    decision: str
    created_at: str


class PolicyRule(BaseModel):
    rule_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    regex_pattern: str
    confidence_threshold: float = 0.80
    action: str = "BLOCK"


class AlertSummary(BaseModel):
    alert_id: str
    scan_id: str
    decision: str
    reason: str
    created_at: str


# ── Startup / shutdown ─────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup() -> None:
    app.state.redis = aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    log.info("dashboard_api_started")


@app.on_event("shutdown")
async def shutdown() -> None:
    await app.state.redis.aclose()


# ── Auth routes ────────────────────────────────────────────────────────────────
@app.post("/api/v1/auth/login", response_model=TokenResponse, tags=["auth"])
async def login(body: LoginRequest) -> TokenResponse:
    # In production, look up user + bcrypt verify from DB.
    # Returning a stub token for demo/skeleton.
    if not body.username or not body.password:
        raise HTTPException(status_code=400, detail="username and password required")
    token = create_access_token(
        {"sub": body.username, "role": "analyst", "tenant_id": "default"}
    )
    return TokenResponse(access_token=token)


# ── Scan routes ────────────────────────────────────────────────────────────────
@app.get("/api/v1/scans", tags=["scans"])
@limiter.limit("100/minute")
async def list_scans(
    request: Any,
    current_user: TokenData = Depends(get_current_user),
) -> list[ScanSummary]:
    API_REQUESTS.labels(route="/api/v1/scans", method="GET").inc()
    # Stub — in production, query PostgreSQL filtered by tenant_id
    return []


@app.get("/api/v1/scans/{scan_id}", tags=["scans"])
async def get_scan(
    scan_id: str,
    current_user: TokenData = Depends(get_current_user),
) -> dict:
    API_REQUESTS.labels(route="/api/v1/scans/{id}", method="GET").inc()
    return {"scan_id": scan_id, "tenant_id": current_user.tenant_id}


# ── Policy routes ──────────────────────────────────────────────────────────────
@app.get("/api/v1/policies", tags=["policies"])
async def list_policies(current_user: TokenData = Depends(get_current_user)) -> list:
    return []


@app.post("/api/v1/policies", tags=["policies"], status_code=201)
async def create_policy(
    rule: PolicyRule,
    current_user: TokenData = Depends(get_current_user),
) -> PolicyRule:
    if current_user.role not in (Role.ADMIN, Role.ANALYST):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    # Persist to DB in production
    return rule


# ── Alert routes ───────────────────────────────────────────────────────────────
@app.get("/api/v1/alerts", tags=["alerts"])
async def list_alerts(current_user: TokenData = Depends(get_current_user)) -> list:
    return []


# ── API Key management ─────────────────────────────────────────────────────────
@app.post("/api/v1/apikeys", tags=["apikeys"])
async def generate_api_key(current_user: TokenData = Depends(get_current_user)) -> dict:
    if current_user.role != Role.ADMIN:
        raise HTTPException(status_code=403, detail="Admin only")
    new_key = secrets.token_urlsafe(32)
    # In production: store hash(new_key) in PostgreSQL api_keys table
    return {"api_key": new_key, "created_by": current_user.sub}


@app.delete("/api/v1/apikeys/{key_id}", tags=["apikeys"])
async def revoke_api_key(
    key_id: str, current_user: TokenData = Depends(get_current_user)
) -> dict:
    if current_user.role != Role.ADMIN:
        raise HTTPException(status_code=403, detail="Admin only")
    # In production: mark revoked in DB
    return {"revoked": key_id}


# ── WebSocket ──────────────────────────────────────────────────────────────────
@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo back or handle ping/pong
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ── Health ─────────────────────────────────────────────────────────────────────
@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}
