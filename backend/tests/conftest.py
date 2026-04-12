from __future__ import annotations

"""Shared pytest fixtures for backend tests.

All app env-vars are set here (at the top of this file) BEFORE any app module
is imported so that module-level validation in services/auth.py succeeds.
"""

import os
import sys

# ---------------------------------------------------------------------------
# Environment — must be set before importing app code
# ---------------------------------------------------------------------------
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-for-pytest-only-32chars!")
os.environ.setdefault(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./test_mycyber_dlp.db",
)

# Add backend/ to sys.path so that `from app.xxx import ...` works inside tests
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from contextlib import asynccontextmanager  # noqa: E402
from typing import AsyncGenerator  # noqa: E402

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

# ---------------------------------------------------------------------------
# Test database engine (SQLite in-process — no PostgreSQL required)
# ---------------------------------------------------------------------------
TEST_DB_URL = "sqlite+aiosqlite:///./test_mycyber_dlp.db"

test_engine = create_async_engine(TEST_DB_URL, echo=False)
TestSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)

# ---------------------------------------------------------------------------
# App imports (after env vars are set)
# ---------------------------------------------------------------------------
from app.db.database import Base, get_db  # noqa: E402
from app.db.models import User  # noqa: E402
from app.main import app  # noqa: E402
from app.services.auth import hash_password  # noqa: E402


# ---------------------------------------------------------------------------
# Replace production lifespan with a lightweight test version that:
#   • creates SQLite tables (no NER model loading, no prod DB init)
# ---------------------------------------------------------------------------
@asynccontextmanager
async def _test_lifespan(_app):  # type: ignore[override]
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app.router.lifespan_context = _test_lifespan  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Override the real get_db with one that uses the test engine
# ---------------------------------------------------------------------------
async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
    async with TestSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


app.dependency_overrides[get_db] = _override_get_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    """Provide an AsyncClient with a fresh database per test."""
    # Drop and re-create all tables for full isolation between tests
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def auth_headers(client: AsyncClient) -> dict:
    """Register + login a test user and return its Authorization headers."""
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "user@test.com",
            "password": "password123",
            "full_name": "Test User",
        },
    )
    resp = await client.post(
        "/api/v1/auth/login",
        data={"username": "user@test.com", "password": "password123"},
    )
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Raw DB session for direct data manipulation in tests."""
    async with TestSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@pytest_asyncio.fixture
async def registered_user(db_session: AsyncSession) -> User:
    """Insert a free-plan test user directly into the DB and return it."""
    user = User(
        email="test@mycyber.com",
        hashed_password=hash_password("password123"),
        full_name="Test User",
        tenant_id="test-tenant-001",
        plan="free",
        scan_count_month=0,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def pro_user_headers(client: AsyncClient, db_session: AsyncSession) -> dict:
    """Create a pro-plan user and return its Authorization headers."""
    user = User(
        email="pro@mycyber.com",
        hashed_password=hash_password("password123"),
        full_name="Pro User",
        tenant_id="pro-tenant-001",
        plan="pro",
        scan_count_month=0,
    )
    db_session.add(user)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/auth/login",
        data={"username": "pro@mycyber.com", "password": "password123"},
    )
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
