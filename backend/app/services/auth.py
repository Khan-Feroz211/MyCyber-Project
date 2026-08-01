from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from jose import ExpiredSignatureError, JWTError, jwt
from passlib.context import CryptContext

from ..config import get_settings
from ..models.schemas import TokenData
from ..db.models import User

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24
RESET_TOKEN_EXPIRE_HOURS = 1

_logger = logging.getLogger(__name__)

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def _get_secret_key() -> str:
    """Get JWT secret key from settings (validates on first call)."""
    return get_settings().jwt_secret


def hash_password(password: str) -> str:
    """Return a bcrypt hash of *password* using 12 rounds."""
    return _pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Return ``True`` if *plain* matches *hashed*, ``False`` otherwise."""
    return _pwd_context.verify(plain, hashed)


# Alias used by some routers / scripts
get_password_hash = hash_password


def authenticate_user(
    db,  # AsyncSession — injected lazily to avoid circular imports
    email: str,
    password: str,
):
    """Look up a user by e-mail and verify their password.

    Returns a coroutine that resolves to the :class:`User` on success,
    ``None`` on failure.  The caller is responsible for the DB session.
    """
    # Imported here to avoid circular dependency at module load time
    from sqlalchemy import select

    async def _check():
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalars().first()
        if user is None or not user.is_active:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user

    return _check()


def create_refresh_token(user_id: int, email: str, tenant_id: str) -> str:
    """Create a long-lived refresh token (7 days) for *user*."""
    now = datetime.now(tz=timezone.utc)
    payload: dict = {
        "sub": str(user_id),
        "email": email,
        "tenant_id": tenant_id,
        "type": "refresh",
        "iat": now,
        "exp": now + timedelta(days=7),
    }
    return jwt.encode(payload, _get_secret_key(), algorithm=ALGORITHM)


def decode_refresh_token(token: str) -> TokenData:
    """Decode a refresh token, raising HTTP 401 on any failure."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, _get_secret_key(), algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise credentials_exception
        user_id_raw: str | None = payload.get("sub")
        email: str | None = payload.get("email")
        tenant_id: str | None = payload.get("tenant_id")
        if user_id_raw is None or email is None or tenant_id is None:
            raise credentials_exception
        return TokenData(user_id=int(user_id_raw), email=email, tenant_id=tenant_id)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError:
        raise credentials_exception


def create_access_token(user_id: int, email: str, tenant_id: str) -> str:
    """Encode a signed JWT containing identity claims and an expiry timestamp."""
    now = datetime.now(tz=timezone.utc)
    payload: dict = {
        "sub": str(user_id),
        "email": email,
        "tenant_id": tenant_id,
        "iat": now,
        "exp": now + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, _get_secret_key(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> TokenData:
    """Decode and validate *token*, raising HTTP 401 on any failure."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, _get_secret_key(), algorithms=[ALGORITHM])
        user_id_raw: str | None = payload.get("sub")
        email: str | None = payload.get("email")
        tenant_id: str | None = payload.get("tenant_id")
        if user_id_raw is None or email is None or tenant_id is None:
            raise credentials_exception
        return TokenData(user_id=int(user_id_raw), email=email, tenant_id=tenant_id)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError:
        raise credentials_exception


def create_reset_token(user_id: int, email: str) -> str:
    """Create a short-lived JWT for password reset."""
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "type": "password_reset",
        "iat": now,
        "exp": now + timedelta(hours=RESET_TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, _get_secret_key(), algorithm=ALGORITHM)


def decode_reset_token(token: str) -> TokenData:
    """Decode a password reset token, raising HTTP 401 on failure."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired reset token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, _get_secret_key(), algorithms=[ALGORITHM])
        if payload.get("type") != "password_reset":
            raise credentials_exception
        user_id_raw: str | None = payload.get("sub")
        email: str | None = payload.get("email")
        if user_id_raw is None or email is None:
            raise credentials_exception
        return TokenData(user_id=int(user_id_raw), email=email, tenant_id=payload.get("tenant_id", ""))
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Reset token has expired. Please request a new one.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError:
        raise credentials_exception
