from __future__ import annotations

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from jose import ExpiredSignatureError, JWTError, jwt
from passlib.context import CryptContext

from ..models.schemas import TokenData

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24
RESET_TOKEN_EXPIRE_HOURS = 1

_logger = logging.getLogger(__name__)

_SECRET_KEY: str | None = os.getenv("JWT_SECRET_KEY")
if not _SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY environment variable is not set. "
        "Set it to a long random secret before starting the application."
    )

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(password: str) -> str:
    """Return a bcrypt hash of *password* using 12 rounds."""
    return _pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Return ``True`` if *plain* matches *hashed*, ``False`` otherwise."""
    return _pwd_context.verify(plain, hashed)


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
    return jwt.encode(payload, _SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> TokenData:
    """Decode and validate *token*, raising HTTP 401 on any failure."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, _SECRET_KEY, algorithms=[ALGORITHM])
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
    return jwt.encode(payload, _SECRET_KEY, algorithm=ALGORITHM)


def decode_reset_token(token: str) -> TokenData:
    """Decode a password reset token, raising HTTP 401 on failure."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired reset token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, _SECRET_KEY, algorithms=[ALGORITHM])
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
