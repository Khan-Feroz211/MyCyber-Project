from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .db.database import get_db
from .db.models import User
from .models.schemas import PLAN_LIMITS, PlanLimitError, UserRole
from .services.auth import decode_access_token
from .services.rate_limiter import check_rate_limit
from .services.audit_log import EVENT_SESSION_EXPIRED, append_audit_log

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

_logger = logging.getLogger(__name__)

# Roles sorted by privilege level (lowest → highest)
_ROLE_HIERARCHY: dict[str, int] = {
    UserRole.VIEWER.value: 0,
    UserRole.ANALYST.value: 1,
    UserRole.ADMIN.value: 2,
}


def _resolve_role(user: User) -> str:
    """Return the effective role: 'admin' if is_admin, else 'role'."""
    if user.is_admin:
        return UserRole.ADMIN.value
    return user.role if user.role else UserRole.VIEWER.value


def require_role(required_role: str):
    """Dependency factory: raise 403 unless the current user has *required_role* or higher."""
    async def _checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        user_role = _resolve_role(current_user)
        user_level = _ROLE_HIERARCHY.get(user_role, 0)
        required_level = _ROLE_HIERARCHY.get(required_role, 0)
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient privileges. Requires role '{required_role}' or higher.",
            )
        return current_user

    return _checker


# Ready-to-use dependencies for the common roles
# (defined after get_current_user below)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Decode the Bearer token, load the matching User, and enforce active status.

    Also enforces session timeout: if the JWT was issued before
    ``SESSION_TIMEOUT_HOURS`` has elapsed, a 419 / re-auth is required.
    """
    token_data = decode_access_token(token)

    result = await db.execute(select(User).where(User.id == token_data.user_id))
    user: User | None = result.scalars().first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        )

    # Session timeout check — if the token's iat is older than the configured
    # session timeout, force re-authentication.
    settings = get_settings()
    session_timeout_hours = int(getattr(settings, "session_timeout_hours", 24))
    try:
        from jose import jwt, JWTError
        # Re-decode to inspect raw claims (decode_access_token strips iat)
        raw_payload = jwt.decode(
            token, settings.jwt_secret, algorithms=["HS256"],
            options={"verify_exp": False}
        )
        iat = raw_payload.get("iat")
        if iat is not None:
            issued_at = datetime.fromtimestamp(iat, tz=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            if (now - issued_at) > timedelta(hours=session_timeout_hours):
                try:
                    await append_audit_log(
                        db=db,
                        event_type=EVENT_SESSION_EXPIRED,
                        resource_type="session",
                        action="expired",
                        tenant_id=user.tenant_id,
                        actor=user,
                        ip_address=None,
                        details={"session_timeout_hours": session_timeout_hours},
                    )
                except Exception:
                    pass
                raise HTTPException(
                    status_code=419,
                    detail="Session has expired. Please re-authenticate.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
    except (JWTError, ValueError):
        pass  # Token validation already passed above; skip session check on decode error

    return user


# Ready-to-use role-based dependencies (defined after get_current_user)
require_admin = require_role(UserRole.ADMIN.value)
require_analyst = require_role(UserRole.ANALYST.value)


async def check_plan_limit(
    current_user: User = Depends(get_current_user),
) -> User:
    """Raise HTTP 429 with a :class:`PlanLimitError` body when the monthly scan quota is exhausted."""
    limit = PLAN_LIMITS.get(current_user.plan)
    if limit is None:
        _logger.warning(
            "Unknown plan '%s' for user %d; defaulting to 'free' limit.",
            current_user.plan,
            current_user.id,
        )
        limit = PLAN_LIMITS["free"]

    if current_user.scan_count_month >= limit:
        error = PlanLimitError(
            message=(
                f"You have reached the {limit} scan limit for the '{current_user.plan}' plan "
                "this month. Please upgrade to continue scanning."
            ),
            current_plan=current_user.plan,
            limit=limit,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=error.model_dump(),
        )

    # Enforce per-user rate limit (optional, requires REDIS_URL)
    try:
        await check_rate_limit(current_user.id)
    except Exception:
        # Let HTTPException propagate (429); swallow other errors to avoid denying service
        raise

    return current_user
