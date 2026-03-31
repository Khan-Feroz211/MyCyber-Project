from __future__ import annotations

import logging

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.database import get_db
from .db.models import User
from .models.schemas import PLAN_LIMITS, PlanLimitError
from .services.auth import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

_logger = logging.getLogger(__name__)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Decode the Bearer token, load the matching User, and enforce active status."""
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

    return user


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

    return current_user
