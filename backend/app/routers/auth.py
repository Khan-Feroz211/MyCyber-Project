from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.models import Subscription, User
from ..dependencies import get_current_user
from ..models.schemas import PLAN_CONFIG, Token, UserCreate, UserOut
from ..services import billing_service
from ..services.auth import (
    create_access_token,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(
    payload: UserCreate,
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Create a new user account.  Returns HTTP 409 if the e-mail is already taken."""
    result = await db.execute(select(User).where(User.email == payload.email))
    if result.scalars().first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists.",
        )

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name or None,
        tenant_id=str(uuid.uuid4()),
    )
    db.add(user)
    await db.flush()
    return UserOut.model_validate(user)


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
) -> Token:
    """Authenticate with e-mail + password and return a JWT Bearer token."""
    result = await db.execute(select(User).where(User.email == form_data.username))
    user: User | None = result.scalars().first()

    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive.",
        )

    user.last_login = datetime.now(tz=timezone.utc)
    await db.flush()

    access_token = create_access_token(user.id, user.email, user.tenant_id)
    return Token(
        access_token=access_token,
        token_type="bearer",
        user=UserOut.model_validate(user),
    )


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)) -> UserOut:
    """Return the profile of the currently authenticated user."""
    return UserOut.model_validate(current_user)


@router.get("/me/full")
async def me_full(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return user profile, subscription, and usage in a single call.

    Intended as the primary dashboard load endpoint so the frontend can
    fetch everything it needs in one round-trip.
    """
    sub_result = await db.execute(
        select(Subscription).where(Subscription.user_id == current_user.id)
    )
    sub = sub_result.scalar_one_or_none()

    if sub:
        scans_remaining = max(0, sub.scan_limit - current_user.scan_count_month)
        subscription: dict | None = {
            "sub_id": sub.sub_id,
            "plan": sub.plan,
            "status": sub.status,
            "scan_limit": sub.scan_limit,
            "price_pkr": sub.price_pkr,
            "current_period_end": sub.current_period_end,
            "scans_used": current_user.scan_count_month,
            "scans_remaining": scans_remaining,
        }
    else:
        plan_cfg = PLAN_CONFIG.get(current_user.plan, PLAN_CONFIG["free"])
        scans_remaining = max(0, plan_cfg["scan_limit"] - current_user.scan_count_month)
        subscription = {
            "sub_id": None,
            "plan": current_user.plan,
            "status": "active",
            "scan_limit": plan_cfg["scan_limit"],
            "price_pkr": plan_cfg["price_pkr"],
            "current_period_end": None,
            "scans_used": current_user.scan_count_month,
            "scans_remaining": scans_remaining,
        }

    usage = await billing_service.get_usage(db=db, user=current_user)

    return {
        "user": UserOut.model_validate(current_user).model_dump(),
        "subscription": subscription,
        "usage": usage,
    }
