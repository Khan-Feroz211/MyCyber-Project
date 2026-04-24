from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.database import get_db
from ..db.models import User
from ..dependencies import get_current_user
from ..models.schemas import (
    MFAVerifyRequest,
    MFASetupResponse,
    MFAStatusResponse,
    Token,
    UserCreate,
    UserOut,
)
from ..services import billing_service
from ..services.auth import (
    create_access_token,
    create_reset_token,
    decode_reset_token,
    hash_password,
    verify_password,
)
from ..services.mfa import build_otpauth_uri, generate_totp_secret, verify_totp_code
from ..services.security_audit import log_security_event
from ..models.schemas import PasswordResetRequest, PasswordResetConfirm

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()


def _extract_client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


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
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    x_mfa_code: str | None = Header(default=None, alias="X-MFA-CODE"),
    db: AsyncSession = Depends(get_db),
) -> Token:
    """Authenticate with e-mail + password and return a JWT Bearer token."""
    now = datetime.now(tz=timezone.utc)
    client_ip = _extract_client_ip(request)
    user_agent = request.headers.get("user-agent")

    result = await db.execute(select(User).where(User.email == form_data.username))
    user: User | None = result.scalars().first()

    if user and user.locked_until and user.locked_until > now:
        await log_security_event(
            db,
            event_type="login_blocked_locked_account",
            severity="MEDIUM",
            user=user,
            ip_address=client_ip,
            user_agent=user_agent,
            details={"locked_until": user.locked_until.isoformat()},
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is temporarily locked due to repeated failed sign-in attempts.",
        )

    if user is None or not verify_password(form_data.password, user.hashed_password):
        if user is not None:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.login_max_failures:
                user.locked_until = now + timedelta(minutes=settings.login_lock_minutes)
            await db.flush()

            await log_security_event(
                db,
                event_type="login_failed",
                severity="MEDIUM",
                user=user,
                ip_address=client_ip,
                user_agent=user_agent,
                details={
                    "failed_login_attempts": user.failed_login_attempts,
                    "lock_threshold": settings.login_max_failures,
                },
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        await log_security_event(
            db,
            event_type="login_blocked_inactive",
            severity="LOW",
            user=user,
            ip_address=client_ip,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive.",
        )

    mfa_required = settings.mfa_rollout_mode == "enforced" or (
        settings.mfa_rollout_mode == "opt_in" and user.mfa_enabled
    )
    if mfa_required:
        if not user.mfa_secret:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "MFA is required for this account but no authenticator setup is available. "
                    "Contact an administrator."
                ),
            )

        if not x_mfa_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "mfa_required",
                    "message": "Multi-factor code is required.",
                    "mfa_required": True,
                },
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not verify_totp_code(user.mfa_secret, x_mfa_code):
            await log_security_event(
                db,
                event_type="mfa_failed",
                severity="HIGH",
                user=user,
                ip_address=client_ip,
                user_agent=user_agent,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid multi-factor code.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    previous_ip = user.last_login_ip
    suspicious_login = bool(previous_ip and client_ip and previous_ip != client_ip)
    user.failed_login_attempts = 0
    user.locked_until = None

    user.last_login = datetime.now(tz=timezone.utc)
    user.last_login_ip = client_ip

    if suspicious_login:
        await log_security_event(
            db,
            event_type="suspicious_login_new_ip",
            severity="HIGH",
            user=user,
            ip_address=client_ip,
            user_agent=user_agent,
            details={"previous_ip": previous_ip, "current_ip": client_ip},
        )

    await log_security_event(
        db,
        event_type="login_success",
        severity="INFO",
        user=user,
        ip_address=client_ip,
        user_agent=user_agent,
    )
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
    subscription = await billing_service.get_subscription_dict(db=db, user=current_user)
    usage = await billing_service.get_usage(db=db, user=current_user)

    return {
        "user": UserOut.model_validate(current_user).model_dump(),
        "subscription": subscription,
        "usage": usage,
    }


@router.get("/mfa/status", response_model=MFAStatusResponse)
async def mfa_status(current_user: User = Depends(get_current_user)) -> MFAStatusResponse:
    return MFAStatusResponse(
        enabled=bool(current_user.mfa_enabled),
        rollout_mode=settings.mfa_rollout_mode,
    )


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def mfa_setup(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MFASetupResponse:
    secret = generate_totp_secret()
    current_user.mfa_secret = secret
    await db.flush()

    issuer = "MyCyber"
    account_name = current_user.email
    provisioning_uri = build_otpauth_uri(secret=secret, account_name=account_name, issuer=issuer)

    await log_security_event(
        db,
        event_type="mfa_setup_started",
        severity="INFO",
        user=current_user,
    )

    return MFASetupResponse(
        secret=secret,
        provisioning_uri=provisioning_uri,
        issuer=issuer,
        account_name=account_name,
    )


@router.post("/mfa/verify", response_model=MFAStatusResponse)
async def mfa_verify(
    payload: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MFAStatusResponse:
    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA setup was not initialized for this account.",
        )

    if not verify_totp_code(current_user.mfa_secret, payload.code):
        await log_security_event(
            db,
            event_type="mfa_verify_failed",
            severity="MEDIUM",
            user=current_user,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid multi-factor code.",
        )

    current_user.mfa_enabled = True
    await log_security_event(
        db,
        event_type="mfa_enabled",
        severity="INFO",
        user=current_user,
    )
    await db.flush()

    return MFAStatusResponse(
        enabled=True,
        rollout_mode=settings.mfa_rollout_mode,
    )


@router.post("/mfa/disable", response_model=MFAStatusResponse)
async def mfa_disable(
    payload: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MFAStatusResponse:
    if not current_user.mfa_secret or not current_user.mfa_enabled:
        return MFAStatusResponse(
            enabled=False,
            rollout_mode=settings.mfa_rollout_mode,
        )

    if not verify_totp_code(current_user.mfa_secret, payload.code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid multi-factor code.",
        )

    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    await log_security_event(
        db,
        event_type="mfa_disabled",
        severity="MEDIUM",
        user=current_user,
    )
    await db.flush()

    return MFAStatusResponse(
        enabled=False,
        rollout_mode=settings.mfa_rollout_mode,
    )


# ---------------------------------------------------------------------------
# Password Reset
# ---------------------------------------------------------------------------


@router.post("/password/reset/request", status_code=status.HTTP_202_ACCEPTED)
async def password_reset_request(
    payload: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Request a password reset. Always returns 202 to prevent email enumeration.

    In production, this would send an email with a reset link.
    For now, the reset token is returned directly (development only).
    """
    result = await db.execute(select(User).where(User.email == payload.email))
    user: User | None = result.scalars().first()

    if not user or not user.is_active:
        # Return success even if user doesn't exist to prevent enumeration
        return {"message": "If an account exists with this email, a reset link has been sent."}

    reset_token = create_reset_token(user.id, user.email)

    await log_security_event(
        db,
        event_type="password_reset_requested",
        severity="INFO",
        user=user,
    )

    # TODO: Send email with reset link containing the token
    # For development, return the token directly
    return {
        "message": "If an account exists with this email, a reset link has been sent.",
        "reset_token": reset_token,  # Remove this in production
    }


@router.post("/password/reset/confirm", status_code=status.HTTP_200_OK)
async def password_reset_confirm(
    payload: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Reset password with a valid reset token."""
    try:
        token_data = decode_reset_token(payload.token)
    except HTTPException as e:
        return {"message": "Invalid or expired reset token."}

    result = await db.execute(select(User).where(User.id == token_data.user_id))
    user: User | None = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user or account inactive.",
        )

    user.hashed_password = hash_password(payload.new_password)
    user.failed_login_attempts = 0
    user.locked_until = None

    await log_security_event(
        db,
        event_type="password_reset_completed",
        severity="INFO",
        user=user,
    )

    await db.flush()

    return {"message": "Password has been reset successfully."}
