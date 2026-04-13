from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.database import get_db
from ..db.models import BillingEvent, Subscription, User
from ..dependencies import get_current_user
from ..mlops.logger import get_logger
from ..models.schemas import (
    PLAN_CONFIG,
    CheckoutResponse,
    PlanCard,
    UpgradeRequest,
    UsageResponse,
)
from ..services import billing_service
from ..services.auth import decode_access_token

router = APIRouter(prefix="/billing", tags=["billing"])

logger = get_logger(__name__)

_optional_oauth2 = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


async def _get_optional_user(
    token: Optional[str] = Depends(_optional_oauth2),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Decode a Bearer token when present; return None if absent or invalid."""
    if not token:
        return None
    try:
        token_data = decode_access_token(token)
        result = await db.execute(select(User).where(User.id == token_data.user_id))
        return result.scalars().first()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# GET /billing/plans
# ---------------------------------------------------------------------------


@router.get("/plans", response_model=list[PlanCard])
async def list_plans(
    current_user: Optional[User] = Depends(_get_optional_user),
) -> list[PlanCard]:
    """Return all subscription plan cards. Marks is_current when authenticated."""
    user_plan = current_user.plan if current_user else None
    return [
        PlanCard(
            plan_id=plan_id,
            name=cfg["name"],
            price_pkr=cfg["price_pkr"],
            scan_limit=cfg["scan_limit"],
            features=cfg["features"],
            is_current=(plan_id == user_plan),
        )
        for plan_id, cfg in PLAN_CONFIG.items()
    ]


# ---------------------------------------------------------------------------
# GET /billing/usage
# ---------------------------------------------------------------------------


@router.get("/usage", response_model=UsageResponse)
async def get_usage(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UsageResponse:
    """Return the current scan quota usage for the authenticated user."""
    usage = await billing_service.get_usage(db=db, user=current_user)
    return UsageResponse(**usage)


# ---------------------------------------------------------------------------
# GET /billing/subscription
# ---------------------------------------------------------------------------


@router.get("/subscription")
async def get_subscription(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return the current subscription.

    Free-plan users who have no Subscription record receive a synthetic
    response indicating their defaults.
    """
    return await billing_service.get_subscription_dict(db=db, user=current_user)


# ---------------------------------------------------------------------------
# POST /billing/upgrade
# ---------------------------------------------------------------------------


@router.post(
    "/upgrade", response_model=CheckoutResponse, status_code=status.HTTP_200_OK
)
async def upgrade_plan(
    body: UpgradeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CheckoutResponse:
    """Initiate a plan upgrade.

    Creates a Safepay checkout session and stores a pending Subscription
    record with the returned token so the webhook handler can locate it
    when the payment/succeeded event arrives.
    Returns a Safepay checkout URL for the user to complete payment.
    """
    if current_user.plan == body.plan:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"You are already subscribed to the '{body.plan}' plan.",
        )

    checkout = await billing_service.create_checkout_session(
        user=current_user,
        plan=body.plan,
        billing_cycle=body.billing_cycle,
    )

    await billing_service.create_pending_subscription(
        db=db,
        user=current_user,
        plan=body.plan,
        billing_cycle=body.billing_cycle,
        safepay_token=checkout["safepay_token"],
    )

    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    return CheckoutResponse(
        checkout_url=checkout["checkout_url"],
        safepay_token=checkout["safepay_token"],
        plan=checkout["plan"],
        amount_pkr=checkout["amount_pkr"],
        expires_at=expires_at,
    )


# ---------------------------------------------------------------------------
# POST /billing/cancel
# ---------------------------------------------------------------------------


@router.post("/cancel")
async def cancel_subscription(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Cancel the active subscription.

    The user retains access at their current plan level until
    current_period_end.
    """
    result = await db.execute(
        select(Subscription).where(
            Subscription.user_id == current_user.id,
            Subscription.status == "active",
        )
    )
    sub = result.scalar_one_or_none()
    if sub is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active subscription found.",
        )

    now = datetime.now(timezone.utc)
    sub.status = "cancelled"
    sub.cancelled_at = now

    event = BillingEvent(
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        event_type="subscription_cancelled",
        plan=sub.plan,
        amount_pkr=0,
    )
    db.add(event)
    await db.flush()

    period_end = sub.current_period_end
    return {
        "message": (f"Subscription cancelled. Access continues until {period_end}.")
    }


# ---------------------------------------------------------------------------
# GET /billing/history
# ---------------------------------------------------------------------------


@router.get("/history")
async def billing_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Return the last 50 billing events for the authenticated user's tenant."""
    result = await db.execute(
        select(BillingEvent)
        .where(BillingEvent.tenant_id == current_user.tenant_id)
        .order_by(desc(BillingEvent.created_at))
        .limit(50)
    )
    events = result.scalars().all()
    return [
        {
            "event_id": e.event_id,
            "event_type": e.event_type,
            "plan": e.plan,
            "amount_pkr": e.amount_pkr,
            "created_at": e.created_at,
        }
        for e in events
    ]


# ---------------------------------------------------------------------------
# POST /billing/webhook  (no auth -- called directly by Safepay)
# ---------------------------------------------------------------------------


@router.post("/webhook", status_code=status.HTTP_200_OK)
async def safepay_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_sfpy_signature: Optional[str] = Header(default=None, alias="X-SFPY-SIGNATURE"),
) -> dict:
    """Receive and process Safepay payment webhooks.

    Signature validation failures return HTTP 400 immediately (Safepay
    will not retry these -- they indicate a configuration or security
    issue).  All other internal processing errors are caught, logged,
    and responded to with HTTP 200 so Safepay does not schedule retries
    for transient failures.
    """
    payload = await request.body()
    settings = get_settings()

    if not x_sfpy_signature:
        logger.warning("Safepay webhook received without signature header")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing webhook signature.",
        )

    if not billing_service.verify_safepay_webhook(
        payload=payload,
        signature=x_sfpy_signature,
        secret=settings.safepay_webhook_secret,
    ):
        logger.warning("Safepay webhook signature verification failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid webhook signature.",
        )

    try:
        data = json.loads(payload)
        event_type: str = data.get("event", "")
        event_data: dict = data.get("data", {})

        if event_type == "payment/succeeded":
            return await _handle_payment_succeeded(db, event_data)

        if event_type == "payment/failed":
            return await _handle_payment_failed(db, event_data)

        if event_type == "subscription/cancelled":
            return await _handle_subscription_cancelled(db, event_data)

        logger.warning(f"Unknown Safepay webhook event type: {event_type}")
        return {"status": "ignored"}

    except Exception as exc:
        logger.error(
            "Webhook processing error",
            extra={"error": str(exc)},
        )
        return {"status": "ok"}


async def _handle_payment_succeeded(db: AsyncSession, event_data: dict) -> dict:
    """Activate the subscription when a payment succeeds."""
    tracker: str = event_data.get("tracker", "")
    token: str = event_data.get("token", "")
    raw_amount: int = event_data.get("amount", 0) or 0
    amount_pkr = raw_amount // 100

    sub_result = await db.execute(
        select(Subscription).where(Subscription.safepay_token == token)
    )
    sub = sub_result.scalar_one_or_none()
    if sub is None:
        logger.warning(f"No subscription found for Safepay token: {token}")
        return {"status": "ok"}

    user_result = await db.execute(select(User).where(User.id == sub.user_id))
    user = user_result.scalar_one_or_none()
    if user is None:
        logger.warning(f"No user found for subscription user_id: {sub.user_id}")
        return {"status": "ok"}

    plan = sub.plan
    await billing_service.activate_subscription(
        db=db,
        user=user,
        plan=plan,
        safepay_token=token,
        safepay_tracker=tracker,
        amount_pkr=amount_pkr if amount_pkr else None,
    )
    await billing_service.log_billing_event(
        db=db,
        user_id=user.id,
        tenant_id=user.tenant_id,
        event_type="payment_succeeded",
        plan=plan,
        amount_pkr=amount_pkr,
        safepay_data=event_data,
    )
    logger.info(
        "Payment succeeded -- subscription activated",
        extra={"user_id": user.id, "plan": plan, "amount_pkr": amount_pkr},
    )
    return {"status": "ok"}


async def _handle_payment_failed(db: AsyncSession, event_data: dict) -> dict:
    """Mark a subscription as past_due when a payment fails."""
    tracker: str = event_data.get("tracker", "")

    sub_result = await db.execute(
        select(Subscription).where(Subscription.safepay_tracker == tracker)
    )
    sub = sub_result.scalar_one_or_none()
    if sub is None:
        logger.warning(f"No subscription found for tracker: {tracker}")
        return {"status": "ok"}

    sub.status = "past_due"
    await billing_service.log_billing_event(
        db=db,
        user_id=sub.user_id,
        tenant_id=sub.tenant_id,
        event_type="payment_failed",
        plan=sub.plan,
        amount_pkr=0,
        safepay_data=event_data,
    )
    await db.flush()
    logger.warning(
        "Payment failed -- subscription marked past_due",
        extra={"user_id": sub.user_id, "plan": sub.plan},
    )
    return {"status": "ok"}


async def _handle_subscription_cancelled(db: AsyncSession, event_data: dict) -> dict:
    """Cancel a subscription when Safepay sends a cancellation event."""
    tracker: str = event_data.get("tracker", "")

    sub_result = await db.execute(
        select(Subscription).where(Subscription.safepay_tracker == tracker)
    )
    sub = sub_result.scalar_one_or_none()
    if sub is None:
        logger.warning(f"No subscription found for tracker: {tracker}")
        return {"status": "ok"}

    sub.status = "cancelled"
    sub.cancelled_at = datetime.now(timezone.utc)
    await db.flush()
    logger.info(
        "Subscription cancelled via Safepay webhook",
        extra={"user_id": sub.user_id},
    )
    return {"status": "ok"}
