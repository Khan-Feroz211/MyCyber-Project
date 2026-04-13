from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
from fastapi import HTTPException
from sqlalchemy import select

from app.config import get_settings
from app.db.models import BillingEvent, Subscription, User
from app.mlops.logger import get_logger
from app.models.schemas import PLAN_CONFIG

logger = get_logger(__name__)

SAFEPAY_SANDBOX = "https://sandbox.api.getsafepay.com"
SAFEPAY_LIVE = "https://api.getsafepay.com"


def get_safepay_base_url() -> str:
    settings = get_settings()
    if settings.app_env == "production":
        return SAFEPAY_LIVE
    return SAFEPAY_SANDBOX


async def create_checkout_session(
    user: User,
    plan: str,
    billing_cycle: str = "monthly",
) -> dict:
    """
    Creates a Safepay checkout session.
    Returns checkout_url, token, amount_pkr.

    Safepay API call:
    POST {base_url}/order/v1/init
    Headers:
      X-SFPY-MERCHANT-SECRET: settings.safepay_secret_key
    Body:
      amount: price in paisas (PKR * 100)
      currency: "PKR"
      order_id: unique order reference
      source: "mycyber-dlp"
      cancel_url: {frontend_url}/billing/cancel
      redirect_url: {frontend_url}/billing/success

    On success returns:
      token — use to build checkout URL:
      {base_url}/checkout?env=sandbox&token={token}

    If Safepay returns error or is unreachable,
    raise HTTPException 502.

    Log the checkout creation to BillingEvent table.
    """
    settings = get_settings()
    plan_cfg = PLAN_CONFIG[plan]
    price_pkr = plan_cfg["price_pkr"]

    if billing_cycle == "semester":
        # 5-month billing for a 6-month period — one month free as a discount
        price_pkr = int(price_pkr * 5)

    order_id = f"MYCYBER-{user.id}-{uuid4().hex[:8].upper()}"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{get_safepay_base_url()}/order/v1/init",
                headers={
                    "X-SFPY-MERCHANT-SECRET": settings.safepay_secret_key,
                    "Content-Type": "application/json",
                },
                json={
                    "amount": price_pkr * 100,
                    "currency": "PKR",
                    "order_id": order_id,
                    "source": "mycyber-dlp",
                    "cancel_url": f"{settings.frontend_url}/billing/cancel",
                    "redirect_url": f"{settings.frontend_url}/billing/success",
                },
            )
            data = response.json()
            if response.status_code != 200:
                raise ValueError(data.get("message", "Safepay error"))
            token = data["data"]["token"]
            base_url = get_safepay_base_url()
            env_param = (
                "production" if get_settings().app_env == "production" else "sandbox"
            )
            checkout_url = f"{base_url}/checkout?env={env_param}&token={token}"
            logger.info(
                "Checkout created",
                extra={
                    "user_id": user.id,
                    "plan": plan,
                    "amount_pkr": price_pkr,
                },
            )
            return {
                "checkout_url": checkout_url,
                "safepay_token": token,
                "plan": plan,
                "amount_pkr": price_pkr,
                "order_id": order_id,
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Safepay checkout failed",
            extra={"user_id": user.id, "error": str(e)},
        )
        raise HTTPException(
            status_code=502,
            detail=f"Payment gateway error: {str(e)}",
        )


def verify_safepay_webhook(
    payload: bytes,
    signature: str,
    secret: str,
) -> bool:
    """
    Verifies Safepay webhook HMAC-SHA256 signature.
    Safepay signs: HMAC-SHA256(payload, secret_key)
    Returns True if signature matches, False otherwise.
    Always verify before processing any webhook.
    """
    expected = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


async def activate_subscription(
    db,
    user: User,
    plan: str,
    safepay_token: str,
    safepay_tracker: str,
) -> Subscription:
    """
    Creates or upgrades a Subscription record.
    Sets user.plan to the new plan.
    Resets scan_count_month to 0.
    Sets period: now to now + 30 days (monthly).
    Logs BillingEvent of type "subscription_created"
    or "plan_upgraded".
    Returns the Subscription record.
    """
    now = datetime.now(timezone.utc)
    plan_cfg = PLAN_CONFIG[plan]

    existing = await db.execute(
        select(Subscription).where(Subscription.user_id == user.id)
    )
    sub = existing.scalar_one_or_none()
    event_type = "plan_upgraded" if sub else "subscription_created"

    if sub:
        sub.plan = plan
        sub.status = "active"
        sub.scan_limit = plan_cfg["scan_limit"]
        sub.price_pkr = plan_cfg["price_pkr"]
        sub.safepay_token = safepay_token
        sub.safepay_tracker = safepay_tracker
        sub.current_period_start = now
        sub.current_period_end = now + timedelta(days=30)
        sub.cancelled_at = None
    else:
        sub = Subscription(
            user_id=user.id,
            tenant_id=user.tenant_id,
            plan=plan,
            status="active",
            scan_limit=plan_cfg["scan_limit"],
            price_pkr=plan_cfg["price_pkr"],
            safepay_token=safepay_token,
            safepay_tracker=safepay_tracker,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
        )
        db.add(sub)

    user.plan = plan
    user.scan_count_month = 0

    event = BillingEvent(
        user_id=user.id,
        tenant_id=user.tenant_id,
        event_type=event_type,
        plan=plan,
        amount_pkr=plan_cfg["price_pkr"],
    )
    db.add(event)
    await db.flush()
    return sub


async def get_usage(
    db,
    user: User,
) -> dict:
    """
    Returns current usage stats for the user.
    Queries subscription for period end date.
    Returns plan, scans_used, scan_limit,
    scans_remaining, percent_used, resets_at.
    """
    plan_cfg = PLAN_CONFIG.get(user.plan, PLAN_CONFIG["free"])
    sub_result = await db.execute(
        select(Subscription).where(
            Subscription.user_id == user.id,
            Subscription.status == "active",
        )
    )
    sub = sub_result.scalar_one_or_none()
    scan_limit = sub.scan_limit if sub else plan_cfg["scan_limit"]
    resets_at = (
        sub.current_period_end
        if sub
        else datetime.now(timezone.utc) + timedelta(days=30)
    )
    scans_remaining = max(0, scan_limit - user.scan_count_month)
    percent_used = round(
        (user.scan_count_month / scan_limit) * 100 if scan_limit > 0 else 0,
        1,
    )
    return {
        "plan": user.plan,
        "scans_used": user.scan_count_month,
        "scan_limit": scan_limit,
        "scans_remaining": scans_remaining,
        "percent_used": percent_used,
        "resets_at": resets_at,
        "plan_config": plan_cfg,
    }


async def get_subscription_dict(db, user: User) -> dict:
    """Build a subscription info dict for the given user.

    Used by both the billing and auth routers to ensure a consistent
    response shape without duplicating query logic.
    """
    result = await db.execute(
        select(Subscription).where(Subscription.user_id == user.id)
    )
    sub = result.scalar_one_or_none()

    if sub:
        scans_remaining = max(0, sub.scan_limit - user.scan_count_month)
        return {
            "sub_id": sub.sub_id,
            "plan": sub.plan,
            "status": sub.status,
            "scan_limit": sub.scan_limit,
            "price_pkr": sub.price_pkr,
            "current_period_end": sub.current_period_end,
            "scans_used": user.scan_count_month,
            "scans_remaining": scans_remaining,
        }

    plan_cfg = PLAN_CONFIG.get(user.plan, PLAN_CONFIG["free"])
    scans_remaining = max(0, plan_cfg["scan_limit"] - user.scan_count_month)
    return {
        "sub_id": None,
        "plan": user.plan,
        "status": "active",
        "scan_limit": plan_cfg["scan_limit"],
        "price_pkr": plan_cfg["price_pkr"],
        "current_period_end": None,
        "scans_used": user.scan_count_month,
        "scans_remaining": scans_remaining,
    }


async def create_pending_subscription(
    db,
    user: User,
    plan: str,
    billing_cycle: str,
    safepay_token: str,
) -> Subscription:
    """Create or update a Subscription in 'pending' status during checkout.

    Stores the Safepay token so the webhook handler can locate the record
    when a payment/succeeded event arrives.  The subscription is promoted
    to 'active' by :func:`activate_subscription` inside the webhook.
    """
    plan_cfg = PLAN_CONFIG[plan]

    existing = await db.execute(
        select(Subscription).where(Subscription.user_id == user.id)
    )
    sub = existing.scalar_one_or_none()

    if sub:
        sub.plan = plan
        sub.status = "pending"
        sub.scan_limit = plan_cfg["scan_limit"]
        sub.price_pkr = plan_cfg["price_pkr"]
        sub.billing_cycle = billing_cycle
        sub.safepay_token = safepay_token
    else:
        sub = Subscription(
            user_id=user.id,
            tenant_id=user.tenant_id,
            plan=plan,
            status="pending",
            scan_limit=plan_cfg["scan_limit"],
            price_pkr=plan_cfg["price_pkr"],
            billing_cycle=billing_cycle,
            safepay_token=safepay_token,
        )
        db.add(sub)

    await db.flush()
    return sub


async def log_billing_event(
    db,
    user_id: int,
    tenant_id: str,
    event_type: str,
    plan: str | None = None,
    amount_pkr: int = 0,
    safepay_data: dict | None = None,
) -> BillingEvent:
    """
    Persists a BillingEvent record.
    safepay_data is serialised to JSON text when provided.
    """
    event = BillingEvent(
        user_id=user_id,
        tenant_id=tenant_id,
        event_type=event_type,
        plan=plan,
        amount_pkr=amount_pkr,
        safepay_data=json.dumps(safepay_data) if safepay_data else None,
    )
    db.add(event)
    await db.flush()
    return event
