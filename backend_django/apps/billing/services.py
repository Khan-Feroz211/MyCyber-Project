"""Billing service (Django port of ``backend/app/services/billing_service.py``)."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from apps.accounts.plans import PLAN_CONFIG, PLAN_LIMITS
from apps.billing.models import BillingEvent, Subscription
from apps.accounts.models import User

from mycyber.services import conf
from mycyber.services.field_encryption import (
    decrypt_payment_token,
    decrypt_payment_tracker,
    encrypt_payment_token,
    encrypt_payment_tracker,
)

logger = logging.getLogger(__name__)

SAFEPAY_SANDBOX = "https://sandbox.api.getsafepay.com"
SAFEPAY_LIVE = "https://api.getsafepay.com"


def get_safepay_base_url() -> str:
    if conf.app_env() == "production":
        return SAFEPAY_LIVE
    return SAFEPAY_SANDBOX


def verify_safepay_webhook(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def create_checkout_session(
    user: User, plan: str, billing_cycle: str = "monthly"
) -> dict:
    """Create a Safepay checkout session (lazy HTTP call)."""
    plan_cfg = PLAN_CONFIG[plan]
    price_pkr = plan_cfg["price_pkr"]
    if billing_cycle == "semester":
        price_pkr = int(price_pkr * 5)

    order_id = f"MYCYBER-{user.id}-{uuid4().hex[:8].upper()}"  # noqa: F821 — uuid4 below
    from uuid import uuid4

    order_id = f"MYCYBER-{user.id}-{uuid4().hex[:8].upper()}"

    try:
        import httpx  # type: ignore  # lazy

        with httpx.Client(timeout=10.0) as client:
            response = client.post(
                f"{get_safepay_base_url()}/order/v1/init",
                headers={
                    "X-SFPY-MERCHANT-SECRET": conf.safepay_secret_key(),
                    "Content-Type": "application/json",
                },
                json={
                    "amount": price_pkr * 100,
                    "currency": "PKR",
                    "order_id": order_id,
                    "source": "mycyber-dlp",
                    "cancel_url": f"{conf.frontend_url()}/billing/cancel",
                    "redirect_url": f"{conf.frontend_url()}/billing/success",
                },
            )
            data = response.json()
            if response.status_code != 200:
                raise ValueError(data.get("message", "Safepay error"))
            token = data["data"]["token"]
            base_url = get_safepay_base_url()
            env_param = "production" if conf.app_env() == "production" else "sandbox"
            checkout_url = f"{base_url}/checkout?env={env_param}&token={token}"
            return {
                "checkout_url": checkout_url,
                "safepay_token": token,
                "plan": plan,
                "amount_pkr": price_pkr,
                "order_id": order_id,
            }
    except Exception as exc:
        logger.error("Safepay checkout failed", extra={"user_id": user.id, "error": str(exc)})
        from rest_framework.exceptions import BadGateway

        raise BadGateway(f"Payment gateway error: {str(exc)}")


def create_pending_subscription(
    user: User, plan: str, billing_cycle: str, safepay_token: str
) -> Subscription:
    plan_cfg = PLAN_CONFIG[plan]
    sub, created = Subscription.objects.get_or_create(
        user=user,
        defaults={
            "tenant_id": str(user.tenant_id),
            "plan": plan,
            "status": "pending",
            "scan_limit": plan_cfg["scan_limit"],
            "price_pkr": plan_cfg["price_pkr"],
            "billing_cycle": billing_cycle,
            "safepay_token": encrypt_payment_token(safepay_token) or safepay_token,
        },
    )
    if not created:
        sub.plan = plan
        sub.status = "pending"
        sub.scan_limit = plan_cfg["scan_limit"]
        sub.price_pkr = plan_cfg["price_pkr"]
        sub.billing_cycle = billing_cycle
        sub.safepay_token = encrypt_payment_token(safepay_token) or safepay_token
        sub.save(update_fields=["plan", "status", "scan_limit", "price_pkr", "billing_cycle", "safepay_token"])
    return sub


def activate_subscription(
    user: User,
    plan: str,
    safepay_token: str,
    safepay_tracker: str,
    amount_pkr: int | None = None,
) -> Subscription:
    """Activate (or upgrade) a subscription after a successful payment."""
    now = datetime.now(timezone.utc)
    plan_cfg = PLAN_CONFIG[plan]
    logged_amount = amount_pkr if amount_pkr is not None else plan_cfg["price_pkr"]

    sub, created = Subscription.objects.get_or_create(
        user=user,
        defaults={
            "tenant_id": str(user.tenant_id),
            "plan": plan,
            "status": "active",
            "scan_limit": plan_cfg["scan_limit"],
            "price_pkr": plan_cfg["price_pkr"],
            "safepay_token": encrypt_payment_token(safepay_token) or safepay_token,
            "safepay_tracker": encrypt_payment_tracker(safepay_tracker) or safepay_tracker,
            "current_period_start": now,
            "current_period_end": now + timedelta(days=30),
        },
    )
    event_type = "plan_upgraded" if not created else "subscription_created"
    if not created:
        sub.plan = plan
        sub.status = "active"
        sub.scan_limit = plan_cfg["scan_limit"]
        sub.price_pkr = plan_cfg["price_pkr"]
        sub.safepay_token = encrypt_payment_token(safepay_token) or safepay_token
        sub.safepay_tracker = encrypt_payment_tracker(safepay_tracker) or safepay_tracker
        sub.current_period_start = now
        sub.current_period_end = now + timedelta(days=30)
        sub.cancelled_at = None
        sub.save(update_fields=[
            "plan", "status", "scan_limit", "price_pkr",
            "safepay_token", "safepay_tracker",
            "current_period_start", "current_period_end", "cancelled_at",
        ])

    user.plan = plan
    user.scan_count_month = 0
    user.save(update_fields=["plan", "scan_count_month"])

    log_billing_event(
        user_id=user.id,
        tenant_id=str(user.tenant_id),
        event_type=event_type,
        plan=plan,
        amount_pkr=logged_amount,
    )
    return sub


def get_usage(user: User) -> dict:
    plan_cfg = PLAN_CONFIG.get(user.plan, PLAN_CONFIG["free"])
    try:
        sub = Subscription.objects.get(user=user, status="active")
    except Subscription.DoesNotExist:
        sub = None
    scan_limit = sub.scan_limit if sub else plan_cfg["scan_limit"]
    resets_at = sub.current_period_end if sub else datetime.now(timezone.utc) + timedelta(days=30)
    scans_remaining = max(0, scan_limit - (user.scan_count_month or 0))
    percent_used = round((user.scan_count_month / scan_limit) * 100, 1) if scan_limit > 0 else 0.0
    return {
        "plan": user.plan,
        "scans_used": user.scan_count_month or 0,
        "scan_limit": scan_limit,
        "scans_remaining": scans_remaining,
        "percent_used": percent_used,
        "resets_at": resets_at,
        "plan_config": plan_cfg,
        "plan_limits": dict(PLAN_LIMITS),
    }


def get_subscription_dict(user: User) -> dict:
    try:
        sub = Subscription.objects.get(user=user)
    except Subscription.DoesNotExist:
        sub = None

    if sub:
        scans_remaining = max(0, sub.scan_limit - (user.scan_count_month or 0))
        return {
            "sub_id": str(sub.sub_id),
            "plan": sub.plan,
            "status": sub.status,
            "scan_limit": sub.scan_limit,
            "price_pkr": sub.price_pkr,
            "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
            "scans_used": user.scan_count_month or 0,
            "scans_remaining": scans_remaining,
        }

    plan_cfg = PLAN_CONFIG.get(user.plan, PLAN_CONFIG["free"])
    scans_remaining = max(0, plan_cfg["scan_limit"] - (user.scan_count_month or 0))
    return {
        "sub_id": None,
        "plan": user.plan,
        "status": "active",
        "scan_limit": plan_cfg["scan_limit"],
        "price_pkr": plan_cfg["price_pkr"],
        "current_period_end": None,
        "scans_used": user.scan_count_month or 0,
        "scans_remaining": scans_remaining,
    }


def log_billing_event(
    user_id: int,
    tenant_id: str,
    event_type: str,
    plan: str | None = None,
    amount_pkr: int = 0,
    safepay_data: dict | None = None,
) -> BillingEvent:
    return BillingEvent.objects.create(
        user_id=user_id,
        tenant_id=tenant_id,
        event_type=event_type,
        plan=plan,
        amount_pkr=amount_pkr,
        safepay_data=json.dumps(safepay_data) if safepay_data else None,
    )
