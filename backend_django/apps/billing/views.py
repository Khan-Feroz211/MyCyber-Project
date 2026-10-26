"""Billing / subscription HTTP views (DRF port of ``backend/app/routers/billing.py``).

Mounted under ``/api/v1/billing/``.
"""
from __future__ import annotations

import json as _json

from rest_framework import permissions, status, views
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.response import Response

from apps.accounts.plans import PLAN_CONFIG


class BillingPlansAPI(views.APIView):
    """GET /billing/plans — list all plan cards."""

    permission_classes = [permissions.AllowAny]

    def get(self, request):
        user_plan = getattr(request.user, "plan", None) if getattr(request.user, "is_authenticated", False) else None
        cards = []
        for plan_id, cfg in PLAN_CONFIG.items():
            cards.append(
                {
                    "plan_id": plan_id,
                    "name": cfg["name"],
                    "price_pkr": cfg["price_pkr"],
                    "scan_limit": cfg["scan_limit"],
                    "features": cfg["features"],
                    "is_current": plan_id == user_plan,
                }
            )
        return Response(cards)


class BillingUsageAPI(views.APIView):
    """GET /billing/usage."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        from apps.billing.services import get_usage

        return Response(get_usage(request.user))


class BillingSubscriptionAPI(views.APIView):
    """GET /billing/subscription."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        from apps.billing.services import get_subscription_dict

        return Response(get_subscription_dict(request.user))


class BillingUpgradeAPI(views.APIView):
    """POST /billing/upgrade."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        from django.utils import timezone

        plan = request.data.get("plan")
        billing_cycle = request.data.get("billing_cycle", "monthly")
        if plan not in PLAN_CONFIG:
            raise ValidationError({"plan": f"Unknown plan: {plan}"})
        if plan == request.user.plan:
            return Response(
                {"detail": f"You are already subscribed to the '{plan}' plan."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        from apps.billing.services import create_checkout_session, create_pending_subscription
        from mycyber.services.audit_log import EVENT_PLAN_CHANGE, append_audit_log

        checkout = create_checkout_session(user=request.user, plan=plan, billing_cycle=billing_cycle)
        create_pending_subscription(
            user=request.user,
            plan=plan,
            billing_cycle=billing_cycle,
            safepay_token=checkout["safepay_token"],
        )
        from datetime import timedelta

        expires_at = timezone.now() + timedelta(hours=1)
        try:
            append_audit_log(
                event_type=EVENT_PLAN_CHANGE,
                resource_type="subscription",
                action="upgrade_initiated",
                tenant_id=str(request.user.tenant_id),
                actor=request.user,
                details={
                    "new_plan": plan,
                    "billing_cycle": billing_cycle,
                    "amount_pkr": checkout["amount_pkr"],
                },
            )
        except Exception:  # noqa: BLE001
            pass
        return Response(
            {
                "checkout_url": checkout["checkout_url"],
                "safepay_token": checkout["safepay_token"],
                "plan": checkout["plan"],
                "amount_pkr": checkout["amount_pkr"],
                "expires_at": expires_at.isoformat(),
            },
            status=status.HTTP_200_OK,
        )


class BillingCancelAPI(views.APIView):
    """POST /billing/cancel."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        from apps.billing.models import Subscription
        from django.utils import timezone
        from mycyber.services.audit_log import EVENT_PLAN_CHANGE, append_audit_log

        try:
            sub = Subscription.objects.get(user=request.user, status="active")
        except Subscription.DoesNotExist:
            raise NotFound("No active subscription found.")
        now = timezone.now()
        sub.status = "cancelled"
        sub.cancelled_at = now
        sub.save(update_fields=["status", "cancelled_at"])
        from apps.billing.services import log_billing_event

        log_billing_event(
            user_id=request.user.id,
            tenant_id=str(request.user.tenant_id),
            event_type="subscription_cancelled",
            plan=sub.plan,
            amount_pkr=0,
        )
        try:
            append_audit_log(
                event_type=EVENT_PLAN_CHANGE,
                resource_type="subscription",
                action="cancel",
                tenant_id=str(request.user.tenant_id),
                actor=request.user,
                details={"plan": sub.plan, "sub_id": str(sub.sub_id)},
            )
        except Exception:  # noqa: BLE001
            pass
        return Response(
            {
                "message": f"Subscription cancelled. Access continues until {sub.current_period_end}.",
            }
        )


class BillingHistoryAPI(views.APIView):
    """GET /billing/history."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        from apps.billing.models import BillingEvent

        events = BillingEvent.objects.filter(tenant_id=str(request.user.tenant_id)).order_by("-created_at")[:50]
        return Response(
            [
                {
                    "event_id": str(e.event_id),
                    "event_type": e.event_type,
                    "plan": e.plan,
                    "amount_pkr": e.amount_pkr,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                }
                for e in events
            ]
        )


class SafepayWebhookAPI(views.APIView):
    """POST /billing/webhook — no auth (called directly by Safepay)."""

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        from mycyber.services import conf
        from apps.billing.services import verify_safepay_webhook

        signature = request.META.get("HTTP_X_SFPY_SIGNATURE")
        payload = request.body
        if not signature:
            return Response({"detail": "Missing webhook signature."}, status=status.HTTP_400_BAD_REQUEST)
        if not verify_safepay_webhook(payload=payload, signature=signature, secret=conf.safepay_webhook_secret()):
            return Response({"detail": "Invalid webhook signature."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            data = _json.loads(payload)
            event_type = data.get("event", "")
            event_data = data.get("data", {})
            if event_type == "payment/succeeded":
                _handle_payment_succeeded(event_data)
            elif event_type == "payment/failed":
                _handle_payment_failed(event_data)
            elif event_type == "subscription/cancelled":
                _handle_subscription_cancelled(event_data)
            return Response({"status": "ok"})
        except Exception as exc:  # noqa: BLE001
            return Response({"status": "ok"})


def _handle_payment_succeeded(event_data: dict):
    from apps.accounts.models import User
    from apps.billing.models import Subscription
    from apps.billing.services import activate_subscription, log_billing_event

    tracker = event_data.get("tracker", "")
    token = event_data.get("token", "")
    amount_pkr = (event_data.get("amount", 0) or 0) // 100
    sub = Subscription.objects.filter(safepay_token__contains=token).first()
    if sub is None:
        return
    try:
        user = User.objects.get(id=sub.user_id)
    except User.DoesNotExist:
        return
    activate_subscription(
        user=user, plan=sub.plan, safepay_token=token, safepay_tracker=tracker, amount_pkr=amount_pkr if amount_pkr else None
    )
    log_billing_event(
        user_id=user.id, tenant_id=str(user.tenant_id), event_type="payment_succeeded", plan=sub.plan, amount_pkr=amount_pkr, safepay_data=event_data
    )


def _handle_payment_failed(event_data: dict):
    from apps.billing.models import Subscription
    from apps.billing.services import log_billing_event

    tracker = event_data.get("tracker", "")
    sub = Subscription.objects.filter(safepay_tracker__contains=tracker).first()
    if sub is None:
        return
    sub.status = "past_due"
    sub.save(update_fields=["status"])
    log_billing_event(
        user_id=sub.user_id, tenant_id=str(sub.tenant_id), event_type="payment_failed", plan=sub.plan, amount_pkr=0, safepay_data=event_data
    )


def _handle_subscription_cancelled(event_data: dict):
    from apps.billing.models import Subscription
    from django.utils import timezone

    tracker = event_data.get("tracker", "")
    sub = Subscription.objects.filter(safepay_tracker__contains=tracker).first()
    if sub is None:
        return
    sub.status = "cancelled"
    sub.cancelled_at = timezone.now()
    sub.save(update_fields=["status", "cancelled_at"])
