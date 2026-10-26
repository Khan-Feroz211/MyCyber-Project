"""Plan / billing configuration (ported from ``backend/app/models/schemas.py``)."""
from __future__ import annotations

UNLIMITED_SCANS: int = 999_999

PLAN_LIMITS: dict[str, int] = {
    "free": 100,
    "pro": 10_000,
    "enterprise": UNLIMITED_SCANS,
}

PLAN_CONFIG: dict = {
    "free": {
        "name": "Free",
        "scan_limit": 100,
        "price_pkr": 0,
        "features": [
            "100 scans per month",
            "Text + file scanning",
            "Email alerts",
            "7-day history",
        ],
    },
    "pro": {
        "name": "Pro",
        "scan_limit": 10000,
        "price_pkr": 4500,
        "features": [
            "10,000 scans per month",
            "Text + file + network scanning",
            "Real-time alerts",
            "90-day history",
            "API access",
            "Priority support",
        ],
    },
    "enterprise": {
        "name": "Enterprise",
        "scan_limit": UNLIMITED_SCANS,
        "price_pkr": 15000,
        "features": [
            "Unlimited scans",
            "All scan types",
            "Custom alert rules",
            "1-year history",
            "Dedicated support",
            "White-label option",
            "SLA guarantee",
        ],
    },
}


def get_usage(user) -> dict:
    """Compute monthly usage for a user from their model fields."""
    limit = PLAN_LIMITS.get(user.plan, PLAN_LIMITS["free"])
    scans_remaining = max(0, limit - (user.scan_count_month or 0))
    percent_used = round((user.scan_count_month / limit * 100) if limit and limit != UNLIMITED_SCANS else 0.0, 2)
    plan_config = PLAN_CONFIG.get(user.plan, PLAN_CONFIG["free"])
    # Next midnight UTC (month reset is per-plan; approximate to 30 days).
    from datetime import timedelta

    resets_at = user.created_at + timedelta(days=30)
    return {
        "plan": user.plan,
        "scans_used": user.scan_count_month or 0,
        "scan_limit": limit,
        "scans_remaining": scans_remaining,
        "percent_used": percent_used,
        "resets_at": resets_at,
        "plan_config": plan_config,
    }
