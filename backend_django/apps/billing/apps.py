from __future__ import annotations

from django.apps import AppConfig


class BillingConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.billing"
    verbose_name = "Billing"

    def ready(self):
        # Register payment tokens for the key-rotation re-encryption job.
        from mycyber.services.field_encryption import register_sensitive_field

        from apps.billing.models import BillingEvent, Subscription

        register_sensitive_field(Subscription, "safepay_token")
        register_sensitive_field(Subscription, "safepay_tracker")
        register_sensitive_field(BillingEvent, "safepay_data")
