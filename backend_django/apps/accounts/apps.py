from __future__ import annotations

from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.accounts"
    verbose_name = "Accounts"

    def ready(self) -> None:
        # Register sensitive fields for the KMS key-rotation job.  Imported
        # here (lazy) to avoid importing models before the app registry is
        # fully initialised.
        from mycyber.services.field_encryption import register_sensitive_field

        from apps.accounts.models import User

        register_sensitive_field(User, "mfa_secret")
