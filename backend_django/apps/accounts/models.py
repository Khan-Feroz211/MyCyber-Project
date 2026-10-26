"""The custom User model for MyCyber DLP.

Mirrors the FastAPI ``User`` SQLAlchemy model (``backend/app/db/models.py``)
so the data contract — email auth, RBAC ``role``, tenant scoping, MFA and
billing/plan fields — is identical during the migration.
"""
from __future__ import annotations

import uuid

from django.contrib.auth.models import AbstractBaseUser
from django.db import models

from .manager import UserManager


class User(AbstractBaseUser):
    """Custom user keyed on ``email``.

    RBAC hierarchy: ``viewer`` < ``analyst`` < ``admin``.  ``is_admin`` is kept
    for backward compatibility; when ``True`` it implies the ``admin`` role.
    """

    email = models.EmailField(unique=True, db_index=True, max_length=255)
    full_name = models.CharField(max_length=255, blank=True, null=True)

    # Django admin flags
    is_active = models.BooleanField(default=True, null=False)
    is_staff = models.BooleanField(default=False, null=False)
    is_superuser = models.BooleanField(default=False, null=False)

    # RBAC
    is_admin = models.BooleanField(default=False, null=False)
    role = models.CharField(max_length=20, default="viewer", null=False)
    tenant_id = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)

    # Billing
    plan = models.CharField(max_length=20, default="free", null=False)
    scan_count_month = models.IntegerField(default=0, null=False)

    # MFA
    mfa_enabled = models.BooleanField(default=False, null=False)
    mfa_secret = models.CharField(max_length=64, blank=True, null=True)

    # Login security
    failed_login_attempts = models.IntegerField(default=0, null=False)
    locked_until = models.DateTimeField(blank=True, null=True)
    last_login_ip = models.CharField(max_length=64, blank=True, null=True)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    class Meta:
        db_table = "users"
        ordering = ["-id"]

    def __str__(self) -> str:
        return self.email

    # -- Django boilerplate -------------------------------------------------
    @property
    def is_authenticated(self):  # type: ignore[override]
        return True

    def has_module_perms(self, app_label):
        return True

    def has_perm(self, perm, obj=None):
        return self.is_staff or self.is_superuser

    def has_module_perms(self, app_label):  # noqa: F811
        return True

    def get_full_name(self) -> str:
        return self.full_name or self.email

    def get_short_name(self) -> str:
        return self.full_name or self.email
