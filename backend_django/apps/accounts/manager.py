"""Managers for the custom User model."""
from __future__ import annotations

import uuid

from django.contrib.auth.base_user import BaseUserManager


class UserManager(BaseUserManager):
    """Manager that uses ``email`` as the username field."""

    use_in_migrations = True

    def _create_user(self, email: str, password: str, **extra):
        if not email:
            raise ValueError("Users must supply an email address.")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra)
        user.set_password(password)
        user.tenant_id = extra.get("tenant_id") or str(uuid.uuid4())
        user.save(using=self._db)
        return user

    def create_user(self, email: str, password: str | None = None, **extra):
        extra.setdefault("is_staff", False)
        extra.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra)

    def create_superuser(self, email: str, password: str, **extra):
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        extra.setdefault("is_admin", True)
        extra.setdefault("is_active", True)
        return self._create_user(email, password, **extra)
