"""RBAC permission classes (mirrors FastAPI ``require_role``)."""
from __future__ import annotations

from rest_framework import permissions

from mycyber.services.auth import resolve_role


class IsAdminRole(permissions.BasePermission):
    """Allow only users whose effective role is ``admin``."""

    message = "Admin privileges are required for this operation."

    def has_permission(self, request, view):
        user = request.user
        return bool(
            getattr(user, "is_authenticated", False)
            and resolve_role(user) == "admin"
        )


class IsAnalystRole(permissions.BasePermission):
    """Allow users with at least the ``analyst`` role."""

    message = "Insufficient privileges. Requires role 'analyst' or higher."

    def has_permission(self, request, view):
        from mycyber.services.auth import _ROLE_HIERARCHY  # noqa

        user = request.user
        if not getattr(user, "is_authenticated", False):
            return False
        role = resolve_role(user)
        required = _ROLE_HIERARCHY.get("analyst", 1)
        return _ROLE_HIERARCHY.get(role, 0) >= required
