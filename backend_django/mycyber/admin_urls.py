"""URL confs for the Django admin (with two-factor auth patched on).

``TWO_FACTOR_PATCH_ADMIN = True`` in settings makes django-two-factor-auth
replace the admin login view automatically (handled in its ``AppConfig.ready``).
We only need to expose ``admin.site.urls`` here.
"""
from __future__ import annotations

from django.contrib import admin
from django.urls import path

urlpatterns = [
    path("", admin.site.urls),
]
