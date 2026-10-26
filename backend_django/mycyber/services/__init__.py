"""Shared security / infra services for the Django backend.

These modules are ported 1:1 from the FastAPI backend (``backend/app/services``)
to keep behaviour — and the test surface — identical during the migration.

They read their configuration **lazily** from environment variables (with safe
defaults) so that test-suite env-vars set in ``conftest``/``settings.test``
are honoured regardless of import order.
"""
from __future__ import annotations
