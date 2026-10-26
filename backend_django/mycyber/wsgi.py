"""
WSGI config for MyCyber DLP project.

Present for compatibility; production uses ASGI (uvicorn / daphne).
"""
from __future__ import annotations

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mycyber.settings.dev")
application = get_wsgi_application()
