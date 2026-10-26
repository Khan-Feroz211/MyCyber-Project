"""
ASGI config for MyCyber DLP project.

Exposes the ASGI callable as a module-level variable named ``application``.

This routes both HTTP requests (via Django Channels) and WebSocket
connections.  In production the app is served by **uvicorn** or
**daphne** behind nginx.
"""
from __future__ import annotations

import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.session import AllowedHostsOriginValidator
from django.core.asgi import get_asgi_application
from django.urls import path

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mycyber.settings.dev")

# Import the routing *after* Django is configured so app_registry is ready
django_asgi_app = get_asgi_application()

from apps.alerts.routing import websocket_urlpatterns  # noqa: E402

application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        "websocket": AllowedHostsOriginValidator(
            AuthMiddlewareStack(URLRouter(websocket_urlpatterns))
        ),
    }
)
