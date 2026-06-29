"""URL pattern factory for softauth's Django auth endpoints.

Usage in your urls.py:
    from django.urls import path, include
    from softauth.django.urls import create_auth_urlpatterns

    urlpatterns = [
        # ... your routes
    ] + create_auth_urlpatterns(auth, auth.config)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from softauth.core.config import SoftAuthConfig
from softauth.django.views import create_auth_views

if TYPE_CHECKING:
    from softauth.core.auth import SoftAuth


def create_auth_urlpatterns(auth: "SoftAuth", config: SoftAuthConfig) -> list[Any]:
    """Return Django URL patterns for all auth endpoints."""
    from django.urls import path

    views = create_auth_views(auth, config)
    prefix = config.auth_prefix.strip("/")

    return [
        path(f"{prefix}/register/", views["register"], name="softauth-register"),
        path(f"{prefix}/login/", views["login"], name="softauth-login"),
        path(f"{prefix}/refresh/", views["refresh"], name="softauth-refresh"),
        path(f"{prefix}/me/", views["me"], name="softauth-me"),
        path(f"{prefix}/logout/", views["logout"], name="softauth-logout"),
    ]
