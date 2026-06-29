"""Django adapter — implements BaseAdapter for Django applications."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from softauth.core.config import SoftAuthConfig
from softauth.interfaces.adapter import BaseAdapter

if TYPE_CHECKING:
    from softauth.core.auth import SoftAuth


class DjangoAdapter(BaseAdapter):
    """Wires SoftAuth into a Django application.

    Responsibilities:
    - Configures ``softauth.django.middleware.SoftAuthMiddleware`` via a
      module-level singleton (called in ``on_startup()``).
    - Appends auto-generated auth URL patterns to the provided ``urlpatterns``
      list in ``init_app(urlpatterns)``.
    - Exposes ``login_required``, ``admin_required``, and ``require_role()``
      as standard Django view decorators.

    Usage::

        # settings.py
        MIDDLEWARE = [
            ...
            "softauth.django.middleware.SoftAuthMiddleware",
        ]

        # urls.py
        urlpatterns = []
        auth.init_app(urlpatterns)   # appends /auth/* patterns
    """

    def __init__(self, auth: "SoftAuth", config: SoftAuthConfig) -> None:
        self._auth = auth
        self._config = config

        from softauth.django.decorators import DecoratorFactory
        self._dec = DecoratorFactory(auth, config)

    def on_startup(self) -> None:
        """Configure the middleware singleton with this adapter's JWT handler."""
        from softauth.django import middleware as mw
        mw.configure(self._auth.jwt)

    def init_app(self, urlpatterns: Any) -> None:
        """Append softauth URL patterns to *urlpatterns* (a Django ``urlpatterns`` list)."""
        from softauth.django.urls import create_auth_urlpatterns
        urlpatterns += create_auth_urlpatterns(self._auth, self._config)

    # ── BaseAdapter ────────────────────────────────────────────────────────────

    def get_current_user_dependency(self) -> Callable[..., Any]:
        return self._dec.login_required

    def get_current_admin_dependency(self) -> Callable[..., Any]:
        return self._dec.admin_required

    def get_require_role_dependency(self, role: str) -> Callable[..., Any]:
        return self._dec.require_role(role)

    # ── Shortcut properties used by SoftAuth ───────────────────────────────────

    @property
    def login_required(self) -> Callable[..., Any]:
        return self._dec.login_required

    @property
    def admin_required(self) -> Callable[..., Any]:
        return self._dec.admin_required

    def require_role(self, role: str) -> Callable[..., Any]:
        return self._dec.require_role(role)
