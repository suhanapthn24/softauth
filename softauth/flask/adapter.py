"""Flask adapter — implements BaseAdapter for Flask applications."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from softauth.core.config import SoftAuthConfig
from softauth.interfaces.adapter import BaseAdapter

if TYPE_CHECKING:
    from flask import Flask
    from softauth.core.auth import SoftAuth


class FlaskAdapter(BaseAdapter):
    """Wires SoftAuth into a Flask application.

    Responsibilities:
    - Registers a ``before_request`` hook that populates ``g.user_id``,
      ``g.user_role``, and ``g.token_payload`` from the JWT.
    - Registers the auto-generated auth Blueprint under ``config.auth_prefix``.
    - Exposes ``login_required``, ``admin_required``, and ``require_role()``
      as standard Flask decorators.
    """

    def __init__(self, auth: "SoftAuth", config: SoftAuthConfig) -> None:
        self._auth = auth
        self._config = config

        from softauth.flask.decorators import DecoratorFactory
        self._dec = DecoratorFactory(auth, config)

    def init_app(self, app: "Flask") -> None:
        from softauth.flask.middleware import setup_jwt_middleware
        from softauth.flask.routes import create_auth_blueprint

        setup_jwt_middleware(app, self._auth.jwt, self._config)
        bp = create_auth_blueprint(self._auth, self._config)
        app.register_blueprint(bp, url_prefix=self._config.auth_prefix)

    # ── BaseAdapter ────────────────────────────────────────────────────────

    def get_current_user_dependency(self) -> Callable[..., Any]:
        return self._dec.login_required

    def get_current_admin_dependency(self) -> Callable[..., Any]:
        return self._dec.admin_required

    def get_require_role_dependency(self, role: str) -> Callable[..., Any]:
        return self._dec.require_role(role)

    # ── Shortcut properties used by SoftAuth ──────────────────────────────

    @property
    def login_required(self) -> Callable[..., Any]:
        return self._dec.login_required

    @property
    def admin_required(self) -> Callable[..., Any]:
        return self._dec.admin_required

    def require_role(self, role: str) -> Callable[..., Any]:
        return self._dec.require_role(role)
