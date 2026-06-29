"""SoftAuth — the public facade for the entire library.

Usage (FastAPI):
    auth = SoftAuth(secret_key="...", framework="fastapi")
    auth.init_app(app)
    auth.init_db()

Usage (Flask):
    auth = SoftAuth(secret_key="...", framework="flask")
    auth.init_app(app)
    auth.init_db()

The core is framework-agnostic: JWT and password handling live in
``softauth.jwt`` and ``softauth.security``.  Framework adapters (FastAPI,
Flask, …) implement ``BaseAdapter`` and are loaded lazily so that having
only one framework installed does not cause import errors.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from softauth.core.config import SoftAuthConfig
from softauth.core.exceptions import AdapterNotInitializedError, ConfigurationError
from softauth.database.session import DatabaseSession
from softauth.interfaces.adapter import BaseAdapter
from softauth.jwt.handler import JWTHandler
from softauth.security.password import PasswordHandler


class SoftAuth:
    """Zero-setup JWT authentication for FastAPI and Flask.

    All arguments to ``__init__`` mirror ``SoftAuthConfig`` fields.
    Pass any SoftAuthConfig field as a keyword argument.
    """

    def __init__(
        self,
        secret_key: str,
        *,
        framework: Optional[str] = None,
        database_url: str = "sqlite:///auth.db",
        algorithm: str = "HS256",
        access_expiry_minutes: int = 15,
        refresh_expiry_days: int = 7,
        auth_prefix: str = "/auth",
        enable_refresh_tokens: bool = True,
    ) -> None:
        self.config = SoftAuthConfig(
            secret_key=secret_key,
            framework=framework,  # type: ignore[arg-type]
            database_url=database_url,
            algorithm=algorithm,
            access_expiry_minutes=access_expiry_minutes,
            refresh_expiry_days=refresh_expiry_days,
            auth_prefix=auth_prefix,
            enable_refresh_tokens=enable_refresh_tokens,
        )
        self.jwt = JWTHandler(self.config)
        self.passwords = PasswordHandler()
        self._db = DatabaseSession(self.config.database_url)
        self._adapter: Optional[BaseAdapter] = None

    # ── Initialisation ────────────────────────────────────────────────────

    def init_app(self, app: Any) -> None:
        """Attach SoftAuth to *app*.

        Mounts routes and middleware for the configured framework.
        Must be called before the first request is served.
        """
        fw = self.config.framework
        if fw == "fastapi":
            from softauth.fastapi.adapter import FastAPIAdapter
            self._adapter = FastAPIAdapter(self, self.config)
        elif fw == "flask":
            from softauth.flask.adapter import FlaskAdapter
            self._adapter = FlaskAdapter(self, self.config)
        elif fw == "django":
            from softauth.django.adapter import DjangoAdapter
            self._adapter = DjangoAdapter(self, self.config)
        elif fw is None:
            raise ConfigurationError(
                "No framework specified.  Pass framework='fastapi' or framework='flask' "
                "to SoftAuth(), or use a custom adapter."
            )
        else:
            raise ConfigurationError(
                f"Unknown framework '{fw}'.  "
                "Built-in choices: 'fastapi', 'flask', 'django'.  "
                "For other frameworks implement BaseAdapter and call use_adapter()."
            )

        self._adapter.on_startup()
        self._adapter.init_app(app)

    def use_adapter(self, adapter: BaseAdapter, app: Any) -> None:
        """Register a custom BaseAdapter instead of a built-in one.

        This is the extension point for Django, Litestar, Quart, or any
        other framework without touching SoftAuth internals.

        Example::

            class DjangoAdapter(BaseAdapter): ...

            auth = SoftAuth(secret_key="...", framework=None)
            auth.use_adapter(DjangoAdapter(auth, auth.config), django_app)
        """
        self._adapter = adapter
        adapter.on_startup()
        adapter.init_app(app)

    def init_db(self) -> None:
        """Create the softauth_users table (and any future tables).

        Idempotent — safe to call on every startup.
        """
        self._db.create_tables()

    # ── Auth dependency / decorator accessors ─────────────────────────────

    def _require_adapter(self) -> BaseAdapter:
        if self._adapter is None:
            raise AdapterNotInitializedError(
                "Call auth.init_app(app) before accessing auth dependencies."
            )
        return self._adapter

    @property
    def current_user(self) -> Any:
        """FastAPI: ``Depends(auth.current_user)``  |  Flask: ``@auth.login_required``."""
        return self._require_adapter().get_current_user_dependency()

    @property
    def current_admin(self) -> Any:
        """FastAPI: ``Depends(auth.current_admin)``  |  Flask: ``@auth.admin_required``."""
        return self._require_adapter().get_current_admin_dependency()

    def require_role(self, role: str) -> Any:
        """FastAPI: ``Depends(auth.require_role('editor'))``
           Flask:   ``@auth.require_role('editor')``
        """
        return self._require_adapter().get_require_role_dependency(role)

    # ── Flask-flavoured shorthand properties ──────────────────────────────

    @property
    def login_required(self) -> Any:
        """Flask convenience alias for ``current_user`` (used as decorator)."""
        adapter = self._require_adapter()
        if not hasattr(adapter, "login_required"):
            return adapter.get_current_user_dependency()
        return adapter.login_required  # type: ignore[union-attr]

    @property
    def admin_required(self) -> Any:
        """Flask convenience alias for ``current_admin`` (used as decorator)."""
        adapter = self._require_adapter()
        if not hasattr(adapter, "admin_required"):
            return adapter.get_current_admin_dependency()
        return adapter.admin_required  # type: ignore[union-attr]

    # ── Convenience passthrough ────────────────────────────────────────────

    def hash_password(self, plain: str) -> str:
        return self.passwords.hash_password(plain)

    def verify_password(self, plain: str, hashed: str) -> bool:
        return self.passwords.verify_password(plain, hashed)

    def create_access_token(self, subject: str, role: Optional[str] = None, **extra: Any) -> str:
        return self.jwt.create_access_token(subject, role=role, extra=extra or None)

    def create_refresh_token(self, subject: str) -> str:
        return self.jwt.create_refresh_token(subject)

    def decode_token(self, token: str) -> dict[str, Any]:
        return self.jwt.decode_token(token)

    def verify_token(self, token: str) -> bool:
        return self.jwt.verify_token(token)
