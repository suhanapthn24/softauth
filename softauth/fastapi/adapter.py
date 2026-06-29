"""FastAPI adapter — implements BaseAdapter for FastAPI applications."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from softauth.core.config import SoftAuthConfig
from softauth.interfaces.adapter import BaseAdapter

if TYPE_CHECKING:
    from fastapi import FastAPI
    from softauth.core.auth import SoftAuth


class FastAPIAdapter(BaseAdapter):
    """Wires SoftAuth into a FastAPI application.

    Responsibilities:
    - Registers ``JWTMiddleware`` so ``request.state.user_*`` is always set.
    - Mounts the auto-generated auth router under ``config.auth_prefix``.
    - Exposes ``current_user``, ``current_admin``, and ``require_role()``
      as FastAPI-native ``Depends()``-compatible callables.
    """

    def __init__(self, auth: "SoftAuth", config: SoftAuthConfig) -> None:
        self._auth = auth
        self._config = config

        from softauth.fastapi.dependencies import DependencyFactory
        self._deps = DependencyFactory(auth, config)

    def init_app(self, app: "FastAPI") -> None:
        from softauth.fastapi.middleware import JWTMiddleware
        from softauth.fastapi.routes import create_auth_router

        app.add_middleware(
            JWTMiddleware,
            config=self._config,
            jwt_handler=self._auth.jwt,
        )
        router = create_auth_router(self._auth, self._config, self._deps)
        app.include_router(
            router,
            prefix=self._config.auth_prefix,
            tags=["Authentication"],
        )

    def get_current_user_dependency(self) -> Callable[..., Any]:
        return self._deps.current_user

    def get_current_admin_dependency(self) -> Callable[..., Any]:
        return self._deps.current_admin

    def get_require_role_dependency(self, role: str) -> Callable[..., Any]:
        return self._deps.require_role(role)
