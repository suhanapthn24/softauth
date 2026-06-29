"""Flask decorators: @login_required, @admin_required, @require_role."""

from __future__ import annotations

from functools import wraps
from typing import TYPE_CHECKING, Any, Callable

from flask import g, jsonify

from softauth.core.config import SoftAuthConfig

if TYPE_CHECKING:
    from softauth.core.auth import SoftAuth


class DecoratorFactory:
    """Builds Flask route decorators that validate the JWT-populated g context."""

    def __init__(self, auth: "SoftAuth", config: SoftAuthConfig) -> None:
        self._auth = auth
        self._config = config

    # ── Shared helper ──────────────────────────────────────────────────────

    def _load_user(self) -> Any:
        """Return the User ORM object for the current request, or None."""
        user_id = g.get("user_id")
        if not user_id:
            return None
        with self._auth._db.session() as s:
            from softauth.database.repository import UserRepository
            return UserRepository(s).get_by_id(user_id)

    # ── Public decorators ──────────────────────────────────────────────────

    def login_required(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Require any authenticated active user."""
        @wraps(fn)
        def _wrapper(*args: Any, **kwargs: Any) -> Any:
            user = self._load_user()
            if user is None or not user.is_active:
                return jsonify({"error": "Authentication required"}), 401
            g.user = user
            return fn(*args, **kwargs)
        return _wrapper

    def admin_required(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Require an authenticated user with role == 'admin'."""
        @wraps(fn)
        def _wrapper(*args: Any, **kwargs: Any) -> Any:
            user = self._load_user()
            if user is None or not user.is_active:
                return jsonify({"error": "Authentication required"}), 401
            if user.role != "admin":
                return jsonify({"error": "Admin role required"}), 403
            g.user = user
            return fn(*args, **kwargs)
        return _wrapper

    def require_role(self, role: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Require an authenticated user with ``role`` (admin is always allowed)."""
        def _decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(fn)
            def _wrapper(*args: Any, **kwargs: Any) -> Any:
                user = self._load_user()
                if user is None or not user.is_active:
                    return jsonify({"error": "Authentication required"}), 401
                if user.role not in (role, "admin"):
                    return jsonify({"error": f"Role '{role}' required"}), 403
                g.user = user
                return fn(*args, **kwargs)
            return _wrapper
        return _decorator
