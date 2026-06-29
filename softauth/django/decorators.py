"""Django decorators: @login_required, @admin_required, @require_role."""

from __future__ import annotations

from functools import wraps
from typing import TYPE_CHECKING, Any, Callable

from django.http import JsonResponse

from softauth.core.config import SoftAuthConfig

if TYPE_CHECKING:
    from softauth.core.auth import SoftAuth


class DecoratorFactory:
    """Builds Django view decorators that validate the JWT-populated request attributes."""

    def __init__(self, auth: "SoftAuth", config: SoftAuthConfig) -> None:
        self._auth = auth
        self._config = config

    def _load_user(self, request: Any) -> Any:
        user_id = getattr(request, "softauth_user_id", None)
        if not user_id:
            return None
        with self._auth._db.session() as s:
            from softauth.database.repository import UserRepository
            return UserRepository(s).get_by_id(user_id)

    def login_required(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Require any authenticated active user."""
        @wraps(fn)
        def _wrapper(request: Any, *args: Any, **kwargs: Any) -> Any:
            user = self._load_user(request)
            if user is None or not user.is_active:
                return JsonResponse({"error": "Authentication required"}, status=401)
            request.softauth_user = user
            return fn(request, *args, **kwargs)
        return _wrapper

    def admin_required(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Require an authenticated user with role == 'admin'."""
        @wraps(fn)
        def _wrapper(request: Any, *args: Any, **kwargs: Any) -> Any:
            user = self._load_user(request)
            if user is None or not user.is_active:
                return JsonResponse({"error": "Authentication required"}, status=401)
            if user.role != "admin":
                return JsonResponse({"error": "Admin role required"}, status=403)
            request.softauth_user = user
            return fn(request, *args, **kwargs)
        return _wrapper

    def require_role(self, role: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Require an authenticated user with ``role`` (admin is always allowed)."""
        def _decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(fn)
            def _wrapper(request: Any, *args: Any, **kwargs: Any) -> Any:
                user = self._load_user(request)
                if user is None or not user.is_active:
                    return JsonResponse({"error": "Authentication required"}, status=401)
                if user.role not in (role, "admin"):
                    return JsonResponse({"error": f"Role '{role}' required"}, status=403)
                request.softauth_user = user
                return fn(request, *args, **kwargs)
            return _wrapper
        return _decorator
