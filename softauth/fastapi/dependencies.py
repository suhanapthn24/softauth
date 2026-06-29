"""FastAPI dependency factories for current_user, current_admin, require_role.

Each property / method returns a *callable* that FastAPI resolves via Depends().
The callables are cached so FastAPI's dependency deduplication works correctly.
"""

from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING, Any, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from softauth.core.config import SoftAuthConfig
from softauth.core.exceptions import InvalidTokenError, TokenExpiredError

if TYPE_CHECKING:
    from softauth.core.auth import SoftAuth


class DependencyFactory:
    """Builds reusable FastAPI dependency callables from a SoftAuth instance."""

    def __init__(self, auth: "SoftAuth", config: SoftAuthConfig) -> None:
        self._auth = auth
        self._config = config
        self._oauth2 = OAuth2PasswordBearer(tokenUrl=f"{config.auth_prefix}/login")

    # ── Internal helper ───────────────────────────────────────────────────

    def _resolve_user(self, token: str) -> Any:
        """Decode token → look up user → validate active status."""
        try:
            payload = self._auth.jwt.decode_token(token)
        except TokenExpiredError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_id: str = payload.get("sub", "")
        with self._auth._db.session() as s:
            from softauth.database.repository import UserRepository
            user = UserRepository(s).get_by_id(user_id)

        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
        return user

    # ── Dependency properties (cached so the function object is stable) ───

    @cached_property
    def current_user(self) -> Callable[..., Any]:
        """Dependency: any authenticated active user."""
        oauth2 = self._oauth2
        resolve = self._resolve_user

        def _dep(token: str = Depends(oauth2)) -> Any:
            return resolve(token)

        _dep.__name__ = "current_user"
        return _dep

    @cached_property
    def current_admin(self) -> Callable[..., Any]:
        """Dependency: authenticated user with role == 'admin'."""
        oauth2 = self._oauth2
        resolve = self._resolve_user

        def _dep(token: str = Depends(oauth2)) -> Any:
            user = resolve(token)
            if user.role != "admin":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Admin role required",
                )
            return user

        _dep.__name__ = "current_admin"
        return _dep

    def require_role(self, role: str) -> Callable[..., Any]:
        """Dependency factory: authenticated user with ``role`` (or admin)."""
        oauth2 = self._oauth2
        resolve = self._resolve_user

        def _dep(token: str = Depends(oauth2)) -> Any:
            user = resolve(token)
            if user.role not in (role, "admin"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role '{role}' required",
                )
            return user

        _dep.__name__ = f"require_role_{role}"
        return _dep
