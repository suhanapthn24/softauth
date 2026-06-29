"""Django middleware: populates request.softauth_* from JWT on every request.

Add to Django settings:
    MIDDLEWARE = [
        ...
        "softauth.django.middleware.SoftAuthMiddleware",
    ]

The middleware reads the jwt_handler configured by DjangoAdapter.on_startup().
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Optional

from softauth.core.exceptions import TokenError

if TYPE_CHECKING:
    from softauth.jwt.handler import JWTHandler

_jwt_handler: Optional["JWTHandler"] = None


def configure(jwt_handler: "JWTHandler") -> None:
    """Register the JWTHandler used by SoftAuthMiddleware. Called by DjangoAdapter."""
    global _jwt_handler
    _jwt_handler = jwt_handler


class SoftAuthMiddleware:
    """Parses JWT from Authorization header and populates request.softauth_* attributes.

    Sets on every request (regardless of whether a token is present):
        request.softauth_user_id   — str | None
        request.softauth_role      — str | None
        request.softauth_payload   — dict | None
    """

    def __init__(self, get_response: Callable[..., Any]) -> None:
        self.get_response = get_response

    def __call__(self, request: Any) -> Any:
        request.softauth_user_id = None
        request.softauth_role = None
        request.softauth_payload = None

        if _jwt_handler is not None:
            auth_header: str = request.META.get("HTTP_AUTHORIZATION", "")
            if auth_header:
                try:
                    token = _jwt_handler.extract_token_from_header(auth_header)
                    payload = _jwt_handler.decode_token(token)
                    request.softauth_user_id = payload.get("sub")
                    request.softauth_role = payload.get("role")
                    request.softauth_payload = payload
                except TokenError:
                    pass

        return self.get_response(request)
