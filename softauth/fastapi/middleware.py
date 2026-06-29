"""JWT parsing middleware for FastAPI / Starlette.

Runs before every request.  Successful decoding populates:
    request.state.user_id   — str | None
    request.state.user_role — str | None
    request.state.token_payload — dict | None

A missing or invalid token is NOT an error here — endpoints that require
authentication enforce it themselves via dependencies.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from softauth.core.config import SoftAuthConfig
from softauth.core.exceptions import InvalidTokenError, TokenExpiredError
from softauth.jwt.handler import JWTHandler


class JWTMiddleware(BaseHTTPMiddleware):  # type: ignore[misc]
    def __init__(self, app: Any, config: SoftAuthConfig, jwt_handler: JWTHandler) -> None:
        super().__init__(app)
        self._config = config
        self._jwt = jwt_handler

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        raw_auth = request.headers.get("Authorization", "")
        token = self._jwt.extract_token_from_header(raw_auth)

        if token:
            try:
                payload = self._jwt.decode_token(token)
                request.state.user_id = payload.get("sub")
                request.state.user_role = payload.get("role")
                request.state.token_payload = payload
            except (TokenExpiredError, InvalidTokenError):
                request.state.user_id = None
                request.state.user_role = None
                request.state.token_payload = None
        else:
            request.state.user_id = None
            request.state.user_role = None
            request.state.token_payload = None

        return await call_next(request)
