"""Flask before-request JWT middleware.

Parses the Authorization header and populates:
    g.user_id      — str | None
    g.user_role    — str | None
    g.token_payload — dict | None

A missing or invalid token is silently ignored; routes that require auth
declare the appropriate decorator.
"""

from __future__ import annotations

from flask import Flask, g, request

from softauth.core.config import SoftAuthConfig
from softauth.core.exceptions import InvalidTokenError, TokenExpiredError
from softauth.jwt.handler import JWTHandler


def setup_jwt_middleware(app: Flask, jwt_handler: JWTHandler, config: SoftAuthConfig) -> None:
    @app.before_request
    def _parse_jwt() -> None:
        raw_auth: str = request.headers.get("Authorization", "")
        token = jwt_handler.extract_token_from_header(raw_auth)

        g.user_id = None
        g.user_role = None
        g.token_payload = None
        g.user = None

        if token:
            try:
                payload = jwt_handler.decode_token(token)
                g.user_id = payload.get("sub")
                g.user_role = payload.get("role")
                g.token_payload = payload
            except (TokenExpiredError, InvalidTokenError):
                pass
