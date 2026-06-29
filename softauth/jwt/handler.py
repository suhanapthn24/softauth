"""Framework-agnostic JWT engine.

This module has zero framework imports.  It creates, decodes, and verifies
JWTs using PyJWT and the values in SoftAuthConfig.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt

from softauth.core.config import SoftAuthConfig
from softauth.core.exceptions import InvalidTokenError, TokenExpiredError


class JWTHandler:
    """Stateless JWT factory and validator.

    All methods are synchronous and framework-independent.
    """

    def __init__(self, config: SoftAuthConfig) -> None:
        self._config = config

    # ── Token creation ────────────────────────────────────────────────────

    def create_access_token(
        self,
        subject: str,
        role: Optional[str] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> str:
        """Return a signed JWT access token."""
        now = datetime.now(timezone.utc)
        payload: dict[str, Any] = {
            "sub": subject,
            "type": "access",
            "iat": now,
            "exp": now + timedelta(minutes=self._config.access_expiry_minutes),
            "jti": str(uuid.uuid4()),
        }
        if role is not None:
            payload["role"] = role
        if extra:
            payload.update(extra)
        return jwt.encode(payload, self._config.secret_key, algorithm=self._config.algorithm)

    def create_refresh_token(self, subject: str) -> str:
        """Return a signed JWT refresh token."""
        now = datetime.now(timezone.utc)
        payload: dict[str, Any] = {
            "sub": subject,
            "type": "refresh",
            "iat": now,
            "exp": now + timedelta(days=self._config.refresh_expiry_days),
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(payload, self._config.secret_key, algorithm=self._config.algorithm)

    # ── Token verification ────────────────────────────────────────────────

    def decode_token(self, token: str) -> dict[str, Any]:
        """Decode and verify *token*.

        Raises:
            TokenExpiredError: if the token's ``exp`` claim is in the past.
            InvalidTokenError: for any other JWT validation failure.
        """
        try:
            return jwt.decode(
                token,
                self._config.secret_key,
                algorithms=[self._config.algorithm],
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpiredError("Token has expired") from exc
        except jwt.InvalidTokenError as exc:
            raise InvalidTokenError(f"Invalid token: {exc}") from exc

    def verify_token(self, token: str) -> bool:
        """Return ``True`` if *token* is currently valid, ``False`` otherwise."""
        try:
            self.decode_token(token)
            return True
        except (TokenExpiredError, InvalidTokenError):
            return False

    def extract_token_from_header(self, authorization: str) -> Optional[str]:
        """Parse ``Authorization: Bearer <token>`` and return the raw token.

        Returns ``None`` if the header is absent or malformed.
        """
        prefix = self._config.token_prefix + " "
        if authorization.startswith(prefix):
            return authorization[len(prefix):]
        return None
