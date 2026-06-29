"""Pydantic schemas for JWT payloads and token responses."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel


class TokenPayload(BaseModel):
    """Decoded JWT payload (both access and refresh tokens share this shape)."""

    sub: str
    type: Literal["access", "refresh"]
    iat: datetime
    exp: datetime
    role: str | None = None
    jti: str | None = None
    extra: dict[str, Any] = {}


class TokenPair(BaseModel):
    """Issued pair of access + refresh tokens."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until the access token expires


class AccessTokenResponse(BaseModel):
    """Issued access token only (used by the /refresh endpoint)."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
