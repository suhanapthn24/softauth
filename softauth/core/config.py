"""Runtime configuration for SoftAuth.

All fields can be overridden by keyword arguments to ``SoftAuth()``.
Environment variables are picked up automatically when ``from_env()`` is used.
"""

from __future__ import annotations

import os
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


class SoftAuthConfig(BaseModel):
    """Immutable configuration object passed through the entire library.

    Prefer constructing via ``SoftAuth(...)`` rather than directly.
    """

    model_config = {"frozen": True}

    # ── Core security ──────────────────────────────────────────────────────
    secret_key: str = Field(..., min_length=16)
    algorithm: str = Field("HS256")

    # ── Token lifetimes ────────────────────────────────────────────────────
    access_expiry_minutes: int = Field(15, gt=0)
    refresh_expiry_days: int = Field(7, gt=0)

    # ── Framework adapter ──────────────────────────────────────────────────
    # None means "framework-agnostic / manual" — useful for testing or custom
    # adapters.  Built-in values: "fastapi", "flask".  Unknown strings are
    # accepted here so that use_adapter() + framework=None works, and so that
    # typos produce a ConfigurationError in init_app() rather than a Pydantic
    # ValidationError at construction time.
    framework: Optional[str] = None

    # ── Database ───────────────────────────────────────────────────────────
    database_url: str = Field("sqlite:///auth.db")

    # ── Routing ────────────────────────────────────────────────────────────
    auth_prefix: str = Field("/auth")
    token_prefix: str = Field("Bearer")

    # ── Behaviour flags ────────────────────────────────────────────────────
    enable_refresh_tokens: bool = True

    @field_validator("secret_key")
    @classmethod
    def _secret_not_placeholder(cls, v: str) -> str:
        if v.lower() in {"secret", "changeme", "change-me", "your-secret-key"}:
            import warnings
            warnings.warn(
                "SoftAuth secret_key looks like a placeholder. "
                "Use a strong random value in production.",
                stacklevel=2,
            )
        return v

    @classmethod
    def from_env(cls, **overrides: object) -> "SoftAuthConfig":
        """Build config from environment variables, with keyword overrides."""
        env: dict[str, object] = {
            "secret_key": os.environ.get("SOFTAUTH_SECRET", ""),
            "database_url": os.environ.get("SOFTAUTH_DB_URL", "sqlite:///auth.db"),
            "algorithm": os.environ.get("SOFTAUTH_ALGORITHM", "HS256"),
        }
        env.update(overrides)
        return cls(**env)  # type: ignore[arg-type]
