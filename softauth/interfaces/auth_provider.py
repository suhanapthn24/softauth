"""AuthProvider — extension point for OAuth2, SSO, and social login.

Future: GoogleAuthProvider, GitHubAuthProvider, MicrosoftAuthProvider, SAMLProvider.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional


class AuthProvider(ABC):
    """Abstract external authentication provider.

    Implement this to plug in OAuth2 flows, SSO, or any other identity
    provider without touching the core JWT engine.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Stable identifier, e.g. ``"google"``, ``"github"``."""

    @abstractmethod
    async def authenticate(self, credential: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Exchange a provider credential for a normalised user dict.

        Return ``None`` if authentication fails; raise on unexpected errors.
        The returned dict must contain at least ``{"email": str}``.
        """

    @abstractmethod
    async def get_user_info(self, provider_token: str) -> Optional[dict[str, Any]]:
        """Fetch the provider's user-info payload for the given token."""
