"""UserStore — extension point for custom identity backends.

Future: LDAPUserStore, ExternalAPIUserStore, multi-tenant stores.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional


class UserStore(ABC):
    """Pluggable user storage backend.

    The built-in implementation persists to the SQLAlchemy database configured
    in SoftAuthConfig.  Override to delegate to an external directory, a
    microservice, or a multi-tenant data model.
    """

    @abstractmethod
    async def get_by_id(self, user_id: str) -> Optional[dict[str, Any]]:
        """Return a user dict or ``None`` if not found."""

    @abstractmethod
    async def get_by_email(self, email: str) -> Optional[dict[str, Any]]:
        """Return a user dict or ``None`` if not found."""

    @abstractmethod
    async def create(
        self,
        email: str,
        hashed_password: str,
        role: str = "user",
    ) -> dict[str, Any]:
        """Persist a new user and return the saved dict (including ``id``)."""

    @abstractmethod
    async def update(self, user_id: str, **fields: Any) -> Optional[dict[str, Any]]:
        """Update arbitrary user fields and return the updated dict."""
