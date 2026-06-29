"""TokenStore — extension point for token blacklisting and session management.

Future: RedisTokenStore, DatabaseTokenStore, MemcachedTokenStore.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime


class TokenStore(ABC):
    """Pluggable token blacklist / session store.

    The default softauth setup has no blacklist (tokens are stateless).
    Implement this interface and pass the instance to SoftAuth to enable
    logout invalidation, Redis-backed revocation, or audit logging.
    """

    @abstractmethod
    async def blacklist(self, jti: str, expires_at: datetime) -> None:
        """Record a token identifier as revoked.

        ``jti`` is the JWT ID claim.  ``expires_at`` tells the store when
        it is safe to purge the record.
        """

    @abstractmethod
    async def is_blacklisted(self, jti: str) -> bool:
        """Return ``True`` if the token has been revoked."""

    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Remove entries whose ``expires_at`` has passed.

        Returns the number of entries removed.
        """
