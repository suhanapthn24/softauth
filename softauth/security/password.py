"""Password hashing utilities.

This module has zero framework imports and no side-effects on import.
It wraps passlib's bcrypt context so the rest of the library never handles
plaintext passwords directly.
"""

from __future__ import annotations

from passlib.context import CryptContext


class PasswordHandler:
    """bcrypt-backed password hashing and verification.

    A single CryptContext is created per instance and is thread-safe.
    """

    def __init__(self) -> None:
        self._ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def hash_password(self, plain: str) -> str:
        """Return a bcrypt hash of *plain*.  Each call produces a unique salt."""
        return self._ctx.hash(plain)

    def verify_password(self, plain: str, hashed: str) -> bool:
        """Return ``True`` if *plain* matches the stored *hashed* value."""
        return self._ctx.verify(plain, hashed)

    def needs_rehash(self, hashed: str) -> bool:
        """Return ``True`` if *hashed* was produced with outdated parameters."""
        return self._ctx.needs_update(hashed)
