"""UserRepository — synchronous CRUD over the default User model.

No framework imports.  Accepts an open SQLAlchemy Session and performs
operations within the caller's transaction boundary.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from softauth.core.exceptions import UserAlreadyExistsError
from softauth.database.models import User


class UserRepository:
    """Data-access object for the softauth_users table."""

    def __init__(self, session: Session) -> None:
        self._s = session

    def get_by_id(self, user_id: str) -> Optional[User]:
        return self._s.get(User, user_id)

    def get_by_email(self, email: str) -> Optional[User]:
        return self._s.query(User).filter(User.email == email).first()

    def create(self, email: str, hashed_password: str, role: str = "user") -> User:
        if self.get_by_email(email) is not None:
            raise UserAlreadyExistsError(f"A user with email '{email}' already exists.")
        user = User(email=email, hashed_password=hashed_password, role=role)
        self._s.add(user)
        self._s.flush()  # populate user.id before the context manager commits
        return user

    def update(self, user: User) -> User:
        self._s.add(user)
        return user

    def deactivate(self, user_id: str) -> Optional[User]:
        user = self.get_by_id(user_id)
        if user:
            user.is_active = False
            self._s.add(user)
        return user
