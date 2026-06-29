"""Database layer tests — models, session, repository."""

from __future__ import annotations

import pytest

from softauth.core.exceptions import UserAlreadyExistsError
from softauth.database.models import User
from softauth.database.repository import UserRepository
from softauth.database.session import DatabaseSession


@pytest.fixture
def repo(db: DatabaseSession):
    with db.session() as s:
        yield UserRepository(s)


class TestUserModel:
    def test_to_dict_keys(self, db: DatabaseSession) -> None:
        with db.session() as s:
            repo = UserRepository(s)
            user = repo.create(email="a@b.com", hashed_password="hashed")
            d = user.to_dict()
        assert set(d) == {"id", "email", "is_active", "role", "created_at", "updated_at"}

    def test_default_role_is_user(self, db: DatabaseSession) -> None:
        with db.session() as s:
            user = UserRepository(s).create("role@test.com", "h")
        assert user.role == "user"

    def test_default_active(self, db: DatabaseSession) -> None:
        with db.session() as s:
            user = UserRepository(s).create("active@test.com", "h")
        assert user.is_active is True


class TestUserRepository:
    def test_create_assigns_id(self, db: DatabaseSession) -> None:
        with db.session() as s:
            user = UserRepository(s).create("id@test.com", "hash")
        assert user.id and len(user.id) == 36

    def test_get_by_id(self, db: DatabaseSession) -> None:
        with db.session() as s:
            created = UserRepository(s).create("byid@test.com", "h")
            uid = created.id
        with db.session() as s:
            found = UserRepository(s).get_by_id(uid)
        assert found is not None and found.email == "byid@test.com"

    def test_get_by_email(self, db: DatabaseSession) -> None:
        email = "byemail@test.com"
        with db.session() as s:
            UserRepository(s).create(email, "h")
        with db.session() as s:
            found = UserRepository(s).get_by_email(email)
        assert found is not None

    def test_get_by_email_missing_returns_none(self, db: DatabaseSession) -> None:
        with db.session() as s:
            assert UserRepository(s).get_by_email("missing@test.com") is None

    def test_duplicate_email_raises(self, db: DatabaseSession) -> None:
        with db.session() as s:
            UserRepository(s).create("dup@test.com", "h")
        with pytest.raises(UserAlreadyExistsError):
            with db.session() as s:
                UserRepository(s).create("dup@test.com", "h")

    def test_deactivate(self, db: DatabaseSession) -> None:
        with db.session() as s:
            user = UserRepository(s).create("deact@test.com", "h")
            uid = user.id
        with db.session() as s:
            UserRepository(s).deactivate(uid)
        with db.session() as s:
            user = UserRepository(s).get_by_id(uid)
        assert user is not None and user.is_active is False

    def test_custom_role(self, db: DatabaseSession) -> None:
        with db.session() as s:
            user = UserRepository(s).create("admin@test.com", "h", role="admin")
        assert user.role == "admin"
