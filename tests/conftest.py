"""Shared pytest fixtures."""

from __future__ import annotations

import pytest
from softauth import SoftAuth


def pytest_configure(config: pytest.Config) -> None:
    """Configure Django settings once, before any test collection runs."""
    try:
        import django
        from django.conf import settings as django_settings
        if not django_settings.configured:
            django_settings.configure(USE_TZ=True)
            django.setup()
    except ImportError:
        pass
from softauth.core.config import SoftAuthConfig
from softauth.database.session import DatabaseSession
from softauth.jwt.handler import JWTHandler
from softauth.security.password import PasswordHandler

_IN_MEMORY = "sqlite:///:memory:"
_SECRET = "test-secret-key-min-16-chars"


@pytest.fixture(scope="session")
def config() -> SoftAuthConfig:
    return SoftAuthConfig(
        secret_key=_SECRET,
        framework="fastapi",
        database_url=_IN_MEMORY,
    )


@pytest.fixture(scope="session")
def jwt_handler(config: SoftAuthConfig) -> JWTHandler:
    return JWTHandler(config)


@pytest.fixture(scope="session")
def password_handler() -> PasswordHandler:
    return PasswordHandler()


@pytest.fixture
def db() -> DatabaseSession:
    """Fresh in-memory DB per test."""
    db = DatabaseSession(_IN_MEMORY)
    db.create_tables()
    yield db
    db.drop_tables()


@pytest.fixture
def fastapi_auth() -> SoftAuth:
    auth = SoftAuth(
        secret_key=_SECRET,
        framework="fastapi",
        database_url=_IN_MEMORY,
    )
    auth.init_db()
    return auth


@pytest.fixture
def flask_auth() -> SoftAuth:
    auth = SoftAuth(
        secret_key=_SECRET,
        framework="flask",
        database_url=_IN_MEMORY,
    )
    auth.init_db()
    return auth


@pytest.fixture
def django_auth() -> SoftAuth:
    auth = SoftAuth(
        secret_key=_SECRET,
        framework="django",
        database_url=_IN_MEMORY,
    )
    auth.init_db()
    urlpatterns: list = []
    auth.init_app(urlpatterns)  # on_startup() configures middleware singleton
    return auth
