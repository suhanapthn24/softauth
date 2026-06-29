"""SQLAlchemy session factory.

Wraps engine + SessionLocal into a single injectable object.
No framework imports.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from softauth.database.models import Base


class DatabaseSession:
    """Thin wrapper around an SQLAlchemy engine and session factory.

    ``expire_on_commit=False`` is intentional: detached User objects returned
    from session contexts remain usable (all columns already loaded in memory).

    For ``sqlite:///:memory:``, ``StaticPool`` is used so all connections share
    the same in-memory database — essential for testing in threaded environments
    such as FastAPI's TestClient.
    """

    def __init__(self, database_url: str) -> None:
        connect_args: dict[str, object] = {}
        kwargs: dict[str, object] = {}

        if database_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
            if ":memory:" in database_url:
                kwargs["poolclass"] = StaticPool

        self._engine = create_engine(database_url, connect_args=connect_args, **kwargs)  # type: ignore[arg-type]
        self._factory = sessionmaker(
            bind=self._engine,
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
        )

    def create_tables(self) -> None:
        """Create all softauth tables (idempotent)."""
        Base.metadata.create_all(self._engine)

    def drop_tables(self) -> None:
        """Drop all softauth tables.  Useful in tests."""
        Base.metadata.drop_all(self._engine)

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """Yield a transactional session; commit on success, rollback on error."""
        s = self._factory()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()
