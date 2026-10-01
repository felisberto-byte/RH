from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import DateTime, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """DateTime sempre "aware" em UTC, igual no PostgreSQL e no SQLite (que
    devolve datetimes ingênuos). Evita conversões erradas de fuso em evidências."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        path = url.removeprefix("sqlite:///")
        if path and path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(url, connect_args={"check_same_thread": False})

        # Contorno documentado do SQLAlchemy para SAVEPOINT funcionar no pysqlite.
        @event.listens_for(engine, "connect")
        def _on_connect(dbapi_conn, _record):  # pragma: no cover - trivial
            dbapi_conn.isolation_level = None
            dbapi_conn.execute("PRAGMA foreign_keys=ON")
            dbapi_conn.execute("PRAGMA busy_timeout=5000")
            dbapi_conn.execute("PRAGMA journal_mode=WAL")

        @event.listens_for(engine, "begin")
        def _on_begin(conn):  # pragma: no cover - trivial
            conn.exec_driver_sql("BEGIN")

        return engine
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5)


class Database:
    def __init__(self, url: str):
        self.engine = make_engine(url)
        self.sessionmaker = sessionmaker(self.engine, expire_on_commit=False)

    def session(self) -> Iterator[Session]:
        with self.sessionmaker() as s:
            yield s

    def create_all(self) -> None:
        from portal import models  # noqa: F401  (registra os modelos)

        Base.metadata.create_all(self.engine)
