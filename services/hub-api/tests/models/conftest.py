"""Real-Postgres fixtures: one container per session, Alembic schema, fresh tenant per test."""

from collections.abc import Iterator
from itertools import count

import pytest
from alembic import command
from alembic.config import Config
from penguin_dal import DB
from testcontainers.postgres import PostgresContainer

from app.models import TenantDB

PG_IMAGE = "postgres:17.6-alpine"
_tenants = count(1)


@pytest.fixture(scope="session")
def pg_url() -> Iterator[str]:
    """Start Postgres and return its URL (container failure fails the session, never skips)."""
    with PostgresContainer(PG_IMAGE, driver="psycopg2") as pg:
        yield pg.get_connection_url()


@pytest.fixture(scope="session")
def alembic_cfg(pg_url: str) -> Config:
    """Return an Alembic config pointed at the test database."""
    cfg = Config("alembic.ini")
    cfg.attributes["url"] = pg_url
    return cfg


@pytest.fixture(scope="session")
def db(pg_url: str, alembic_cfg: Config) -> Iterator[DB]:
    """Migrate to head and return a reflecting penguin-dal DB."""
    command.upgrade(alembic_cfg, "head")
    dal = DB(pg_url, pool_size=2)
    yield dal
    dal.close()


@pytest.fixture
def tdb(db: DB) -> TenantDB:
    """A TenantDB for a tenant id unique to this test."""
    return TenantDB(db, next(_tenants))


@pytest.fixture
def other(db: DB) -> TenantDB:
    """A second, distinct tenant for isolation tests."""
    return TenantDB(db, 100_000 + next(_tenants))
