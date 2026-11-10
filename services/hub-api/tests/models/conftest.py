"""Model-test fixtures: a fresh tenant per test on the shared session database."""

from itertools import count

import pytest
from penguin_dal import DB

from app.models import TenantDB

_tenants = count(1)


@pytest.fixture
def tdb(db: DB) -> TenantDB:
    """A TenantDB for a tenant id unique to this test."""
    return TenantDB(db, next(_tenants))


@pytest.fixture
def other(db: DB) -> TenantDB:
    """A second, distinct tenant for isolation tests."""
    return TenantDB(db, 100_000 + next(_tenants))
