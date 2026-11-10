"""Tenant isolation, identity columns and enum round-trip against real Postgres."""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import IntEnum

import pytest
from alembic import command
from alembic.config import Config
from penguin_dal import DB, Row
from sqlalchemy import Uuid
from sqlalchemy.exc import IntegrityError

from app.models import (
    AgentStatus,
    ApplyResult,
    FlagScope,
    ModuleStatus,
    Platform,
    TenantDB,
    TenantViolationError,
)
from app.models.schema import ENTITY_TABLES, metadata
from tests.models.factories import SUB, agent, group, module


def test_every_table_has_identity_columns() -> None:
    """Every entity table has BIGINT id, unique UUID public_id, tenant_id and timestamps."""
    assert len(ENTITY_TABLES) == 10
    for name in ENTITY_TABLES:
        cols = metadata.tables[name].c
        assert cols.id.primary_key and str(cols.id.type) == "BIGINT", name
        assert isinstance(cols.public_id.type, Uuid) and cols.public_id.unique, name
        assert not cols.tenant_id.nullable, name
        assert {"created_at", "updated_at"} <= set(cols.keys()), name


def test_insert_stamps_identity(tdb: TenantDB) -> None:
    """Insert assigns a BIGINT id, a UUID public_id, the tenant and timestamps."""
    row = group(tdb, "g")
    assert isinstance(row.id, int) and isinstance(row.public_id, uuid.UUID)
    assert row.tenant_id == tdb.tenant_id
    assert row.created_at is not None and row.updated_at is not None
    assert row.created_by == SUB


def test_reads_are_tenant_isolated(tdb: TenantDB, other: TenantDB) -> None:
    """A tenant can never see, count, update or delete another tenant's rows."""
    mine = group(tdb, "same-name")
    theirs = group(other, "same-name")
    assert other.get("groups", mine.public_id) is None
    assert [r.public_id for r in tdb.select("groups")] == [mine.public_id]
    assert other.count("groups") == 1
    assert other.update("groups", mine.public_id, description="x") == 0
    assert other.delete("groups", other.field("groups", "id") == mine.id) == 0
    assert tdb.get("groups", mine.public_id) is not None
    assert tdb.get_by_id("groups", theirs.id) is None


def test_cross_tenant_fk_rejected(tdb: TenantDB, other: TenantDB) -> None:
    """Linking to another tenant's row is rejected at the data layer."""
    g = group(tdb, "g")
    foreign_agent = agent(other)
    with pytest.raises(TenantViolationError, match="agent_id"):
        tdb.insert("group_members", group_id=g.id, agent_id=foreign_agent.id)
    with pytest.raises(TenantViolationError):
        tdb.update("flags", uuid.uuid4(), group_id=group(other, "x").id)


@pytest.mark.parametrize("col", ["id", "public_id", "tenant_id", "created_at", "updated_at"])
def test_protected_columns_not_writable(tdb: TenantDB, col: str) -> None:
    """Callers cannot set identity, tenant or timestamp columns."""
    with pytest.raises(TenantViolationError, match="protected"):
        tdb.insert("groups", name="g", created_by=SUB, **{col: 1})
    with pytest.raises(TenantViolationError, match="protected"):
        tdb.update("groups", uuid.uuid4(), **{col: 1})


@pytest.mark.parametrize("bad", [0, -1, True, "1", None])
def test_tenant_id_must_be_positive_int(db: DB, bad: object) -> None:
    """A TenantDB cannot be built without a real tenant."""
    with pytest.raises(TenantViolationError):
        TenantDB(db, bad)  # type: ignore[arg-type]


def test_unknown_table_rejected(tdb: TenantDB) -> None:
    """Only schema tables are reachable."""
    with pytest.raises(TenantViolationError, match="unknown table"):
        tdb.select("pg_user")


def test_update_bumps_updated_at(tdb: TenantDB) -> None:
    """Update sets updated_at to now."""
    g = group(tdb, "g")
    assert tdb.update("groups", g.public_id, description="d") == 1
    after = tdb.get("groups", g.public_id)
    assert after is not None and after.description == "d"
    assert after.updated_at >= g.updated_at


def test_unique_constraints(tdb: TenantDB) -> None:
    """Group name per tenant, member pair and module version are unique."""
    g = group(tdb, "g")
    a = agent(tdb)
    tdb.insert("group_members", group_id=g.id, agent_id=a.id)
    with pytest.raises(IntegrityError):
        tdb.insert("group_members", group_id=g.id, agent_id=a.id)
    with pytest.raises(IntegrityError):
        group(tdb, "g")
    module(tdb)
    with pytest.raises(IntegrityError):
        module(tdb)


def test_all_tables_insertable(tdb: TenantDB) -> None:
    """Each remaining table accepts a tenant-scoped row with FK checks passing."""
    g = group(tdb, "g")
    a = agent(tdb)
    mv = module(tdb)
    tdb.insert("group_members", group_id=g.id, agent_id=a.id)
    tdb.insert("group_modules", group_id=g.id, module_version_id=mv.id)
    tdb.insert("flags", key="penguind.x", enabled=True, scope=FlagScope.GROUP, group_id=g.id)
    tdb.insert("flags", key="penguind.y", enabled=False, scope=FlagScope.TENANT, group_id=None)
    tdb.insert(
        "bootstrap_tokens",
        token_hash="$argon2id$h1",  # noqa: S106 - synthetic hash fixture
        group_ids=[str(g.public_id)],
        expires_at=datetime.now(UTC) + timedelta(days=1),
        used_by_agent_id=a.id,
        created_by=SUB,
    )
    tdb.insert("refresh_tokens", agent_id=a.id, hash="h", chain_id=uuid.uuid4())
    tdb.insert("tenant_configs", policy={"limits": {"max_fuel": 5}})
    tdb.insert("audit_events", action=1, target_type=1, target_public_id=g.public_id, actor=SUB)
    assert {t: tdb.count(t) for t in ENTITY_TABLES} == dict.fromkeys(ENTITY_TABLES, 1) | {
        "flags": 2
    }


@pytest.mark.parametrize(
    ("table", "col", "value"),
    [
        ("agents", "status", AgentStatus.REVOKED),
        ("agents", "platform", Platform.WINDOWS),
        ("module_versions", "status", ModuleStatus.YANKED),
        ("flags", "scope", FlagScope.GROUP),
    ],
)
def test_enum_round_trip(tdb: TenantDB, table: str, col: str, value: IntEnum) -> None:
    """Enums persist as int codes and convert back to the same IntEnum member."""
    rows: dict[str, Callable[[TenantDB], Row]] = {"agents": agent, "module_versions": module}
    if table == "flags":
        row = tdb.insert("flags", key="k", enabled=True, scope=FlagScope.TENANT)
    else:
        row = rows[table](tdb)
    tdb.update(table, row.public_id, **{col: value})
    stored = tdb.get(table, row.public_id)
    assert stored is not None
    raw = stored[col]
    assert type(raw) is int and raw == int(value)
    assert type(value)(raw) is value


@pytest.mark.parametrize(
    ("enum", "codes"),
    [
        (AgentStatus, [1, 2, 3]),
        (Platform, [1, 2, 3]),
        (ModuleStatus, [1, 2]),
        (FlagScope, [1, 2]),
        (ApplyResult, [1, 2, 3]),
    ],
)
def test_enum_codes_match_contract(enum: type[IntEnum], codes: list[int]) -> None:
    """Enum code maps match openapi/v1.yaml exactly."""
    assert [int(m) for m in enum] == codes


def test_migration_round_trip(alembic_cfg: Config, db: DB) -> None:
    """Downgrade drops all tables and upgrade restores them."""
    command.downgrade(alembic_cfg, "base")
    command.upgrade(alembic_cfg, "head")
    fresh = DB(alembic_cfg.attributes["url"], pool_size=1)
    try:
        assert set(ENTITY_TABLES) <= set(fresh.tables)
    finally:
        fresh.close()
