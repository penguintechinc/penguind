"""SQLAlchemy Core schema for hub-api, the single source for Alembic and penguin-dal.

Every table carries a BIGINT identity PK, a unique public_id UUID, a tenant_id and
created_at/updated_at. No PII: actors are opaque OIDC subs, agents are UUIDs.
"""

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    MetaData,
    SmallInteger,
    String,
    Table,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB

metadata = MetaData(
    naming_convention={
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }
)


def _base_columns() -> list[Column[object]]:
    """Return the identity/tenant/timestamp columns shared by every entity table."""
    return [
        Column("id", BigInteger, Identity(always=True), primary_key=True),
        Column("public_id", Uuid, nullable=False, unique=True),
        Column("tenant_id", BigInteger, nullable=False, index=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    ]


def _fk(name: str, target: str, *, nullable: bool = False) -> Column[object]:
    """Return a BIGINT FK column to ``target.id`` with cascade delete."""
    return Column(
        name,
        BigInteger,
        ForeignKey(f"{target}.id", ondelete="CASCADE"),
        nullable=nullable,
        index=True,
    )


tenant_configs = Table(
    "tenant_configs",
    metadata,
    *_base_columns(),
    Column("policy", JSONB, nullable=False, server_default="{}"),
    UniqueConstraint("tenant_id", name="uq_tenant_configs_tenant"),
)

groups = Table(
    "groups",
    metadata,
    *_base_columns(),
    Column("name", String(128), nullable=False),
    Column("description", String(1024), nullable=False, server_default=""),
    Column("policy", JSONB, nullable=False, server_default="{}"),
    Column("created_by", String(255), nullable=False),
    UniqueConstraint("tenant_id", "name", name="uq_groups_tenant_name"),
)

agents = Table(
    "agents",
    metadata,
    *_base_columns(),
    Column("status", SmallInteger, nullable=False),
    Column("platform", SmallInteger, nullable=False),
    Column("agent_version", String(64), nullable=False),
    Column("spiffe_id", String(512), nullable=True),
    Column("override", JSONB, nullable=True),
    Column("last_seen_at", DateTime(timezone=True), nullable=True),
    Column("applied_etag", String(128), nullable=True),
    Column("last_report", JSONB, nullable=True),
)

group_members = Table(
    "group_members",
    metadata,
    *_base_columns(),
    _fk("group_id", "groups"),
    _fk("agent_id", "agents"),
    UniqueConstraint("group_id", "agent_id", name="uq_group_members_pair"),
)

module_versions = Table(
    "module_versions",
    metadata,
    *_base_columns(),
    Column("module_id", String(128), nullable=False),
    Column("version", String(64), nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("signature", String(4096), nullable=False),
    Column("size_bytes", BigInteger, nullable=False),
    Column("blob_key", String(1024), nullable=False),
    Column("status", SmallInteger, nullable=False),
    Column("created_by", String(255), nullable=False),
    UniqueConstraint("tenant_id", "module_id", "version", name="uq_module_versions_tmv"),
)

group_modules = Table(
    "group_modules",
    metadata,
    *_base_columns(),
    _fk("group_id", "groups"),
    _fk("module_version_id", "module_versions"),
    UniqueConstraint("group_id", "module_version_id", name="uq_group_modules_pair"),
)

flags = Table(
    "flags",
    metadata,
    *_base_columns(),
    Column("key", String(128), nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("scope", SmallInteger, nullable=False),
    _fk("group_id", "groups", nullable=True),
    Index("ix_flags_tenant_key", "tenant_id", "key"),
)

bootstrap_tokens = Table(
    "bootstrap_tokens",
    metadata,
    *_base_columns(),
    Column("token_hash", String(255), nullable=False, unique=True),
    Column("group_ids", JSONB, nullable=False, server_default="[]"),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    _fk("used_by_agent_id", "agents", nullable=True),
    Column("created_by", String(255), nullable=False),
)

refresh_tokens = Table(
    "refresh_tokens",
    metadata,
    *_base_columns(),
    _fk("agent_id", "agents"),
    Column("hash", String(255), nullable=False, unique=True),
    Column("chain_id", Uuid, nullable=False, index=True),
    Column("rotated_at", DateTime(timezone=True), nullable=True),
    Column("revoked_at", DateTime(timezone=True), nullable=True),
)

ENTITY_TABLES: tuple[str, ...] = tuple(metadata.tables)
