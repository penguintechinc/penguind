"""tenants public_id map and global-unique agents.spiffe_id

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-10 20:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

_BACKFILL = (
    "INSERT INTO tenants (id, public_id) OVERRIDING SYSTEM VALUE "
    "SELECT tenant_id, gen_random_uuid() FROM ("
    "SELECT tenant_id FROM tenant_configs UNION "
    "SELECT tenant_id FROM groups UNION "
    "SELECT tenant_id FROM agents UNION "
    "SELECT tenant_id FROM group_members UNION "
    "SELECT tenant_id FROM module_versions UNION "
    "SELECT tenant_id FROM group_modules UNION "
    "SELECT tenant_id FROM flags UNION "
    "SELECT tenant_id FROM bootstrap_tokens UNION "
    "SELECT tenant_id FROM refresh_tokens UNION "
    "SELECT tenant_id FROM audit_events"
    ") AS t"
)


def upgrade() -> None:
    """Create tenants (backfilled from existing tenant_id values) and make spiffe_id global.

    The unique constraint fails the migration loudly if two tenants already registered the
    same SPIFFE id; an operator must resolve that ambiguity before upgrading.
    """
    op.create_table(
        "tenants",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tenants")),
        sa.UniqueConstraint("public_id", name=op.f("uq_tenants_public_id")),
    )
    op.execute(_BACKFILL)
    op.execute(
        "SELECT setval(pg_get_serial_sequence('tenants', 'id'), "
        "COALESCE((SELECT MAX(id) FROM tenants), 0) + 1, false)"
    )
    op.create_unique_constraint(op.f("uq_agents_spiffe_id"), "agents", ["spiffe_id"])


def downgrade() -> None:
    """Drop the global SPIFFE uniqueness and the tenants map."""
    op.drop_constraint(op.f("uq_agents_spiffe_id"), "agents", type_="unique")
    op.drop_table("tenants")
