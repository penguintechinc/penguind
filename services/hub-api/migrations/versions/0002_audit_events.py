"""audit events for admin writes

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-10 18:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create audit_events (tenant-scoped, int action codes, actor = opaque OIDC sub)."""
    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("action", sa.SmallInteger(), nullable=False),
        sa.Column("target_type", sa.SmallInteger(), nullable=False),
        sa.Column("target_public_id", sa.Uuid(), nullable=True),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
        sa.UniqueConstraint("public_id", name=op.f("uq_audit_events_public_id")),
    )
    op.create_index(op.f("ix_audit_events_tenant_id"), "audit_events", ["tenant_id"])


def downgrade() -> None:
    """Drop audit_events."""
    op.drop_index(op.f("ix_audit_events_tenant_id"), table_name="audit_events")
    op.drop_table("audit_events")
