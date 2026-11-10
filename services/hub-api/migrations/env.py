"""Alembic environment for hub-api; DB URL from HUB_DB_MIGRATE_URL (migration account only)."""

import os

from alembic import context
from sqlalchemy import create_engine, pool

from app.models.schema import metadata

config = context.config


def _url() -> str:
    """Return the migration DB URL from config attributes or the environment (fail loudly)."""
    url = config.attributes.get("url") or os.environ.get("HUB_DB_MIGRATE_URL")
    if not url:
        raise RuntimeError("HUB_DB_MIGRATE_URL is not set")
    return str(url)


def run_migrations_offline() -> None:
    """Emit SQL for the migration chain without connecting."""
    context.configure(url=_url(), target_metadata=metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply the migration chain against a live connection."""
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
