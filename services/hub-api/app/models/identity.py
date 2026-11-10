"""Credential and identity lookups that run before a tenant is known.

These are the only cross-tenant reads in hub-api. Each resolves a bearer secret or an
agent identifier to its owning tenant id, after which every other access goes through
TenantDB. Nothing here returns data beyond the identity columns.
"""

from __future__ import annotations

import uuid
from typing import Any

from penguin_dal import DB, Row


def _first(rows: Any) -> Row | None:
    """Return the first row of a penguin-dal select result, or None."""
    items = list(rows)
    return items[0] if items else None


def resolve_agent_tenant(db: DB, agent_public_id: uuid.UUID) -> int | None:
    """Return the tenant id owning an agent public_id, or None if no such agent exists."""
    row = _first(db(db.agents.public_id == agent_public_id).select(limitby=(0, 1)))
    return None if row is None else int(row.tenant_id)


def resolve_agent_by_spiffe(db: DB, spiffe_id: str) -> Row | None:
    """Return the agent row registered under a SPIFFE id (tenant_id, public_id, id)."""
    return _first(db(db.agents.spiffe_id == spiffe_id).select(limitby=(0, 1)))


def resolve_bootstrap(db: DB, token_hash: str) -> Row | None:
    """Return the bootstrap token row for a sha256 digest of its secret, or None."""
    return _first(db(db.bootstrap_tokens.token_hash == token_hash).select(limitby=(0, 1)))


def resolve_refresh(db: DB, token_hash: str) -> Row | None:
    """Return the refresh token row for a sha256 digest of its secret, or None."""
    return _first(db(db.refresh_tokens.hash == token_hash).select(limitby=(0, 1)))
