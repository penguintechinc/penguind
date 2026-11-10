"""Credential and identity lookups that run before a tenant is known.

These are the only cross-tenant reads in hub-api. Each resolves a bearer secret or an
agent identifier to its owning tenant id, after which every other access goes through
TenantDB. Nothing here returns data beyond the identity columns.
"""

from __future__ import annotations

import uuid
from typing import Any

from penguin_dal import DB, Row
from penguintechinc_utils import get_logger
from sqlalchemy.exc import IntegrityError

_log = get_logger("hub_api.identity")


def _first(rows: Any) -> Row | None:
    """Return the first row of a penguin-dal select result, or None."""
    items = list(rows)
    return items[0] if items else None


def resolve_agent_tenant(db: DB, agent_public_id: uuid.UUID) -> int | None:
    """Return the tenant id owning an agent public_id, or None if no such agent exists."""
    row = _first(db(db.agents.public_id == agent_public_id).select(limitby=(0, 1)))
    return None if row is None else int(row.tenant_id)


def resolve_agent_by_spiffe(db: DB, spiffe_id: str) -> Row | None:
    """Return the single agent row registered under a SPIFFE id, failing closed on ambiguity.

    A SPIFFE id is globally unique (DB constraint); if more than one row ever matches, the
    identity is ambiguous across tenants, so None is returned and the event is logged.
    """
    rows = list(db(db.agents.spiffe_id == spiffe_id).select(limitby=(0, 2)))
    if len(rows) > 1:
        _log.error("ambiguous spiffe_id matches multiple agents; refusing identity")
        return None
    return rows[0] if rows else None


def spiffe_registered(db: DB, spiffe_id: str) -> bool:
    """Return True if any tenant already has an agent registered under ``spiffe_id``."""
    return bool(db(db.agents.spiffe_id == spiffe_id).count())


def is_unique_violation(exc: BaseException) -> bool:
    """Return True if ``exc`` is (or wraps) a database integrity/unique violation."""
    return isinstance(exc, IntegrityError) or isinstance(exc.__cause__, IntegrityError)


def resolve_tenant(db: DB, public_id: uuid.UUID) -> int | None:
    """Return the internal tenant id for a tenant public_id UUID, or None if unknown."""
    row = _first(db(db.tenants.public_id == public_id).select(limitby=(0, 1)))
    return None if row is None else int(row.id)


def ensure_tenant(db: DB, public_id: uuid.UUID) -> int:
    """Return the internal tenant id for ``public_id``, registering the tenant on first sight.

    Only called with a tenant claim from a token that already passed signature, issuer, audience
    and expiry checks, so the identity provider is the authority on which tenants exist.
    """
    existing = resolve_tenant(db, public_id)
    if existing is not None:
        return existing
    try:
        db.tenants.insert(public_id=public_id)
    except Exception as exc:
        if not is_unique_violation(exc):
            raise
    created = resolve_tenant(db, public_id)
    if created is None:
        raise RuntimeError("tenant row missing after insert")
    return created


def tenant_public_id(db: DB, tenant_id: int) -> uuid.UUID:
    """Return the public_id UUID of an internal tenant id; a missing row is a data error."""
    row = _first(db(db.tenants.id == tenant_id).select(limitby=(0, 1)))
    if row is None:
        raise LookupError("tenant not registered")
    return uuid.UUID(str(row.public_id))


def resolve_bootstrap(db: DB, token_hash: str) -> Row | None:
    """Return the bootstrap token row for a sha256 digest of its secret, or None."""
    return _first(db(db.bootstrap_tokens.token_hash == token_hash).select(limitby=(0, 1)))


def resolve_refresh(db: DB, token_hash: str) -> Row | None:
    """Return the refresh token row for a sha256 digest of its secret, or None."""
    return _first(db(db.refresh_tokens.hash == token_hash).select(limitby=(0, 1)))
