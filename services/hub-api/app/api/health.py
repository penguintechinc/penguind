"""Liveness and readiness probes at the root (unauthenticated, not feature-flagged)."""

from __future__ import annotations

import asyncio
from typing import Any

from quart import Blueprint
from quart_schema import validate_response

from app.context import hub
from app.dto import Health
from app.envelope import envelope, envelope_type
from app.problems import unavailable

bp = Blueprint("health", __name__)


def _db_reachable() -> bool:
    """Return True if the database answers a trivial query (blocking; run in a thread)."""
    try:
        db = hub().db
        list(db(db.tenant_configs.id > 0).select(limitby=(0, 1)))
    except Exception:
        return False
    return True


@bp.get("/healthz")
@validate_response(envelope_type(Health))
async def healthz() -> Any:
    """Liveness: the process is serving requests."""
    return envelope(Health, Health(status="ok"))


@bp.get("/readyz")
@validate_response(envelope_type(Health))
async def readyz() -> Any:
    """Readiness: database and blob store are reachable; otherwise 503."""
    db_ok = await asyncio.to_thread(_db_reachable)
    blob_ok = await hub().blobs.ready()
    if not (db_ok and blob_ok):
        raise unavailable("database or blob store unreachable")
    return envelope(Health, Health(status="ok"))
