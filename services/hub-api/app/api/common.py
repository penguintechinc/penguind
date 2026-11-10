"""Shared handler helpers: thread offload, pagination args, actor and tenant access."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from quart import g, request

from app.context import hub
from app.models import TenantDB
from app.problems import bad_request

MAX_LIMIT = 200
DEFAULT_LIMIT = 50


async def run[T](fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run a blocking data-layer function in a worker thread."""
    return await asyncio.to_thread(fn, *args, **kwargs)


def limit_arg() -> int:
    """Return the ``limit`` query parameter (1..200, default 50); anything else is 400."""
    raw = request.args.get("limit", str(DEFAULT_LIMIT))
    if not raw.isdigit() or not 1 <= int(raw) <= MAX_LIMIT:
        raise bad_request("limit must be an integer between 1 and 200")
    return int(raw)


def cursor_arg() -> str | None:
    """Return the opaque ``cursor`` query parameter (max 512 chars) or None."""
    raw = request.args.get("cursor")
    if raw is not None and len(raw) > 512:
        raise bad_request("cursor too long")
    return raw or None


def admin_tdb() -> TenantDB:
    """Return a TenantDB bound to the authenticated admin's tenant."""
    principal = g.admin
    return TenantDB(hub().db, principal.tenant_id)


def actor() -> str:
    """Return the OIDC subject of the authenticated admin (audit actor)."""
    subject: str = g.admin.subject
    return subject


def with_headers[T](value: T, headers: dict[str, str]) -> T:
    """Attach response headers, applied in the after-request hook.

    quart-schema rewrites custom header names (ETag becomes e-tag) on validated responses, so
    headers are never returned as a tuple.
    """
    g.extra_headers = {**getattr(g, "extra_headers", {}), **headers}
    return value


def with_etag[T](value: T, etag: str) -> T:
    """Attach an ETag header to this response (see with_headers)."""
    return with_headers(value, {"ETag": etag})


def if_match() -> str | None:
    """Return the If-Match header value, if any."""
    return request.headers.get("If-Match")
