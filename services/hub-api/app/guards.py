"""Request guards: feature flags, rate limits, admin/agent authentication, tenant and scope checks.

Order for admin routes: flag -> bearer verify (401) -> tenant claim (403) -> scope (403).
Order for agent routes: flag -> identity (mTLS or JWT) -> tenant match (403) -> revoked (410)
-> scope (403). Every check runs before the handler body touches data.
"""

from __future__ import annotations

import asyncio
import functools
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from penguin_dal import Row
from quart import g, request

from app.auth import (
    TokenInvalidError,
    parse_scopes,
    tenant_from_admin_claims,
    verify_agent_token,
)
from app.context import hub
from app.models import AgentStatus, TenantDB
from app.models.identity import resolve_agent_by_spiffe, resolve_agent_tenant
from app.problems import forbidden, gone, not_found, rate_limited, unauthorized

F = TypeVar("F", bound=Callable[..., Awaitable[Any]])

AGENT_SCOPES: frozenset[str] = frozenset({"hub:agent:sync", "hub:agent:report"})


@dataclass(slots=True, frozen=True)
class AdminPrincipal:
    """A verified admin caller bound to one tenant."""

    subject: str
    tenant_id: int
    scopes: frozenset[str]


@dataclass(slots=True)
class AgentPrincipal:
    """A verified agent caller: its tenant-bound DB view and its agent row."""

    tdb: TenantDB
    agent: Row
    scopes: frozenset[str]


def bearer_token() -> str | None:
    """Return the bearer token from the Authorization header, or None."""
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def require_flag(key: str) -> Callable[[F], F]:
    """Return 404 unless PostHog flag ``key`` is ON for this request's tenant context."""

    def deco(fn: F) -> F:
        """Wrap the handler with the flag check."""

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            """Reject with 404 while the flag is OFF (feature hidden, not forbidden)."""
            if not hub().flags.enabled(key, "hub-api"):
                raise not_found("route")
            return await fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return deco


def rate_limit(bucket: str, key_fn: Callable[[], str] | None = None) -> Callable[[F], F]:
    """Return 429 (with Retry-After) once a key exceeds its per-minute budget."""

    def deco(fn: F) -> F:
        """Wrap the handler with the limiter."""

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            """Count the hit; reject when the window is full."""
            key = key_fn() if key_fn is not None else str(request.remote_addr or "unknown")
            retry = hub().limiter.hit(f"{bucket}:{key}")
            if retry is not None:
                raise rate_limited(retry)
            return await fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return deco


def require_admin(scope: str) -> Callable[[F], F]:
    """Authenticate an admin OIDC bearer, enforce the tenant claim, then require ``scope``."""

    def deco(fn: F) -> F:
        """Wrap the handler with admin authentication."""

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            """Verify the token, then tenant, then scope; store the principal on ``g``."""
            ctx = hub()
            token = bearer_token()
            if token is None:
                raise unauthorized()
            try:
                claims = await ctx.verifier.verify(token)
            except TokenInvalidError as exc:
                ctx.telemetry.instruments.auth_failures.add(1, {"plane": "admin"})
                raise unauthorized(str(exc)) from exc
            try:
                tenant_id = tenant_from_admin_claims(claims)
            except TokenInvalidError as exc:
                ctx.telemetry.instruments.auth_failures.add(1, {"plane": "admin"})
                raise forbidden(str(exc)) from exc
            try:
                scopes = parse_scopes(claims.get("scope"))
            except TokenInvalidError as exc:
                raise unauthorized(str(exc)) from exc
            if scope not in scopes:
                raise forbidden(f"scope {scope} required")
            g.admin = AdminPrincipal(str(claims["sub"]), tenant_id, scopes)
            return await fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return deco


async def _mtls_identity(spiffe_uri: str) -> tuple[uuid.UUID, int]:
    """Resolve a trusted SPIFFE URI to its registered agent; never read an id from the path.

    The URI must match a registered ``spiffe_id`` exactly; agent id and tenant come from that row.
    """
    ctx = hub()
    row = await asyncio.to_thread(resolve_agent_by_spiffe, ctx.db, spiffe_uri)
    if row is None:
        ctx.telemetry.instruments.auth_failures.add(1, {"plane": "agent", "reason": "unregistered"})
        raise unauthorized("unregistered agent identity")
    return uuid.UUID(str(row.public_id)), int(row.tenant_id)


async def _agent_identity() -> tuple[uuid.UUID | None, int | None, frozenset[str], int | None]:
    """Return (path-free agent id, JWT-claimed tenant, scopes, mTLS row tenant).

    Exactly one identity source is used: a trusted SPIFFE URI (mTLS) wins over a bearer JWT.
    """
    spiffe_uri = g.get("forwarded_spiffe")
    if spiffe_uri is not None:
        pid, row_tenant = await _mtls_identity(spiffe_uri)
        return pid, None, AGENT_SCOPES, row_tenant
    token = bearer_token()
    if token is None:
        raise unauthorized()
    try:
        claims = await asyncio.to_thread(verify_agent_token, hub().settings.agent_jwt_secret, token)
    except TokenInvalidError as exc:
        hub().telemetry.instruments.auth_failures.add(1, {"plane": "agent"})
        raise unauthorized(str(exc)) from exc
    return claims.agent_public_id, claims.tenant, claims.scopes, None


async def authenticate_agent(scope: str) -> AgentPrincipal:
    """Resolve the calling agent, check tenant match, revocation and ``scope``."""
    ctx = hub()
    agent_pid, jwt_tenant, scopes, row_tenant = await _agent_identity()
    if agent_pid is None:
        raise unauthorized("unknown agent")
    owner = row_tenant
    if owner is None:
        owner = await asyncio.to_thread(resolve_agent_tenant, ctx.db, agent_pid)
    if owner is None:
        raise unauthorized("unknown agent")
    if jwt_tenant is not None and jwt_tenant != owner:
        raise forbidden("tenant claim does not match agent")
    tdb = TenantDB(ctx.db, owner)
    agent = await asyncio.to_thread(tdb.get, "agents", agent_pid)
    if agent is None:
        raise unauthorized("unknown agent")
    if int(agent.status) == AgentStatus.REVOKED:
        raise gone()
    if scope not in scopes:
        raise forbidden(f"scope {scope} required")
    return AgentPrincipal(tdb, agent, scopes)


def require_agent(scope: str) -> Callable[[F], F]:
    """Authenticate an agent (mTLS or machine JWT) and require ``scope``."""

    def deco(fn: F) -> F:
        """Wrap the handler with agent authentication."""

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            """Run authenticate_agent and pass the principal into the handler via ``g``."""
            g.agent = await authenticate_agent(scope)
            return await fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return deco
