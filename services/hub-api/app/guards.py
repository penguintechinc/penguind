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
from app.models.identity import (
    ensure_tenant,
    resolve_agent_by_spiffe,
    resolve_agent_tenant,
    tenant_public_id,
)
from app.mtls import parse_agent_spiffe
from app.problems import forbidden, gone, not_found, rate_limited, unauthorized

F = TypeVar("F", bound=Callable[..., Awaitable[Any]])

AGENT_SCOPES: frozenset[str] = frozenset({"hub:agent:sync", "hub:agent:report"})


@dataclass(slots=True, frozen=True)
class AdminPrincipal:
    """A verified admin caller bound to one tenant."""

    subject: str
    tenant_id: int
    tenant_public_id: uuid.UUID
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
                tenant_pid = tenant_from_admin_claims(claims)
            except TokenInvalidError as exc:
                ctx.telemetry.instruments.auth_failures.add(1, {"plane": "admin"})
                raise forbidden(str(exc)) from exc
            try:
                scopes = parse_scopes(claims.get("scope"))
            except TokenInvalidError as exc:
                raise unauthorized(str(exc)) from exc
            if scope not in scopes:
                raise forbidden(f"scope {scope} required")
            tenant_id = await asyncio.to_thread(ensure_tenant, ctx.db, tenant_pid)
            g.admin = AdminPrincipal(str(claims["sub"]), tenant_id, tenant_pid, scopes)
            return await fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return deco


def _mtls_lookup(db: Any, spiffe_uri: str, trust_domain: str) -> tuple[uuid.UUID, int] | str:
    """Blocking part of mTLS resolution; returns (agent id, tenant id) or a failure reason."""
    parsed = parse_agent_spiffe(spiffe_uri, trust_domain)
    if parsed is None:
        return "malformed"
    row = resolve_agent_by_spiffe(db, spiffe_uri)
    if row is None:
        return "unregistered"
    if tenant_public_id(db, int(row.tenant_id)) != parsed[0]:
        return "tenant_mismatch"
    return uuid.UUID(str(row.public_id)), int(row.tenant_id)


async def _mtls_identity(spiffe_uri: str) -> tuple[uuid.UUID, int]:
    """Resolve a trusted SPIFFE URI to its registered agent; never read an id from the path.

    The URI must have the form ``spiffe://<trust-domain>/tenant/<tenant public_id>/agent/<id>``
    with the configured trust domain, match a registered ``spiffe_id`` exactly, and its tenant
    segment must equal the registered row's tenant. Agent id and tenant come from that row.
    """
    ctx = hub()
    found = await asyncio.to_thread(
        _mtls_lookup, ctx.db, spiffe_uri, ctx.settings.spiffe_trust_domain
    )
    if isinstance(found, str):
        ctx.telemetry.instruments.auth_failures.add(1, {"plane": "agent", "reason": found})
        raise unauthorized("unregistered agent identity")
    return found


async def _agent_identity() -> tuple[
    uuid.UUID | None, uuid.UUID | None, frozenset[str], int | None
]:
    """Return (path-free agent id, JWT-claimed tenant public_id, scopes, mTLS row tenant id).

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
    if jwt_tenant is not None:
        owner_pid = await asyncio.to_thread(tenant_public_id, ctx.db, owner)
        if jwt_tenant != owner_pid:
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
