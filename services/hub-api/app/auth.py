"""Credential verification: OIDC bearer tokens for admins, machine JWTs for agents.

Admin tokens are verified against the OIDC issuer's JWKS (resource-server role, no client
secret needed). Agent machine JWTs are signed by the hub itself with HS256 from
HUB_AGENT_JWT_SECRET; the hub never holds module-signing keys.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx
import jwt
from jwt import PyJWKClient

AGENT_JWT_ISSUER = "hub-api"
AGENT_JWT_AUDIENCE = "hub-api-agent"
_OIDC_ALGORITHMS = ["RS256", "ES256"]
_AGENT_ALGORITHM = "HS256"


class TokenInvalidError(Exception):
    """Raised when a bearer token fails signature, claim or expiry checks."""


def parse_scopes(raw: Any) -> frozenset[str]:
    """Normalise a ``scope`` claim (space-separated string or list) into a set."""
    if raw is None:
        return frozenset()
    if isinstance(raw, str):
        return frozenset(part for part in raw.split() if part)
    if isinstance(raw, list) and all(isinstance(s, str) for s in raw):
        return frozenset(raw)
    raise TokenInvalidError("scope claim must be a string or list of strings")


class TokenVerifier(Protocol):
    """Anything that turns an admin bearer token into its verified claims."""

    async def verify(self, token: str) -> Mapping[str, Any]:
        """Return verified claims or raise TokenInvalidError."""
        ...


@dataclass(slots=True)
class OidcVerifier:
    """Verify OIDC access tokens with the issuer's JWKS (discovered once, lazily)."""

    issuer: str
    audience: str
    _jwks: PyJWKClient | None = field(default=None, init=False)

    def _client(self) -> PyJWKClient:
        """Return the JWKS client, discovering jwks_uri from the issuer on first use."""
        if self._jwks is None:
            meta = httpx.get(f"{self.issuer}/.well-known/openid-configuration", timeout=5.0)
            meta.raise_for_status()
            self._jwks = PyJWKClient(str(meta.json()["jwks_uri"]), cache_keys=True)
        return self._jwks

    def _verify_sync(self, token: str) -> Mapping[str, Any]:
        """Blocking verification; run in a worker thread by ``verify``."""
        try:
            key = self._client().get_signing_key_from_jwt(token).key
            claims: Mapping[str, Any] = jwt.decode(
                token,
                key,
                algorithms=_OIDC_ALGORITHMS,
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except (jwt.PyJWTError, httpx.HTTPError, KeyError, ValueError) as exc:
            raise TokenInvalidError(str(exc)) from exc
        return claims

    async def verify(self, token: str) -> Mapping[str, Any]:
        """Verify an admin token without blocking the event loop."""
        return await asyncio.to_thread(self._verify_sync, token)


@dataclass(slots=True, frozen=True)
class AgentClaims:
    """Verified machine-JWT claims for one agent."""

    agent_public_id: uuid.UUID
    tenant: int
    scopes: frozenset[str]


def issue_agent_token(
    secret: str,
    agent_public_id: uuid.UUID,
    tenant: int,
    scopes: frozenset[str],
    ttl_s: int,
) -> str:
    """Sign a machine JWT (<=1h) for an agent: sub=agent public_id, tenant, scope."""
    now = dt.datetime.now(dt.UTC)
    payload = {
        "iss": AGENT_JWT_ISSUER,
        "aud": AGENT_JWT_AUDIENCE,
        "sub": str(agent_public_id),
        "tenant": str(tenant),
        "scope": " ".join(sorted(scopes)),
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(seconds=ttl_s)).timestamp()),
    }
    return jwt.encode(payload, secret, algorithm=_AGENT_ALGORITHM)


def verify_agent_token(secret: str, token: str) -> AgentClaims:
    """Verify a machine JWT's signature, issuer, audience and expiry; return its claims."""
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=[_AGENT_ALGORITHM],
            audience=AGENT_JWT_AUDIENCE,
            issuer=AGENT_JWT_ISSUER,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "tenant"]},
        )
        tenant_raw = str(claims["tenant"])
        if not tenant_raw.isdigit() or int(tenant_raw) <= 0:
            raise TokenInvalidError("tenant claim must be a positive integer")
        return AgentClaims(
            agent_public_id=uuid.UUID(str(claims["sub"])),
            tenant=int(tenant_raw),
            scopes=parse_scopes(claims.get("scope")),
        )
    except (jwt.PyJWTError, ValueError, KeyError) as exc:
        raise TokenInvalidError(str(exc)) from exc


def tenant_from_admin_claims(claims: Mapping[str, Any]) -> int:
    """Return the positive integer tenant id from an admin token; missing or invalid = error."""
    raw = claims.get("tenant")
    if raw is None or raw == "":
        raise TokenInvalidError("tenant claim required")
    text = str(raw)
    if not text.isdigit() or int(text) <= 0:
        raise TokenInvalidError("tenant claim must be a positive integer")
    return int(text)
