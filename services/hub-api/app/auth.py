"""Credential verification: OIDC bearer tokens for admins, machine JWTs for agents.

Admin tokens are verified by penguin-aaa (OIDC relying party, issuer JWKS). Agent machine JWTs
are signed and verified by the hub itself with HS256 from HUB_AGENT_JWT_SECRET, because
penguin-aaa's verifiers are asymmetric-only and its provider needs a managed keystore; the
hub never holds module-signing keys. The ``tenant`` claim is always the tenant public_id UUID.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import jwt
from penguin_aaa.authn import OIDCRelyingParty, OIDCRPConfig
from pydantic import ValidationError

AGENT_JWT_ISSUER = "hub-api"
AGENT_JWT_AUDIENCE = "hub-api-agent"
_OIDC_ALGORITHMS = ["RS256", "ES256"]
_AGENT_ALGORITHM = "HS256"
# The hub is a resource server: it never runs the authorization-code flow, so these two
# penguin-aaa config fields are required by the library but unused here.
_UNUSED_RP_SECRET = "unused-resource-server"  # noqa: S105 # nosec B105 - placeholder, not a secret
_UNUSED_RP_REDIRECT = "https://localhost/unused"


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


def parse_tenant_claim(raw: Any) -> uuid.UUID:
    """Return the tenant public_id UUID from a ``tenant`` claim; anything else is invalid.

    Only the canonical lowercase hyphenated form is accepted so one tenant has one spelling.
    """
    if raw is None or raw == "":
        raise TokenInvalidError("tenant claim required")
    text = str(raw)
    try:
        tenant = uuid.UUID(text)
    except ValueError as exc:
        raise TokenInvalidError("tenant claim must be a tenant public_id UUID") from exc
    if str(tenant) != text:
        raise TokenInvalidError("tenant claim must be a canonical lowercase UUID")
    return tenant


class TokenVerifier(Protocol):
    """Anything that turns an admin bearer token into its verified claims."""

    async def verify(self, token: str) -> Mapping[str, Any]:
        """Return verified claims or raise TokenInvalidError."""
        ...


class OidcVerifier:
    """Verify admin OIDC access tokens with penguin-aaa's OIDC relying party.

    penguin-aaa discovers the issuer's JWKS, checks signature, issuer, audience, expiry and
    requires the ``tenant`` claim through its strict ``Claims`` model. This class only maps
    its failures onto TokenInvalidError and its ``Claims`` onto a plain mapping.
    """

    def __init__(self, issuer: str, audience: str) -> None:
        """Configure the relying party for ``issuer`` with ``audience`` as the expected aud."""
        self._rp = OIDCRelyingParty(
            OIDCRPConfig(
                issuer_url=issuer,
                client_id=audience,
                client_secret=_UNUSED_RP_SECRET,
                redirect_url=_UNUSED_RP_REDIRECT,
                algorithms=list(_OIDC_ALGORITHMS),
            )
        )

    async def verify(self, token: str) -> Mapping[str, Any]:
        """Validate ``token`` via penguin-aaa and return sub, scope and tenant claims."""
        try:
            claims = await self._rp.validate_token(token)
        except (jwt.PyJWTError, ValidationError, ValueError) as exc:
            raise TokenInvalidError(str(exc)) from exc
        except Exception as exc:  # httpx.HTTPError during discovery and similar network faults
            raise TokenInvalidError(f"token verification failed: {type(exc).__name__}") from exc
        return {"sub": claims.sub, "scope": list(claims.scope), "tenant": claims.tenant}


@dataclass(slots=True, frozen=True)
class AgentClaims:
    """Verified machine-JWT claims for one agent."""

    agent_public_id: uuid.UUID
    tenant: uuid.UUID
    scopes: frozenset[str]


def issue_agent_token(
    secret: str,
    agent_public_id: uuid.UUID,
    tenant: uuid.UUID,
    scopes: frozenset[str],
    ttl_s: int,
) -> str:
    """Sign a machine JWT (<=1h): sub=agent public_id, tenant=tenant public_id, scope."""
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
        return AgentClaims(
            agent_public_id=uuid.UUID(str(claims["sub"])),
            tenant=parse_tenant_claim(claims["tenant"]),
            scopes=parse_scopes(claims.get("scope")),
        )
    except (jwt.PyJWTError, ValueError, KeyError) as exc:
        raise TokenInvalidError(str(exc)) from exc


def tenant_from_admin_claims(claims: Mapping[str, Any]) -> uuid.UUID:
    """Return the tenant public_id UUID from an admin token; missing or invalid = error."""
    return parse_tenant_claim(claims.get("tenant"))
