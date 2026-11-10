"""Identity regressions: global SPIFFE ids, fail-closed ambiguity, tenant map, OIDC verify."""

import time
import uuid
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from penguin_dal import DB
from quart.testing import QuartClient

from app.auth import OidcVerifier, TokenInvalidError
from app.models import TenantDB
from app.models.identity import (
    ensure_tenant,
    is_unique_violation,
    resolve_agent_by_spiffe,
    resolve_tenant,
    tenant_public_id,
)
from tests.api.helpers import spiffe_for

ISSUER = "https://idp.test"
AUDIENCE = "hub-api"


async def test_same_spiffe_id_cannot_be_registered_by_two_tenants(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]]
) -> None:
    """A SPIFFE id is global: the second tenant to register it gets 409 (or 403 for the segment)."""
    first, second = uuid.uuid4(), uuid.uuid4()
    uri = spiffe_for(first)
    body = {"spiffe_id": uri, "platform": 1, "agent_version": "0.1.0"}
    assert (
        await client.post("/api/v1/agents", json=body, headers=admin_headers(first))
    ).status_code == 201
    assert (
        await client.post("/api/v1/agents", json=body, headers=admin_headers(first))
    ).status_code == 409
    # Another tenant cannot claim it: the tenant segment names `first`, not `second`.
    assert (
        await client.post("/api/v1/agents", json=body, headers=admin_headers(second))
    ).status_code == 403


def test_database_rejects_duplicate_spiffe_across_tenants(db: DB) -> None:
    """The unique constraint itself refuses a second row with the same spiffe_id, any tenant."""
    uri = spiffe_for(uuid.uuid4())
    first = TenantDB(db, 30_000_001)
    second = TenantDB(db, 30_000_002)
    first.insert("agents", status=1, platform=1, agent_version="0.1.0", spiffe_id=uri)
    with pytest.raises(Exception) as info:
        second.insert("agents", status=1, platform=1, agent_version="0.1.0", spiffe_id=uri)
    assert is_unique_violation(info.value)
    assert not is_unique_violation(ValueError("nope"))
    assert second.count("agents", second.field("agents", "spiffe_id") == uri) == 0


def test_resolve_agent_by_spiffe_fails_closed_on_multiple_rows() -> None:
    """If two rows ever match one SPIFFE id, no identity is returned (never 'first wins')."""

    class _Query:
        """Fake query set returning two rows."""

        def __init__(self, rows: list[object]) -> None:
            """Hold the rows to return."""
            self.rows = rows

        def select(self, **_: Any) -> list[object]:
            """Return all configured rows."""
            return self.rows

    class _Db:
        """Fake DB whose agents table matches two tenants' rows."""

        agents = SimpleNamespace(spiffe_id="x")

        def __call__(self, _q: object) -> _Query:
            """Return a query set holding two matching rows."""
            return _Query([SimpleNamespace(tenant_id=1), SimpleNamespace(tenant_id=2)])

    assert resolve_agent_by_spiffe(_Db(), "spiffe://x/tenant/y/agent/z") is None  # type: ignore[arg-type]


def test_tenant_map_round_trip_and_idempotence(db: DB) -> None:
    """ensure_tenant registers once, resolves both ways, and a missing tenant is an error."""
    pid = uuid.uuid4()
    assert resolve_tenant(db, pid) is None
    tid = ensure_tenant(db, pid)
    assert ensure_tenant(db, pid) == tid
    assert resolve_tenant(db, pid) == tid
    assert tenant_public_id(db, tid) == pid
    with pytest.raises(LookupError):
        tenant_public_id(db, 99_999_999_999)


def test_ensure_tenant_survives_insert_race(db: DB, monkeypatch: pytest.MonkeyPatch) -> None:
    """If another replica inserts first, the unique violation is absorbed and the row is read."""
    pid = uuid.uuid4()
    real = ensure_tenant(db, pid)
    calls = iter([None, real])
    monkeypatch.setattr("app.models.identity.resolve_tenant", lambda *_: next(calls))
    assert ensure_tenant(db, pid) == real


def test_ensure_tenant_reraises_non_unique_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only unique violations are absorbed; any other insert failure propagates."""

    class _Tenants:
        """Fake table whose insert fails."""

        def insert(self, **_: Any) -> None:
            """Fail like a broken connection."""
            raise RuntimeError("db down")

    monkeypatch.setattr("app.models.identity.resolve_tenant", lambda *_: None)
    with pytest.raises(RuntimeError, match="db down"):
        ensure_tenant(SimpleNamespace(tenants=_Tenants()), uuid.uuid4())  # type: ignore[arg-type]


def test_ensure_tenant_missing_after_insert_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A row that vanishes right after a clean insert is reported, never returned as None."""
    monkeypatch.setattr("app.models.identity.resolve_tenant", lambda *_: None)
    tenants = SimpleNamespace(insert=lambda **_: None)
    with pytest.raises(RuntimeError, match="missing after insert"):
        ensure_tenant(SimpleNamespace(tenants=tenants), uuid.uuid4())  # type: ignore[arg-type]


def _verifier_with_key(monkeypatch: pytest.MonkeyPatch) -> tuple[OidcVerifier, Any]:
    """Build an OidcVerifier whose penguin-aaa relying party already holds a test RSA key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = OidcVerifier(ISSUER, AUDIENCE)
    rp = verifier._rp
    rp._discovery = {"issuer": ISSUER}
    rp._jwks_client = SimpleNamespace(
        get_signing_key_from_jwt=lambda _t: SimpleNamespace(key=key.public_key())
    )
    return verifier, key


def _token(key: Any, **overrides: Any) -> str:
    """Sign an admin token with the given claim overrides."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": "oidc|admin",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 300,
        "scope": "hub:groups:read hub:groups:write",
        "tenant": str(uuid.uuid4()),
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256")


async def test_penguin_aaa_verifier_accepts_valid_and_maps_claims(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A correctly signed token yields sub, scope list and the tenant claim via penguin-aaa."""
    verifier, key = _verifier_with_key(monkeypatch)
    tenant = str(uuid.uuid4())
    claims = await verifier.verify(_token(key, tenant=tenant))
    assert claims["sub"] == "oidc|admin" and claims["tenant"] == tenant
    assert set(claims["scope"]) == {"hub:groups:read", "hub:groups:write"}


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://evil.test"},
        {"aud": "someone-else"},
        {"exp": 1},
        {"tenant": None},
        {"sub": None},
    ],
)
async def test_penguin_aaa_verifier_rejects_bad_tokens(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
) -> None:
    """Wrong issuer/audience, expired, and missing tenant/sub are all TokenInvalidError."""
    verifier, key = _verifier_with_key(monkeypatch)
    with pytest.raises(TokenInvalidError):
        await verifier.verify(_token(key, **overrides))


async def test_penguin_aaa_verifier_rejects_foreign_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A token signed by a different key fails signature verification."""
    verifier, _ = _verifier_with_key(monkeypatch)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(TokenInvalidError):
        await verifier.verify(_token(other))
