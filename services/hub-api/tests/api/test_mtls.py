"""mTLS identity regressions: XFCC parsing, trusted-peer gate, exact registration, no path ids."""

import uuid
from collections.abc import Callable
from ipaddress import ip_network

import pytest
from quart import Quart
from quart.testing import QuartClient
from werkzeug.datastructures import Headers

from app.models import TenantDB
from app.models.identity import ensure_tenant
from app.mtls import parse_agent_spiffe, single_spiffe_uri, trusted_peer
from tests.api.helpers import SPIFFE, envelope_data, spiffe_for

TRUSTED_PEER = "10.0.0.5"
UNTRUSTED_PEER = "203.0.113.9"
SYNC = "/api/v1/agent/sync"


@pytest.fixture
def mtls_on(app: Quart) -> Quart:
    """Enable the forwarded-cert path with 10.0.0.0/8 as the only trusted proxy network."""
    settings = app.config["HUB"].settings
    object.__setattr__(settings, "trust_forwarded_cert", True)
    object.__setattr__(settings, "trusted_proxy_cidrs", (ip_network("10.0.0.0/8"),))
    return app


async def _register(
    client: QuartClient, admin: dict[str, str], tenant: uuid.UUID
) -> tuple[str, str]:
    """Pre-register an agent under a fresh SPIFFE id; return (agent public id, spiffe uri)."""
    spiffe = spiffe_for(tenant)
    resp = await client.post(
        "/api/v1/agents",
        json={"spiffe_id": spiffe, "platform": 1, "agent_version": "0.1.0"},
        headers=admin,
    )
    assert resp.status_code == 201, await resp.get_data(as_text=True)
    return envelope_data(await resp.get_json())["id"], spiffe


def _at(peer: str) -> dict[str, object]:
    """Test-client scope override that sets the TCP peer address."""
    return {"client": (peer, 40000)}


async def test_registered_uri_from_trusted_peer_authenticates(
    mtls_on: Quart,
    client: QuartClient,
    admin_headers: Callable[..., dict[str, str]],
    tenant: uuid.UUID,
) -> None:
    """A single XFCC entry with one URI, from a trusted peer, matching a registration -> 200."""
    _, spiffe = await _register(client, admin_headers(tenant), tenant)
    resp = await client.get(
        SYNC,
        headers={"X-Forwarded-Client-Cert": f"Hash=ab;URI={spiffe}"},
        scope_base=_at(TRUSTED_PEER),
    )
    assert resp.status_code == 200, await resp.get_data(as_text=True)


async def test_injected_second_entry_is_rejected(
    mtls_on: Quart,
    client: QuartClient,
    admin_headers: Callable[..., dict[str, str]],
    tenant: uuid.UUID,
) -> None:
    """A second comma-separated XFCC element (client-appended identity) is refused: 401."""
    _, spiffe = await _register(client, admin_headers(tenant), tenant)
    injected = f"Hash=ab;URI={spiffe},Hash=cd;URI={SPIFFE}other"
    resp = await client.get(
        SYNC, headers={"X-Forwarded-Client-Cert": injected}, scope_base=_at(TRUSTED_PEER)
    )
    assert resp.status_code == 401


async def test_second_uri_in_one_element_is_rejected(
    mtls_on: Quart,
    client: QuartClient,
    admin_headers: Callable[..., dict[str, str]],
    tenant: uuid.UUID,
) -> None:
    """Two URI= pairs inside one element are ambiguous and refused: 401."""
    _, spiffe = await _register(client, admin_headers(tenant), tenant)
    ambiguous = f"URI={spiffe};URI={SPIFFE}other"
    resp = await client.get(
        SYNC, headers={"X-Forwarded-Client-Cert": ambiguous}, scope_base=_at(TRUSTED_PEER)
    )
    assert resp.status_code == 401


async def test_quoted_comma_does_not_split_elements(
    mtls_on: Quart,
    client: QuartClient,
    admin_headers: Callable[..., dict[str, str]],
    tenant: uuid.UUID,
) -> None:
    """A comma inside a quoted Subject is part of one value, so the single URI still matches."""
    _, spiffe = await _register(client, admin_headers(tenant), tenant)
    quoted = f'Subject="CN=a,OU=b";URI={spiffe}'
    resp = await client.get(
        SYNC, headers={"X-Forwarded-Client-Cert": quoted}, scope_base=_at(TRUSTED_PEER)
    )
    assert resp.status_code == 200


async def test_quoted_separator_cannot_hide_second_uri(
    mtls_on: Quart,
    client: QuartClient,
    admin_headers: Callable[..., dict[str, str]],
    tenant: uuid.UUID,
) -> None:
    """Quoting a second URI into a value does not smuggle it past the parser: unbalanced -> 401."""
    _, spiffe = await _register(client, admin_headers(tenant), tenant)
    smuggled = f'URI={spiffe};Subject="x,URI={SPIFFE}other'
    resp = await client.get(
        SYNC, headers={"X-Forwarded-Client-Cert": smuggled}, scope_base=_at(TRUSTED_PEER)
    )
    assert resp.status_code == 401


async def test_untrusted_remote_addr_cannot_use_forwarded_identity(
    mtls_on: Quart,
    client: QuartClient,
    admin_headers: Callable[..., dict[str, str]],
    tenant: uuid.UUID,
) -> None:
    """Even with trust on, XFCC from a peer outside the proxy CIDRs is ignored: 401."""
    _, spiffe = await _register(client, admin_headers(tenant), tenant)
    resp = await client.get(
        SYNC, headers={"X-Forwarded-Client-Cert": f"URI={spiffe}"}, scope_base=_at(UNTRUSTED_PEER)
    )
    assert resp.status_code == 401


async def test_empty_proxy_allowlist_refuses_all_forwarded_identity(
    mtls_on: Quart,
    client: QuartClient,
    admin_headers: Callable[..., dict[str, str]],
    tenant: uuid.UUID,
) -> None:
    """With HUB_TRUSTED_PROXY_CIDRS empty, trust=1 still refuses every XFCC: 401."""
    object.__setattr__(mtls_on.config["HUB"].settings, "trusted_proxy_cidrs", ())
    _, spiffe = await _register(client, admin_headers(tenant), tenant)
    resp = await client.get(
        SYNC, headers={"X-Forwarded-Client-Cert": f"URI={spiffe}"}, scope_base=_at(TRUSTED_PEER)
    )
    assert resp.status_code == 401


async def test_unregistered_uri_is_rejected(
    mtls_on: Quart, client: QuartClient, tenant: uuid.UUID
) -> None:
    """A well-formed SPIFFE URI with no registration row is 401, never an implicit agent."""
    uri = spiffe_for(tenant)
    resp = await client.get(
        SYNC, headers={"X-Forwarded-Client-Cert": f"URI={uri}"}, scope_base=_at(TRUSTED_PEER)
    )
    assert resp.status_code == 401
    assert (await resp.get_json())["data"]["detail"] == "unregistered agent identity"


async def test_path_spoofed_agent_id_is_not_identity(
    mtls_on: Quart,
    client: QuartClient,
    admin_headers: Callable[..., dict[str, str]],
    tenant: uuid.UUID,
) -> None:
    """An agent UUID in the URL path never identifies the caller.

    The XFCC URI carries the registered agent's UUID but no registration exists for that exact
    URI, so the request is 401 even though the path names a real agent.
    """
    agent_pid, registered = await _register(client, admin_headers(tenant), tenant)
    spoofs = [
        f"{registered}-spoof",
        f"{registered}/extra",
        f"{registered}/../agent/{agent_pid}",
        f"{registered}?x=1",
        spiffe_for(tenant, agent_pid),
        registered.replace("/agent/", "/agent//"),
        registered.replace("/tenant/", "/tenant/../tenant/"),
    ]
    for spoofed_uri in spoofs:
        resp = await client.get(
            f"/api/v1/agent/modules/{agent_pid}/binary",
            headers={"X-Forwarded-Client-Cert": f"URI={spoofed_uri}"},
            scope_base=_at(TRUSTED_PEER),
        )
        assert resp.status_code == 401, spoofed_uri


async def test_multiple_xfcc_header_lines_are_rejected(
    mtls_on: Quart,
    client: QuartClient,
    admin_headers: Callable[..., dict[str, str]],
    tenant: uuid.UUID,
) -> None:
    """Two XFCC header lines (any casing) are ambiguous and refused, even if both are valid."""
    _, spiffe = await _register(client, admin_headers(tenant), tenant)
    _, other = await _register(client, admin_headers(tenant), tenant)
    for second_name in (
        "X-Forwarded-Client-Cert",
        "x-forwarded-client-cert",
        "X-FORWARDED-CLIENT-CERT",
    ):
        headers = Headers(
            [("X-Forwarded-Client-Cert", f"URI={spiffe}"), (second_name, f"URI={other}")]
        )
        resp = await client.get(SYNC, headers=headers, scope_base=_at(TRUSTED_PEER))
        assert resp.status_code == 401, second_name


async def test_xfcc_header_name_is_case_insensitive(
    mtls_on: Quart,
    client: QuartClient,
    admin_headers: Callable[..., dict[str, str]],
    tenant: uuid.UUID,
) -> None:
    """A lower-case header name is the same single header line and authenticates normally."""
    _, spiffe = await _register(client, admin_headers(tenant), tenant)
    resp = await client.get(
        SYNC, headers={"x-forwarded-client-cert": f"URI={spiffe}"}, scope_base=_at(TRUSTED_PEER)
    )
    assert resp.status_code == 200


async def test_cross_tenant_tenant_segment_mismatch_is_rejected(
    mtls_on: Quart,
    client: QuartClient,
    admin_headers: Callable[..., dict[str, str]],
    tenant: uuid.UUID,
    app: Quart,
) -> None:
    """A registered URI whose tenant segment names another tenant never authenticates.

    The row is planted directly (the API refuses such a registration) to prove the guard itself
    compares the URI's tenant segment with the owning row's tenant.
    """
    other = uuid.uuid4()
    foreign_uri = spiffe_for(other)
    await client.get("/api/v1/groups", headers=admin_headers(tenant))  # registers `tenant`
    ctx = app.config["HUB"]
    tenant_id = ensure_tenant(ctx.db, tenant)
    TenantDB(ctx.db, tenant_id).insert(
        "agents", status=1, platform=1, agent_version="0.1.0", spiffe_id=foreign_uri
    )
    resp = await client.get(
        SYNC,
        headers={"X-Forwarded-Client-Cert": f"URI={foreign_uri}"},
        scope_base=_at(TRUSTED_PEER),
    )
    assert resp.status_code == 401


async def test_wrong_trust_domain_uri_is_rejected(
    mtls_on: Quart, client: QuartClient, tenant: uuid.UUID
) -> None:
    """A URI from a different trust domain is refused before any lookup."""
    uri = spiffe_for(tenant).replace("penguintech.io", "evil.example")
    resp = await client.get(
        SYNC, headers={"X-Forwarded-Client-Cert": f"URI={uri}"}, scope_base=_at(TRUSTED_PEER)
    )
    assert resp.status_code == 401


async def test_register_rejects_foreign_tenant_segment_and_domain(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: uuid.UUID
) -> None:
    """Pre-registration must name the caller's own tenant and the configured trust domain."""
    h = admin_headers(tenant)
    body = {"platform": 1, "agent_version": "0.1.0"}
    foreign = await client.post(
        "/api/v1/agents", json={"spiffe_id": spiffe_for(uuid.uuid4()), **body}, headers=h
    )
    assert foreign.status_code == 403
    domain = await client.post(
        "/api/v1/agents",
        json={"spiffe_id": spiffe_for(tenant).replace("penguintech.io", "evil.example"), **body},
        headers=h,
    )
    assert domain.status_code == 400
    legacy = await client.post(
        "/api/v1/agents",
        json={"spiffe_id": f"spiffe://penguintech.io/test/penguind/{uuid.uuid4()}", **body},
        headers=h,
    )
    assert legacy.status_code == 400


def test_parse_agent_spiffe_exact_shape() -> None:
    """Only spiffe://<td>/tenant/<canonical uuid>/agent/<one safe segment> parses."""
    tenant = uuid.uuid4()
    ok = f"spiffe://penguintech.io/tenant/{tenant}/agent/a1"
    assert parse_agent_spiffe(ok, "penguintech.io") == (tenant, "a1")
    assert parse_agent_spiffe(ok, "PenguinTech.io") == (tenant, "a1")
    bad = [
        ok.replace("tenant/", "tenants/"),
        ok.replace("/agent/", "/node/"),
        ok + "/x",
        ok.replace("a1", ".."),
        ok.replace("a1", "a b"),
        ok.replace(str(tenant), str(tenant).upper()),
        ok.replace(str(tenant), "42"),
        ok.replace("penguintech.io", "other.io"),
        "http://x/tenant/y/agent/z",
        "",
    ]
    for uri in bad:
        assert parse_agent_spiffe(uri, "penguintech.io") is None, uri
    assert parse_agent_spiffe(ok, "") is None


async def test_path_agent_id_without_forwarded_identity_is_401(
    mtls_on: Quart,
    client: QuartClient,
    admin_headers: Callable[..., dict[str, str]],
    tenant: uuid.UUID,
) -> None:
    """Naming a registered agent in the path, with no identity source, is still 401."""
    agent_pid, _ = await _register(client, admin_headers(tenant), tenant)
    resp = await client.get(
        f"/api/v1/agent/modules/{agent_pid}/binary", scope_base=_at(TRUSTED_PEER)
    )
    assert resp.status_code == 401


async def test_forwarded_header_is_removed_before_handlers(
    mtls_on: Quart,
    client: QuartClient,
    admin_headers: Callable[..., dict[str, str]],
    tenant: uuid.UUID,
) -> None:
    """The XFCC header is stripped on every path, including untrusted requests."""
    _, spiffe = await _register(client, admin_headers(tenant), tenant)
    seen: dict[str, object] = {}

    @mtls_on.get("/api/v1/_probe_header")
    async def probe() -> dict[str, object]:
        """Report whether the forwarded header survived to the handler."""
        from quart import request

        seen["present"] = "X-Forwarded-Client-Cert" in request.headers
        return {"ok": True}

    await client.get(
        "/api/v1/_probe_header",
        headers={"X-Forwarded-Client-Cert": f"URI={spiffe}"},
        scope_base=_at(UNTRUSTED_PEER),
    )
    assert seen == {"present": False}


@pytest.mark.parametrize(
    "xfcc",
    [
        "",
        "Hash=1",
        "URI=http://example.com/x",
        "URI=spiffe://a b/c",
        'URI="spiffe://a/b',
        "URI=spiffe://a/x,URI=spiffe://a/y",
        "URI=spiffe://a/x;URI=spiffe://a/y",
        "A=1,B=2",
    ],
)
def test_single_spiffe_uri_rejects_ambiguous_or_foreign_values(xfcc: str) -> None:
    """Only a single element with a single clean spiffe:// URI is accepted."""
    assert single_spiffe_uri(xfcc) is None


def test_single_spiffe_uri_accepts_quoted_value() -> None:
    """A quoted URI value is unwrapped to the bare spiffe:// string."""
    assert single_spiffe_uri(f'By=x;URI="{SPIFFE}ok"') == f"{SPIFFE}ok"


def test_trusted_peer_handles_bad_and_missing_addresses() -> None:
    """Missing, malformed and out-of-range peers are untrusted; an in-range peer is trusted."""
    nets = (ip_network("10.0.0.0/8"),)
    assert trusted_peer(None, nets) is False
    assert trusted_peer("not-an-ip", nets) is False
    assert trusted_peer("10.1.2.3", nets) is True
    assert trusted_peer("10.1.2.3", ()) is False
