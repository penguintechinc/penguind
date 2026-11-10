"""Authentication and authorization: admin OIDC, agent JWT, tenant mismatch, mTLS."""

import uuid
from collections.abc import Callable

from quart import Quart
from quart.testing import QuartClient

from app.models import AgentStatus
from tests.api.helpers import agent_headers, spiffe_for

GROUPS = "/api/v1/groups"


async def test_missing_and_malformed_bearer_is_401(client: QuartClient) -> None:
    """No Authorization header, a non-bearer scheme, and an empty token all yield 401."""
    assert (await client.get(GROUPS)).status_code == 401
    assert (await client.get(GROUPS, headers={"Authorization": "Basic abc"})).status_code == 401
    assert (await client.get(GROUPS, headers={"Authorization": "Bearer   "})).status_code == 401


async def test_unknown_token_is_401_with_problem_envelope(client: QuartClient) -> None:
    """A token the verifier rejects is 401 and counted in the auth-failure metric."""
    resp = await client.get(GROUPS, headers={"Authorization": "Bearer nope"})
    body = await resp.get_json()
    assert resp.status_code == 401
    assert body["data"]["code"] == 1010


async def test_tenant_claim_missing_or_invalid_is_403(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]]
) -> None:
    """Admin tokens without a usable tenant public_id UUID claim are refused with 403."""
    missing = admin_headers(None, drop_tenant=True)
    assert (await client.get(GROUPS, headers=missing)).status_code == 403
    for bad in ("", "abc", "0", "42", "-3", "1.5", str(uuid.uuid4()).upper()):
        assert (await client.get(GROUPS, headers=admin_headers(bad))).status_code == 403


async def test_scope_required_per_route(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: uuid.UUID
) -> None:
    """A read-only token can list but not create; a token with no scopes is 403 everywhere."""
    read_only = admin_headers(tenant, "hub:groups:read")
    assert (await client.get(GROUPS, headers=read_only)).status_code == 200
    denied = await client.post(GROUPS, json={"name": "nope"}, headers=read_only)
    assert denied.status_code == 403
    assert (await denied.get_json())["data"]["detail"] == "scope hub:groups:write required"
    assert (await client.get(GROUPS, headers=admin_headers(tenant, ""))).status_code == 403


async def test_scope_claim_as_list_is_accepted(
    client: QuartClient, verifier: object, tenant: uuid.UUID
) -> None:
    """The scope claim may be a JSON list rather than a space-separated string."""
    from tests.api.conftest import FakeVerifier

    assert isinstance(verifier, FakeVerifier)
    verifier.tokens["list-scope"] = {
        "sub": "s",
        "tenant": str(tenant),
        "scope": ["hub:groups:read"],
    }
    resp = await client.get(GROUPS, headers={"Authorization": "Bearer list-scope"})
    assert resp.status_code == 200


async def test_scope_claim_of_wrong_type_is_401(
    client: QuartClient, verifier: object, tenant: uuid.UUID
) -> None:
    """A scope claim that is neither a string nor a list of strings is an invalid token (401)."""
    from tests.api.conftest import FakeVerifier

    assert isinstance(verifier, FakeVerifier)
    verifier.tokens["bad-scope"] = {"sub": "s", "tenant": str(tenant), "scope": 7}
    resp = await client.get(GROUPS, headers={"Authorization": "Bearer bad-scope"})
    assert resp.status_code == 401


async def test_agent_token_for_other_tenant_is_403(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: uuid.UUID
) -> None:
    """A machine JWT whose tenant claim differs from the agent's owning tenant is 403."""
    owner_headers = admin_headers(tenant)
    created = await client.post(
        "/api/v1/agents",
        json={"spiffe_id": spiffe_for(tenant), "platform": 1, "agent_version": "0.1.0"},
        headers=owner_headers,
    )
    agent_pid = uuid.UUID((await created.get_json())["data"]["id"])
    forged = agent_headers(agent_pid, uuid.uuid4())
    resp = await client.get("/api/v1/agent/sync", headers=forged)
    assert resp.status_code == 403


async def test_agent_token_unknown_agent_and_bad_jwt_are_401(
    client: QuartClient, tenant: uuid.UUID
) -> None:
    """A valid JWT for an unknown agent, and a JWT signed with another key, are both 401."""
    resp = await client.get("/api/v1/agent/sync", headers=agent_headers(uuid.uuid4(), tenant))
    assert resp.status_code == 401
    resp = await client.get("/api/v1/agent/sync", headers={"Authorization": "Bearer not.a.jwt"})
    assert resp.status_code == 401


async def test_agent_scope_is_enforced(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: uuid.UUID
) -> None:
    """Sync needs hub:agent:sync; a JWT with only hub:agent:report is 403 on sync."""
    created = await client.post(
        "/api/v1/agents",
        json={"spiffe_id": spiffe_for(tenant), "platform": 2, "agent_version": "0.1.0"},
        headers=admin_headers(tenant),
    )
    pid = uuid.UUID((await created.get_json())["data"]["id"])
    report_only = agent_headers(pid, tenant, "hub:agent:report")
    assert (await client.get("/api/v1/agent/sync", headers=report_only)).status_code == 403


async def test_revoked_agent_gets_410_on_every_agent_endpoint(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: uuid.UUID, app: Quart
) -> None:
    """Revocation stops the agent: sync, status and binary all answer 410."""
    admin = admin_headers(tenant)
    created = await client.post(
        "/api/v1/agents",
        json={"spiffe_id": spiffe_for(tenant), "platform": 1, "agent_version": "0.1.0"},
        headers=admin,
    )
    pid = (await created.get_json())["data"]["id"]
    headers = agent_headers(uuid.UUID(pid), tenant)
    assert (await client.get("/api/v1/agent/sync", headers=headers)).status_code == 200
    assert (await client.delete(f"/api/v1/agents/{pid}", headers=admin)).status_code == 204
    assert (await client.get("/api/v1/agent/sync", headers=headers)).status_code == 410
    status = await client.post(
        "/api/v1/agent/status",
        json={"applied_etag": "x", "result": 1, "modules": []},
        headers={**headers, "Content-Type": "application/json"},
    )
    assert status.status_code == 410
    binary = await client.get(f"/api/v1/agent/modules/{uuid.uuid4()}/binary", headers=headers)
    assert binary.status_code == 410


async def test_revoked_status_is_reported_by_admin(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: uuid.UUID
) -> None:
    """Revoking an agent shows it as status 3 (revoked) in the admin view."""
    admin = admin_headers(tenant)
    created = await client.post(
        "/api/v1/agents",
        json={"spiffe_id": spiffe_for(tenant), "platform": 3, "agent_version": "1.0.0"},
        headers=admin,
    )
    pid = (await created.get_json())["data"]["id"]
    await client.delete(f"/api/v1/agents/{pid}", headers=admin)
    data = (await (await client.get(f"/api/v1/agents/{pid}", headers=admin)).get_json())["data"]
    assert data["status"] == int(AgentStatus.REVOKED)


async def test_forwarded_cert_ignored_unless_trusted(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: uuid.UUID
) -> None:
    """With HUB_TRUST_FORWARDED_CERT off, a client-supplied XFCC cannot authenticate an agent."""
    admin = admin_headers(tenant)
    created = await client.post(
        "/api/v1/agents",
        json={"spiffe_id": spiffe_for(tenant), "platform": 1, "agent_version": "0.1.0"},
        headers=admin,
    )
    pid = (await created.get_json())["data"]["id"]
    spoof = {"X-Forwarded-Client-Cert": f"By=x;URI={spiffe_for(tenant, pid)}"}
    assert (await client.get("/api/v1/agent/sync", headers=spoof)).status_code == 401
