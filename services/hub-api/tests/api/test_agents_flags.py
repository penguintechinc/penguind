"""Agent admin endpoints, override precondition, flags, audit, and cross-tenant isolation."""

import uuid
from collections.abc import Callable

from quart.testing import QuartClient

from tests.api.helpers import create_group, envelope_data, spiffe_for

AGENTS = "/api/v1/agents"
FLAGS = "/api/v1/flags"


async def _register(
    client: QuartClient,
    h: dict[str, str],
    tenant: uuid.UUID,
    group_ids: list[str] | None = None,
) -> dict[str, object]:
    """Pre-register an agent and return its data; asserts 201."""
    body: dict[str, object] = {
        "spiffe_id": spiffe_for(tenant),
        "platform": 1,
        "agent_version": "0.1.0",
    }
    if group_ids:
        body["group_ids"] = group_ids
    resp = await client.post(AGENTS, json=body, headers=h)
    assert resp.status_code == 201, await resp.get_data(as_text=True)
    return envelope_data(await resp.get_json())


async def test_register_agent_exact_fields_and_duplicate_spiffe(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: uuid.UUID
) -> None:
    """Pre-registration returns the Agent field set; reusing a SPIFFE id is 409; bad URI is 400."""
    h = admin_headers(tenant)
    spiffe = spiffe_for(tenant)
    first = await client.post(
        AGENTS, json={"spiffe_id": spiffe, "platform": 1, "agent_version": "0.1.0"}, headers=h
    )
    agent = envelope_data(await first.get_json())
    assert set(agent) == {
        "id",
        "status",
        "platform",
        "agent_version",
        "group_ids",
        "enrolled_at",
        "last_seen_at",
        "applied_etag",
    }
    assert agent["status"] == 2  # never seen -> stale
    same = {"spiffe_id": spiffe, "platform": 1, "agent_version": "0.1.0"}
    assert (await client.post(AGENTS, json=same, headers=h)).status_code == 409
    bad = {"spiffe_id": "http://nope", "platform": 1, "agent_version": "0.1.0"}
    assert (await client.post(AGENTS, json=bad, headers=h)).status_code == 400
    unknown_platform = {
        "spiffe_id": spiffe_for(tenant),
        "platform": 9,
        "agent_version": "0.1.0",
    }
    assert (await client.post(AGENTS, json=unknown_platform, headers=h)).status_code == 422


async def test_register_with_unknown_group_is_404(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: uuid.UUID
) -> None:
    """Membership in a group outside the tenant (or nonexistent) is 404."""
    h = admin_headers(tenant)
    body = {
        "spiffe_id": spiffe_for(tenant),
        "platform": 1,
        "agent_version": "0.1.0",
        "group_ids": [str(uuid.uuid4())],
    }
    assert (await client.post(AGENTS, json=body, headers=h)).status_code == 404


async def test_list_agents_filters_group_status_stale(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: uuid.UUID
) -> None:
    """Agents list filters by group membership, computed status and staleness, with paging."""
    h = admin_headers(tenant)
    g = await create_group(client, h, "fleet")
    a = await _register(client, h, tenant, [g["id"]])
    b = await _register(client, h, tenant)
    in_group = envelope_data(
        await (await client.get(AGENTS, query_string={"group_id": g["id"]}, headers=h)).get_json()
    )
    assert [x["id"] for x in in_group["items"]] == [a["id"]]
    stale = envelope_data(
        await (await client.get(AGENTS, query_string={"stale": "true"}, headers=h)).get_json()
    )
    assert {x["id"] for x in stale["items"]} == {a["id"], b["id"]}
    active = await client.get(AGENTS, query_string={"status": 1}, headers=h)
    assert envelope_data(await active.get_json())["items"] == []
    paged = envelope_data(
        await (await client.get(AGENTS, query_string={"limit": 1}, headers=h)).get_json()
    )
    assert len(paged["items"]) == 1 and paged["next_cursor"] is not None
    assert (await client.get(AGENTS, query_string={"status": "x"}, headers=h)).status_code == 400
    assert (
        await client.get(AGENTS, query_string={"group_id": "bad"}, headers=h)
    ).status_code == 404


async def test_agent_detail_has_effective_policy_and_override_etag(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: uuid.UUID
) -> None:
    """Detail carries override, effective config and last_report; override PUT honours If-Match."""
    h = admin_headers(tenant)
    a = await _register(client, h, tenant)
    aid = a["id"]
    detail = await client.get(f"/api/v1/agents/{aid}", headers=h)
    data = envelope_data(await detail.get_json())
    assert {"override", "effective", "last_report"} <= set(data)
    assert data["effective"] == {"limits": {}, "settings": {}}
    etag = detail.headers["ETag"]
    put = await client.put(
        f"/api/v1/agents/{aid}/override",
        json={"allowed_tools": ["t1"], "limits": {"poll_interval_s": 120}},
        headers={**h, "If-Match": etag},
    )
    assert put.status_code == 200
    assert envelope_data(await put.get_json())["allowed_tools"] == ["t1"]
    stale = await client.put(
        f"/api/v1/agents/{aid}/override", json={"limits": {}}, headers={**h, "If-Match": etag}
    )
    assert stale.status_code == 412
    bad = await client.put(f"/api/v1/agents/{aid}/override", json={"limits": {"x": 1}}, headers=h)
    assert bad.status_code == 422
    not_obj = await client.put(f"/api/v1/agents/{aid}/override", json=[1], headers=h)
    assert not_obj.status_code == 400
    assert (await client.delete(f"/api/v1/agents/{aid}/override", headers=h)).status_code == 204
    after = envelope_data(await (await client.get(f"/api/v1/agents/{aid}", headers=h)).get_json())
    assert after["override"] is None


async def test_flags_upsert_list_delete_and_scope_rules(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: uuid.UUID
) -> None:
    """Flags upsert in place, validate key/scope, filter by group, and delete cleanly."""
    h = admin_headers(tenant)
    g = await create_group(client, h, "flagged")
    body = {"key": "penguind.hub-api.canary", "enabled": False, "scope": 1}
    first = await client.put(FLAGS, json=body, headers=h)
    assert first.status_code == 200
    flag = envelope_data(await first.get_json())
    assert set(flag) == {"id", "key", "enabled", "scope", "group_id", "updated_at"}
    again = envelope_data(
        await (await client.put(FLAGS, json={**body, "enabled": True}, headers=h)).get_json()
    )
    assert again["id"] == flag["id"] and again["enabled"] is True
    scoped = await client.put(
        FLAGS,
        json={"key": "penguind.hub-api.canary", "enabled": False, "scope": 2, "group_id": g["id"]},
        headers=h,
    )
    assert scoped.status_code == 200
    only_group = envelope_data(
        await (await client.get(FLAGS, query_string={"group_id": g["id"]}, headers=h)).get_json()
    )
    assert [f["group_id"] for f in only_group["items"]] == [g["id"]]
    assert (
        await client.put(FLAGS, json={"key": "Bad Key", "enabled": True, "scope": 1}, headers=h)
    ).status_code == 422
    assert (
        await client.put(FLAGS, json={"key": "a.b", "enabled": True, "scope": 2}, headers=h)
    ).status_code == 422
    assert (
        await client.put(
            FLAGS, json={"key": "a.b", "enabled": True, "scope": 1, "group_id": g["id"]}, headers=h
        )
    ).status_code == 422
    assert (
        await client.put(FLAGS, json={"key": "a.b", "enabled": True, "scope": 9}, headers=h)
    ).status_code == 422
    missing_group = await client.put(
        FLAGS,
        json={"key": "a.b", "enabled": True, "scope": 2, "group_id": str(uuid.uuid4())},
        headers=h,
    )
    assert missing_group.status_code == 404
    assert (await client.delete(f"{FLAGS}/{flag['id']}", headers=h)).status_code == 204
    assert (await client.delete(f"{FLAGS}/{flag['id']}", headers=h)).status_code == 404


async def test_audit_events_record_every_admin_write(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: uuid.UUID
) -> None:
    """Each admin write appends one audit event with int action codes and no PII."""
    h = admin_headers(tenant)
    g = await create_group(client, h, "audited")
    await client.put(
        FLAGS, json={"key": "penguind.hub-api.x", "enabled": True, "scope": 1}, headers=h
    )
    page = envelope_data(await (await client.get("/api/v1/audit-events", headers=h)).get_json())
    actions = [e["action"] for e in page["items"]]
    assert actions == [1, 14]  # group.create, flag.upsert
    first = page["items"][0]
    assert set(first) == {"id", "action", "target_type", "target_id", "actor", "created_at"}
    assert first["target_id"] == g["id"] and first["actor"] == "oidc|test-admin"
    assert first["target_type"] == 1


async def test_cross_tenant_resources_are_invisible(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: uuid.UUID
) -> None:
    """Tenant B cannot list, read, patch, delete or reference tenant A's objects (404 or absent)."""
    a = admin_headers(tenant)
    b = admin_headers(uuid.uuid4())
    group = await create_group(client, a, "private-to-a")
    agent = await _register(client, a, tenant, [group["id"]])
    assert (await client.get(f"/api/v1/groups/{group['id']}", headers=b)).status_code == 404
    assert (
        await client.patch(f"/api/v1/groups/{group['id']}", json={"description": "x"}, headers=b)
    ).status_code == 404
    assert (await client.delete(f"/api/v1/groups/{group['id']}", headers=b)).status_code == 404
    assert (await client.get(f"/api/v1/agents/{agent['id']}", headers=b)).status_code == 404
    assert (
        await client.put(f"/api/v1/groups/{group['id']}/members", json={"agent_ids": []}, headers=b)
    ).status_code == 404
    listed = envelope_data(await (await client.get("/api/v1/groups", headers=b)).get_json())
    assert all(g["id"] != group["id"] for g in listed["items"])
    other_agents = envelope_data(await (await client.get(AGENTS, headers=b)).get_json())
    assert other_agents["items"] == []
    cross = await client.put(
        f"/api/v1/groups/{group['id']}/members", json={"agent_ids": [agent["id"]]}, headers=b
    )
    assert cross.status_code == 404
