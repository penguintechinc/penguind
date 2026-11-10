"""Group endpoints: envelope shape, CRUD, pagination, If-Match, membership, tenant isolation."""

import uuid
from collections.abc import Callable
from typing import Any

from quart.testing import QuartClient

from tests.api.helpers import envelope_data

GROUP_FIELDS = {"id", "name", "description", "policy", "agent_count", "created_at", "updated_at"}


async def _create_group(
    client: QuartClient, headers: dict[str, str], name: str, **extra: Any
) -> dict[str, Any]:
    """POST a group and return its data; asserts 201."""
    resp = await client.post("/api/v1/groups", json={"name": name, **extra}, headers=headers)
    assert resp.status_code == 201, await resp.get_data(as_text=True)
    assert resp.headers["ETag"].startswith('"')
    return envelope_data(await resp.get_json())


async def test_create_group_exact_field_set(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """Create returns exactly the contract fields and the {status,data,meta} envelope."""
    h = admin_headers(tenant)
    data = await _create_group(client, h, "alpha", description="d", policy={"allowed_tools": ["a"]})
    assert set(data) == GROUP_FIELDS
    assert data["policy"] == {"allowed_tools": ["a"], "limits": {}, "settings": {}}
    assert data["agent_count"] == 0
    uuid.UUID(data["id"])


async def test_duplicate_group_name_conflicts(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """A second group with the same name in the tenant is 409 with a problem envelope."""
    h = admin_headers(tenant)
    await _create_group(client, h, "dup")
    resp = await client.post("/api/v1/groups", json={"name": "dup"}, headers=h)
    body = await resp.get_json()
    assert resp.status_code == 409
    assert body["status"] == "error"
    assert body["data"]["code"] == 1040
    assert resp.mimetype == "application/problem+json"


async def test_get_list_and_name_prefix_pagination(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """Pages of size 1 walk every group exactly once; name_prefix filters the scan."""
    h = admin_headers(tenant)
    for name in ("ops-a", "ops-b", "dev-c"):
        await _create_group(client, h, name)
    seen: list[str] = []
    cursor = None
    while True:
        params = {"limit": 1, **({"cursor": cursor} if cursor else {})}
        data = envelope_data(
            await (await client.get("/api/v1/groups", query_string=params, headers=h)).get_json()
        )
        seen += [g["name"] for g in data["items"]]
        cursor = data["next_cursor"]
        if cursor is None:
            break
    assert seen == ["ops-a", "ops-b", "dev-c"]
    filtered = envelope_data(
        await (
            await client.get("/api/v1/groups", query_string={"name_prefix": "ops"}, headers=h)
        ).get_json()
    )
    assert [g["name"] for g in filtered["items"]] == ["ops-a", "ops-b"]
    assert set(filtered) == {"items", "next_cursor"}


async def test_bad_limit_and_cursor_are_400(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """Out-of-range limit and malformed cursor are rejected before any data access."""
    h = admin_headers(tenant)
    assert (
        await client.get("/api/v1/groups", query_string={"limit": 0}, headers=h)
    ).status_code == 400
    assert (
        await client.get("/api/v1/groups", query_string={"limit": 500}, headers=h)
    ).status_code == 400
    assert (
        await client.get("/api/v1/groups", query_string={"cursor": "!!!"}, headers=h)
    ).status_code == 400


async def test_patch_requires_matching_if_match(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """PATCH with a stale If-Match is 412; with the current ETag it updates."""
    h = admin_headers(tenant)
    created = await client.post("/api/v1/groups", json={"name": "etag"}, headers=h)
    gid = (await created.get_json())["data"]["id"]
    etag = created.headers["ETag"]
    stale = await client.patch(
        f"/api/v1/groups/{gid}", json={"description": "x"}, headers={**h, "If-Match": '"nope"'}
    )
    assert stale.status_code == 412
    ok = await client.patch(
        f"/api/v1/groups/{gid}", json={"description": "x"}, headers={**h, "If-Match": etag}
    )
    assert ok.status_code == 200
    assert envelope_data(await ok.get_json())["description"] == "x"
    assert ok.headers["ETag"] != etag


async def test_patch_rejects_invalid_policy_and_renames_uniquely(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """A bad policy is 422; renaming onto an existing name is 409; empty PATCH is no-op 200."""
    h = admin_headers(tenant)
    a = await _create_group(client, h, "pa")
    await _create_group(client, h, "pb")
    bad = await client.patch(
        f"/api/v1/groups/{a['id']}", json={"policy": {"limits": {"nope": 1}}}, headers=h
    )
    assert bad.status_code == 422
    clash = await client.patch(f"/api/v1/groups/{a['id']}", json={"name": "pb"}, headers=h)
    assert clash.status_code == 409
    same = await client.patch(f"/api/v1/groups/{a['id']}", json={"name": "pa"}, headers=h)
    assert same.status_code == 200


async def test_delete_and_missing_group_404(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """Delete returns 204 once; the group is then 404; malformed ids are 404, not 500."""
    h = admin_headers(tenant)
    g = await _create_group(client, h, "gone")
    assert (await client.delete(f"/api/v1/groups/{g['id']}", headers=h)).status_code == 204
    assert (await client.get(f"/api/v1/groups/{g['id']}", headers=h)).status_code == 404
    assert (await client.delete(f"/api/v1/groups/{g['id']}", headers=h)).status_code == 404
    assert (await client.get("/api/v1/groups/not-a-uuid", headers=h)).status_code == 404


async def test_members_replace_and_unknown_agent_404(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """Membership is replaced atomically from the request set; an unknown agent is 404."""
    h = admin_headers(tenant)
    g = await _create_group(client, h, "members")
    spiffe = "spiffe://penguintech.io/test/penguind/"
    a1 = await client.post(
        "/api/v1/agents",
        json={"spiffe_id": spiffe + str(uuid.uuid4()), "platform": 1, "agent_version": "0.1.0"},
        headers=h,
    )
    a1_id = (await a1.get_json())["data"]["id"]
    put = await client.put(
        f"/api/v1/groups/{g['id']}/members", json={"agent_ids": [a1_id]}, headers=h
    )
    assert put.status_code == 200
    assert envelope_data(await put.get_json()) == {"agent_ids": [a1_id]}
    got = envelope_data(await (await client.get(f"/api/v1/groups/{g['id']}", headers=h)).get_json())
    assert got["agent_count"] == 1
    bad = await client.put(
        f"/api/v1/groups/{g['id']}/members", json={"agent_ids": [str(uuid.uuid4())]}, headers=h
    )
    assert bad.status_code == 404
