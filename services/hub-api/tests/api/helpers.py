"""Request helpers shared by API tests (agent credentials, envelope assertions)."""

import uuid
from collections.abc import Mapping
from typing import Any

from quart.testing import QuartClient

from app.auth import issue_agent_token

AGENT_SECRET = "s" * 48
SPIFFE = "spiffe://penguintech.io/test/penguind/"


def agent_headers(
    agent_pid: uuid.UUID, tenant: int, scopes: str = "hub:agent:sync hub:agent:report"
) -> dict[str, str]:
    """Return a Bearer header with a machine JWT for an agent (signed with the test secret)."""
    token = issue_agent_token(AGENT_SECRET, agent_pid, tenant, frozenset(scopes.split()), 3600)
    return {"Authorization": f"Bearer {token}"}


def envelope_data(body: Mapping[str, Any]) -> Any:
    """Return ``data`` from a success envelope, asserting its status and meta shape."""
    assert body["status"] == "success"
    assert set(body["meta"]) == {"version", "timestamp", "trace_id"}
    return body["data"]


async def create_group(
    client: QuartClient, headers: dict[str, str], name: str, **extra: Any
) -> dict[str, Any]:
    """POST a group and return its data; asserts 201."""
    resp = await client.post("/api/v1/groups", json={"name": name, **extra}, headers=headers)
    assert resp.status_code == 201, await resp.get_data(as_text=True)
    data: dict[str, Any] = envelope_data(await resp.get_json())
    return data
