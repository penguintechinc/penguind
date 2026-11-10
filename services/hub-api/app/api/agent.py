"""Agent API blueprint: /api/v1/agent enroll, token rotation, sync, status and binary download.

Enroll and token are authenticated by their one-time or rotating secrets and are rate limited
per client address. Sync, status and binary require a verified agent identity (mTLS or
machine JWT) and the matching hub:agent:* scope.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from quart import Blueprint, g, redirect, request
from quart_schema import validate_request, validate_response

from app import agent_service
from app.api.common import run, with_headers
from app.context import hub
from app.dto import (
    EnrollRequest,
    ModuleManifest,
    RefreshRequest,
    StatusReport,
    SyncBundle,
    TokenResponse,
)
from app.envelope import envelope, envelope_type
from app.flags import FLAG_AGENT_API
from app.guards import AgentPrincipal, bearer_token, rate_limit, require_agent, require_flag
from app.problems import unauthorized

bp = Blueprint("agent", __name__, url_prefix="/api/v1/agent")
_AGENT = require_flag(FLAG_AGENT_API)


def _client_key() -> str:
    """Rate-limit key for unauthenticated agent calls: the client address."""
    return str(request.remote_addr or "unknown")


def _principal() -> AgentPrincipal:
    """Return the principal stored by require_agent (set before the handler runs)."""
    principal: AgentPrincipal = g.agent
    return principal


@bp.post("/enroll")
@_AGENT
@rate_limit("enroll", _client_key)
@validate_request(EnrollRequest)
@validate_response(envelope_type(TokenResponse), status_code=201)
async def enroll(data: EnrollRequest) -> Any:
    """Exchange a one-time bootstrap token for a machine JWT and refresh token."""
    secret = bearer_token()
    if secret is None:
        raise unauthorized("bootstrap token required")
    resp = await asyncio.to_thread(agent_service.enroll, hub(), secret, data)
    return envelope(TokenResponse, resp), 201


@bp.post("/token")
@_AGENT
@rate_limit("token", _client_key)
@validate_request(RefreshRequest)
@validate_response(envelope_type(TokenResponse))
async def refresh(data: RefreshRequest) -> Any:
    """Rotate a refresh token; reuse of a rotated token revokes the whole chain."""
    resp = await asyncio.to_thread(agent_service.refresh, hub(), data.refresh_token)
    return envelope(TokenResponse, resp)


@bp.get("/sync")
@_AGENT
@require_agent("hub:agent:sync")
@validate_response(envelope_type(SyncBundle))
async def sync() -> Any:
    """Return desired state, or 304 when If-None-Match names the current ETag."""
    ctx = hub()
    instruments = ctx.telemetry.instruments
    started = time.perf_counter()
    principal = _principal()
    result = await run(agent_service.sync, ctx, principal, request.headers.get("If-None-Match"))
    code = "304" if result.bundle is None else "200"
    instruments.sync_requests.add(1, {"result": code})
    instruments.sync_latency.record(time.perf_counter() - started, {"result": code})
    if result.bundle is None:
        return with_headers("", {"ETag": result.etag}), 304
    bundle = result.bundle
    dto = SyncBundle(
        agent_id=bundle["agent_id"],
        generated_at=bundle["generated_at"],
        policy=bundle["policy"],
        flags=bundle["flags"],
        modules=[ModuleManifest(**m) for m in bundle["modules"]],
        poll_interval_s=bundle["poll_interval_s"],
        max_stale_s=bundle["max_stale_s"],
    )
    headers = {"ETag": result.etag, "Cache-Control": "private, max-age=300"}
    return with_headers(envelope(SyncBundle, dto), headers), 200


@bp.post("/status")
@_AGENT
@require_agent("hub:agent:report")
@validate_request(StatusReport)
async def status(data: StatusReport) -> Any:
    """Record the agent's applied ETag, load results and version."""
    await run(agent_service.record_status, _principal(), data)
    return "", 204


@bp.get("/modules/<module_version_id>/binary")
@_AGENT
@require_agent("hub:agent:sync")
async def binary(module_version_id: str) -> Any:
    """302 to a short-lived presigned URL for an assigned, non-yanked module binary."""
    principal = _principal()
    mv = await run(agent_service.module_for_agent, principal, module_version_id)
    url = await hub().blobs.presign_get(str(mv.blob_key))
    return redirect(url, code=302)
