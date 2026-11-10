"""Agent-facing operations: enrollment, refresh rotation, sync bundle, status, binary lookup.

Credentials are high-entropy random secrets stored as sha256 digests and resolved by
indexed lookup (identity.py). Each call then runs against a TenantDB bound to the tenant
that owns the credential row.
"""

from __future__ import annotations

import datetime as dt
import secrets
import uuid
from dataclasses import dataclass
from typing import Any

from penguin_dal import Row

from app.auth import issue_agent_token
from app.context import HubContext
from app.dto import EnrollRequest, StatusReport, TokenResponse
from app.envelope import iso
from app.guards import AgentPrincipal
from app.models import AgentStatus, ApplyResult, ModuleStatus, TenantDB, effective_config
from app.models.identity import resolve_bootstrap, resolve_refresh
from app.models.policy import ConfigRevision
from app.problems import bad_request, gone, not_found, unauthorized
from app.service import digest, parse_pid

POLL_DEFAULT_S = 300
TOKEN_TYPE = "Bearer"  # noqa: S105 # nosec B105 - OAuth token type label (RFC 6750), not a secret
POLL_MIN_S = 60
STALE_MIN_S = 300


@dataclass(slots=True)
class SyncResult:
    """Outcome of a sync call: either a fresh bundle or a 304 with its ETag."""

    etag: str
    bundle: dict[str, Any] | None


def _now() -> dt.datetime:
    """Return the current aware UTC time."""
    return dt.datetime.now(dt.UTC)


def _revoke_chain(tdb: TenantDB, chain_id: uuid.UUID) -> None:
    """Revoke every refresh token in a chain (reuse = compromise signal)."""
    now = _now()
    for token in tdb.select("refresh_tokens", tdb.field("refresh_tokens", "chain_id") == chain_id):
        if token.revoked_at is None:
            tdb.update("refresh_tokens", token.public_id, revoked_at=now)


def _new_refresh(tdb: TenantDB, agent_id: int, chain_id: uuid.UUID) -> str:
    """Insert a fresh refresh token row in ``chain_id`` and return its plaintext secret."""
    secret = secrets.token_urlsafe(32)
    tdb.insert("refresh_tokens", agent_id=agent_id, hash=digest(secret), chain_id=chain_id)
    return secret


def _token_response(ctx: HubContext, agent: Row, tenant_id: int, refresh: str) -> TokenResponse:
    """Build the TokenResponse with a freshly signed machine JWT."""
    ttl = ctx.settings.agent_token_ttl_s
    access = issue_agent_token(
        ctx.settings.agent_jwt_secret,
        agent.public_id,
        tenant_id,
        frozenset({"hub:agent:sync", "hub:agent:report"}),
        ttl,
    )
    return TokenResponse(
        agent_id=str(agent.public_id),
        access_token=access,
        token_type=TOKEN_TYPE,
        expires_in=ttl,
        refresh_token=refresh,
    )


def enroll(ctx: HubContext, bootstrap_secret: str, body: EnrollRequest) -> TokenResponse:
    """Consume a one-time bootstrap token and create the agent it enrolls.

    The token is claimed by compare-and-set on used_by_agent_id; a losing racer gets 401 and
    its provisional agent row is deleted.
    """
    if body.csr_pem:
        raise bad_request("csr_pem is not supported; the hub issues machine JWTs")
    token_row = resolve_bootstrap(ctx.db, digest(bootstrap_secret))
    if token_row is None:
        raise unauthorized("bootstrap token invalid")
    tdb = TenantDB(ctx.db, int(token_row.tenant_id))
    now = _now()
    if token_row.used_by_agent_id is not None or token_row.expires_at <= now:
        raise unauthorized("bootstrap token invalid")
    agent = tdb.insert(
        "agents",
        status=int(AgentStatus.ACTIVE),
        platform=body.platform,
        agent_version=body.agent_version,
    )
    won = tdb.compare_and_update(
        "bootstrap_tokens",
        (tdb.field("bootstrap_tokens", "id") == token_row.id)
        & (tdb.field("bootstrap_tokens", "used_by_agent_id") == None)  # noqa: E711 - SQL IS NULL
        & (tdb.field("bootstrap_tokens", "expires_at") > now),
        used_by_agent_id=agent.id,
    )
    if won != 1:
        tdb.delete("agents", tdb.field("agents", "public_id") == agent.public_id)
        raise unauthorized("bootstrap token invalid")
    for raw_gid in token_row.group_ids or []:
        group = tdb.get("groups", uuid.UUID(str(raw_gid)))
        if group is not None:
            tdb.insert("group_members", group_id=group.id, agent_id=agent.id)
    refresh = _new_refresh(tdb, agent.id, uuid.uuid4())
    return _token_response(ctx, agent, int(token_row.tenant_id), refresh)


def refresh(ctx: HubContext, refresh_secret: str) -> TokenResponse:
    """Rotate a refresh token; reuse of a rotated token revokes its whole chain."""
    row = resolve_refresh(ctx.db, digest(refresh_secret))
    if row is None:
        raise unauthorized("refresh token invalid")
    tdb = TenantDB(ctx.db, int(row.tenant_id))
    if row.revoked_at is not None:
        raise unauthorized("refresh token revoked")
    if row.rotated_at is not None:
        _revoke_chain(tdb, row.chain_id)
        raise unauthorized("refresh token reuse detected; chain revoked")
    agent = tdb.get_by_id("agents", int(row.agent_id))
    if agent is None or int(agent.status) == AgentStatus.REVOKED:
        raise gone()
    won = tdb.compare_and_update(
        "refresh_tokens",
        (tdb.field("refresh_tokens", "id") == row.id)
        & (tdb.field("refresh_tokens", "rotated_at") == None),  # noqa: E711 - SQL IS NULL
        rotated_at=_now(),
    )
    if won != 1:
        _revoke_chain(tdb, row.chain_id)
        raise unauthorized("refresh token reuse detected; chain revoked")
    new_refresh = _new_refresh(tdb, int(row.agent_id), row.chain_id)
    return _token_response(ctx, agent, int(row.tenant_id), new_refresh)


def _flags_for(tdb: TenantDB, group_ids: set[int]) -> dict[str, bool]:
    """Compute restrict-only flags: a key is ON only if every applicable flag is ON."""
    out: dict[str, bool] = {}
    for flag in tdb.select("flags"):
        applies = flag.group_id is None or int(flag.group_id) in group_ids
        if applies:
            out[flag.key] = out.get(flag.key, True) and bool(flag.enabled)
    return out


def _version_key(version: str) -> tuple[int, int, int, int]:
    """Sort key for a SemVer string: numeric triple, then release above prerelease."""
    core, _, pre = version.partition("-")
    major, minor, patch = (int(p) for p in core.split("."))
    return (major, minor, patch, 0 if pre else 1)


def _assigned_versions(tdb: TenantDB, group_ids: set[int]) -> list[Row]:
    """Return available module versions assigned to any of the given groups."""
    if not group_ids:
        return []
    links = tdb.select(
        "group_modules", tdb.field("group_modules", "group_id").belongs(sorted(group_ids))
    )
    rows: list[Row] = []
    for link in links:
        mv = tdb.get_by_id("module_versions", int(link.module_version_id))
        if mv is not None and int(mv.status) == ModuleStatus.AVAILABLE:
            rows.append(mv)
    return rows


def _manifests(tdb: TenantDB, group_ids: set[int], base_url: str) -> list[dict[str, Any]]:
    """Build one ModuleManifest per module id: the highest assigned, available version."""
    best: dict[str, Row] = {}
    for mv in _assigned_versions(tdb, group_ids):
        current = best.get(mv.module_id)
        if current is None or _version_key(mv.version) > _version_key(current.version):
            best[mv.module_id] = mv
    return [
        {
            "id": module_id,
            "version": mv.version,
            "sha256": mv.sha256,
            "signature": mv.signature,
            "binary_url": f"{base_url}/api/v1/agent/modules/{mv.public_id}/binary",
        }
        for module_id, mv in sorted(best.items())
    ]


def _group_ids(tdb: TenantDB, agent_id: int) -> set[int]:
    """Return the internal ids of every group the agent belongs to."""
    links = tdb.select("group_members", tdb.field("group_members", "agent_id") == agent_id)
    return {int(link.group_id) for link in links}


def sync(ctx: HubContext, principal: AgentPrincipal, if_none_match: str | None) -> SyncResult:
    """Return the agent's effective desired state, or a 304 when its ETag is current."""
    tdb = principal.tdb
    agent = principal.agent
    tdb.update("agents", agent.public_id, last_seen_at=_now())
    policy = effective_config(tdb, agent.public_id)
    if policy is None:
        raise not_found("agent")
    limits = policy.limits
    poll = max(POLL_MIN_S, int(limits.get("poll_interval_s", POLL_DEFAULT_S)))
    stale = max(STALE_MIN_S, int(limits.get("max_stale_s", ctx.settings.stale_after_s)))
    group_ids = _group_ids(tdb, agent.id)
    payload: dict[str, Any] = {
        "agent_id": str(agent.public_id),
        "policy": policy.to_doc(),
        "flags": _flags_for(tdb, group_ids),
        "modules": _manifests(tdb, group_ids, ctx.settings.base_url),
        "poll_interval_s": poll,
        "max_stale_s": stale,
    }
    revision = ConfigRevision.of(payload)
    if revision.matches(if_none_match):
        return SyncResult(revision.etag, None)
    bundle = {"generated_at": iso(_now()), **payload}
    return SyncResult(revision.etag, bundle)


def record_status(principal: AgentPrincipal, report: StatusReport) -> None:
    """Persist an agent's applied state; the last report is kept for admin inspection."""
    if int(report.result) not in {int(r) for r in ApplyResult}:
        raise bad_request("unknown apply result code")
    tdb = principal.tdb
    values: dict[str, Any] = {
        "applied_etag": report.applied_etag,
        "last_report": {
            "applied_etag": report.applied_etag,
            "result": int(report.result),
            "agent_version": report.agent_version,
            "modules": [
                {"id": m.id, "version": m.version, "loaded": m.loaded, "error_code": m.error_code}
                for m in report.modules
            ],
        },
        "last_seen_at": _now(),
    }
    if report.agent_version is not None:
        values["agent_version"] = report.agent_version
    tdb.update("agents", principal.agent.public_id, **values)


def module_for_agent(principal: AgentPrincipal, module_pid: str) -> Row:
    """Return a module version the calling agent may download; 404 unless assigned, 410 yanked."""
    tdb = principal.tdb
    mv = tdb.get("module_versions", parse_pid(module_pid, "module version"))
    if mv is None:
        raise not_found("module version")
    if int(mv.status) == ModuleStatus.YANKED:
        raise gone("module version yanked")
    group_ids = _group_ids(tdb, principal.agent.id)
    assigned = bool(group_ids) and tdb.count(
        "group_modules",
        (tdb.field("group_modules", "module_version_id") == mv.id)
        & tdb.field("group_modules", "group_id").belongs(sorted(group_ids)),
    )
    if not assigned:
        raise not_found("module version")
    return mv
