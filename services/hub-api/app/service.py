"""Admin domain operations, executed synchronously against one TenantDB.

Every function here receives a tenant-bound TenantDB and never a raw DB handle, so tenant
scoping cannot be skipped. Route handlers run these in a worker thread and map ApiError.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import secrets
import uuid
from typing import Any

from penguin_dal import Row

from app.context import encode_cursor
from app.dto import (
    AgentCreate,
    BootstrapTokenCreate,
    BootstrapTokenSecret,
    FlagInput,
    GroupCreate,
    GroupUpdate,
    ModuleAssignment,
)
from app.envelope import iso
from app.models import (
    AgentStatus,
    AuditAction,
    FlagScope,
    ModuleStatus,
    Platform,
    TargetType,
    TenantDB,
    TenantViolationError,
    effective_config,
)
from app.models.policy import ConfigRevision, Policy, PolicyError
from app.problems import bad_request, conflict, not_found, precondition_failed, unprocessable

FLAG_KEY_RE = re.compile(r"^[a-z0-9-]+\.[a-z0-9.-]+$")
BOOTSTRAP_TTL_MIN_S = 60
BOOTSTRAP_TTL_MAX_S = 604800
_MAX_PAGE_SCAN = 10_000


def parse_pid(value: str, what: str) -> uuid.UUID:
    """Parse a public_id path/body value; malformed ids are reported as not found."""
    try:
        return uuid.UUID(value)
    except (ValueError, TypeError) as exc:
        raise not_found(what) from exc


def parse_policy(doc: dict[str, Any] | None) -> Policy:
    """Validate a ConfigPolicy document; semantic errors are 422."""
    try:
        return Policy.parse(doc)
    except PolicyError as exc:
        raise unprocessable(str(exc)) from exc


def write_audit(
    tdb: TenantDB,
    actor: str,
    action: AuditAction,
    target: TargetType,
    target_pid: uuid.UUID | None,
) -> None:
    """Record one admin write in audit_events; a failed write fails the request."""
    tdb.insert(
        "audit_events",
        action=int(action),
        target_type=int(target),
        target_public_id=target_pid,
        actor=actor,
    )


def _if_match(current: str, if_match: str | None) -> None:
    """Raise 412 unless If-Match is absent or equals the current ETag."""
    if if_match is not None and if_match.strip() != current:
        raise precondition_failed()


def page_scan(fetch: Any, after: int, limit: int, keep: Any) -> tuple[list[Any], str | None]:
    """Scan id-ordered batches until ``limit`` rows pass ``keep``; return (items, next_cursor).

    ``fetch(after_id, batch)`` returns rows with id > after_id in id order. Scanning continues
    past filtered-out rows so a filtered page is still full while more rows exist.
    """
    out: list[Any] = []
    cursor_id = after
    scanned = 0
    while len(out) <= limit and scanned < _MAX_PAGE_SCAN:
        batch = fetch(cursor_id, limit + 1)
        if not batch:
            return out[:limit], None
        for row in batch:
            cursor_id = int(row.id)
            scanned += 1
            if keep(row):
                out.append(row)
                if len(out) > limit:
                    break
        if len(batch) <= limit and len(out) <= limit:
            return out[:limit], None
    if len(out) > limit:
        return out[:limit], encode_cursor(int(out[limit - 1].id))
    return out, None


# ---- groups -------------------------------------------------------------------------------


def group_row(tdb: TenantDB, group_pid: uuid.UUID) -> Row:
    """Return the tenant's group with ``group_pid`` or raise 404."""
    row = tdb.get("groups", group_pid)
    if row is None:
        raise not_found("group")
    return row


def group_etag(row: Row) -> str:
    """Return the strong ETag of a group (digest of its mutable fields)."""
    return ConfigRevision.of(
        {
            "id": str(row.public_id),
            "name": row.name,
            "description": row.description,
            "policy": row.policy,
            "updated_at": iso(row.updated_at),
        }
    ).etag


def group_agent_count(tdb: TenantDB, group_id: int) -> int:
    """Return how many agents are members of a group."""
    return tdb.count("group_members", tdb.field("group_members", "group_id") == group_id)


def list_groups(
    tdb: TenantDB, after: int, limit: int, name_prefix: str | None
) -> tuple[list[Row], str | None]:
    """Return one page of groups ordered by internal id, optionally by name prefix."""

    def fetch(after_id: int, batch: int) -> list[Row]:
        """Fetch the next id-ordered batch of groups."""
        query = tdb.field("groups", "id") > after_id
        if name_prefix:
            query = query & tdb.field("groups", "name").startswith(name_prefix)
        return tdb.select("groups", query, limitby=(0, batch))

    return page_scan(fetch, after, limit, lambda _r: True)


def create_group(tdb: TenantDB, body: GroupCreate, actor: str) -> Row:
    """Create a group after checking the tenant-unique name; audit the write."""
    if tdb.count("groups", tdb.field("groups", "name") == body.name):
        raise conflict(f"group name {body.name!r} already exists")
    policy = parse_policy(body.policy).to_doc()
    row = tdb.insert(
        "groups", name=body.name, description=body.description, policy=policy, created_by=actor
    )
    write_audit(tdb, actor, AuditAction.GROUP_CREATE, TargetType.GROUP, row.public_id)
    return row


def update_group(
    tdb: TenantDB, group_pid: uuid.UUID, body: GroupUpdate, if_match: str | None, actor: str
) -> Row:
    """Apply a PATCH after the If-Match precondition; a renamed group must stay unique."""
    current = group_row(tdb, group_pid)
    _if_match(group_etag(current), if_match)
    values: dict[str, Any] = {}
    if body.name is not None and body.name != current.name:
        if tdb.count("groups", tdb.field("groups", "name") == body.name):
            raise conflict(f"group name {body.name!r} already exists")
        values["name"] = body.name
    if body.description is not None:
        values["description"] = body.description
    if body.policy is not None:
        values["policy"] = parse_policy(body.policy).to_doc()
    if values:
        tdb.update("groups", group_pid, **values)
    row = group_row(tdb, group_pid)
    write_audit(tdb, actor, AuditAction.GROUP_UPDATE, TargetType.GROUP, group_pid)
    return row


def delete_group(tdb: TenantDB, group_pid: uuid.UUID, actor: str) -> None:
    """Delete a group; memberships, module assignments and scoped flags cascade."""
    group_row(tdb, group_pid)
    tdb.delete("groups", tdb.field("groups", "public_id") == group_pid)
    write_audit(tdb, actor, AuditAction.GROUP_DELETE, TargetType.GROUP, group_pid)


def set_members(
    tdb: TenantDB, group_pid: uuid.UUID, agent_pids: list[str], actor: str
) -> list[str]:
    """Replace a group's membership with the given agents (all must exist in the tenant)."""
    group = group_row(tdb, group_pid)
    agents = []
    for raw in agent_pids:
        agent = tdb.get("agents", parse_pid(raw, "agent"))
        if agent is None:
            raise not_found("agent")
        agents.append(agent)
    tdb.delete("group_members", tdb.field("group_members", "group_id") == group.id)
    for agent in agents:
        tdb.insert("group_members", group_id=group.id, agent_id=agent.id)
    write_audit(tdb, actor, AuditAction.GROUP_MEMBERS_SET, TargetType.GROUP, group_pid)
    return [str(a.public_id) for a in agents]


def list_group_modules(tdb: TenantDB, group_pid: uuid.UUID) -> list[ModuleAssignment]:
    """Return the module versions assigned to a group."""
    group = group_row(tdb, group_pid)
    links = tdb.select("group_modules", tdb.field("group_modules", "group_id") == group.id)
    out: list[ModuleAssignment] = []
    for link in links:
        mv = tdb.get_by_id("module_versions", link.module_version_id)
        if mv is not None:
            out.append(ModuleAssignment(str(mv.public_id), mv.module_id, mv.version))
    return out


def set_group_modules(
    tdb: TenantDB, group_pid: uuid.UUID, version_pids: list[str], actor: str
) -> list[ModuleAssignment]:
    """Replace a group's module assignments; unknown or yanked versions are 422."""
    group = group_row(tdb, group_pid)
    versions: dict[str, Row] = {}
    for raw in version_pids:
        mv = tdb.get("module_versions", parse_pid(raw, "module version"))
        if mv is None or int(mv.status) != ModuleStatus.AVAILABLE:
            raise unprocessable(f"module version {raw} is unknown or yanked")
        versions[str(mv.public_id)] = mv
    tdb.delete("group_modules", tdb.field("group_modules", "group_id") == group.id)
    for mv in versions.values():
        tdb.insert("group_modules", group_id=group.id, module_version_id=mv.id)
    write_audit(tdb, actor, AuditAction.GROUP_MODULES_SET, TargetType.GROUP, group_pid)
    return [ModuleAssignment(pid, mv.module_id, mv.version) for pid, mv in versions.items()]


# ---- agents -------------------------------------------------------------------------------


def agent_row(tdb: TenantDB, agent_pid: uuid.UUID) -> Row:
    """Return the tenant's agent with ``agent_pid`` or raise 404."""
    row = tdb.get("agents", agent_pid)
    if row is None:
        raise not_found("agent")
    return row


def agent_group_pids(tdb: TenantDB, agent_id: int) -> list[str]:
    """Return the public ids of every group the agent belongs to."""
    links = tdb.select("group_members", tdb.field("group_members", "agent_id") == agent_id)
    out: list[str] = []
    for link in links:
        group = tdb.get_by_id("groups", link.group_id)
        if group is not None:
            out.append(str(group.public_id))
    return sorted(out)


def computed_status(row: Row, stale_after_s: int, now: dt.datetime) -> int:
    """Return AgentStatus: revoked if revoked, stale if never seen or silent too long."""
    if int(row.status) == AgentStatus.REVOKED:
        return int(AgentStatus.REVOKED)
    last = row.last_seen_at
    if last is None or (now - last).total_seconds() > stale_after_s:
        return int(AgentStatus.STALE)
    return int(AgentStatus.ACTIVE)


def create_agent(tdb: TenantDB, body: AgentCreate, actor: str) -> Row:
    """Pre-register an agent's SPIFFE identity and group membership (no credentials issued)."""
    spiffe = body.spiffe_id.strip()
    if not spiffe.startswith("spiffe://") or len(spiffe) > 512:
        raise bad_request("spiffe_id must be a spiffe:// URI")
    if tdb.count("agents", tdb.field("agents", "spiffe_id") == spiffe):
        raise conflict("spiffe_id already registered")
    if body.platform not in {int(p) for p in Platform}:
        raise unprocessable("unknown platform code")
    groups = []
    for raw in body.group_ids:
        group = tdb.get("groups", parse_pid(raw, "group"))
        if group is None:
            raise not_found("group")
        groups.append(group)
    row = tdb.insert(
        "agents",
        status=int(AgentStatus.ACTIVE),
        platform=body.platform,
        agent_version=body.agent_version,
        spiffe_id=spiffe,
    )
    for group in groups:
        tdb.insert("group_members", group_id=group.id, agent_id=row.id)
    write_audit(tdb, actor, AuditAction.AGENT_CREATE, TargetType.AGENT, row.public_id)
    return row


def revoke_agent(tdb: TenantDB, agent_pid: uuid.UUID, actor: str) -> None:
    """Revoke an agent and every refresh token it holds; its next call gets 410."""
    agent = agent_row(tdb, agent_pid)
    tdb.update("agents", agent_pid, status=int(AgentStatus.REVOKED))
    now = dt.datetime.now(dt.UTC)
    for token in tdb.select("refresh_tokens", tdb.field("refresh_tokens", "agent_id") == agent.id):
        if token.revoked_at is None:
            tdb.update("refresh_tokens", token.public_id, revoked_at=now)
    write_audit(tdb, actor, AuditAction.AGENT_REVOKE, TargetType.AGENT, agent_pid)


def override_etag(row: Row) -> str:
    """Return the ETag of an agent override (digest of the stored override document)."""
    return ConfigRevision.of(row.override or {}).etag


def set_override(
    tdb: TenantDB, agent_pid: uuid.UUID, doc: dict[str, Any], if_match: str | None, actor: str
) -> dict[str, Any]:
    """Store an agent override after the If-Match check; returns the canonical document."""
    row = agent_row(tdb, agent_pid)
    _if_match(override_etag(row), if_match)
    canonical = parse_policy(doc).to_doc()
    tdb.update("agents", agent_pid, override=canonical)
    write_audit(tdb, actor, AuditAction.AGENT_OVERRIDE_SET, TargetType.AGENT, agent_pid)
    return canonical


def clear_override(tdb: TenantDB, agent_pid: uuid.UUID, actor: str) -> None:
    """Remove an agent's override so the group merge applies again."""
    agent_row(tdb, agent_pid)
    tdb.update("agents", agent_pid, override=None)
    write_audit(tdb, actor, AuditAction.AGENT_OVERRIDE_CLEAR, TargetType.AGENT, agent_pid)


def effective_doc(tdb: TenantDB, agent_pid: uuid.UUID) -> dict[str, Any]:
    """Return the agent's computed effective ConfigPolicy document."""
    policy = effective_config(tdb, agent_pid)
    if policy is None:
        raise not_found("agent")
    return policy.to_doc()


# ---- bootstrap tokens ---------------------------------------------------------------------


def digest(secret: str) -> str:
    """Return the sha256 hex digest stored for a high-entropy secret (indexed lookup)."""
    return hashlib.sha256(secret.encode()).hexdigest()


def create_bootstrap(tdb: TenantDB, body: BootstrapTokenCreate, actor: str) -> tuple[Row, str]:
    """Mint a one-time bootstrap token; return (row, plaintext secret shown once)."""
    if not BOOTSTRAP_TTL_MIN_S <= body.ttl_s <= BOOTSTRAP_TTL_MAX_S:
        raise bad_request("ttl_s must be between 60 and 604800")
    group_ids: list[str] = []
    for raw in body.group_ids:
        group = tdb.get("groups", parse_pid(raw, "group"))
        if group is None:
            raise bad_request(f"group {raw} not found in tenant")
        group_ids.append(str(group.public_id))
    secret = secrets.token_urlsafe(32)
    expires = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=body.ttl_s)
    row = tdb.insert(
        "bootstrap_tokens",
        token_hash=digest(secret),
        group_ids=group_ids,
        expires_at=expires,
        created_by=actor,
    )
    write_audit(tdb, actor, AuditAction.BOOTSTRAP_CREATE, TargetType.BOOTSTRAP_TOKEN, row.public_id)
    return row, secret


def bootstrap_dto(tdb: TenantDB, row: Row) -> dict[str, Any]:
    """Return the public metadata of a bootstrap token row (no secret).

    ``used_by_agent_id`` is translated to the agent's public id; the internal PK never leaves.
    """
    used_by: str | None = None
    if row.used_by_agent_id is not None:
        agent = tdb.get_by_id("agents", int(row.used_by_agent_id))
        used_by = None if agent is None else str(agent.public_id)
    return {
        "id": str(row.public_id),
        "group_ids": list(row.group_ids or []),
        "expires_at": iso(row.expires_at),
        "used": row.used_by_agent_id is not None,
        "used_by_agent_id": used_by,
    }


def bootstrap_secret_dto(tdb: TenantDB, row: Row, secret: str) -> BootstrapTokenSecret:
    """Build the one-time creation response."""
    meta = bootstrap_dto(tdb, row)
    return BootstrapTokenSecret(
        id=meta["id"],
        expires_at=meta["expires_at"],
        used=meta["used"],
        group_ids=meta["group_ids"],
        used_by_agent_id=meta["used_by_agent_id"],
        token=secret,
    )


def list_bootstrap(tdb: TenantDB, after: int, limit: int) -> tuple[list[Row], str | None]:
    """Return one page of bootstrap token metadata."""

    def fetch(after_id: int, batch: int) -> list[Row]:
        """Fetch the next id-ordered batch of tokens."""
        return tdb.select(
            "bootstrap_tokens", tdb.field("bootstrap_tokens", "id") > after_id, limitby=(0, batch)
        )

    return page_scan(fetch, after, limit, lambda _r: True)


def revoke_bootstrap(tdb: TenantDB, token_pid: uuid.UUID, actor: str) -> None:
    """Delete an unused bootstrap token; a used token is a 409 (the agent already enrolled)."""
    row = tdb.get("bootstrap_tokens", token_pid)
    if row is None:
        raise not_found("bootstrap token")
    if row.used_by_agent_id is not None:
        raise conflict("bootstrap token already used")
    tdb.delete("bootstrap_tokens", tdb.field("bootstrap_tokens", "public_id") == token_pid)
    write_audit(tdb, actor, AuditAction.BOOTSTRAP_REVOKE, TargetType.BOOTSTRAP_TOKEN, token_pid)


# ---- modules ------------------------------------------------------------------------------


def module_dto(row: Row) -> dict[str, Any]:
    """Return the Module wire shape for a module_versions row."""
    return {
        "id": str(row.public_id),
        "module_id": row.module_id,
        "version": row.version,
        "sha256": row.sha256,
        "signature": row.signature,
        "status": int(row.status),
        "size_bytes": int(row.size_bytes),
        "created_at": iso(row.created_at),
    }


def module_row(tdb: TenantDB, module_pid: uuid.UUID) -> Row:
    """Return the tenant's module version or raise 404."""
    row = tdb.get("module_versions", module_pid)
    if row is None:
        raise not_found("module version")
    return row


def ensure_version_free(tdb: TenantDB, module_id: str, version: str) -> None:
    """Reject a second (module_id, version) in the tenant with 409."""
    query = (tdb.field("module_versions", "module_id") == module_id) & (
        tdb.field("module_versions", "version") == version
    )
    if tdb.count("module_versions", query):
        raise conflict(f"{module_id} {version} already exists")


def list_modules(
    tdb: TenantDB, after: int, limit: int, module_id: str | None, status: int | None
) -> tuple[list[Row], str | None]:
    """Return one page of module versions, filtered by module id and/or status."""

    def fetch(after_id: int, batch: int) -> list[Row]:
        """Fetch the next id-ordered batch of module versions."""
        return tdb.select(
            "module_versions", tdb.field("module_versions", "id") > after_id, limitby=(0, batch)
        )

    def keep(row: Row) -> bool:
        """Apply the optional module id and status filters."""
        if module_id is not None and row.module_id != module_id:
            return False
        return status is None or int(row.status) == status

    return page_scan(fetch, after, limit, keep)


def set_module_status(tdb: TenantDB, module_pid: uuid.UUID, status: int, actor: str) -> Row:
    """Change a module version's status (yank = 2); yanked versions leave agent manifests."""
    if status not in {int(s) for s in ModuleStatus}:
        raise unprocessable("unknown module status code")
    module_row(tdb, module_pid)
    tdb.update("module_versions", module_pid, status=status)
    write_audit(tdb, actor, AuditAction.MODULE_STATUS_SET, TargetType.MODULE, module_pid)
    return module_row(tdb, module_pid)


# ---- flags --------------------------------------------------------------------------------


def flag_dto(row: Row, group_pid: str | None) -> dict[str, Any]:
    """Return the Flag wire shape; group_pid is supplied by the caller (group rows are separate)."""
    return {
        "id": str(row.public_id),
        "key": row.key,
        "enabled": bool(row.enabled),
        "scope": int(row.scope),
        "group_id": group_pid,
        "updated_at": iso(row.updated_at),
    }


def group_pid_for(tdb: TenantDB, group_id: int | None) -> str | None:
    """Return the public id of an internal group id, or None for tenant-scoped flags."""
    if group_id is None:
        return None
    group = tdb.get_by_id("groups", group_id)
    return None if group is None else str(group.public_id)


def list_flags(
    tdb: TenantDB, after: int, limit: int, group_pid: uuid.UUID | None
) -> tuple[list[Row], str | None]:
    """Return one page of flags, optionally only those scoped to one group."""
    group_id: int | None = None
    if group_pid is not None:
        group_id = group_row(tdb, group_pid).id

    def fetch(after_id: int, batch: int) -> list[Row]:
        """Fetch the next id-ordered batch of flags."""
        return tdb.select("flags", tdb.field("flags", "id") > after_id, limitby=(0, batch))

    def keep(row: Row) -> bool:
        """Keep only flags of the requested group when a filter was given."""
        return group_pid is None or row.group_id == group_id

    return page_scan(fetch, after, limit, keep)


def upsert_flag(tdb: TenantDB, body: FlagInput, actor: str) -> Row:
    """Create or update a flag at tenant or group scope; keys match the contract pattern."""
    if not FLAG_KEY_RE.match(body.key):
        raise unprocessable("flag key must match {product}.{feature}")
    if body.scope not in {int(s) for s in FlagScope}:
        raise unprocessable("unknown flag scope code")
    group_id: int | None = None
    if body.scope == int(FlagScope.GROUP):
        if body.group_id is None:
            raise unprocessable("group-scoped flag requires group_id")
        group_id = group_row(tdb, parse_pid(body.group_id, "group")).id
    elif body.group_id is not None:
        raise unprocessable("tenant-scoped flag must not set group_id")
    existing = [
        f
        for f in tdb.select("flags", tdb.field("flags", "key") == body.key)
        if int(f.scope) == body.scope and f.group_id == group_id
    ]
    try:
        if existing:
            tdb.update("flags", existing[0].public_id, enabled=body.enabled)
            row = tdb.get("flags", existing[0].public_id)
            pid = existing[0].public_id
        else:
            row = tdb.insert(
                "flags", key=body.key, enabled=body.enabled, scope=body.scope, group_id=group_id
            )
            pid = row.public_id
    except TenantViolationError as exc:
        raise not_found("group") from exc
    if row is None:
        raise RuntimeError("flag vanished immediately after write")
    write_audit(tdb, actor, AuditAction.FLAG_UPSERT, TargetType.FLAG, pid)
    return row


def delete_flag(tdb: TenantDB, flag_pid: uuid.UUID, actor: str) -> None:
    """Delete a flag, removing its restriction."""
    if tdb.get("flags", flag_pid) is None:
        raise not_found("flag")
    tdb.delete("flags", tdb.field("flags", "public_id") == flag_pid)
    write_audit(tdb, actor, AuditAction.FLAG_DELETE, TargetType.FLAG, flag_pid)


# ---- audit --------------------------------------------------------------------------------


def list_audit(tdb: TenantDB, after: int, limit: int) -> tuple[list[Row], str | None]:
    """Return one page of audit events for the tenant, oldest first."""

    def fetch(after_id: int, batch: int) -> list[Row]:
        """Fetch the next id-ordered batch of audit events."""
        return tdb.select(
            "audit_events", tdb.field("audit_events", "id") > after_id, limitby=(0, batch)
        )

    return page_scan(fetch, after, limit, lambda _r: True)


def audit_dto(row: Row) -> dict[str, Any]:
    """Return the AuditEvent wire shape: public ids and int codes only."""
    return {
        "id": str(row.public_id),
        "action": int(row.action),
        "target_type": int(row.target_type),
        "target_id": None if row.target_public_id is None else str(row.target_public_id),
        "actor": row.actor,
        "created_at": iso(row.created_at),
    }
