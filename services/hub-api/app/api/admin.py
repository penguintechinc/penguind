"""Admin API blueprint: /api/v1 groups, agents, bootstrap tokens, modules, flags, audit.

Decorator order per route (outermost first): flag gate, admin auth (verify -> tenant ->
scope), body validation, response validation. Writes call the service layer, which records
an audit event before the response is returned.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import re
import uuid
from typing import Any

from quart import Blueprint, request
from quart_schema import validate_request, validate_response

from app import service
from app.api.common import actor, admin_tdb, cursor_arg, if_match, limit_arg, run, with_etag
from app.blobs import BlobError, spool_and_hash
from app.context import decode_cursor, hub
from app.dto import (
    Agent,
    AgentCreate,
    AgentDetail,
    AuditEvent,
    BootstrapToken,
    BootstrapTokenCreate,
    BootstrapTokenSecret,
    Flag,
    FlagInput,
    Group,
    GroupCreate,
    GroupUpdate,
    MemberSet,
    Module,
    ModuleAssignment,
    ModuleAssignmentInput,
    ModuleStatusUpdate,
)
from app.envelope import envelope, envelope_type, iso, page_type
from app.flags import FLAG_ADMIN_API, FLAG_MODULE_UPLOAD
from app.guards import require_admin, require_flag
from app.models import AgentStatus, AuditAction, ModuleStatus, TargetType, TenantDB
from app.models.policy import ConfigRevision
from app.problems import bad_request, too_large, unavailable, unprocessable
from app.service import parse_pid
from app.signing import MinisignKey, SignatureInvalidError, verify_module_signature

bp = Blueprint("admin", __name__, url_prefix="/api/v1")
_log = logging.getLogger(__name__)
_ADMIN = require_flag(FLAG_ADMIN_API)
MODULE_ID_RE = re.compile(r"[a-z][a-z0-9-]{1,62}")
SEMVER_RE = re.compile(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?")
SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _group_dto(tdb: TenantDB, row: Any) -> Group:
    """Map a groups row to the Group DTO (with live agent count)."""
    return Group(
        id=str(row.public_id),
        name=row.name,
        description=row.description or "",
        policy=row.policy,
        agent_count=service.group_agent_count(tdb, int(row.id)),
        created_at=iso(row.created_at) or "",
        updated_at=iso(row.updated_at) or "",
    )


def _agent_dto(tdb: TenantDB, row: Any, now: dt.datetime) -> Agent:
    """Map an agents row to the Agent DTO; status is computed on read."""
    return Agent(
        id=str(row.public_id),
        status=service.computed_status(row, hub().settings.stale_after_s, now),
        platform=int(row.platform),
        agent_version=row.agent_version,
        group_ids=service.agent_group_pids(tdb, int(row.id)),
        enrolled_at=iso(row.created_at) or "",
        last_seen_at=iso(row.last_seen_at),
        applied_etag=row.applied_etag,
    )


def _page_items(items: list[Any], nxt: str | None, item_type: type) -> Any:
    """Build the typed page object for a list response."""
    return page_type(item_type)(items=items, next_cursor=nxt)


@bp.get("/groups")
@_ADMIN
@require_admin("hub:groups:read")
@validate_response(envelope_type(page_type(Group)))
async def list_groups() -> Any:
    """List groups in the caller's tenant, optionally by name prefix."""
    tdb = admin_tdb()
    rows, nxt = await run(
        service.list_groups,
        tdb,
        decode_cursor(cursor_arg()),
        limit_arg(),
        request.args.get("name_prefix"),
    )
    items = await run(lambda: [_group_dto(tdb, r) for r in rows])
    return envelope(page_type(Group), _page_items(items, nxt, Group))


@bp.post("/groups")
@_ADMIN
@require_admin("hub:groups:write")
@validate_request(GroupCreate)
@validate_response(envelope_type(Group), status_code=201)
async def create_group(data: GroupCreate) -> Any:
    """Create a group; 409 on a duplicate name."""
    tdb = admin_tdb()
    row = await run(service.create_group, tdb, data, actor())
    dto = await run(_group_dto, tdb, row)
    return with_etag(envelope(Group, dto), service.group_etag(row)), 201


@bp.get("/groups/<group_id>")
@_ADMIN
@require_admin("hub:groups:read")
@validate_response(envelope_type(Group))
async def get_group(group_id: str) -> Any:
    """Return one group with its ETag."""
    tdb = admin_tdb()
    row = await run(service.group_row, tdb, parse_pid(group_id, "group"))
    dto = await run(_group_dto, tdb, row)
    return with_etag(envelope(Group, dto), service.group_etag(row)), 200


@bp.patch("/groups/<group_id>")
@_ADMIN
@require_admin("hub:groups:write")
@validate_request(GroupUpdate)
@validate_response(envelope_type(Group))
async def update_group(group_id: str, data: GroupUpdate) -> Any:
    """Patch a group; If-Match guards against lost updates (412)."""
    tdb = admin_tdb()
    row = await run(
        service.update_group, tdb, parse_pid(group_id, "group"), data, if_match(), actor()
    )
    dto = await run(_group_dto, tdb, row)
    return with_etag(envelope(Group, dto), service.group_etag(row)), 200


@bp.delete("/groups/<group_id>")
@_ADMIN
@require_admin("hub:groups:write")
async def delete_group(group_id: str) -> Any:
    """Delete a group; agents lose its assignments on their next poll."""
    await run(service.delete_group, admin_tdb(), parse_pid(group_id, "group"), actor())
    return "", 204


@bp.put("/groups/<group_id>/members")
@_ADMIN
@require_admin("hub:groups:write")
@validate_request(MemberSet)
@validate_response(envelope_type(MemberSet))
async def set_group_members(group_id: str, data: MemberSet) -> Any:
    """Replace the group's membership with the given agent set."""
    ids = await run(
        service.set_members,
        admin_tdb(),
        parse_pid(group_id, "group"),
        list(data.agent_ids),
        actor(),
    )
    return envelope(MemberSet, MemberSet(agent_ids=ids))


@bp.get("/groups/<group_id>/modules")
@_ADMIN
@require_admin("hub:groups:read")
@validate_response(envelope_type(list[ModuleAssignment]))
async def list_group_modules(group_id: str) -> Any:
    """List module versions assigned to a group."""
    items = await run(service.list_group_modules, admin_tdb(), parse_pid(group_id, "group"))
    return envelope(list[ModuleAssignment], items)


@bp.put("/groups/<group_id>/modules")
@_ADMIN
@require_admin("hub:groups:write")
@validate_response(envelope_type(list[ModuleAssignment]))
async def set_group_modules(group_id: str) -> Any:
    """Replace the group's module assignments (JSON array, max 256 entries)."""
    raw = await request.get_json()
    if not isinstance(raw, list) or len(raw) > 256:
        raise bad_request("body must be an array of at most 256 assignments")
    inputs = [ModuleAssignmentInput(**_strict(item, {"module_version_id"})) for item in raw]
    items = await run(
        service.set_group_modules,
        admin_tdb(),
        parse_pid(group_id, "group"),
        [i.module_version_id for i in inputs],
        actor(),
    )
    return envelope(list[ModuleAssignment], items)


def _strict(item: Any, allowed: set[str]) -> dict[str, Any]:
    """Require a JSON object whose only keys are ``allowed``; return it as kwargs."""
    if not isinstance(item, dict) or set(item) - allowed or not set(item) == allowed:
        raise bad_request(f"assignment must be an object with exactly {sorted(allowed)}")
    return {k: str(v) for k, v in item.items()}


@bp.get("/agents")
@_ADMIN
@require_admin("hub:agents:read")
@validate_response(envelope_type(page_type(Agent)))
async def list_agents() -> Any:
    """List agents, filtered by group, computed status and staleness."""
    tdb = admin_tdb()
    group_raw = request.args.get("group_id")
    status_raw = request.args.get("status")
    stale_raw = request.args.get("stale")
    status_filter = None if status_raw is None else _int_arg("status", status_raw)
    stale_filter = None if stale_raw is None else stale_raw.lower() in {"1", "true"}
    group_pid = None if group_raw is None else parse_pid(group_raw, "group")
    rows, nxt = await run(
        _list_agents_sync,
        tdb,
        decode_cursor(cursor_arg()),
        limit_arg(),
        group_pid,
        status_filter,
        stale_filter,
    )
    items = await run(lambda: [_agent_dto(tdb, r, dt.datetime.now(dt.UTC)) for r in rows])
    return envelope(page_type(Agent), _page_items(items, nxt, Agent))


def _int_arg(name: str, raw: str) -> int:
    """Parse an integer query parameter or raise 400."""
    if not raw.lstrip("-").isdigit():
        raise bad_request(f"{name} must be an integer code")
    return int(raw)


def _list_agents_sync(
    tdb: TenantDB,
    after: int,
    limit: int,
    group_pid: uuid.UUID | None,
    status: int | None,
    stale: bool | None,
) -> tuple[list[Any], str | None]:
    """Scan agents applying the group, status and stale filters (computed on read)."""
    member_ids: set[int] | None = None
    if group_pid is not None:
        group = service.group_row(tdb, group_pid)
        member_ids = {
            int(link.agent_id)
            for link in tdb.select(
                "group_members", tdb.field("group_members", "group_id") == group.id
            )
        }
    now = dt.datetime.now(dt.UTC)
    stale_after = hub().settings.stale_after_s

    def fetch(after_id: int, batch: int) -> list[Any]:
        """Fetch the next id-ordered batch of agents."""
        return tdb.select("agents", tdb.field("agents", "id") > after_id, limitby=(0, batch))

    def keep(row: Any) -> bool:
        """Apply every requested filter to one agent row."""
        if member_ids is not None and int(row.id) not in member_ids:
            return False
        computed = service.computed_status(row, stale_after, now)
        if status is not None and computed != status:
            return False
        if stale is not None and (computed == int(AgentStatus.STALE)) != stale:
            return False
        return True

    return service.page_scan(fetch, after, limit, keep)


@bp.post("/agents")
@_ADMIN
@require_admin("hub:agents:write")
@validate_request(AgentCreate)
@validate_response(envelope_type(Agent), status_code=201)
async def create_agent(data: AgentCreate) -> Any:
    """Pre-register an agent's SPIFFE identity and group membership."""
    tdb = admin_tdb()
    row = await run(service.create_agent, tdb, data, actor())
    dto = await run(_agent_dto, tdb, row, dt.datetime.now(dt.UTC))
    return envelope(Agent, dto), 201


@bp.get("/agents/<agent_id>")
@_ADMIN
@require_admin("hub:agents:read")
@validate_response(envelope_type(AgentDetail))
async def get_agent(agent_id: str) -> Any:
    """Return an agent with its override, effective policy and last report."""
    tdb = admin_tdb()
    pid = parse_pid(agent_id, "agent")
    row = await run(service.agent_row, tdb, pid)
    now = dt.datetime.now(dt.UTC)
    base = await run(_agent_dto, tdb, row, now)
    effective = await run(service.effective_doc, tdb, pid)
    detail = AgentDetail(
        **{k: getattr(base, k) for k in base.__dataclass_fields__},
        effective=effective,
        override=row.override,
        last_report=row.last_report,
    )
    etag = service.override_etag(row)  # If-Match on PUT override is checked against this
    return with_etag(envelope(AgentDetail, detail), etag), 200


@bp.delete("/agents/<agent_id>")
@_ADMIN
@require_admin("hub:agents:write")
async def revoke_agent(agent_id: str) -> Any:
    """Revoke an agent: credentials stop working and it receives 410."""
    await run(service.revoke_agent, admin_tdb(), parse_pid(agent_id, "agent"), actor())
    return "", 204


@bp.put("/agents/<agent_id>/override")
@_ADMIN
@require_admin("hub:agents:write")
@validate_response(envelope_type(dict))
async def set_agent_override(agent_id: str) -> Any:
    """Set the agent-level override (validated as ConfigPolicy); If-Match optional."""
    body = await request.get_json()
    if not isinstance(body, dict):
        raise bad_request("body must be a ConfigPolicy object")
    doc = await run(
        service.set_override, admin_tdb(), parse_pid(agent_id, "agent"), body, if_match(), actor()
    )
    return with_etag(envelope(dict, doc), ConfigRevision.of(doc).etag), 200


@bp.delete("/agents/<agent_id>/override")
@_ADMIN
@require_admin("hub:agents:write")
async def clear_agent_override(agent_id: str) -> Any:
    """Remove the agent-level override."""
    await run(service.clear_override, admin_tdb(), parse_pid(agent_id, "agent"), actor())
    return "", 204


@bp.post("/bootstrap-tokens")
@_ADMIN
@require_admin("hub:bootstrap:write")
@validate_request(BootstrapTokenCreate)
@validate_response(envelope_type(BootstrapTokenSecret), status_code=201)
async def create_bootstrap_token(data: BootstrapTokenCreate) -> Any:
    """Mint a one-time bootstrap token; the secret is returned only in this response."""
    row, secret = await run(service.create_bootstrap, admin_tdb(), data, actor())
    dto = service.bootstrap_secret_dto(admin_tdb(), row, secret)
    return envelope(BootstrapTokenSecret, dto), 201


@bp.get("/bootstrap-tokens")
@_ADMIN
@require_admin("hub:bootstrap:read")
@validate_response(envelope_type(page_type(BootstrapToken)))
async def list_bootstrap_tokens() -> Any:
    """List bootstrap token metadata (never secrets)."""
    rows, nxt = await run(
        service.list_bootstrap, admin_tdb(), decode_cursor(cursor_arg()), limit_arg()
    )
    tdb = admin_tdb()
    items = [BootstrapToken(**service.bootstrap_dto(tdb, r)) for r in rows]
    return envelope(page_type(BootstrapToken), _page_items(items, nxt, BootstrapToken))


@bp.delete("/bootstrap-tokens/<token_id>")
@_ADMIN
@require_admin("hub:bootstrap:write")
async def revoke_bootstrap_token(token_id: str) -> Any:
    """Revoke an unused bootstrap token."""
    await run(
        service.revoke_bootstrap, admin_tdb(), parse_pid(token_id, "bootstrap token"), actor()
    )
    return "", 204


@bp.get("/modules")
@_ADMIN
@require_admin("hub:modules:read")
@validate_response(envelope_type(page_type(Module)))
async def list_modules() -> Any:
    """List module versions, optionally filtered by module id and status."""
    module_id = request.args.get("module_id")
    status_raw = request.args.get("status")
    status = None if status_raw is None else _int_arg("status", status_raw)
    rows, nxt = await run(
        service.list_modules,
        admin_tdb(),
        decode_cursor(cursor_arg()),
        limit_arg(),
        module_id,
        status,
    )
    items = [Module(**service.module_dto(r)) for r in rows]
    return envelope(page_type(Module), _page_items(items, nxt, Module))


async def _upload_fields() -> tuple[str, str, str, str | None]:
    """Read and syntax-check the multipart text fields of a module upload."""
    form = await request.form
    module_id = form.get("module_id", "")
    version = form.get("version", "")
    signature = form.get("signature", "")
    sha_claim = form.get("sha256") or None
    if not MODULE_ID_RE.fullmatch(module_id):
        raise unprocessable("module_id must match ^[a-z][a-z0-9-]{1,62}$")
    if not SEMVER_RE.fullmatch(version):
        raise unprocessable("version must be SemVer")
    if not signature.strip() or len(signature) > 4096:
        raise unprocessable("signature is required (max 4096 chars)")
    if sha_claim is not None and not SHA256_RE.fullmatch(sha_claim):
        raise unprocessable("sha256 must be 64 lowercase hex chars")
    return module_id, version, signature.strip(), sha_claim


def _verify_signature(ctx: Any, module_id: str, version: str, sha: str, signature: str) -> None:
    """Early-reject a signature that no configured trusted key verifies (no-op when unset)."""
    if not ctx.settings.trusted_pubkeys:
        return
    try:
        keys = tuple(MinisignKey.parse(k) for k in ctx.settings.trusted_pubkeys)
        ok = verify_module_signature(keys, module_id, version, sha, signature)
    except SignatureInvalidError as exc:
        ctx.telemetry.instruments.module_verify.add(1, {"result": "fail"})
        raise unprocessable(str(exc)) from exc
    ctx.telemetry.instruments.module_verify.add(1, {"result": "ok" if ok else "fail"})
    if not ok:
        raise unprocessable("signature does not verify against a trusted key")


def _insert_module(
    tdb: TenantDB, who: str, module_id: str, version: str, sha: str, sig: str, size: int, key: str
) -> Any:
    """Insert the version row and audit it (run in a worker thread; ``who`` is precomputed)."""
    row = tdb.insert(
        "module_versions",
        module_id=module_id,
        version=version,
        sha256=sha,
        signature=sig,
        size_bytes=size,
        blob_key=key,
        status=int(ModuleStatus.AVAILABLE),
        created_by=who,
    )
    service.write_audit(tdb, who, AuditAction.MODULE_UPLOAD, TargetType.MODULE, row.public_id)
    return row


@bp.post("/modules")
@require_flag(FLAG_MODULE_UPLOAD)
@require_admin("hub:modules:write")
@validate_response(envelope_type(Module), status_code=201)
async def upload_module() -> Any:
    """Upload a pre-signed WASM module: stream with a size cap, recompute sha256, store with SSE."""
    ctx = hub()
    cap = ctx.settings.max_upload_bytes
    if request.content_length is not None and request.content_length > cap + 65536:
        raise too_large(f"module exceeds {cap} bytes")
    module_id, version, signature, sha_claim = await _upload_fields()
    who = actor()
    files = await request.files
    binary = files.get("binary")
    if binary is None:
        raise bad_request("binary part is required")
    spool, sha, size = await asyncio.to_thread(spool_and_hash, binary.stream, cap)
    try:
        if sha_claim is not None and sha_claim != sha:
            raise unprocessable("sha256 does not match uploaded bytes")
        await asyncio.to_thread(_verify_signature, ctx, module_id, version, sha, signature)
        ctx.telemetry.instruments.upload_bytes.record(size)
        tdb = admin_tdb()
        await run(service.ensure_version_free, tdb, module_id, version)  # 409 before any storage
        key = f"modules/{tdb.tenant_id}/{module_id}/{version}/{sha}.wasm"
        try:
            await ctx.blobs.store(key, spool, size)
        except BlobError as exc:
            raise unavailable(f"blob store unavailable: {exc}") from exc
    finally:
        spool.close()
    try:
        row = await run(_insert_module, tdb, who, module_id, version, sha, signature, size, key)
    except Exception:
        await _drop_blob(ctx, key)
        raise
    return envelope(Module, Module(**service.module_dto(row))), 201


async def _drop_blob(ctx: Any, key: str) -> None:
    """Best-effort removal of a blob whose metadata insert failed."""
    try:
        await ctx.blobs.delete(key)
    except BlobError:
        _log.warning("orphaned module blob; manual cleanup needed", extra={"blob_key": key})


@bp.get("/modules/<module_version_id>")
@_ADMIN
@require_admin("hub:modules:read")
@validate_response(envelope_type(Module))
async def get_module(module_version_id: str) -> Any:
    """Return one module version."""
    row = await run(service.module_row, admin_tdb(), parse_pid(module_version_id, "module version"))
    return envelope(Module, Module(**service.module_dto(row))), 200


@bp.patch("/modules/<module_version_id>")
@_ADMIN
@require_admin("hub:modules:write")
@validate_request(ModuleStatusUpdate)
@validate_response(envelope_type(Module))
async def set_module_status(module_version_id: str, data: ModuleStatusUpdate) -> Any:
    """Change a module version's status (yank removes it from agent manifests)."""
    row = await run(
        service.set_module_status,
        admin_tdb(),
        parse_pid(module_version_id, "module version"),
        int(data.status),
        actor(),
    )
    return envelope(Module, Module(**service.module_dto(row))), 200


@bp.get("/flags")
@_ADMIN
@require_admin("hub:flags:read")
@validate_response(envelope_type(page_type(Flag)))
async def list_flags() -> Any:
    """List hub flags, optionally only those scoped to one group."""
    group_raw = request.args.get("group_id")
    group_pid = None if group_raw is None else parse_pid(group_raw, "group")
    tdb = admin_tdb()
    rows, nxt = await run(
        service.list_flags, tdb, decode_cursor(cursor_arg()), limit_arg(), group_pid
    )
    items = await run(lambda: [_flag_dto(tdb, r) for r in rows])
    return envelope(page_type(Flag), _page_items(items, nxt, Flag))


def _flag_dto(tdb: TenantDB, row: Any) -> Flag:
    """Map a flags row to the Flag DTO."""
    return Flag(**service.flag_dto(row, service.group_pid_for(tdb, row.group_id)))


@bp.put("/flags")
@_ADMIN
@require_admin("hub:flags:write")
@validate_request(FlagInput)
@validate_response(envelope_type(Flag))
async def upsert_flag(data: FlagInput) -> Any:
    """Create or update a restrict-only flag at tenant or group scope."""
    tdb = admin_tdb()
    row = await run(service.upsert_flag, tdb, data, actor())
    return envelope(Flag, _flag_dto(tdb, row)), 200


@bp.delete("/flags/<flag_id>")
@_ADMIN
@require_admin("hub:flags:write")
async def delete_flag(flag_id: str) -> Any:
    """Delete a flag, removing its restriction."""
    await run(service.delete_flag, admin_tdb(), parse_pid(flag_id, "flag"), actor())
    return "", 204


@bp.get("/audit-events")
@_ADMIN
@require_admin("hub:agents:read")
@validate_response(envelope_type(page_type(AuditEvent)))
async def list_audit_events() -> Any:
    """List audit events for the caller's tenant, oldest first."""
    rows, nxt = await run(service.list_audit, admin_tdb(), decode_cursor(cursor_arg()), limit_arg())
    items = [AuditEvent(**service.audit_dto(r)) for r in rows]
    return envelope(page_type(AuditEvent), _page_items(items, nxt, AuditEvent))
