"""Agent enrollment, refresh rotation, sync (ETag/304, manifests, flags), status, binary."""

import base64
import dataclasses
import datetime as dt
import hashlib
import io
import uuid
from collections.abc import Callable
from typing import Any

from penguin_dal import DB
from quart import Quart
from quart.testing import QuartClient
from werkzeug.datastructures import FileStorage

from app.models.identity import resolve_bootstrap
from app.service import digest
from tests.api.helpers import create_group, envelope_data

BOOT = "/api/v1/bootstrap-tokens"


async def _bootstrap(
    client: QuartClient, h: dict[str, str], group_ids: list[str] | None = None, ttl: int = 3600
) -> tuple[str, dict[str, Any]]:
    """Mint a bootstrap token; return (plaintext secret, response data)."""
    resp = await client.post(BOOT, json={"group_ids": group_ids or [], "ttl_s": ttl}, headers=h)
    assert resp.status_code == 201, await resp.get_data(as_text=True)
    data = envelope_data(await resp.get_json())
    return data["token"], data


async def _enroll(client: QuartClient, secret: str, platform: int = 1) -> Any:
    """Enroll with a bootstrap secret and return the raw response."""
    return await client.post(
        "/api/v1/agent/enroll",
        json={"platform": platform, "agent_version": "0.2.0"},
        headers={"Authorization": f"Bearer {secret}"},
    )


async def test_bootstrap_secret_shown_once_and_metadata_only_in_list(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """Creation returns the secret; the list returns metadata without any token field."""
    h = admin_headers(tenant)
    secret, data = await _bootstrap(client, h)
    assert data["token"] == secret and len(secret) >= 40
    assert set(data) == {"id", "expires_at", "used", "group_ids", "used_by_agent_id", "token"}
    listed = envelope_data(await (await client.get(BOOT, headers=h)).get_json())
    assert listed["items"] and all("token" not in item for item in listed["items"])
    assert set(listed["items"][0]) == {"id", "expires_at", "used", "group_ids", "used_by_agent_id"}


async def test_bootstrap_validation_and_revocation(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """TTL bounds and unknown groups are 400; an unused token can be revoked, a used one cannot."""
    h = admin_headers(tenant)
    assert (await client.post(BOOT, json={"ttl_s": 10}, headers=h)).status_code == 400
    assert (
        await client.post(BOOT, json={"group_ids": [str(uuid.uuid4())]}, headers=h)
    ).status_code == 400
    _secret, data = await _bootstrap(client, h)
    assert (await client.delete(f"{BOOT}/{data['id']}", headers=h)).status_code == 204
    assert (await client.delete(f"{BOOT}/{data['id']}", headers=h)).status_code == 404
    secret2, data2 = await _bootstrap(client, h)
    assert (await _enroll(client, secret2)).status_code == 201
    assert (await client.delete(f"{BOOT}/{data2['id']}", headers=h)).status_code == 409
    assert (await client.delete(f"{BOOT}/not-a-uuid", headers=h)).status_code == 404
    assert (await client.get(BOOT, query_string={"limit": 1}, headers=h)).status_code == 200


async def test_enroll_joins_groups_and_bootstrap_is_single_use(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """Enrollment returns the token pair, joins the token's groups, and a reused token is 401."""
    h = admin_headers(tenant)
    group = await create_group(client, h, "edge")
    secret, _ = await _bootstrap(client, h, [group["id"]])
    resp = await _enroll(client, secret)
    assert resp.status_code == 201
    tokens = envelope_data(await resp.get_json())
    assert set(tokens) == {"agent_id", "access_token", "token_type", "expires_in", "refresh_token"}
    assert tokens["expires_in"] == 3600
    assert tokens["token_type"] == "Bearer"  # noqa: S105 - OAuth token type label
    assert (await _enroll(client, secret)).status_code == 401
    detail = envelope_data(
        await (await client.get(f"/api/v1/agents/{tokens['agent_id']}", headers=h)).get_json()
    )
    assert detail["group_ids"] == [group["id"]]
    listed = envelope_data(await (await client.get(BOOT, headers=h)).get_json())
    used = [t for t in listed["items"] if t["used"]]
    assert used and used[0]["used_by_agent_id"] == tokens["agent_id"]


async def test_enroll_rejects_missing_unknown_expired_and_csr(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int, db: DB
) -> None:
    """No bearer, an unknown secret, an expired token, or a CSR are all refused."""
    assert (
        await client.post("/api/v1/agent/enroll", json={"platform": 1, "agent_version": "0.1.0"})
    ).status_code == 401
    assert (await _enroll(client, "unknown-secret")).status_code == 401
    h = admin_headers(tenant)
    secret, _data = await _bootstrap(client, h)
    token_row = resolve_bootstrap(db, digest(secret))
    assert token_row is not None
    db(db.bootstrap_tokens.id == token_row.id).update(
        expires_at=dt.datetime.now(dt.UTC) - dt.timedelta(seconds=5)
    )
    assert (await _enroll(client, secret)).status_code == 401
    secret2, _ = await _bootstrap(client, h)
    csr = await client.post(
        "/api/v1/agent/enroll",
        json={
            "platform": 1,
            "agent_version": "0.1.0",
            "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----",
        },
        headers={"Authorization": f"Bearer {secret2}"},
    )
    assert csr.status_code == 400


async def test_enroll_rate_limited_per_client(client: QuartClient, app: Quart) -> None:
    """Once the enroll budget is spent the client gets 429 with Retry-After."""
    from app.ratelimit import RateLimiter

    app.config["HUB"].limiter = RateLimiter(2)
    for _ in range(2):
        await _enroll(client, "x")
    resp = await _enroll(client, "x")
    assert resp.status_code == 429
    assert int(resp.headers["Retry-After"]) >= 1
    assert (await resp.get_json())["data"]["code"] == 1080


async def test_refresh_rotates_and_reuse_revokes_chain(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """Refresh issues a new pair; reusing the old refresh token revokes the whole chain."""
    h = admin_headers(tenant)
    secret, _ = await _bootstrap(client, h)
    first = envelope_data(await (await _enroll(client, secret)).get_json())
    rotated = await client.post(
        "/api/v1/agent/token", json={"refresh_token": first["refresh_token"]}
    )
    assert rotated.status_code == 200
    second = envelope_data(await rotated.get_json())
    assert second["refresh_token"] != first["refresh_token"]
    reuse = await client.post("/api/v1/agent/token", json={"refresh_token": first["refresh_token"]})
    assert reuse.status_code == 401
    dead = await client.post("/api/v1/agent/token", json={"refresh_token": second["refresh_token"]})
    assert dead.status_code == 401
    assert (
        await client.post("/api/v1/agent/token", json={"refresh_token": "nope"})
    ).status_code == 401


async def test_revoked_agent_refresh_is_401(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """A revoked agent cannot rotate its refresh token and is told to re-enroll (410)."""
    h = admin_headers(tenant)
    secret, _ = await _bootstrap(client, h)
    tokens = envelope_data(await (await _enroll(client, secret)).get_json())
    assert (
        await client.delete(f"/api/v1/agents/{tokens['agent_id']}", headers=h)
    ).status_code == 204
    resp = await client.post("/api/v1/agent/token", json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 401  # revoking the agent also revoked its refresh chain


async def test_refresh_gone_when_agent_revoked_but_token_live(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int, db: DB
) -> None:
    """If the agent is revoked without its refresh chain being revoked, refresh answers 410."""
    from app.models import AgentStatus

    h = admin_headers(tenant)
    secret, _ = await _bootstrap(client, h)
    tokens = envelope_data(await (await _enroll(client, secret)).get_json())
    db(db.agents.public_id == uuid.UUID(tokens["agent_id"])).update(status=int(AgentStatus.REVOKED))
    resp = await client.post("/api/v1/agent/token", json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 410


async def test_sync_manifest_etag_and_304(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """Sync returns the exact bundle shape with ETag; If-None-Match yields 304 with no body."""
    h = admin_headers(tenant)
    secret, _ = await _bootstrap(client, h)
    tokens = envelope_data(await (await _enroll(client, secret)).get_json())
    auth = {"Authorization": f"Bearer {tokens['access_token']}"}
    first = await client.get("/api/v1/agent/sync", headers=auth)
    assert first.status_code == 200
    assert first.headers["Cache-Control"] == "private, max-age=300"
    bundle = envelope_data(await first.get_json())
    assert set(bundle) == {
        "agent_id",
        "generated_at",
        "policy",
        "flags",
        "modules",
        "poll_interval_s",
        "max_stale_s",
    }
    assert bundle["poll_interval_s"] == 300 and bundle["max_stale_s"] == 86400
    etag = first.headers["ETag"]
    again = await client.get("/api/v1/agent/sync", headers={**auth, "If-None-Match": etag})
    assert again.status_code == 304
    assert await again.get_data() == b""
    assert again.headers["ETag"] == etag


async def test_sync_flags_are_restrict_only(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """A group-scoped OFF flag restricts agents in that group; tenant ON flags do not grant."""
    h = admin_headers(tenant)
    group = await create_group(client, h, "flagged-group")
    await client.put(
        "/api/v1/flags",
        json={"key": "penguind.hub-api.feature", "enabled": True, "scope": 1},
        headers=h,
    )
    await client.put(
        "/api/v1/flags",
        json={
            "key": "penguind.hub-api.kill",
            "enabled": False,
            "scope": 2,
            "group_id": group["id"],
        },
        headers=h,
    )
    secret, _ = await _bootstrap(client, h, [group["id"]])
    tokens = envelope_data(await (await _enroll(client, secret)).get_json())
    bundle = envelope_data(
        await (
            await client.get(
                "/api/v1/agent/sync", headers={"Authorization": f"Bearer {tokens['access_token']}"}
            )
        ).get_json()
    )
    assert bundle["flags"] == {"penguind.hub-api.feature": True, "penguind.hub-api.kill": False}


async def test_sync_applies_override_limits_and_clamps(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """Override limits feed poll/stale values; values below the floor are clamped up."""
    h = admin_headers(tenant)
    secret, _ = await _bootstrap(client, h)
    tokens = envelope_data(await (await _enroll(client, secret)).get_json())
    await client.put(
        f"/api/v1/agents/{tokens['agent_id']}/override",
        json={"limits": {"poll_interval_s": 1, "max_stale_s": 2}, "allowed_tools": ["ocr"]},
        headers=h,
    )
    bundle = envelope_data(
        await (
            await client.get(
                "/api/v1/agent/sync", headers={"Authorization": f"Bearer {tokens['access_token']}"}
            )
        ).get_json()
    )
    assert bundle["poll_interval_s"] == 60 and bundle["max_stale_s"] == 300
    assert bundle["policy"]["allowed_tools"] == ["ocr"]


async def _upload(
    client: QuartClient,
    h: dict[str, str],
    module_id: str,
    version: str,
    body: bytes,
    sig: str = "c2ln",
    sha: str | None = None,
) -> Any:
    """POST a multipart module upload and return the response."""
    form: dict[str, str] = {"module_id": module_id, "version": version, "signature": sig}
    if sha is not None:
        form["sha256"] = sha
    part = FileStorage(
        stream=io.BytesIO(body), filename="module.wasm", content_type="application/wasm"
    )
    return await client.post("/api/v1/modules", form=form, files={"binary": part}, headers=h)


async def test_module_upload_recomputes_sha_and_rejects_mismatch(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """Upload stores a module with the server-computed sha256; a wrong claimed digest is 422."""
    h = admin_headers(tenant)
    body = b"\x00asm-test-module"
    real = hashlib.sha256(body).hexdigest()
    resp = await _upload(client, h, "waddle-ai", "1.0.0", body)
    assert resp.status_code == 201, await resp.get_data(as_text=True)
    data = envelope_data(await resp.get_json())
    assert set(data) == {
        "id",
        "module_id",
        "version",
        "sha256",
        "signature",
        "status",
        "size_bytes",
        "created_at",
    }
    assert data["sha256"] == real and data["size_bytes"] == len(body) and data["status"] == 1
    bad = await _upload(client, h, "waddle-ai", "1.0.1", body, sha="0" * 64)
    assert bad.status_code == 422
    right = await _upload(client, h, "waddle-ai", "1.0.2", body, sha=real)
    assert right.status_code == 201
    dup = await _upload(client, h, "waddle-ai", "1.0.0", body)
    assert dup.status_code == 409


async def test_module_upload_input_validation(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """Bad module id, SemVer, empty signature, malformed sha and a missing binary are rejected."""
    h = admin_headers(tenant)
    assert (await _upload(client, h, "Bad_Id", "1.0.0", b"x")).status_code == 422
    assert (await _upload(client, h, "okmod", "v1", b"x")).status_code == 422
    assert (await _upload(client, h, "okmod", "1.0.0", b"x", sig="  ")).status_code == 422
    assert (await _upload(client, h, "okmod", "1.0.0", b"x", sha="XYZ")).status_code == 422
    no_binary = await client.post(
        "/api/v1/modules",
        form={"module_id": "okmod", "version": "1.0.0", "signature": "c2ln"},
        headers=h,
    )
    assert no_binary.status_code == 400


async def test_module_upload_size_cap_streams_and_rejects(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int, app: Quart
) -> None:
    """A body over the configured cap is refused with 413 while streaming, before storage."""
    h = admin_headers(tenant)
    cap = app.config["HUB"].settings.max_upload_bytes
    resp = await _upload(client, h, "bigmod", "1.0.0", b"a" * (cap + 1))
    assert resp.status_code == 413
    assert (await resp.get_json())["data"]["code"] == 1060


async def test_module_upload_blob_outage_is_503(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int, app: Quart
) -> None:
    """A failing blob store answers 503 and leaves no module row behind."""
    from app.blobs import BlobError

    class Down:
        """Blob store that always fails."""

        async def store(self, key: str, body: Any, size: int) -> None:
            """Fail the upload."""
            raise BlobError("s3 down")

        async def delete(self, key: str) -> None:
            """No-op."""

        async def presign_get(self, key: str) -> str:
            """Unused here."""
            raise BlobError("s3 down")

        async def ready(self) -> bool:
            """Report not ready."""
            return False

    app.config["HUB"].blobs = Down()  # type: ignore[assignment]
    h = admin_headers(tenant)
    resp = await _upload(client, h, "downmod", "1.0.0", b"payload")
    assert resp.status_code == 503
    listed = envelope_data(await (await client.get("/api/v1/modules", headers=h)).get_json())
    assert listed["items"] == []


def _minisign(message: bytes) -> tuple[str, str]:
    """Return (public key line, signature line) produced like `minisign -S` (Ed, not prehashed)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = Ed25519PrivateKey.generate()
    keyid = uuid.uuid4().bytes[:8]
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig = key.sign(message)
    return base64.b64encode(b"Ed" + keyid + pub).decode(), base64.b64encode(
        b"Ed" + keyid + sig
    ).decode()


async def test_module_signature_verified_when_keys_configured(
    admin_headers: Callable[..., dict[str, str]],
    tenant: int,
    db: DB,
    blobs: Any,
    verifier: Any,
    settings: Any,
    telemetry: Any,
) -> None:
    """With trusted keys configured, a valid minisign signature stores and a bad one is 422."""
    from app.factory import create_app
    from app.flags import ALL_FLAGS, StaticFlagGate

    body = b"signed-module"
    sha = hashlib.sha256(body).hexdigest()
    message = f"penguin-wasm-module/v1\nid=signedmod\nversion=1.0.0\nsha256={sha}\n".encode()
    pub, sig = _minisign(message)
    keyed = create_app(
        dataclasses.replace(settings, trusted_pubkeys=(pub,)),
        db=db,
        verifier=verifier,
        blobs=blobs,
        flags=StaticFlagGate(frozenset(ALL_FLAGS)),
        telemetry=telemetry,
    )
    async with keyed.test_app():
        kc = keyed.test_client()
        h = admin_headers(tenant)
        good = await _upload(kc, h, "signedmod", "1.0.0", body, sig=sig)
        assert good.status_code == 201, await good.get_data(as_text=True)
        bad = await _upload(kc, h, "signedmod", "1.0.1", body, sig=sig)
        assert bad.status_code == 422
        junk = await _upload(kc, h, "signedmod", "1.0.2", body, sig="%%%")
        assert junk.status_code == 422


async def test_status_report_and_binary_download(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """Status is recorded for admins; binary is a 302 presigned URL for assigned modules."""
    h = admin_headers(tenant)
    up = await _upload(client, h, "dl-mod", "2.0.0", b"binary-bytes")
    mv = envelope_data(await up.get_json())
    group = await create_group(client, h, "dl-group")
    assigned = await client.put(
        f"/api/v1/groups/{group['id']}/modules", json=[{"module_version_id": mv["id"]}], headers=h
    )
    assert assigned.status_code == 200
    secret, _ = await _bootstrap(client, h, [group["id"]])
    tokens = envelope_data(await (await _enroll(client, secret)).get_json())
    auth = {"Authorization": f"Bearer {tokens['access_token']}"}
    binary = await client.get(f"/api/v1/agent/modules/{mv['id']}/binary", headers=auth)
    assert binary.status_code == 302
    assert (
        "X-Amz-Signature" in binary.headers["Location"] or "Signature" in binary.headers["Location"]
    )
    unknown = await client.get(f"/api/v1/agent/modules/{uuid.uuid4()}/binary", headers=auth)
    assert unknown.status_code == 404
    manifest = envelope_data(
        await (await client.get("/api/v1/agent/sync", headers=auth)).get_json()
    )
    assert (
        manifest["modules"][0]["binary_url"]
        == f"https://hub.test/api/v1/agent/modules/{mv['id']}/binary"
    )
    report = {
        "applied_etag": '"abc"',
        "result": 1,
        "agent_version": "0.2.1",
        "modules": [{"id": "dl-mod", "version": "2.0.0", "loaded": True}],
    }
    accepted = await client.post("/api/v1/agent/status", json=report, headers=auth)
    assert accepted.status_code == 204
    detail = envelope_data(
        await (await client.get(f"/api/v1/agents/{tokens['agent_id']}", headers=h)).get_json()
    )
    assert detail["applied_etag"] == '"abc"' and detail["agent_version"] == "0.2.1"
    assert detail["last_report"]["modules"][0]["loaded"] is True
    bad_report = await client.post(
        "/api/v1/agent/status", json={**report, "result": 9}, headers=auth
    )
    assert bad_report.status_code == 400


async def test_yanked_module_is_removed_and_410_on_download(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """Yanking drops the module from the manifest and makes its binary answer 410."""
    h = admin_headers(tenant)
    mv = envelope_data(await (await _upload(client, h, "yank-mod", "1.0.0", b"y")).get_json())
    group = await create_group(client, h, "yank-group")
    await client.put(
        f"/api/v1/groups/{group['id']}/modules", json=[{"module_version_id": mv["id"]}], headers=h
    )
    secret, _ = await _bootstrap(client, h, [group["id"]])
    tokens = envelope_data(await (await _enroll(client, secret)).get_json())
    auth = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert (
        await client.patch(f"/api/v1/modules/{mv['id']}", json={"status": 2}, headers=h)
    ).status_code == 200
    manifest = envelope_data(
        await (await client.get("/api/v1/agent/sync", headers=auth)).get_json()
    )
    assert manifest["modules"] == []
    gone = await client.get(f"/api/v1/agent/modules/{mv['id']}/binary", headers=auth)
    assert gone.status_code == 410
    bad = await client.patch(f"/api/v1/modules/{mv['id']}", json={"status": 7}, headers=h)
    assert bad.status_code == 422


async def test_highest_version_wins_in_manifest(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """With two assigned versions of one module the manifest carries the highest SemVer."""
    h = admin_headers(tenant)
    low = envelope_data(await (await _upload(client, h, "multi", "1.9.0", b"low")).get_json())
    high = envelope_data(await (await _upload(client, h, "multi", "1.10.0", b"high")).get_json())
    prerelease = envelope_data(
        await (await _upload(client, h, "multi", "1.10.0-rc.1", b"rc")).get_json()
    )
    group = await create_group(client, h, "multi-group")
    await client.put(
        f"/api/v1/groups/{group['id']}/modules",
        json=[
            {"module_version_id": low["id"]},
            {"module_version_id": high["id"]},
            {"module_version_id": prerelease["id"]},
        ],
        headers=h,
    )
    listed = envelope_data(
        await (await client.get(f"/api/v1/groups/{group['id']}/modules", headers=h)).get_json()
    )
    assert {m["version"] for m in listed} == {"1.9.0", "1.10.0", "1.10.0-rc.1"}
    secret, _ = await _bootstrap(client, h, [group["id"]])
    tokens = envelope_data(await (await _enroll(client, secret)).get_json())
    manifest = envelope_data(
        await (
            await client.get(
                "/api/v1/agent/sync", headers={"Authorization": f"Bearer {tokens['access_token']}"}
            )
        ).get_json()
    )
    assert [(m["id"], m["version"]) for m in manifest["modules"]] == [("multi", "1.10.0")]
    assert manifest["modules"][0]["sha256"] == hashlib.sha256(b"high").hexdigest()


async def test_group_module_assignment_validation(
    client: QuartClient, admin_headers: Callable[..., dict[str, str]], tenant: int
) -> None:
    """Assignments must be an array of exactly {module_version_id}; unknown ids are 422."""
    h = admin_headers(tenant)
    group = await create_group(client, h, "validate-group")
    url = f"/api/v1/groups/{group['id']}/modules"
    assert (await client.put(url, json={"module_version_id": "x"}, headers=h)).status_code == 400
    assert (
        await client.put(url, json=[{"module_version_id": "x", "extra": 1}], headers=h)
    ).status_code == 400
    assert (
        await client.put(url, json=[{"module_version_id": str(uuid.uuid4())}], headers=h)
    ).status_code == 422
    assert (await client.put(url, json=[], headers=h)).status_code == 200
