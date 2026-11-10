"""Unit-level checks for helpers that the HTTP tests reach only through their error branches."""

import base64
import uuid
from typing import Any

import pytest
from penguintechinc_utils import configure_logging, get_logger
from quart import Quart
from quart.testing import QuartClient

from app.auth import (
    OidcVerifier,
    TokenInvalidError,
    issue_agent_token,
    parse_scopes,
    tenant_from_admin_claims,
    verify_agent_token,
)
from app.blobs import S3BlobStore, spool_and_hash
from app.config import Settings
from app.context import decode_cursor, encode_cursor
from app.flags import FLAG_ADMIN_API, PostHogFlagGate, StaticFlagGate, build_flag_gate
from app.models.policy import (
    ConfigRevision,
    GroupPolicy,
    Policy,
    PolicyError,
    merge_groups,
    resolve,
)
from app.problems import ApiError
from app.ratelimit import RateLimiter
from app.signing import MinisignKey, SignatureInvalidError, module_message, verify_module_signature
from app.telemetry import Telemetry, install_log_forwarder
from tests.api.helpers import AGENT_SECRET


def test_parse_scopes_accepts_string_list_and_none() -> None:
    """Scope claims parse from a space-separated string, a list, or absence."""
    assert parse_scopes("a:read  b:write") == frozenset({"a:read", "b:write"})
    assert parse_scopes(["x"]) == frozenset({"x"})
    assert parse_scopes(None) == frozenset()
    with pytest.raises(TokenInvalidError):
        parse_scopes([1])


@pytest.mark.parametrize(
    "claims",
    [
        {},
        {"tenant": ""},
        {"tenant": "abc"},
        {"tenant": "42"},
        {"tenant": "0"},
        {"tenant": str(uuid.uuid4()).upper()},
    ],
)
def test_admin_tenant_claim_rejections(claims: dict[str, Any]) -> None:
    """Missing, empty, integer, non-UUID and non-canonical tenant claims are refused."""
    with pytest.raises(TokenInvalidError):
        tenant_from_admin_claims(claims)


def test_admin_tenant_claim_accepts_canonical_uuid() -> None:
    """A canonical lowercase tenant public_id UUID resolves to its UUID value."""
    tenant = uuid.uuid4()
    assert tenant_from_admin_claims({"tenant": str(tenant)}) == tenant


def test_agent_jwt_round_trip_and_rejections() -> None:
    """A signed agent JWT verifies; wrong secret, bad tenant and bad sub are rejected."""
    pid = uuid.uuid4()
    tenant = uuid.uuid4()
    token = issue_agent_token(AGENT_SECRET, pid, tenant, frozenset({"hub:agent:sync"}), 60)
    claims = verify_agent_token(AGENT_SECRET, token)
    assert claims.agent_public_id == pid and claims.tenant == tenant
    assert claims.scopes == frozenset({"hub:agent:sync"})
    with pytest.raises(TokenInvalidError):
        verify_agent_token("x" * 40, token)
    bad_tenant = issue_agent_token(AGENT_SECRET, pid, tenant, frozenset(), 60)
    import jwt

    forged = jwt.encode(
        {
            **jwt.decode(bad_tenant, AGENT_SECRET, algorithms=["HS256"], audience="hub-api-agent"),
            "tenant": "nan",
        },
        AGENT_SECRET,
        algorithm="HS256",
    )
    with pytest.raises(TokenInvalidError):
        verify_agent_token(AGENT_SECRET, forged)
    not_uuid = jwt.encode(
        {
            **jwt.decode(bad_tenant, AGENT_SECRET, algorithms=["HS256"], audience="hub-api-agent"),
            "sub": "nope",
        },
        AGENT_SECRET,
        algorithm="HS256",
    )
    with pytest.raises(TokenInvalidError):
        verify_agent_token(AGENT_SECRET, not_uuid)


async def test_oidc_verifier_reports_unreachable_issuer_as_invalid() -> None:
    """If discovery fails the verifier raises TokenInvalidError (mapped to 401), never a 500."""
    verifier = OidcVerifier("https://127.0.0.1:9", "hub-api")
    with pytest.raises(TokenInvalidError):
        await verifier.verify("a.b.c")


def test_cursor_round_trip_and_rejects_garbage() -> None:
    """Cursors decode back to the row id; malformed or negative values are 400."""
    assert decode_cursor(None) == 0
    assert decode_cursor(encode_cursor(123)) == 123
    for bad in (
        "!!",
        base64.urlsafe_b64encode(b"-5").decode(),
        base64.urlsafe_b64encode(b"\xff").decode(),
    ):
        with pytest.raises(ApiError) as exc:
            decode_cursor(bad)
        assert exc.value.status == 400


def test_rate_limiter_window_and_retry_after() -> None:
    """A key is limited inside the window and freed once the window slides past."""
    now = [0.0]
    limiter = RateLimiter(2, clock=lambda: now[0])
    assert limiter.hit("k") is None
    assert limiter.hit("k") is None
    retry = limiter.hit("k")
    assert retry is not None and retry >= 1
    assert limiter.hit("other") is None
    now[0] = 61.0
    assert limiter.hit("k") is None


def test_minisign_parsing_and_verification_edges() -> None:
    """Malformed keys/signatures raise SignatureInvalidError; prehashed ED signatures verify too."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    with pytest.raises(SignatureInvalidError):
        MinisignKey.parse("%%%")
    with pytest.raises(SignatureInvalidError):
        MinisignKey.parse(base64.b64encode(b"short").decode())
    key = Ed25519PrivateKey.generate()
    keyid = b"\x01" * 8
    pub_line = base64.b64encode(
        b"Ed" + keyid + key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    mk = MinisignKey.parse(pub_line)
    msg = module_message("mod-x", "1.2.3", "a" * 64)
    import hashlib

    prehash = hashlib.blake2b(msg, digest_size=64).digest()
    sig_ed = base64.b64encode(b"ED" + keyid + key.sign(prehash)).decode()
    assert verify_module_signature((mk,), "mod-x", "1.2.3", "a" * 64, sig_ed) is True
    plain = base64.b64encode(b"Ed" + keyid + key.sign(msg)).decode()
    assert verify_module_signature((mk,), "mod-x", "1.2.3", "a" * 64, plain) is True
    assert verify_module_signature((mk,), "mod-x", "9.9.9", "a" * 64, plain) is False
    other = MinisignKey.parse(
        base64.b64encode(
            b"Ed" + b"\x09" * 8 + key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
    )
    assert verify_module_signature((other,), "mod-x", "1.2.3", "a" * 64, plain) is False
    with pytest.raises(SignatureInvalidError):
        verify_module_signature((mk,), "mod-x", "1.2.3", "a" * 64, "not base64 !!")
    with pytest.raises(SignatureInvalidError):
        verify_module_signature(
            (mk,), "mod-x", "1.2.3", "a" * 64, base64.b64encode(b"Zz" + b"\x00" * 72).decode()
        )
    full_text = f"untrusted comment: x\n{plain}\n"
    assert verify_module_signature((mk,), "mod-x", "1.2.3", "a" * 64, full_text) is True


def test_spool_and_hash_enforces_cap_and_rewinds() -> None:
    """Chunked spooling hashes the bytes, rewinds for upload, and refuses past the cap."""
    import io

    from app.problems import ApiError as Err

    spool, sha, size = spool_and_hash(io.BytesIO(b"abc"), 10)
    assert spool.read() == b"abc" and size == 3
    assert sha == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    spool.close()
    with pytest.raises(Err) as exc:
        spool_and_hash(io.BytesIO(b"x" * 11), 10)
    assert exc.value.status == 413


async def test_s3_blob_store_presign_delete_and_ready(blobs: S3BlobStore) -> None:
    """The S3 adapter stores, presigns, deletes and reports readiness against moto."""
    import io

    await blobs.store("k/a.wasm", io.BytesIO(b"data"), 4)
    url = await blobs.presign_get("k/a.wasm")
    assert "k/a.wasm" in url
    assert await blobs.ready() is True
    await blobs.delete("k/a.wasm")
    missing_bucket = S3BlobStore("does-not-exist-bucket", None, "us-east-1")
    assert await missing_bucket.ready() is False


def test_flag_gate_defaults_off_and_falls_back_to_last_known() -> None:
    """Without a PostHog key every flag is OFF; a failing backend answers its last known value."""
    settings = _settings(trust=False)
    gate = build_flag_gate(settings)
    assert gate.enabled(FLAG_ADMIN_API, "anyone") is False

    class Flaky:
        """Stand-in client that answers once, then errors."""

        def __init__(self) -> None:
            """Start with a healthy first answer."""
            self.calls = 0

        def feature_enabled(self, key: str, distinct: str) -> bool:
            """Answer True once, then raise."""
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError("posthog unreachable")
            return True

    live = PostHogFlagGate(Flaky())  # type: ignore[arg-type]
    assert live.enabled("penguind.hub-api.x", "d") is True
    assert live.enabled("penguind.hub-api.x", "d") is True
    assert live.enabled("penguind.hub-api.never-seen", "d") is False
    assert StaticFlagGate(frozenset({"k"})).enabled("k", "d") is True


def test_policy_parse_merge_and_resolve_rules() -> None:
    """Group merge intersects tools, takes minimum limits, and an override wins per field."""
    p1 = Policy.parse({"allowed_tools": ["a", "b"], "limits": {"max_fuel": 100}})
    p2 = Policy.parse({"allowed_tools": ["b", "c"], "limits": {"max_fuel": 50}})
    merged = merge_groups(
        [GroupPolicy("g1", uuid.uuid4(), p1), GroupPolicy("g2", uuid.uuid4(), p2)]
    )
    assert merged.allowed_tools == frozenset({"b"}) and merged.limits == {"max_fuel": 50}
    default = Policy.parse({"allowed_tools": None})
    override = Policy.parse({"limits": {"max_fuel": 10}})
    assert resolve(default, [], override).limits == {"max_fuel": 10}
    assert resolve(default, [], None).has_tools is True
    with pytest.raises(PolicyError):
        Policy.parse({"allowed_tools": "x"})
    with pytest.raises(PolicyError):
        Policy.parse([])
    with pytest.raises(PolicyError):
        Policy.parse({"settings": {"m": 1}})
    with pytest.raises(PolicyError):
        Policy.parse({"limits": {"max_fuel": True}})
    assert ConfigRevision.of({"a": 1}).matches('W/"' + ConfigRevision.of({"a": 1}).digest + '"')
    assert ConfigRevision.of({"a": 1}).matches("*") is True
    assert ConfigRevision.of({"a": 1}).matches(None) is False


def test_telemetry_in_memory_collects_logs_metrics_and_spans() -> None:
    """Penguin logs bridge into OTel logs; instruments reach the in-memory metric reader."""
    configure_logging(json_output=False)
    install_log_forwarder()
    tel = Telemetry.in_memory()
    get_logger("hub-test").info("telemetry smoke", component="unit")
    tel.instruments.requests.add(1, {"route": "/x"})
    tel.instruments.request_latency.record(0.01, {"route": "/x"})
    with tel.tracer.start_as_current_span("span"):
        pass
    tel.shutdown()
    mem = tel.memory_signals()
    metrics = mem["metrics"].get_metrics_data()
    names = {
        m.name for rm in metrics.resource_metrics for sm in rm.scope_metrics for m in sm.metrics
    }
    assert {"hub.http.requests", "hub.http.duration"} <= names
    assert len(mem["logs"].get_finished_logs()) >= 1
    assert len(mem["spans"].get_finished_spans()) >= 1


def test_telemetry_from_env_builds_with_default_grpc(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default protocol builds gRPC exporters without contacting any endpoint."""
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_PROTOCOL", raising=False)
    tel = Telemetry.from_env()
    tel.shutdown()
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
    tel2 = Telemetry.from_env()
    tel2.shutdown()


async def test_problem_envelope_for_unknown_route_and_method(client: QuartClient) -> None:
    """Framework 404/405 answers use the problem envelope, never HTML."""
    missing = await client.get("/api/v1/nope")
    assert missing.status_code == 404
    body = await missing.get_json()
    assert body["status"] == "error" and body["data"]["status"] == 404
    wrong = await client.delete("/healthz")
    assert wrong.status_code == 405
    assert wrong.mimetype == "application/problem+json"


async def test_unexpected_exception_is_500_without_internals(
    client: QuartClient, app: Quart, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unexpected exception is logged and answered with a generic 500 problem."""
    from app.api import health

    def boom() -> bool:
        """Simulate an internal failure in the readiness probe."""
        raise RuntimeError("secret internals")

    monkeypatch.setattr(health, "_db_reachable", boom)
    resp = await client.get("/readyz")
    assert resp.status_code == 500
    body = await resp.get_json()
    assert body["data"]["detail"] is None
    assert "secret" not in str(body)


def _settings(*, trust: bool) -> Settings:
    """Settings with the given forwarded-cert trust flag and fixed SPIFFE prefix."""
    return Settings(
        database_dsn="x",
        base_url="https://hub.test",
        oidc_issuer_url="https://idp.test",
        oidc_audience="hub",
        agent_jwt_secret=AGENT_SECRET,
        s3_bucket="b",
        s3_endpoint=None,
        s3_region=None,
        trusted_pubkeys=(),
        trust_forwarded_cert=trust,
        trusted_proxy_cidrs=(),
        spiffe_trust_domain="penguintech.io",
        posthog_api_key=None,
        posthog_host=None,
        max_upload_bytes=1024,
        stale_after_s=300,
        rate_limit_per_min=10,
        agent_token_ttl_s=60,
    )


def test_settings_from_env_requires_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing required env fails at boot; a short JWT secret is refused; a full set loads."""
    for name in (
        "HUB_DATABASE_DSN",
        "BASE_URL",
        "OIDC_ISSUER_URL",
        "OIDC_AUDIENCE",
        "HUB_AGENT_JWT_SECRET",
        "HUB_S3_BUCKET",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError, match=r"HUB_AGENT_JWT_SECRET|HUB_DATABASE_DSN"):
        Settings.from_env()
    env = {
        "HUB_DATABASE_DSN": "postgresql://u:p@h/db",
        "BASE_URL": "https://hub.example/",
        "OIDC_ISSUER_URL": "https://idp.example/",
        "OIDC_AUDIENCE": "hub",
        "HUB_AGENT_JWT_SECRET": "short",
        "HUB_S3_BUCKET": "bkt",
        "HUB_SPIFFE_TRUST_DOMAIN": " Penguintech.IO ",
        "HUB_TRUSTED_PUBKEYS": "k1, k2",
        "HUB_TRUST_FORWARDED_CERT": "1",
        "POSTHOG_API_KEY": "phc_x",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(RuntimeError, match="at least 32"):
        Settings.from_env()
    monkeypatch.setenv("HUB_AGENT_JWT_SECRET", "z" * 40)
    loaded = Settings.from_env()
    assert loaded.base_url == "https://hub.example" and loaded.trusted_pubkeys == ("k1", "k2")
    assert loaded.trust_forwarded_cert is True and loaded.posthog_api_key == "phc_x"
    assert loaded.agent_token_ttl_s == 3600
    assert loaded.spiffe_trust_domain == "penguintech.io"
