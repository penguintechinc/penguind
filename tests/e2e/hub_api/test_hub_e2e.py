"""T6 end-to-end: real hub + real pdcli + real penguin-hub-client + real wasm host.

Doubles allowed by the plan and nothing else: the OIDC issuer (local JWKS signer) and S3
(MinIO). Steps run in file order and share one environment; every check is counted and
``run.sh`` fails the run when zero checks ran or any failed.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import boto3
import httpx
import pytest
from alembic import command
from alembic.config import Config
from harness import AgentDriver, Issuer, OtlpSink, Pki, free_port, pubkey_line
from testcontainers.core.container import DockerContainer
from testcontainers.core.docker_client import DockerClient
from testcontainers.core.waiting_utils import wait_for_logs
from testcontainers.postgres import PostgresContainer

ROOT = Path(__file__).resolve().parents[3]
HUB_DIR = ROOT / "services" / "hub-api"
PG_IMAGE = (
    "postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94"
)
MINIO_IMAGE = (
    "cgr.dev/chainguard/minio"
    "@sha256:fb893e36fc369d41e92f678b17ec27378fa5bf0576aeef7ac15460c13629ab5a"
)
BUCKET = "hub-modules"
MODULE_ID = "e2e-demo"
HUB_MEMORY_MB = 32  # below the agent's 64 MiB ceiling: the hub wins
HUB_FUEL = 10**12  # above the agent's 50M ceiling: the ceiling wins
CEILING_FUEL = 50_000_000
SUMMARY = Path(os.environ.get("HUB_E2E_SUMMARY", "/dev/null"))


@dataclass
class Checks:
    """Counts every assertion so a run with zero checks can be failed by run.sh."""

    passed: int = 0
    failed: list[str] = field(default_factory=list)

    def __call__(self, cond: bool, label: str, detail: Any = None) -> None:
        """Record one check; a failure is also a pytest failure."""
        if cond:
            self.passed += 1
            print(f"PASS {label}")
            return
        self.failed.append(label)
        pytest.fail(f"{label}: {detail!r}")


CHECKS = Checks()


@dataclass
class Env:
    """Everything the steps share."""

    tmp: Path
    pki: Pki
    issuer: Issuer
    sink: OtlpSink
    pg_url: str
    s3: Any
    s3_endpoint: str
    s3_host: str
    hub_env: dict[str, str]
    tls_port: int
    http_port: int
    agent: AgentDriver
    pdcli: str
    pdcli_env: dict[str, str]
    hub: subprocess.Popen[bytes] | None = None
    ids: dict[str, str] = field(default_factory=dict)

    @property
    def hub_url(self) -> str:
        """Agent-facing TLS base URL."""
        return f"https://127.0.0.1:{self.tls_port}/"

    def start_hub(self) -> None:
        """Launch the real hub and wait for /healthz over TLS."""
        log = (self.tmp / "hub.log").open("ab")
        self.hub = subprocess.Popen(  # noqa: S603
            [sys.executable, str(Path(__file__).with_name("hub_launcher.py"))],
            cwd=HUB_DIR,
            env=self.hub_env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 60
        last: object = None
        ctx = ssl.create_default_context(cafile=str(self.pki.ca_pem))
        while time.monotonic() < deadline:
            if self.hub.poll() is not None:
                raise RuntimeError(f"hub exited rc={self.hub.returncode}; see {self.tmp}/hub.log")
            try:
                r = httpx.get(f"{self.hub_url}healthz", verify=ctx, timeout=2)
                if r.status_code == 200:
                    return
                last = r.status_code
            except httpx.HTTPError as exc:
                last = exc
            time.sleep(0.5)
        raise RuntimeError(f"hub did not become healthy in 60s: {last!r}")

    def kill_hub(self) -> None:
        """SIGTERM the hub (flushes telemetry) and wait for exit."""
        assert self.hub is not None
        self.hub.terminate()
        self.hub.wait(timeout=30)
        self.hub = None

    def pdcli_run(self, *args: str, expect_ok: bool = True) -> subprocess.CompletedProcess[str]:
        """Run the real ``pdcli hub`` binary."""
        proc = subprocess.run(  # noqa: S603
            [self.pdcli, "hub", *args],
            env=self.pdcli_env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if expect_ok and proc.returncode != 0:
            raise RuntimeError(f"pdcli hub {' '.join(args)} rc={proc.returncode}: {proc.stderr}")
        return proc

    def pdcli_json(self, *args: str) -> Any:
        """Run pdcli with --json and parse stdout."""
        return json.loads(self.pdcli_run(*args, "--json").stdout)

    def login(self, tenant: str) -> None:
        """``pdcli hub login`` against the local issuer as ``tenant``."""
        self.issuer.tenant = tenant
        self.pdcli_run("login", "--issuer", f"http://127.0.0.1:{self.issuer.http_port}")

    def agent_spec(self, name: str, bootstrap: str | None) -> dict[str, Any]:
        """Driver spec for agent ``name`` with its own cache dir."""
        cidrs = ["127.0.0.1/32"]
        hosts = ["127.0.0.1"]
        if self.s3_host not in hosts:
            hosts.append(self.s3_host)
            try:
                import ipaddress

                ipaddress.ip_address(self.s3_host)
                cidrs.append(f"{self.s3_host}/32")
            except ValueError:
                pass
        spec: dict[str, Any] = {
            "cmd": "agent",
            "name": name,
            "hub_url": self.hub_url,
            "ca": str(self.pki.ca_pem),
            "cache": str(self.tmp / f"cache-{name}"),
            "allow_hosts": hosts,
            "allow_cidrs": cidrs,
        }
        if bootstrap is not None:
            spec["bootstrap"] = bootstrap
        return spec

    def bootstrap(self, group: str) -> str:
        """``pdcli hub agent create --group`` and return the one-time token."""
        data = self.pdcli_json("agent", "create", "--group", group)
        token: str = data["token"]
        return token


@pytest.fixture(scope="module")
def env() -> Iterator[Env]:
    """Bring up Postgres, MinIO, issuer, OTLP sink, the hub and the agent driver."""
    tmp = Path(tempfile.mkdtemp(prefix="hub-e2e-", dir=os.environ.get("HUB_E2E_WORK")))
    docker_host = DockerClient().host()
    pki = Pki.create(tmp / "pki", ["127.0.0.1", "localhost", docker_host])
    sink = OtlpSink()
    sink.start()
    issuer = Issuer(pki)
    issuer.start()
    certs = tmp / "minio-certs"
    certs.mkdir()
    shutil.copy(pki.cert_pem, certs / "public.crt")
    shutil.copy(pki.key_pem, certs / "private.key")
    (certs / "private.key").chmod(0o644)
    certs.chmod(0o755)
    access, secret = "e2e" + secrets.token_hex(6), secrets.token_hex(20)
    minio = (
        DockerContainer(MINIO_IMAGE)
        .with_command("server /data --certs-dir /certs")
        .with_env("MINIO_ROOT_USER", access)
        .with_env("MINIO_ROOT_PASSWORD", secret)
        # Built-in single-key KMS so the hub's mandatory SSE (AES256) works at rest.
        .with_env("MINIO_KMS_SECRET_KEY", f"e2e-key:{base64.b64encode(os.urandom(32)).decode()}")
        .with_volume_mapping(str(certs), "/certs", "ro")
        .with_exposed_ports(9000)
    )
    with PostgresContainer(PG_IMAGE, driver="psycopg2") as pg, minio:
        wait_for_logs(minio, "API:", timeout=60)
        s3_host = minio.get_container_host_ip()
        s3_endpoint = f"https://{s3_host}:{minio.get_exposed_port(9000)}"
        os.environ["AWS_CA_BUNDLE"] = str(pki.bundle)
        s3 = boto3.client(
            "s3",
            endpoint_url=s3_endpoint,
            aws_access_key_id=access,
            aws_secret_access_key=secret,
            region_name="us-east-1",
        )
        s3.create_bucket(Bucket=BUCKET)
        pg_url = pg.get_connection_url()
        cfg = Config(str(HUB_DIR / "alembic.ini"))
        cfg.set_main_option("script_location", str(HUB_DIR / "migrations"))
        cfg.attributes["url"] = pg_url
        command.upgrade(cfg, "head")

        agent = AgentDriver(os.environ["HUB_E2E_AGENT_BIN"])
        signed = agent.call(cmd="sign", out=str(tmp / "module"), id=MODULE_ID, version="1.0.0")
        tls_port, http_port = free_port(), free_port()
        hub_env = {
            **os.environ,
            "PYTHONPATH": str(HUB_DIR),
            "HUB_DATABASE_DSN": pg_url,
            "BASE_URL": f"https://127.0.0.1:{tls_port}",
            "OIDC_ISSUER_URL": issuer.issuer,
            "OIDC_AUDIENCE": "hub-api-admin",
            "HUB_AGENT_JWT_SECRET": secrets.token_urlsafe(48),
            "HUB_S3_BUCKET": BUCKET,
            "HUB_S3_ENDPOINT": s3_endpoint,
            "HUB_S3_REGION": "us-east-1",
            "AWS_ACCESS_KEY_ID": access,
            "AWS_SECRET_ACCESS_KEY": secret,
            "AWS_CA_BUNDLE": str(pki.bundle),
            "SSL_CERT_FILE": str(pki.bundle),
            "HUB_TRUSTED_PUBKEYS": pubkey_line(Path(signed["pubkey"])),
            "HUB_SPIFFE_TRUST_DOMAIN": "penguintech.io",
            "HUB_RATE_LIMIT_PER_MIN": "600",
            "HUB_E2E_TLS_BIND": f"127.0.0.1:{tls_port}",
            "HUB_E2E_HTTP_BIND": f"127.0.0.1:{http_port}",
            "HUB_E2E_CERT": str(pki.cert_pem),
            "HUB_E2E_KEY": str(pki.key_pem),
            "OTEL_SERVICE_NAME": "hub-api-e2e",
            "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
            "OTEL_EXPORTER_OTLP_ENDPOINT": f"http://127.0.0.1:{sink.port}",
            "OTEL_BLRP_SCHEDULE_DELAY": "500",
            "OTEL_BSP_SCHEDULE_DELAY": "500",
        }
        pdcli_env = {**os.environ, "PDCLI_HUB_URL": f"http://127.0.0.1:{http_port}"}
        e = Env(
            tmp,
            pki,
            issuer,
            sink,
            pg_url,
            s3,
            s3_endpoint,
            s3_host,
            hub_env,
            tls_port,
            http_port,
            agent,
            os.environ["HUB_E2E_PDCLI_BIN"],
            pdcli_env,
        )
        e.ids.update(signed)
        e.ids["tenant_a"] = str(uuid.uuid4())
        e.ids["tenant_b"] = str(uuid.uuid4())
        e.start_hub()
        try:
            yield e
        finally:
            if e.hub is not None:
                e.kill_hub()
            agent.close()
            issuer.stop()
            sink.stop()
            SUMMARY.write_text(
                json.dumps(
                    {
                        "checks_passed": CHECKS.passed,
                        "checks_failed": CHECKS.failed,
                        "otel": {
                            "log_records": sink.log_records,
                            "metric_points": sink.metric_points,
                            "histogram_points": sink.histogram_points,
                            "spans": sink.spans,
                            "export_requests": sink.requests,
                            "decode_errors": sink.errors,
                        },
                    }
                )
            )
            shutil.rmtree(tmp, ignore_errors=True)


def _load(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [ev for ev in report["events"] if ev["event"] == "load"]


def test_01_admin_flow_via_pdcli(env: Env) -> None:
    """publish → group → agent create (bootstrap) → assign → policy (logger) + limits."""
    env.login(env.ids["tenant_a"])
    mod = env.pdcli_json(
        "module",
        "publish",
        env.ids["wasm"],
        "--manifest",
        env.ids["manifest"],
        "--pubkey",
        env.ids["pubkey"],
    )
    CHECKS(mod.get("module_id") == MODULE_ID, "publish returns the module", mod)
    env.ids["module"] = mod["id"]
    group = env.pdcli_json("group", "create", "e2e-group")
    env.ids["group"] = group["id"]
    for name in ("a", "b", "r"):
        env.ids[f"boot_{name}"] = env.bootstrap(group["id"])
    CHECKS(all(env.ids[f"boot_{n}"] for n in "abr"), "agent create returns bootstrap tokens")
    env.pdcli_json("assign", group["id"], mod["id"])
    policy = env.tmp / "policy.json"
    policy.write_text(json.dumps({"allowed_tools": ["logger"]}))
    env.pdcli_json("config", "set", "--group", group["id"], "--file", str(policy))
    out = env.pdcli_json(
        "limits",
        "set",
        "--group",
        group["id"],
        "--max-memory-mb",
        str(HUB_MEMORY_MB),
        "--max-fuel",
        str(HUB_FUEL),
    )
    pol = out.get("policy", out)
    CHECKS(pol.get("allowed_tools") == ["logger"], "policy keeps logger tool after limits", out)
    CHECKS(pol.get("limits", {}).get("max_memory_mb") == HUB_MEMORY_MB, "limits stored", out)


def test_02_agent_sync_runs_verified_module_with_clamped_limits(env: Env) -> None:
    """bootstrap → JWT exchange, sync, VerifiedModule runs via run_fetched_wasm."""
    env.agent.call(**env.agent_spec("a", env.ids["boot_a"]))
    rep = env.agent.call(cmd="sync", name="a")
    CHECKS(rep["result"] == {"kind": "applied", "result": 1}, "first sync applied", rep)
    loads = _load(rep)
    CHECKS(len(loads) == 1, "exactly one module loaded", rep["events"])
    ld = loads[0]
    CHECKS(ld["verified_sha256"] == env.ids["sha256"], "VerifiedModule digest matches", ld)
    # ABI: a call result >= 0 is bytes written (success), < 0 is a typed error.
    CHECKS(ld["exit_code"] >= 0, "module run succeeded", ld)
    CHECKS(
        [c["tool"] for c in ld["calls"]] == ["logger"] and ld["calls"][0]["code"] >= 0,
        "logger tool call succeeded",
        ld,
    )
    CHECKS(ld["rejected_calls"] == 0, "no rejected tool calls", ld)
    CHECKS(ld["limits"]["allowed_tools"] == ["logger"], "tools clamp = logger", ld)
    CHECKS(
        ld["limits"]["max_memory_bytes"] == HUB_MEMORY_MB * 1024 * 1024,
        "memory narrowed to hub value",
        ld,
    )
    CHECKS(ld["limits"]["fuel"] == CEILING_FUEL, "fuel clamped to local ceiling", ld)
    CHECKS(rep["applied"] == [[MODULE_ID, "1.0.0"]], "snapshot lists module", rep)


def test_03_second_poll_is_etag_304(env: Env) -> None:
    """Unchanged desired state → 304 Not Modified, nothing reloaded."""
    rep = env.agent.call(cmd="sync", name="a")
    CHECKS(rep["result"] == {"kind": "not_modified"}, "second poll 304", rep)
    CHECKS(_load(rep) == [], "no reload on 304", rep["events"])


def test_04_revocation_target_agent_loaded(env: Env) -> None:
    """Agent r loads the module now so revocation can be observed later."""
    env.agent.call(**env.agent_spec("r", env.ids["boot_r"]))
    rep = env.agent.call(cmd="sync", name="r")
    CHECKS(rep["loaded"] == [MODULE_ID], "agent r loaded module", rep)


def test_05_tampered_binary_in_s3_is_rejected(env: Env) -> None:
    """Overwrite the stored object in MinIO; a fresh agent must refuse it."""
    objs = env.s3.list_objects_v2(Bucket=BUCKET)["Contents"]
    CHECKS(len(objs) == 1, "one stored blob", objs)
    key = objs[0]["Key"]
    original = env.s3.get_object(Bucket=BUCKET, Key=key)["Body"].read()
    env.s3.put_object(Bucket=BUCKET, Key=key, Body=original[:-1] + bytes([original[-1] ^ 0xFF]))
    try:
        env.agent.call(**env.agent_spec("b", env.ids["boot_b"]))
        rep = env.agent.call(cmd="sync", name="b")
        CHECKS(rep["result"]["kind"] == "applied", "tamper sync completed", rep)
        CHECKS(rep["result"].get("result") in (2, 3), "apply partial/rejected", rep)
        CHECKS(_load(rep) == [] and rep["loaded"] == [], "tampered binary not loaded", rep)
    finally:
        env.s3.put_object(Bucket=BUCKET, Key=key, Body=original)


def test_06_cross_tenant_isolation(env: Env) -> None:
    """Tenant B's admin and agent see none of tenant A's modules or assignments."""
    env.login(env.ids["tenant_b"])
    try:
        group_b = env.pdcli_json("group", "create", "tenant-b-group")
        boot_c = env.bootstrap(group_b["id"])
        shown = env.pdcli_run("module", "show", env.ids["module"], expect_ok=False)
        CHECKS(shown.returncode != 0, "tenant B cannot read tenant A module", shown.stdout)
        listed = env.pdcli_json("module", "list")
        items = listed if isinstance(listed, list) else listed.get("items", [])
        CHECKS(items == [], "tenant B module list empty", listed)
        env.agent.call(**env.agent_spec("c", boot_c))
        rep = env.agent.call(cmd="sync", name="c")
        CHECKS(rep["result"] == {"kind": "applied", "result": 1}, "agent c synced", rep)
        CHECKS(rep["applied"] == [] and _load(rep) == [], "agent c sees no assignments", rep)
    finally:
        env.login(env.ids["tenant_a"])


def test_07_hub_killed_cached_module_still_runs(env: Env) -> None:
    """With the hub down, a restarted agent re-verifies and runs its cached module."""
    env.kill_hub()
    env.agent.call(cmd="restart", name="a")
    rep = env.agent.call(cmd="start", name="a")
    CHECKS(rep["result"] == {"kind": "restored", "modules": 1}, "cache restored 1", rep)
    loads = _load(rep)
    CHECKS(len(loads) == 1 and loads[0]["exit_code"] >= 0, "cached module ran", rep)
    CHECKS(
        [c["tool"] for c in loads[0]["calls"]] == ["logger"] and loads[0]["calls"][0]["code"] >= 0,
        "cached run used logger",
        rep,
    )
    rep = env.agent.call(cmd="sync", name="a")
    CHECKS(rep["result"]["kind"] in ("backoff", "retry_after"), "hub down → backoff", rep)
    CHECKS(rep["loaded"] == [MODULE_ID], "module stays loaded while hub down", rep)


def test_08_tampered_cache_is_rejected(env: Env) -> None:
    """A flipped byte in the cached binary means nothing loads on restart."""
    t = env.agent.call(cmd="tamper_cache", name="a")
    CHECKS(t["tampered"] >= 1, "cached blob tampered", t)
    env.agent.call(cmd="restart", name="a")
    rep = env.agent.call(cmd="start", name="a")
    CHECKS(rep["result"] == {"kind": "restored", "modules": 0}, "tampered cache not restored", rep)
    CHECKS(_load(rep) == [], "tampered cache never ran", rep)


def test_09_revoked_module_is_unloaded(env: Env) -> None:
    """Hub back up; ``pdcli hub module revoke`` → agent r unloads on next sync."""
    env.start_hub()
    env.pdcli_json("module", "revoke", env.ids["module"])
    rep = env.agent.call(cmd="sync", name="r")
    CHECKS(rep["result"]["kind"] == "applied", "post-revoke sync applied", rep)
    unloads = [ev for ev in rep["events"] if ev["event"] == "unload"]
    CHECKS(unloads == [{"event": "unload", "id": MODULE_ID}], "module unloaded", rep)
    CHECKS(rep["loaded"] == [] and rep["applied"] == [], "nothing loaded after revoke", rep)


def test_10_hub_telemetry_reached_otlp_sink(env: Env) -> None:
    """Hub OTel: ≥1 log record, ≥1 metric point, ≥1 histogram point (counts printed)."""
    env.kill_hub()  # graceful stop flushes every provider
    s = env.sink
    print(
        f"OTEL log_records={s.log_records} metric_points={s.metric_points} "
        f"histogram_points={s.histogram_points} spans={s.spans} requests={s.requests}"
    )
    CHECKS(s.errors == 0, "sink decoded every export", s.errors)
    CHECKS(s.log_records >= 1, "≥1 log record", s.log_records)
    CHECKS(s.metric_points >= 1, "≥1 metric point", s.metric_points)
    CHECKS(s.histogram_points >= 1, "≥1 histogram point", s.histogram_points)
