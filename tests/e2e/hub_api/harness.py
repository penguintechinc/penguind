"""Support pieces for the hub E2E: test PKI, the local OIDC issuer, the OTLP sink and drivers.

Only two things here stand in for production services, as T6 allows: the OIDC issuer (a
local JWKS signer with a device-flow endpoint for ``pdcli hub login``) and S3 (MinIO, started
by the test). Everything else the test talks to is the real component.
"""

from __future__ import annotations

import base64
import datetime as dt
import gzip
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
    ExportMetricsServiceRequest,
)
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

ADMIN_AUDIENCE = "hub-api-admin"
ADMIN_SCOPES = (
    "openid offline_access hub:groups:read hub:groups:write hub:agents:read hub:agents:write "
    "hub:modules:read hub:modules:write hub:flags:read hub:flags:write hub:bootstrap:read "
    "hub:bootstrap:write"
)


def free_port() -> int:
    """Return a currently unused loopback TCP port."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@dataclass(slots=True)
class Pki:
    """A throwaway CA and one leaf cert covering every host the test serves TLS on."""

    ca_pem: Path
    cert_pem: Path
    key_pem: Path
    bundle: Path

    @classmethod
    def create(cls, out: Path, hosts: list[str]) -> Pki:
        """Write CA, leaf (SANs = ``hosts``) and a CA bundle (system roots + test CA)."""
        out.mkdir(parents=True, exist_ok=True)
        now = dt.datetime.now(dt.UTC)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "penguind hub e2e CA")])
        ca = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        key = ec.generate_private_key(ec.SECP256R1())
        sans: list[x509.GeneralName] = []
        for h in dict.fromkeys(hosts):
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(h)))
            except ValueError:
                sans.append(x509.DNSName(h))
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        ca_pem = out / "ca.pem"
        cert_pem = out / "public.crt"
        key_pem = out / "private.key"
        ca_pem.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        cert_pem.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        key_pem.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        # MinIO runs as a non-root uid in its container and must read the test key.
        os.chmod(key_pem, 0o644)
        system = Path(ssl.get_default_verify_paths().cafile or "/etc/ssl/certs/ca-certificates.crt")
        roots = system.read_bytes() if system.exists() else b""
        bundle = out / "bundle.pem"
        bundle.write_bytes(roots + b"\n" + ca_pem.read_bytes())
        return cls(ca_pem, cert_pem, key_pem, bundle)

    def server_context(self) -> ssl.SSLContext:
        """TLS server context presenting the leaf certificate."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(self.cert_pem), str(self.key_pem))
        return ctx


@dataclass
class Issuer:
    """Local OIDC issuer: discovery, JWKS and an always-approving RFC 8628 device flow.

    Serves https (the issuer identity the hub trusts) and plain http on loopback (what
    ``pdcli hub login`` polls; pdcli permits http only for loopback). ``tenant`` selects the
    tenant claim of the next issued token so one run can act as two tenants.
    """

    pki: Pki
    tenant: str = field(default_factory=lambda: str(uuid.uuid4()))
    tokens_issued: int = 0

    def __post_init__(self) -> None:
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = uuid.uuid4().hex
        self.https_port = free_port()
        self.http_port = free_port()
        self.issuer = f"https://127.0.0.1:{self.https_port}"
        self._servers: list[ThreadingHTTPServer] = []

    def jwks(self) -> dict[str, Any]:
        """Public JWKS for the signing key."""
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self._key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def mint(self) -> str:
        """Sign an admin access token for the current tenant."""
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "aud": ADMIN_AUDIENCE,
            "sub": f"admin-{self.tenant[:8]}",
            "iat": now,
            "exp": now + 3600,
            "scope": ADMIN_SCOPES,
            "tenant": self.tenant,
            "teams": [],
            "roles": ["admin"],
        }
        self.tokens_issued += 1
        return jwt.encode(claims, self._key, algorithm="RS256", headers={"kid": self.kid})

    def _handler(self, base: str) -> type[BaseHTTPRequestHandler]:
        issuer = self

        class Handler(BaseHTTPRequestHandler):
            """Routes the four issuer endpoints."""

            def log_message(self, fmt: str, *args: Any) -> None:
                del fmt, args

            def _json(self, code: int, body: dict[str, Any]) -> None:
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                if self.path == "/.well-known/openid-configuration":
                    self._json(
                        200,
                        {
                            "issuer": issuer.issuer,
                            "jwks_uri": f"{base}/jwks",
                            "authorization_endpoint": f"{base}/authorize",
                            "token_endpoint": f"{base}/token",
                            "device_authorization_endpoint": f"{base}/device",
                        },
                    )
                elif self.path == "/jwks":
                    self._json(200, issuer.jwks())
                else:
                    self._json(404, {"error": "not_found"})

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                form = parse_qs(self.rfile.read(length).decode())
                if self.path == "/device":
                    self._json(
                        200,
                        {
                            "device_code": uuid.uuid4().hex,
                            "user_code": "E2E-TEST",
                            "verification_uri": f"{base}/verify",
                            "expires_in": 60,
                            "interval": 1,
                        },
                    )
                elif self.path == "/token" and form.get("device_code"):
                    self._json(
                        200,
                        {
                            "access_token": issuer.mint(),
                            "token_type": "Bearer",
                            "expires_in": 3600,
                            "refresh_token": uuid.uuid4().hex,
                        },
                    )
                else:
                    self._json(400, {"error": "unsupported_grant_type"})

        return Handler

    def start(self) -> None:
        """Serve https and http listeners on background threads."""
        tls = ThreadingHTTPServer(("127.0.0.1", self.https_port), self._handler(self.issuer))
        tls.socket = self.pki.server_context().wrap_socket(tls.socket, server_side=True)
        plain = ThreadingHTTPServer(
            ("127.0.0.1", self.http_port), self._handler(f"http://127.0.0.1:{self.http_port}")
        )
        for srv in (tls, plain):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self._servers.append(srv)

    def stop(self) -> None:
        """Stop both listeners."""
        for srv in self._servers:
            srv.shutdown()


@dataclass
class OtlpSink:
    """OTLP/HTTP protobuf receiver counting log records, metric points, histograms, spans."""

    port: int = field(default_factory=free_port)
    log_records: int = 0
    metric_points: int = 0
    histogram_points: int = 0
    spans: int = 0
    requests: int = 0
    errors: int = 0

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None

    def _ingest(self, path: str, body: bytes) -> None:
        with self._lock:
            self.requests += 1
            if path == "/v1/logs":
                req = ExportLogsServiceRequest.FromString(body)
                for rl in req.resource_logs:
                    for sl in rl.scope_logs:
                        self.log_records += len(sl.log_records)
            elif path == "/v1/metrics":
                req = ExportMetricsServiceRequest.FromString(body)
                for rm in req.resource_metrics:
                    for sm in rm.scope_metrics:
                        for m in sm.metrics:
                            kind = m.WhichOneof("data")
                            points = len(getattr(m, kind).data_points) if kind else 0
                            self.metric_points += points
                            if kind in ("histogram", "exponential_histogram"):
                                self.histogram_points += points
            elif path == "/v1/traces":
                req = ExportTraceServiceRequest.FromString(body)
                for rs in req.resource_spans:
                    for ss in rs.scope_spans:
                        self.spans += len(ss.spans)

    def start(self) -> None:
        """Serve on a background thread; failing to bind raises (never a skip)."""
        sink = self

        class Handler(BaseHTTPRequestHandler):
            """Accepts OTLP exports and answers an empty success."""

            def log_message(self, fmt: str, *args: Any) -> None:
                del fmt, args

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if self.headers.get("Content-Encoding") == "gzip":
                    body = gzip.decompress(body)
                try:
                    sink._ingest(self.path, body)
                    code = 200
                except Exception:
                    with sink._lock:
                        sink.errors += 1
                    code = 400
                self.send_response(code)
                self.send_header("Content-Type", "application/x-protobuf")
                self.send_header("Content-Length", "0")
                self.end_headers()

        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        """Stop the receiver."""
        if self._server is not None:
            self._server.shutdown()


class AgentDriver:
    """Line-JSON client for the ``hub_e2e_agent`` Rust driver process."""

    def __init__(self, binary: str) -> None:
        self._proc = subprocess.Popen(  # noqa: S603 - fixed binary path from the harness
            [binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def call(self, **req: Any) -> dict[str, Any]:
        """Send one command; return its ``data`` or raise with the driver's error."""
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write(json.dumps(req) + "\n")
        self._proc.stdin.flush()
        # The daemon's tracing logs share stdout; replies are the lines carrying "ok".
        while True:
            line = self._proc.stdout.readline()
            if not line:
                raise RuntimeError(f"agent driver exited (rc={self._proc.poll()})")
            try:
                reply = json.loads(line)
            except json.JSONDecodeError:
                reply = None
            if isinstance(reply, dict) and "ok" in reply:
                break
            print(f"[agent] {line.rstrip()}")
        if not reply["ok"]:
            raise RuntimeError(f"agent driver {req.get('cmd')}: {reply['error']}")
        data: dict[str, Any] = reply["data"]
        return data

    def close(self) -> None:
        """Close stdin and wait for the driver to exit."""
        if self._proc.stdin is not None:
            self._proc.stdin.close()
        self._proc.wait(timeout=30)


def pubkey_line(pubkey_file: Path) -> str:
    """Return the base64 key line of a minisign public key file."""
    lines = [ln for ln in pubkey_file.read_text().splitlines() if ln.strip()]
    key = lines[-1].strip()
    base64.b64decode(key, validate=True)
    return key
