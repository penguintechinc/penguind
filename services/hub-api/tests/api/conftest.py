"""API test fixtures: app on the shared Postgres, fake OIDC verifier, moto S3, in-memory OTel."""

import itertools
import uuid
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from typing import Any

import boto3
import pytest
from moto import mock_aws
from penguin_dal import DB
from quart import Quart
from quart.testing import QuartClient

from app.auth import TokenInvalidError
from app.blobs import S3BlobStore
from app.config import Settings
from app.factory import create_app
from app.flags import ALL_FLAGS, StaticFlagGate
from app.telemetry import Telemetry
from tests.api.helpers import AGENT_SECRET, SPIFFE

BUCKET = "hub-test"
ADMIN_SCOPES = (
    "hub:groups:read hub:groups:write hub:agents:read hub:agents:write "
    "hub:modules:read hub:modules:write hub:flags:read hub:flags:write "
    "hub:bootstrap:read hub:bootstrap:write"
)
_tenant_ids = itertools.count(1000)


class FakeVerifier:
    """Admin token verifier that maps opaque test tokens to fixed claims."""

    def __init__(self) -> None:
        """Start with no registered tokens."""
        self.tokens: dict[str, Mapping[str, Any]] = {}

    async def verify(self, token: str) -> Mapping[str, Any]:
        """Return the registered claims or raise TokenInvalidError like the real verifier."""
        claims = self.tokens.get(token)
        if claims is None:
            raise TokenInvalidError("unknown token")
        return claims


@pytest.fixture
def verifier() -> FakeVerifier:
    """A fresh fake OIDC verifier per test."""
    return FakeVerifier()


@pytest.fixture
def tenant() -> int:
    """A tenant id unique to this test (integer, as carried by the token claim)."""
    return next(_tenant_ids)


@pytest.fixture
def admin_headers(verifier: FakeVerifier) -> Callable[..., dict[str, str]]:
    """Factory: register an admin token for ``tenant`` with ``scope`` and return its header."""

    def make(
        tenant: int | str | None, scope: str = ADMIN_SCOPES, *, drop_tenant: bool = False
    ) -> dict[str, str]:
        """Return an Authorization header whose verified claims carry the given tenant."""
        token = f"adm-{uuid.uuid4().hex}"
        claims: dict[str, Any] = {"sub": "oidc|test-admin", "scope": scope}
        if not drop_tenant:
            claims["tenant"] = str(tenant)
        verifier.tokens[token] = claims
        return {"Authorization": f"Bearer {token}"}

    return make


@pytest.fixture
def settings() -> Settings:
    """Deterministic settings with generous limits; no environment is read."""
    return Settings(
        database_dsn="unused-by-tests",
        base_url="https://hub.test",
        oidc_issuer_url="https://127.0.0.1:9",
        oidc_audience="hub-api",
        agent_jwt_secret=AGENT_SECRET,
        s3_bucket=BUCKET,
        s3_endpoint=None,
        s3_region="us-east-1",
        trusted_pubkeys=(),
        trust_forwarded_cert=False,
        spiffe_prefix=SPIFFE,
        posthog_api_key=None,
        posthog_host=None,
        max_upload_bytes=1024 * 1024,
        stale_after_s=86400,
        rate_limit_per_min=10_000,
        agent_token_ttl_s=3600,
    )


@pytest.fixture(autouse=True)
def aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give boto3 dummy credentials so moto never touches real AWS."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def blobs() -> Iterator[S3BlobStore]:
    """An S3BlobStore on a moto bucket; the mock is active for the whole test."""
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=BUCKET)
        yield S3BlobStore(BUCKET, None, "us-east-1")


@pytest.fixture
def telemetry() -> Telemetry:
    """Telemetry that keeps metrics, spans and logs in memory for assertions."""
    return Telemetry.in_memory()


@pytest.fixture
def app_db(db: DB) -> DB:
    """The shared session database (migrated to head by the root conftest)."""
    return db


@pytest.fixture
def app(
    app_db: DB,
    settings: Settings,
    verifier: FakeVerifier,
    blobs: S3BlobStore,
    telemetry: Telemetry,
) -> Quart:
    """A hub-api app with every flag ON and all collaborators injected."""
    return create_app(
        settings,
        db=app_db,
        verifier=verifier,
        blobs=blobs,
        flags=StaticFlagGate(frozenset(ALL_FLAGS)),
        telemetry=telemetry,
    )


@pytest.fixture
async def client(app: Quart) -> AsyncIterator[QuartClient]:
    """Quart test client bound to the app."""
    async with app.test_app():
        yield app.test_client()
