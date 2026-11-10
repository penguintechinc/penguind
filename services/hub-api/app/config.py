"""Environment-driven settings for hub-api; every required value fails loudly at boot."""

from __future__ import annotations

import os
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_network

_TRUE = frozenset({"1", "true", "yes", "on"})
_MIN_SECRET_LEN = 32


def _env(name: str) -> str:
    """Return required env var ``name``; raise RuntimeError when unset or empty."""
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _flag(name: str) -> bool:
    """Return True when env var ``name`` is a truthy token (default False)."""
    return os.environ.get(name, "").strip().lower() in _TRUE


def _cidrs(raw: str) -> tuple[IPv4Network | IPv6Network, ...]:
    """Parse a comma-separated CIDR list; empty input means no trusted proxies."""
    return tuple(ip_network(part.strip(), strict=False) for part in raw.split(",") if part.strip())


@dataclass(slots=True, frozen=True)
class Settings:
    """Immutable runtime configuration built once per process."""

    database_dsn: str
    base_url: str
    oidc_issuer_url: str
    oidc_audience: str
    agent_jwt_secret: str
    s3_bucket: str
    s3_endpoint: str | None
    s3_region: str | None
    trusted_pubkeys: tuple[str, ...]
    trust_forwarded_cert: bool
    trusted_proxy_cidrs: tuple[IPv4Network | IPv6Network, ...]
    posthog_api_key: str | None
    posthog_host: str | None
    max_upload_bytes: int
    stale_after_s: int
    rate_limit_per_min: int
    agent_token_ttl_s: int

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from the environment; raise RuntimeError on missing required values."""
        secret = _env("HUB_AGENT_JWT_SECRET")
        if len(secret) < _MIN_SECRET_LEN:
            raise RuntimeError(f"HUB_AGENT_JWT_SECRET must be at least {_MIN_SECRET_LEN} chars")
        keys = tuple(k.strip() for k in os.environ.get("HUB_TRUSTED_PUBKEYS", "").split(",") if k)
        return cls(
            database_dsn=_env("HUB_DATABASE_DSN"),
            base_url=_env("BASE_URL").rstrip("/"),
            oidc_issuer_url=_env("OIDC_ISSUER_URL").rstrip("/"),
            oidc_audience=_env("OIDC_AUDIENCE"),
            agent_jwt_secret=secret,
            s3_bucket=_env("HUB_S3_BUCKET"),
            s3_endpoint=os.environ.get("HUB_S3_ENDPOINT") or None,
            s3_region=os.environ.get("HUB_S3_REGION") or None,
            trusted_pubkeys=keys,
            trust_forwarded_cert=_flag("HUB_TRUST_FORWARDED_CERT"),
            trusted_proxy_cidrs=_cidrs(os.environ.get("HUB_TRUSTED_PROXY_CIDRS", "")),
            posthog_api_key=os.environ.get("POSTHOG_API_KEY") or None,
            posthog_host=os.environ.get("POSTHOG_HOST") or None,
            max_upload_bytes=int(os.environ.get("HUB_MAX_UPLOAD_BYTES", str(64 * 1024 * 1024))),
            stale_after_s=int(os.environ.get("HUB_STALE_AFTER_S", "86400")),
            rate_limit_per_min=int(os.environ.get("HUB_RATE_LIMIT_PER_MIN", "60")),
            agent_token_ttl_s=min(3600, int(os.environ.get("HUB_AGENT_TOKEN_TTL_S", "3600"))),
        )
