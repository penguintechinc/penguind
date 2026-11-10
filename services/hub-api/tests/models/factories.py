"""Row builders for model tests; values are synthetic, never PII."""

from typing import Any

from penguin_dal import Row

from app.models import AgentStatus, ModuleStatus, Platform, TenantDB

SUB = "oidc|0f3c9a"  # opaque OIDC sub, not an identity


def group(tdb: TenantDB, name: str, policy: dict[str, Any] | None = None) -> Row:
    """Insert a group with ``policy``."""
    return tdb.insert("groups", name=name, policy=policy or {}, created_by=SUB)


def agent(tdb: TenantDB, override: dict[str, Any] | None = None) -> Row:
    """Insert an active linux agent."""
    return tdb.insert(
        "agents",
        status=AgentStatus.ACTIVE,
        platform=Platform.LINUX,
        agent_version="0.1.0",
        override=override,
    )


def module(tdb: TenantDB, module_id: str = "mod-a", version: str = "1.0.0") -> Row:
    """Insert an available module version."""
    return tdb.insert(
        "module_versions",
        module_id=module_id,
        version=version,
        sha256="a" * 64,
        signature="sig",
        size_bytes=10,
        blob_key=f"blobs/{module_id}/{version}",
        status=ModuleStatus.AVAILABLE,
        created_by=SUB,
    )
