"""Request and response dataclasses, one per schema in openapi/v1.yaml.

Fields mirror the contract exactly; UUIDs and timestamps are strings on the wire; enums are
int codes. Policy documents stay raw dicts so that key presence (absent vs null
allowed_tools) survives validation; ``app.models.policy.Policy.parse`` is the authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Health:
    """Probe body: overall status."""

    status: str


@dataclass(slots=True)
class Group:
    """A named agent group with its restrict-only policy."""

    id: str
    name: str
    description: str
    policy: dict[str, Any]
    agent_count: int
    created_at: str
    updated_at: str


@dataclass(slots=True)
class GroupCreate:
    """Body of POST /api/v1/groups."""

    name: str
    description: str = ""
    policy: dict[str, Any] | None = None


@dataclass(slots=True)
class GroupUpdate:
    """Body of PATCH /api/v1/groups/{group_id}; at least one field required."""

    name: str | None = None
    description: str | None = None
    policy: dict[str, Any] | None = None


@dataclass(slots=True)
class MemberSet:
    """Replacement agent membership for a group."""

    agent_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ModuleAssignmentInput:
    """One module version to assign to a group."""

    module_version_id: str


@dataclass(slots=True)
class ModuleAssignment:
    """A module version assigned to a group."""

    module_version_id: str
    module_id: str
    version: str


@dataclass(slots=True)
class ModuleAssignmentList:
    """Wrapper so a bare list of assignments can be enveloped by the typed envelope."""

    items: list[ModuleAssignment]


@dataclass(slots=True)
class AgentCreate:
    """Body of POST /api/v1/agents: pre-register an agent's SPIFFE identity."""

    spiffe_id: str
    platform: int
    agent_version: str
    group_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Agent:
    """An enrolled or pre-registered agent; ``status`` is computed on read."""

    id: str
    status: int
    platform: int
    group_ids: list[str]
    enrolled_at: str
    agent_version: str | None = None
    last_seen_at: str | None = None
    applied_etag: str | None = None


@dataclass(slots=True)
class AgentDetail:
    """Agent plus its override, computed effective policy and last status report."""

    id: str
    status: int
    platform: int
    group_ids: list[str]
    enrolled_at: str
    effective: dict[str, Any]
    agent_version: str | None = None
    last_seen_at: str | None = None
    applied_etag: str | None = None
    override: dict[str, Any] | None = None
    last_report: dict[str, Any] | None = None


@dataclass(slots=True)
class BootstrapTokenCreate:
    """Body of POST /api/v1/bootstrap-tokens."""

    group_ids: list[str] = field(default_factory=list)
    ttl_s: int = 86400


@dataclass(slots=True)
class BootstrapToken:
    """Bootstrap token metadata (never the secret)."""

    id: str
    expires_at: str
    used: bool
    group_ids: list[str]
    used_by_agent_id: str | None = None


@dataclass(slots=True)
class BootstrapTokenSecret(BootstrapToken):
    """Creation response: metadata plus the one-time plaintext secret."""

    token: str = ""


@dataclass(slots=True)
class Module:
    """A stored module version."""

    id: str
    module_id: str
    version: str
    sha256: str
    signature: str
    status: int
    size_bytes: int
    created_at: str


@dataclass(slots=True)
class ModuleStatusUpdate:
    """Body of PATCH /api/v1/modules/{module_version_id}."""

    status: int


@dataclass(slots=True)
class Flag:
    """A restrict-only hub flag at tenant or group scope."""

    id: str
    key: str
    enabled: bool
    scope: int
    updated_at: str
    group_id: str | None = None


@dataclass(slots=True)
class FlagInput:
    """Body of PUT /api/v1/flags (upsert)."""

    key: str
    enabled: bool
    scope: int
    group_id: str | None = None


@dataclass(slots=True)
class EnrollRequest:
    """Body of POST /api/v1/agent/enroll."""

    platform: int
    agent_version: str
    csr_pem: str | None = None


@dataclass(slots=True)
class RefreshRequest:
    """Body of POST /api/v1/agent/token."""

    refresh_token: str


@dataclass(slots=True)
class TokenResponse:
    """Enroll and refresh response: machine JWT plus rotated refresh token."""

    agent_id: str
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str


@dataclass(slots=True)
class ModuleManifest:
    """Exactly the shape penguin-wasm-host fetcher.rs deserialises."""

    id: str
    version: str
    sha256: str
    signature: str
    binary_url: str


@dataclass(slots=True)
class SyncBundle:
    """Desired state for one agent; its digest (without generated_at) is the ETag."""

    agent_id: str
    generated_at: str
    policy: dict[str, Any]
    flags: dict[str, bool]
    modules: list[ModuleManifest]
    poll_interval_s: int
    max_stale_s: int


@dataclass(slots=True)
class ModuleReport:
    """One module's load outcome inside a StatusReport."""

    id: str
    version: str
    loaded: bool
    error_code: int | None = None


@dataclass(slots=True)
class StatusReport:
    """Agent-applied state; stored as the agent's last_report."""

    applied_etag: str
    result: int
    modules: list[ModuleReport]
    agent_version: str | None = None


@dataclass(slots=True)
class AuditEvent:
    """One admin write, identified by public ids only."""

    id: str
    action: int
    target_type: int
    actor: str
    created_at: str
    target_id: str | None = None
