"""Effective-config resolution and the ConfigRevision digest used as the sync ETag.

Precedence per field: agent override > merged groups > tenant default. Group merge:
allowed_tools = intersection, numeric limits = minimum, settings = per-module last-write
with groups ordered by name (ties by public_id) so the result is deterministic.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from app.models.tenant_db import TenantDB

LIMIT_KEYS: tuple[str, ...] = (
    "max_memory_mb",
    "max_fuel",
    "max_tool_calls_per_min",
    "max_concurrent_instances",
    "poll_interval_s",
    "max_stale_s",
)
_POLICY_KEYS = frozenset({"allowed_tools", "limits", "settings"})


class PolicyError(ValueError):
    """Raised when a stored or submitted policy document is malformed."""


@dataclass(slots=True, frozen=True)
class Policy:
    """A parsed ConfigPolicy; ``has_tools`` distinguishes absent from explicit null."""

    has_tools: bool = False
    allowed_tools: frozenset[str] | None = None
    limits: Mapping[str, int] = field(default_factory=dict)
    settings: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    @classmethod
    def parse(cls, doc: Mapping[str, Any] | None) -> Policy:
        """Validate and parse a ConfigPolicy JSON document (None = empty policy)."""
        if doc is None:
            return cls()
        if not isinstance(doc, Mapping):
            raise PolicyError("policy must be an object")
        unknown = set(doc) - _POLICY_KEYS
        if unknown:
            raise PolicyError(f"unknown policy keys: {sorted(unknown)}")
        has_tools = "allowed_tools" in doc
        tools_raw = doc.get("allowed_tools")
        tools: frozenset[str] | None = None
        if tools_raw is not None:
            if not isinstance(tools_raw, list) or not all(isinstance(t, str) for t in tools_raw):
                raise PolicyError("allowed_tools must be a list of strings or null")
            tools = frozenset(tools_raw)
        limits_raw = doc.get("limits", {})
        if not isinstance(limits_raw, Mapping):
            raise PolicyError("limits must be an object")
        limits: dict[str, int] = {}
        for key, value in limits_raw.items():
            if key not in LIMIT_KEYS:
                raise PolicyError(f"unknown limit {key!r}")
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise PolicyError(f"limit {key!r} must be a positive integer")
            limits[key] = value
        settings_raw = doc.get("settings", {})
        if not isinstance(settings_raw, Mapping) or not all(
            isinstance(v, Mapping) for v in settings_raw.values()
        ):
            raise PolicyError("settings must be an object of objects")
        return cls(has_tools, tools, limits, {k: dict(v) for k, v in settings_raw.items()})

    def to_doc(self) -> dict[str, Any]:
        """Serialize to a canonical ConfigPolicy document (sorted tools)."""
        doc: dict[str, Any] = {
            "limits": dict(sorted(self.limits.items())),
            "settings": {k: dict(self.settings[k]) for k in sorted(self.settings)},
        }
        if self.has_tools:
            doc["allowed_tools"] = (
                None if self.allowed_tools is None else sorted(self.allowed_tools)
            )
        return doc


@dataclass(slots=True, frozen=True)
class GroupPolicy:
    """A group's policy plus the keys that make merge order deterministic."""

    name: str
    public_id: uuid.UUID
    policy: Policy


def merge_groups(groups: Iterable[GroupPolicy]) -> Policy:
    """Fold groups: tools intersect (null = unrestricted), limits min, settings last-by-name."""
    ordered = sorted(groups, key=lambda g: (g.name, str(g.public_id)))
    tools: frozenset[str] | None = None
    has_tools = False
    limits: dict[str, int] = {}
    settings: dict[str, Mapping[str, Any]] = {}
    for g in ordered:
        p = g.policy
        if p.allowed_tools is not None:
            tools = p.allowed_tools if tools is None else tools & p.allowed_tools
            has_tools = True
        for key, value in p.limits.items():
            limits[key] = min(value, limits.get(key, value))
        settings.update(p.settings)
    return Policy(has_tools, tools, limits, settings)


def resolve(default: Policy, groups: Iterable[GroupPolicy], override: Policy | None) -> Policy:
    """Resolve per field: override > merged groups > tenant default."""
    layers = [default, merge_groups(groups)]
    if override is not None:
        layers.append(override)
    has_tools, tools = False, None
    limits: dict[str, int] = {}
    settings: dict[str, Mapping[str, Any]] = {}
    for layer in layers:
        if layer.has_tools:
            has_tools, tools = True, layer.allowed_tools
        limits.update(layer.limits)
        settings.update(layer.settings)
    return Policy(has_tools, tools, limits, settings)


@dataclass(slots=True, frozen=True)
class ConfigRevision:
    """A content digest of a sync payload; ``etag`` is the strong HTTP ETag form."""

    digest: str

    @property
    def etag(self) -> str:
        """Return the quoted strong ETag."""
        return f'"{self.digest}"'

    @classmethod
    def of(cls, payload: Mapping[str, Any]) -> ConfigRevision:
        """Digest ``payload`` as sha256 over canonical JSON (sorted keys, no whitespace)."""
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
        )
        return cls(hashlib.sha256(canonical.encode("utf-8")).hexdigest())

    def matches(self, if_none_match: str | None) -> bool:
        """Return True if an If-None-Match header names this revision."""
        if not if_none_match:
            return False
        tags = {t.strip().removeprefix("W/") for t in if_none_match.split(",")}
        return "*" in tags or self.etag in tags


def tenant_default(tdb: TenantDB) -> Policy:
    """Load the tenant default policy (empty if the tenant has none)."""
    rows = tdb.select("tenant_configs")
    return Policy.parse(rows[0].policy) if rows else Policy()


def agent_groups(tdb: TenantDB, agent_pk: int) -> list[GroupPolicy]:
    """Load the policies of every group the agent belongs to, within the tenant."""
    links = tdb.select("group_members", tdb.field("group_members", "agent_id") == agent_pk)
    out: list[GroupPolicy] = []
    for link in links:
        g = tdb.get_by_id("groups", link.group_id)
        if g is not None:
            out.append(GroupPolicy(g.name, g.public_id, Policy.parse(g.policy)))
    return out


def effective_config(tdb: TenantDB, agent_public_id: uuid.UUID) -> Policy | None:
    """Resolve the effective hub policy for an agent; None if not in this tenant."""
    agent = tdb.get("agents", agent_public_id)
    if agent is None:
        return None
    override = Policy.parse(agent.override) if agent.override is not None else None
    return resolve(tenant_default(tdb), agent_groups(tdb, agent.id), override)
