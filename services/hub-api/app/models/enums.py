"""Int enum codes for hub-api entities.

Single source of the code maps documented in openapi/v1.yaml; stored as SMALLINT, never strings.
"""

from enum import IntEnum


class AgentStatus(IntEnum):
    """Agent lifecycle state (OpenAPI AgentStatus)."""

    ACTIVE = 1
    STALE = 2
    REVOKED = 3


class Platform(IntEnum):
    """Agent operating system (OpenAPI Platform)."""

    LINUX = 1
    MACOS = 2
    WINDOWS = 3


class ModuleStatus(IntEnum):
    """Module version availability (OpenAPI ModuleStatus)."""

    AVAILABLE = 1
    YANKED = 2


class FlagScope(IntEnum):
    """Hub flag scope (OpenAPI FlagScope)."""

    TENANT = 1
    GROUP = 2


class AuditAction(IntEnum):
    """Admin write recorded in audit_events (int code, never a string)."""

    GROUP_CREATE = 1
    GROUP_UPDATE = 2
    GROUP_DELETE = 3
    GROUP_MEMBERS_SET = 4
    GROUP_MODULES_SET = 5
    AGENT_CREATE = 6
    AGENT_REVOKE = 7
    AGENT_OVERRIDE_SET = 8
    AGENT_OVERRIDE_CLEAR = 9
    BOOTSTRAP_CREATE = 10
    BOOTSTRAP_REVOKE = 11
    MODULE_UPLOAD = 12
    MODULE_STATUS_SET = 13
    FLAG_UPSERT = 14
    FLAG_DELETE = 15


class TargetType(IntEnum):
    """Resource kind an audit event refers to (int code)."""

    GROUP = 1
    AGENT = 2
    BOOTSTRAP_TOKEN = 3
    MODULE = 4
    FLAG = 5


class ApplyResult(IntEnum):
    """Agent apply outcome reported in StatusReport (OpenAPI ApplyResult)."""

    APPLIED = 1
    PARTIAL = 2
    REJECTED = 3
