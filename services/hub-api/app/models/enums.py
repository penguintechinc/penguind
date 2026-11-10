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


class ApplyResult(IntEnum):
    """Agent apply outcome reported in StatusReport (OpenAPI ApplyResult)."""

    APPLIED = 1
    PARTIAL = 2
    REJECTED = 3
