"""PostHog feature-flag gate for hub-api routes; every flag is default OFF.

Flags are read per request with the caller's distinct id. Without POSTHOG_API_KEY, or when
PostHog is unreachable, the last known value is used (never-seen flags are OFF), so the
service never crashes on flag-backend failure.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

from posthog import Posthog

from app.config import Settings

FLAG_ADMIN_API = "penguind.hub-api.admin-api"
FLAG_AGENT_API = "penguind.hub-api.agent-api"
FLAG_MODULE_UPLOAD = "penguind.hub-api.module-upload"
ALL_FLAGS: tuple[str, ...] = (FLAG_ADMIN_API, FLAG_AGENT_API, FLAG_MODULE_UPLOAD)

_log = logging.getLogger(__name__)


class FlagGate(Protocol):
    """Answers whether a hub feature flag is ON for a distinct id."""

    def enabled(self, key: str, distinct_id: str) -> bool:
        """Return True only when the flag is positively ON."""
        ...


@dataclass(slots=True)
class StaticFlagGate:
    """A gate with a fixed set of ON flags (tests, air-gapped defaults)."""

    on: frozenset[str] = field(default_factory=frozenset)

    def enabled(self, key: str, distinct_id: str) -> bool:
        """Return True if ``key`` is in the fixed ON set."""
        del distinct_id
        return key in self.on


@dataclass(slots=True)
class PostHogFlagGate:
    """FlagGate backed by a self-hosted PostHog; last-known values survive outages."""

    client: Posthog
    _last_known: dict[str, bool] = field(default_factory=dict)

    def enabled(self, key: str, distinct_id: str) -> bool:
        """Evaluate the flag; on any backend error return the last known value (default OFF)."""
        try:
            value = bool(self.client.feature_enabled(key, distinct_id))
        except Exception:
            _log.warning("flag evaluation failed; using last known value", extra={"flag": key})
            return self._last_known.get(key, False)
        self._last_known[key] = value
        return value


def build_flag_gate(settings: Settings) -> FlagGate:
    """Return a PostHog gate when configured, else an all-OFF static gate."""
    if settings.posthog_api_key is None:
        return StaticFlagGate()
    client = Posthog(settings.posthog_api_key, host=settings.posthog_host)
    return PostHogFlagGate(client)
