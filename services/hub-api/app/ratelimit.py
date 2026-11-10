"""In-process sliding-window rate limiter for auth and agent endpoints.

Limits are per replica (hub runs several replicas); a shared store is a follow-up. Each key
keeps only the timestamps inside the window, so memory is bounded by the limit.
"""

from __future__ import annotations

import threading
import time
from collections import deque

WINDOW_S = 60.0


class RateLimiter:
    """Sliding-window limiter keyed by an arbitrary string (IP, agent id, route)."""

    def __init__(self, limit_per_window: int, clock: object | None = None) -> None:
        """Allow ``limit_per_window`` hits per 60 s per key; ``clock`` overrides time.monotonic."""
        self._limit = limit_per_window
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._clock = clock if clock is not None else time.monotonic

    def hit(self, key: str) -> int | None:
        """Record one hit; return None if allowed, else seconds until a slot frees."""
        now = float(self._clock())  # type: ignore[operator]
        with self._lock:
            window = self._hits.setdefault(key, deque())
            while window and now - window[0] >= WINDOW_S:
                window.popleft()
            if len(window) >= self._limit:
                return max(1, int(WINDOW_S - (now - window[0])) + 1)
            window.append(now)
            return None
