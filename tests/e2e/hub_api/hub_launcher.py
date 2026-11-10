"""Run the real hub-api under hypercorn with every ``penguind.hub-api.*`` flag ON.

The only difference from production is the flag gate: the test config turns the hub's flags
on with a static gate instead of a PostHog server (the E2E has no PostHog). Settings,
database, S3, OIDC verifier and telemetry are the production implementations built from the
environment. TLS on ``HUB_E2E_TLS_BIND`` (agents) and plain http on the loopback-only
``HUB_E2E_HTTP_BIND`` (pdcli, which permits http for loopback). SIGTERM shuts down cleanly,
which flushes telemetry.
"""

from __future__ import annotations

import asyncio
import os
import signal

from app.factory import create_app
from app.flags import ALL_FLAGS, StaticFlagGate
from hypercorn.asyncio import serve
from hypercorn.config import Config


async def main() -> None:
    """Serve until SIGTERM/SIGINT."""
    app = create_app(flags=StaticFlagGate(frozenset(ALL_FLAGS)))
    cfg = Config()
    cfg.bind = [os.environ["HUB_E2E_TLS_BIND"]]
    cfg.insecure_bind = [os.environ["HUB_E2E_HTTP_BIND"]]
    cfg.certfile = os.environ["HUB_E2E_CERT"]
    cfg.keyfile = os.environ["HUB_E2E_KEY"]
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await serve(app, cfg, shutdown_trigger=stop.wait)  # type: ignore[arg-type]


if __name__ == "__main__":
    asyncio.run(main())
