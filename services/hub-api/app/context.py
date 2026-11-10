"""Per-process dependency container and the cursor helpers shared by list endpoints."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Any

from penguin_dal import DB
from quart import current_app

from app.auth import TokenVerifier
from app.blobs import BlobStore
from app.config import Settings
from app.flags import FlagGate
from app.problems import bad_request
from app.ratelimit import RateLimiter
from app.telemetry import Telemetry


@dataclass(slots=True)
class HubContext:
    """Everything a request handler needs; built once in ``create_app``."""

    settings: Settings
    db: DB
    blobs: BlobStore
    verifier: TokenVerifier
    flags: FlagGate
    limiter: RateLimiter
    telemetry: Telemetry


def hub() -> HubContext:
    """Return the HubContext of the running application."""
    ctx: HubContext = current_app.config["HUB"]
    return ctx


def encode_cursor(last_id: int) -> str:
    """Encode the last internal row id of a page as an opaque URL-safe cursor."""
    return base64.urlsafe_b64encode(str(last_id).encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> int:
    """Decode a cursor to its row id (0 when absent); malformed cursors are 400."""
    if not cursor:
        return 0
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        value = int(base64.urlsafe_b64decode(padded.encode()).decode())
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise bad_request("malformed cursor") from exc
    if value < 0:
        raise bad_request("malformed cursor")
    return value


def page_rows(rows: list[Any], limit: int) -> tuple[list[Any], str | None]:
    """Split limit+1 fetched rows into (page items, next_cursor)."""
    if len(rows) > limit:
        return rows[:limit], encode_cursor(int(rows[limit - 1].id))
    return rows, None
