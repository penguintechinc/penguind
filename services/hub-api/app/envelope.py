"""Response envelope {status,data,meta} and cached typed envelope/page dataclasses."""

from __future__ import annotations

import dataclasses
import datetime as dt
from dataclasses import dataclass
from functools import cache
from typing import Any

from quart import g

API_VERSION = 1


@dataclass(slots=True)
class Meta:
    """Envelope metadata: API major version, server time and OTel trace id."""

    version: int
    timestamp: str
    trace_id: str | None


@cache
def envelope_type(data_type: type) -> type:
    """Return a dataclass ``Envelope[data_type]`` with status, data and meta fields."""
    return dataclasses.make_dataclass(
        f"Envelope_{data_type.__name__}",
        [("status", str), ("data", data_type), ("meta", Meta)],
        slots=True,
    )


@cache
def page_type(item_type: type) -> type:
    """Return a dataclass ``Page[item_type]`` with items and an opaque next_cursor."""
    return dataclasses.make_dataclass(
        f"Page_{item_type.__name__}",
        [("items", list[item_type]), ("next_cursor", str | None)],  # type: ignore[valid-type]
        slots=True,
    )


@cache
def list_type(item_type: type) -> Any:
    """Return the envelope type for a bare list response of ``item_type``."""
    return envelope_type(list[item_type])  # type: ignore[valid-type]


def now_iso() -> str:
    """Return the current UTC time as an RFC 3339 string."""
    return dt.datetime.now(dt.UTC).isoformat()


def iso(value: dt.datetime | None) -> str | None:
    """Format an optional datetime as RFC 3339 (None stays None)."""
    return None if value is None else value.isoformat()


def meta() -> Meta:
    """Build the Meta for the current request, including its trace id when present."""
    return Meta(API_VERSION, now_iso(), getattr(g, "trace_id", None))


def envelope(data_type: type, data: Any) -> Any:
    """Wrap ``data`` (an instance of ``data_type``) in the typed envelope for this request."""
    return envelope_type(data_type)(status="success", data=data, meta=meta())
