"""RFC 9457 problem errors and the stable hub error-code table, rendered in the envelope."""

from __future__ import annotations

from dataclasses import dataclass


class Code:
    """Stable integer hub error codes (OpenAPI Error.code)."""

    BAD_REQUEST = 1000
    VALIDATION = 1001
    UNAUTHORIZED = 1010
    FORBIDDEN = 1020
    NOT_FOUND = 1030
    CONFLICT = 1040
    PRECONDITION = 1050
    TOO_LARGE = 1060
    UNPROCESSABLE = 1070
    RATE_LIMITED = 1080
    GONE = 1090
    UNAVAILABLE = 1100
    INTERNAL = 1500


@dataclass(slots=True)
class ApiError(Exception):
    """An expected failure that maps to one HTTP status and one stable hub code."""

    status: int
    code: int
    title: str
    detail: str | None = None
    retry_after: int | None = None

    def __str__(self) -> str:
        """Return the title and detail for logs."""
        return f"{self.title}: {self.detail or ''}".rstrip(": ")


def unauthorized(detail: str = "missing or invalid credentials") -> ApiError:
    """Build a 401 error."""
    return ApiError(401, Code.UNAUTHORIZED, "Unauthorized", detail)


def forbidden(detail: str) -> ApiError:
    """Build a 403 error (missing scope, tenant claim missing or mismatched)."""
    return ApiError(403, Code.FORBIDDEN, "Forbidden", detail)


def not_found(what: str = "resource") -> ApiError:
    """Build a 404 error; cross-tenant ids are reported the same way as missing ones."""
    return ApiError(404, Code.NOT_FOUND, "Not Found", f"{what} not found in caller's tenant")


def conflict(detail: str) -> ApiError:
    """Build a 409 error for duplicate natural keys."""
    return ApiError(409, Code.CONFLICT, "Conflict", detail)


def precondition_failed() -> ApiError:
    """Build a 412 error for a mismatched If-Match."""
    return ApiError(412, Code.PRECONDITION, "Precondition Failed", "If-Match does not match")


def unprocessable(detail: str) -> ApiError:
    """Build a 422 error for semantically invalid input."""
    return ApiError(422, Code.UNPROCESSABLE, "Unprocessable", detail)


def bad_request(detail: str) -> ApiError:
    """Build a 400 error for malformed input."""
    return ApiError(400, Code.BAD_REQUEST, "Bad Request", detail)


def too_large(detail: str) -> ApiError:
    """Build a 413 error for uploads over the configured cap."""
    return ApiError(413, Code.TOO_LARGE, "Payload Too Large", detail)


def gone(detail: str = "agent revoked; re-enroll") -> ApiError:
    """Build a 410 error: the agent must stop syncing."""
    return ApiError(410, Code.GONE, "Gone", detail)


def unavailable(detail: str) -> ApiError:
    """Build a 503 error for a failed dependency."""
    return ApiError(503, Code.UNAVAILABLE, "Unavailable", detail)


def rate_limited(retry_after: int) -> ApiError:
    """Build a 429 error carrying Retry-After seconds."""
    return ApiError(429, Code.RATE_LIMITED, "Too Many Requests", None, retry_after)
