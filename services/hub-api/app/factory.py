"""Application factory: wires settings, data layer, auth, telemetry, routes and error handling.

``create_app()`` with no arguments reads the environment (hypercorn ``app:create_app()``).
Tests inject collaborators (db, verifier, blobs, flags, telemetry) through the keyword args.
"""

from __future__ import annotations

import dataclasses
import logging
import time
from typing import Any

from penguin_dal import DB
from penguintechinc_utils import configure_logging, get_logger
from quart import Quart, g, jsonify, request
from quart_schema import QuartSchema, RequestSchemaValidationError
from werkzeug.exceptions import HTTPException

from app.api import admin, agent, health
from app.auth import OidcVerifier, TokenVerifier
from app.blobs import BlobStore, S3BlobStore
from app.config import Settings
from app.context import HubContext
from app.envelope import meta
from app.flags import ALL_FLAGS, FlagGate, build_flag_gate
from app.mtls import take_forwarded_identity
from app.problems import ApiError, Code
from app.ratelimit import RateLimiter
from app.telemetry import Telemetry, install_log_forwarder

_log = logging.getLogger("hub_api")
_PROBLEM = "application/problem+json"


def _problem(err: ApiError) -> Any:
    """Render an ApiError as the envelope with an RFC 9457 problem object in data."""
    body = {
        "status": "error",
        "data": {
            "type": "about:blank",
            "title": err.title,
            "status": err.status,
            "code": err.code,
            "detail": err.detail,
            "instance": request.path,
            "trace_id": getattr(g, "trace_id", None),
        },
        "meta": dataclasses.asdict(meta()),
    }
    response = jsonify(body)
    response.status_code = err.status
    response.mimetype = _PROBLEM
    if err.retry_after is not None:
        response.headers["Retry-After"] = str(err.retry_after)
    return response


def _register_errors(app: Quart) -> None:
    """Map every failure class onto the problem envelope; unexpected errors become 500."""

    @app.errorhandler(ApiError)
    async def api_error(err: ApiError) -> Any:
        """Render a domain error."""
        return _problem(err)

    @app.errorhandler(RequestSchemaValidationError)
    async def schema_error(err: RequestSchemaValidationError) -> Any:
        """Render a body/query validation failure as 400."""
        return _problem(ApiError(400, Code.VALIDATION, "Bad Request", str(err)))

    @app.errorhandler(HTTPException)
    async def http_error(err: HTTPException) -> Any:
        """Render routing and framework HTTP errors in the envelope."""
        code = err.code or 500
        return _problem(
            ApiError(code, Code.BAD_REQUEST if code < 500 else Code.INTERNAL, err.name, None)
        )

    @app.errorhandler(Exception)
    async def unexpected(err: Exception) -> Any:
        """Log the traceback and answer 500 without leaking internals."""
        _log.error("unhandled error", exc_info=err)
        return _problem(ApiError(500, Code.INTERNAL, "Internal Server Error", None))


def _register_hooks(app: Quart, ctx: HubContext) -> None:
    """Install request tracing, identity-header stripping and per-request metrics."""
    tracer = ctx.telemetry.tracer
    instruments = ctx.telemetry.instruments

    @app.before_request
    async def start_request() -> None:
        """Strip untrusted identity headers, open the request span, stamp timing."""
        g.forwarded_spiffe = take_forwarded_identity(
            request.headers, ctx.settings, request.remote_addr
        )
        g.started = time.perf_counter()
        span = tracer.start_span(f"{request.method} {request.path}")
        g.span = span
        g.trace_id = format(span.get_span_context().trace_id, "032x")

    @app.after_request
    async def finish_request(response: Any) -> Any:
        """Record request count and latency, labelled by route template (not raw path)."""
        route = request.url_rule.rule if request.url_rule is not None else "unmatched"
        attrs = {"route": route, "method": request.method, "status": str(response.status_code)}
        instruments.requests.add(1, attrs)
        instruments.request_latency.record(time.perf_counter() - g.started, attrs)
        for name, value in getattr(g, "extra_headers", {}).items():
            response.headers[name] = value
        return response

    @app.teardown_request
    async def end_span(_exc: BaseException | None) -> None:
        """Close the request span; exporter failures never reach the request."""
        span = g.pop("span", None)
        if span is not None:
            span.end()


def create_app(
    settings: Settings | None = None,
    *,
    db: DB | None = None,
    verifier: TokenVerifier | None = None,
    blobs: BlobStore | None = None,
    flags: FlagGate | None = None,
    telemetry: Telemetry | None = None,
) -> Quart:
    """Build the hub-api Quart application.

    Collaborators default to production implementations built from ``settings``; any can be
    replaced for tests.
    """
    configure_logging(level=logging.INFO, json_output=True)
    install_log_forwarder()
    cfg = settings if settings is not None else Settings.from_env()
    app = Quart("hub_api")
    app.config["MAX_CONTENT_LENGTH"] = cfg.max_upload_bytes + 65536
    QuartSchema(app, openapi_path=None, swagger_ui_path=None, redoc_ui_path=None)
    ctx = HubContext(
        settings=cfg,
        db=db if db is not None else DB(cfg.database_dsn, pool_size=10),
        blobs=blobs
        if blobs is not None
        else S3BlobStore(cfg.s3_bucket, cfg.s3_endpoint, cfg.s3_region),
        verifier=verifier
        if verifier is not None
        else OidcVerifier(cfg.oidc_issuer_url, cfg.oidc_audience),
        flags=flags if flags is not None else build_flag_gate(cfg),
        limiter=RateLimiter(cfg.rate_limit_per_min),
        telemetry=telemetry if telemetry is not None else Telemetry.from_env(),
    )
    app.config["HUB"] = ctx
    get_logger("hub_api").info("hub-api configured", tenant_flags=len(ALL_FLAGS), version="0.1.0")
    app.register_blueprint(health.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(agent.bp)
    _register_errors(app)
    _register_hooks(app, ctx)

    @app.after_serving
    async def shutdown() -> None:
        """Flush telemetry on process stop."""
        ctx.telemetry.shutdown()

    return app
