"""OpenTelemetry logs, metrics and traces for hub-api, configured only from OTEL_* env vars.

Logs flow from penguin logging (structlog over stdlib) into the OTel LoggingHandler on the
root logger. Exporters never block requests: the SDK batch processors drop on overflow.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import structlog
from opentelemetry._logs import LogRecord, SeverityNumber
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter as GrpcLogs
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
    OTLPMetricExporter as GrpcMetrics,
)
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
    OTLPSpanExporter as GrpcSpans,
)
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter as HttpLogs
from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
    OTLPMetricExporter as HttpMetrics,
)
from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
    OTLPSpanExporter as HttpSpans,
)
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor, InMemoryLogRecordExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    InMemoryMetricReader,
    PeriodicExportingMetricReader,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

_SEVERITY = {
    "debug": SeverityNumber.DEBUG,
    "info": SeverityNumber.INFO,
    "warning": SeverityNumber.WARN,
    "error": SeverityNumber.ERROR,
    "critical": SeverityNumber.FATAL,
    "exception": SeverityNumber.ERROR,
}
_OTEL_TARGET: dict[str, Any] = {"logger": None}


@dataclass(slots=True)
class Instruments:
    """Named metric instruments; histograms for every latency and size signal."""

    requests: Any
    request_latency: Any
    sync_requests: Any
    sync_latency: Any
    module_verify: Any
    upload_bytes: Any
    auth_failures: Any


@dataclass(slots=True)
class Telemetry:
    """Owns the providers for one app instance and exposes its instruments."""

    tracer: Any
    meter: Any
    instruments: Instruments
    _providers: list[Any] = field(default_factory=list)
    _memory: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> Telemetry:
        """Build exporters from OTEL_* env vars; an unset endpoint still collects locally."""
        protocol = os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc").lower()
        http = protocol.startswith("http")
        resource = Resource.create({"service.name": os.environ.get("OTEL_SERVICE_NAME", "hub-api")})
        spans = HttpSpans() if http else GrpcSpans()
        metric_exp = HttpMetrics() if http else GrpcMetrics()
        logs_exp = HttpLogs() if http else GrpcLogs()
        return cls._assemble(
            resource,
            span_exporter=spans,
            metric_reader=PeriodicExportingMetricReader(metric_exp, export_interval_millis=10_000),
            log_exporter=logs_exp,
        )

    @classmethod
    def in_memory(cls) -> Telemetry:
        """Build a telemetry set that keeps every signal in memory (tests and smoke)."""
        resource = Resource.create({"service.name": "hub-api-test"})
        reader = InMemoryMetricReader()
        spans = InMemorySpanExporter()
        logs = InMemoryLogRecordExporter()  # type: ignore[no-untyped-call]
        tel = cls._assemble(resource, span_exporter=spans, metric_reader=reader, log_exporter=logs)
        tel._memory = {"metrics": reader, "spans": spans, "logs": logs}
        return tel

    @classmethod
    def _assemble(
        cls,
        resource: Resource,
        *,
        span_exporter: SpanExporter,
        metric_reader: Any,
        log_exporter: Any,
    ) -> Telemetry:
        """Wire providers (not global) and create the instruments."""
        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
        meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        logger_provider = LoggerProvider(resource=resource)
        logger_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))
        meter = meter_provider.get_meter("hub-api")
        instruments = Instruments(
            requests=meter.create_counter("hub.http.requests", unit="1"),
            request_latency=meter.create_histogram("hub.http.duration", unit="s"),
            sync_requests=meter.create_counter("hub.sync.requests", unit="1"),
            sync_latency=meter.create_histogram("hub.sync.latency", unit="s"),
            module_verify=meter.create_counter("hub.module.verify", unit="1"),
            upload_bytes=meter.create_histogram("hub.module.upload.bytes", unit="By"),
            auth_failures=meter.create_counter("hub.auth.failures", unit="1"),
        )
        _attach_log_bridge(logger_provider)
        _OTEL_TARGET["logger"] = logger_provider.get_logger("hub-api")
        return cls(
            tracer=tracer_provider.get_tracer("hub-api"),
            meter=meter,
            instruments=instruments,
            _providers=[tracer_provider, meter_provider, logger_provider],
        )

    def memory_signals(self) -> dict[str, Any]:
        """Return the in-memory readers when built with ``in_memory``; empty otherwise."""
        return self._memory

    def shutdown(self) -> None:
        """Flush and stop every provider; exporter failures are swallowed by the SDK."""
        for provider in self._providers:
            try:
                provider.shutdown()
            except Exception:
                logging.getLogger(__name__).debug("telemetry shutdown failed", exc_info=True)


def _forward_to_otel(_logger: Any, method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """structlog processor: emit each penguin log event as an OTel LogRecord.

    Placed after penguin's sanitizer and before its renderer, so only sanitized fields leave.
    Forwarding failures are swallowed: telemetry must never break a log call.
    """
    target = _OTEL_TARGET["logger"]
    if target is not None:
        try:
            attrs = {
                k: v
                for k, v in event_dict.items()
                if k not in {"event", "timestamp", "level"}
                and isinstance(v, (str, int, float, bool))
            }
            target.emit(
                LogRecord(
                    timestamp=time.time_ns(),
                    severity_text=method_name.upper(),
                    severity_number=_SEVERITY.get(method_name, SeverityNumber.INFO),
                    body=str(event_dict.get("event", "")),
                    attributes=attrs,
                )
            )
        except Exception:
            return event_dict
    return event_dict


def install_log_forwarder() -> None:
    """Insert the OTel forwarder into penguin's structlog chain (idempotent)."""
    processors = list(structlog.get_config()["processors"])
    if not processors:
        raise RuntimeError("penguin logging must be configured before the OTel forwarder")
    if _forward_to_otel in processors:
        return
    chain: list[Any] = [*processors[:-1], _forward_to_otel, processors[-1]]
    structlog.configure(processors=chain)


def _attach_log_bridge(logger_provider: LoggerProvider) -> None:
    """Attach one OTel handler to the root logger, replacing any earlier hub-api bridge."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_hub_api_bridge", False):
            root.removeHandler(handler)
    handler = LoggingHandler(level=logging.INFO, logger_provider=logger_provider)
    handler._hub_api_bridge = True  # type: ignore[attr-defined]
    root.addHandler(handler)
