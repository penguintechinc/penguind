//! Logging and metrics for the daemon: the Go `telemetry` package ported, with
//! the PII-sanitisation stub completed for real.
//!
//! [`Telemetry`] installs a JSON tracing subscriber and a prometheus registry
//! and hands modules a redacting [`TracingLogger`] plus a namespaced metrics
//! handle. The redaction core ([`sanitize`]) is a small pure module the logger
//! applies to every field, so a module author cannot forget to mask a secret.
//!
//! [`otel`] adds OTLP emission (logs, metrics, traces) alongside — never in
//! place of — the tracing/prometheus stack above, gated behind the
//! `penguind.otel-telemetry` feature flag; see that module's doc.
//! [`duration`] is the one new metrics primitive this adds: a
//! latency/duration histogram dual-written to prometheus and OTLP.

pub mod duration;
pub mod logger;
pub mod otel;
pub mod sanitize;
mod telemetry;

pub use duration::DurationHistogram;
pub use logger::TracingLogger;
pub use otel::{OtelConfig, OtelPipeline, OtelProtocol};
pub use sanitize::{is_sensitive_key, mask_secret, sanitize_value};
pub use telemetry::{Telemetry, TelemetryError};
