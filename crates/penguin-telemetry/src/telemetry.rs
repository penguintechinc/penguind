//! The daemon's logging + metrics setup.
//!
//! [`Telemetry::new`] installs the global tracing subscriber (JSON output, the
//! Go zap parity) and builds a prometheus registry with the process collector.
//! It hands modules a redacting [`Logger`] and a namespaced [`Metrics`] handle.
//!
//! Only *module* logs (everything through [`crate::TracingLogger`]) are
//! redacted; daemon-internal `tracing::` calls are written by us and never carry
//! secrets, so a global redaction layer is unnecessary.

use std::sync::Arc;

use penguin_sdk::{Logger, Metrics, MetricsError};
use tracing::level_filters::LevelFilter;

use crate::duration::DurationHistogram;
use crate::logger::TracingLogger;
use crate::otel::OtelPipeline;

/// A telemetry setup failure (only an invalid log level or a collector that
/// fails to register).
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct TelemetryError(pub String);

/// Owns the metrics registry and vends per-module logging/metrics handles.
pub struct Telemetry {
    registry: prometheus::Registry,
}

impl Telemetry {
    /// Builds telemetry at the given log level and installs the global tracing
    /// subscriber. An unrecognised level is an error (matching Go's zap
    /// `ParseLevel`); the known level set plus zap's `dpanic`/`panic`/`fatal`
    /// are accepted.
    pub fn new(level: &str) -> Result<Telemetry, TelemetryError> {
        let filter = parse_level(level)?;
        install_subscriber(filter);

        let registry = prometheus::Registry::new();
        register_process_collector(&registry)?;
        Ok(Telemetry { registry })
    }

    /// Returns a redacting logger tagged with the module name.
    pub fn module_logger(&self, name: &str) -> Arc<dyn Logger> {
        Arc::new(TracingLogger::new(name))
    }

    /// Returns a metrics handle that registers collectors into the shared
    /// registry under the module's name.
    pub fn module_registerer(&self, name: &str) -> Arc<dyn Metrics> {
        Arc::new(ModuleMetrics {
            module: name.to_string(),
            registry: self.registry.clone(),
        })
    }

    /// The shared registry, for the daemon's `/metrics` scrape endpoint.
    pub fn registry(&self) -> &prometheus::Registry {
        &self.registry
    }

    /// Builds a named duration/latency histogram, registered into the shared
    /// prometheus registry and — when `otel` is `Some` (the
    /// `penguind.otel-telemetry` flag is on) — also backed by an OTel
    /// histogram instrument, so one `record` call feeds both the `/metrics`
    /// scrape surface and the OTLP metrics pipeline. `name` must be unique
    /// within this `Telemetry`'s registry; a duplicate is a [`TelemetryError`],
    /// matching [`Telemetry::module_registerer`]'s duplicate-registration
    /// behavior.
    pub fn duration_histogram(
        &self,
        name: &str,
        help: &str,
        otel: Option<&OtelPipeline>,
    ) -> Result<DurationHistogram, TelemetryError> {
        DurationHistogram::new(&self.registry, name, help, otel)
    }
}

/// Maps a log-level string to a tracing filter, rejecting unknown values.
fn parse_level(level: &str) -> Result<LevelFilter, TelemetryError> {
    match level {
        "debug" => Ok(LevelFilter::DEBUG),
        "info" => Ok(LevelFilter::INFO),
        "warn" => Ok(LevelFilter::WARN),
        // zap's dpanic/panic/fatal all sit at or above error; tracing has no
        // higher level, so they collapse to the error threshold.
        "error" | "dpanic" | "panic" | "fatal" => Ok(LevelFilter::ERROR),
        _ => Err(TelemetryError(format!("invalid log level: {level:?}"))),
    }
}

/// Installs the JSON tracing subscriber. A second call in the same process is a
/// no-op: `try_init` fails only when a subscriber is already set, which we
/// intentionally ignore.
fn install_subscriber(filter: LevelFilter) {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_max_level(filter)
        .try_init();
}

/// Registers the procfs-based process collector (Linux/macOS only).
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn register_process_collector(registry: &prometheus::Registry) -> Result<(), TelemetryError> {
    let process = prometheus::process_collector::ProcessCollector::for_self();
    match registry.register(Box::new(process)) {
        Ok(()) => Ok(()),
        Err(err) => Err(TelemetryError(format!("register process collector: {err}"))),
    }
}

/// On platforms without procfs the registry simply carries no process metrics.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn register_process_collector(_registry: &prometheus::Registry) -> Result<(), TelemetryError> {
    Ok(())
}

/// A [`Metrics`] handle bound to one module and the shared registry.
///
/// Per-module const-label namespacing (Go's `WrapRegistererWith`) lands in M5
/// with the first metrics-emitting module; for now collectors register into the
/// shared registry, with the module name attributed on error.
struct ModuleMetrics {
    module: String,
    registry: prometheus::Registry,
}

impl Metrics for ModuleMetrics {
    fn register(
        &self,
        collector: Box<dyn prometheus::core::Collector>,
    ) -> Result<(), MetricsError> {
        match self.registry.register(collector) {
            Ok(()) => Ok(()),
            Err(err) => Err(MetricsError(format!("module {}: {err}", self.module))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Counter;

    #[test]
    fn parse_level_accepts_the_known_levels() {
        let ok = ["debug", "info", "warn", "error", "dpanic", "panic", "fatal"];
        for level in ok {
            assert!(parse_level(level).is_ok(), "{level} should parse");
        }
    }

    #[test]
    fn parse_level_rejects_unknown() {
        assert!(parse_level("invalid_level").is_err());
        assert!(parse_level("trace").is_err());
        assert!(parse_level("").is_err());
    }

    #[test]
    fn new_succeeds_for_valid_levels() {
        for level in ["debug", "info", "warn", "error", "fatal", "panic"] {
            let telemetry = Telemetry::new(level);
            assert!(telemetry.is_ok(), "New({level}) should succeed");
        }
    }

    #[test]
    fn new_fails_for_an_invalid_level() {
        assert!(Telemetry::new("nonsense").is_err());
    }

    #[test]
    fn module_logger_is_usable() {
        let telemetry = Telemetry::new("info").unwrap();
        let logger = telemetry.module_logger("squawk");
        logger.info("hello", &[("k", "v")]);
    }

    #[test]
    fn module_registerer_registers_and_rejects_duplicates() {
        let telemetry = Telemetry::new("info").unwrap();
        let metrics = telemetry.module_registerer("squawk");

        let first = Counter::new("t_requests_total", "test counter").unwrap();
        assert!(metrics.register(Box::new(first)).is_ok());

        // A second collector with the same name must be rejected, and the error
        // must name the module.
        let dup = Counter::new("t_requests_total", "test counter").unwrap();
        let err = metrics.register(Box::new(dup)).unwrap_err();
        assert!(err.to_string().contains("squawk"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn registry_gathers_process_metrics() {
        let telemetry = Telemetry::new("info").unwrap();
        let families = telemetry.registry().gather();
        assert!(!families.is_empty());

        let mut has_process = false;
        for family in &families {
            if family.name().starts_with("process_") {
                has_process = true;
            }
        }
        assert!(has_process, "expected process_* metrics from the collector");
    }
}
