//! OTLP emission: logs, metrics, and traces alongside the existing
//! tracing/prometheus stack — never a replacement for either (see
//! `critical-rules.md` Observability).
//!
//! [`init`] is the single entry point: it is always safe to call (never
//! panics, never blocks), returns [`None`] when the feature flag is off or
//! the pipeline fails to build, and returns a live [`OtelPipeline`]
//! otherwise. The destination is read from the standard `OTEL_*` env vars
//! ([`OtelConfig::from_env`]) — never hardcoded, never a vendor-specific URL
//! or SDK. Dead-exporter safety is inherited from the OTel SDK's own batch
//! processors: a bounded, background-flushed queue that drops on backpressure
//! or exporter failure rather than blocking the caller.

use std::collections::HashMap;
use std::time::Duration;

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Meter, MeterProvider as _};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{
    LogExporter, MetricExporter, SpanExporter, WithExportConfig, WithHttpConfig, WithTonicConfig,
};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::Layer;
use tracing_subscriber::registry::LookupSpan;

use crate::TelemetryError;

/// Default service name attached to every span/log/metric when
/// `OTEL_SERVICE_NAME` is unset — the daemon's own binary name.
const DEFAULT_SERVICE_NAME: &str = "penguind";

/// How long an export attempt waits before giving up. Short and fixed
/// (rather than configurable) so a dead collector cannot make a batch flush
/// hang for longer than this on any one attempt — the batch processor drops
/// the batch and moves on.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// The wire protocol OTLP exports use, selected by `OTEL_EXPORTER_OTLP_PROTOCOL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtelProtocol {
    /// OTLP/gRPC over the pinned `tonic` stack — the spec default.
    Grpc,
    /// OTLP/HTTP with protobuf bodies — the spec's one documented alternate.
    HttpProtobuf,
}

impl OtelProtocol {
    /// Parses `OTEL_EXPORTER_OTLP_PROTOCOL`'s value. Per the OTel spec, `grpc`
    /// is the default and `http/protobuf` is the only alternate this daemon
    /// implements; any other value (including the spec's `http/json`, which
    /// this daemon does not support) falls back to `grpc` rather than
    /// failing daemon startup over a telemetry config typo.
    pub fn parse(value: Option<&str>) -> OtelProtocol {
        match value.map(str::trim) {
            Some("http/protobuf") => OtelProtocol::HttpProtobuf,
            _ => OtelProtocol::Grpc,
        }
    }
}

/// Parsed, ready-to-use OTLP destination config — the env-configurable
/// surface required by the Observability standard. Never hardcodes a
/// destination: an absent `OTEL_EXPORTER_OTLP_ENDPOINT` leaves `endpoint` as
/// `None`, and the exporter builders fall back to the OTel SDK's own
/// documented default (`http://localhost:4317` for gRPC,
/// `http://localhost:4318` for HTTP), never a PenguinTech- or vendor-specific
/// URL.
pub struct OtelConfig {
    /// `OTEL_EXPORTER_OTLP_ENDPOINT`. `None` means "use the SDK default".
    pub endpoint: Option<String>,
    /// `OTEL_EXPORTER_OTLP_PROTOCOL`.
    pub protocol: OtelProtocol,
    /// `OTEL_EXPORTER_OTLP_HEADERS` — e.g. bearer auth for the collector.
    /// Never logged (see `Debug` below) and never sent anywhere but the
    /// exporter's own request metadata.
    pub headers: HashMap<String, String>,
    /// `OTEL_SERVICE_NAME`, defaulting to [`DEFAULT_SERVICE_NAME`].
    pub service_name: String,
    /// `OTEL_RESOURCE_ATTRIBUTES` — extra resource key/values merged
    /// alongside `service.name`.
    pub resource_attributes: Vec<(String, String)>,
}

impl std::fmt::Debug for OtelConfig {
    /// Redacts header values — `OTEL_EXPORTER_OTLP_HEADERS` routinely carries
    /// collector auth tokens, and Token & Secret Hygiene forbids letting them
    /// reach a log line via a careless `{config:?}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtelConfig")
            .field("endpoint", &self.endpoint)
            .field("protocol", &self.protocol)
            .field("headers", &format!("<{} redacted>", self.headers.len()))
            .field("service_name", &self.service_name)
            .field("resource_attributes", &self.resource_attributes)
            .finish()
    }
}

impl OtelConfig {
    /// Reads the standard `OTEL_*` env vars. Pure wiring over
    /// [`parse_protocol`]/[`parse_kv_list`]/[`non_empty_env`] — those are
    /// what unit tests exercise directly, since mutating process env vars
    /// from `#[test]` would race other tests in the same binary (and, as of
    /// this workspace's pinned toolchain, `std::env::set_var` is `unsafe`,
    /// which the workspace-wide `unsafe_code = "deny"` lint forbids here
    /// anyway).
    pub fn from_env() -> OtelConfig {
        let endpoint = non_empty_env("OTEL_EXPORTER_OTLP_ENDPOINT");
        let protocol =
            OtelProtocol::parse(std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL").ok().as_deref());
        let headers = parse_kv_list(non_empty_env("OTEL_EXPORTER_OTLP_HEADERS").as_deref());
        let service_name =
            non_empty_env("OTEL_SERVICE_NAME").unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_string());
        let resource_attributes: Vec<(String, String)> =
            parse_kv_list(non_empty_env("OTEL_RESOURCE_ATTRIBUTES").as_deref())
                .into_iter()
                .collect();

        OtelConfig {
            endpoint,
            protocol,
            headers,
            service_name,
            resource_attributes,
        }
    }
}

/// Reads an env var, treating both "unset" and "set but empty" as absent —
/// an operator clearing a var by setting it to `""` should get the default,
/// not an exporter builder call with an empty string.
fn non_empty_env(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}

/// Parses the `key1=value1,key2=value2` shape shared by
/// `OTEL_EXPORTER_OTLP_HEADERS` and `OTEL_RESOURCE_ATTRIBUTES`. Splits each
/// pair on the *first* `=` only, so a value that itself contains `=` (a
/// base64-padded bearer token, for instance) survives intact. Deliberately
/// does not percent-decode values — the OTel spec allows it for values
/// containing `,`/`=`, but every real deployment this daemon targets ships
/// plain bearer tokens, and adding a decode step (and a dependency to do it)
/// for a case with no known caller is not worth the complexity;
/// documented here rather than silently assumed.
fn parse_kv_list(value: Option<&str>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(value) = value else {
        return out;
    };
    for pair in value.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some((key, val)) = pair.split_once('=') {
            let key = key.trim();
            if !key.is_empty() {
                out.insert(key.to_string(), val.trim().to_string());
            }
        }
    }
    out
}

/// Builds the OTel `Resource` (the identity attached to every span/log/metric)
/// from `service_name` + `resource_attributes`.
fn build_resource(config: &OtelConfig) -> Resource {
    let attributes: Vec<KeyValue> = config
        .resource_attributes
        .iter()
        .map(|(k, v)| KeyValue::new(k.clone(), v.clone()))
        .collect();
    Resource::builder()
        .with_service_name(config.service_name.clone())
        .with_attributes(attributes)
        .build()
}

/// Converts `OTEL_EXPORTER_OTLP_HEADERS` into gRPC request metadata.
/// A header whose key or value cannot be parsed as ASCII metadata is skipped
/// (logged at `warn`, not a fatal build error) rather than failing the whole
/// pipeline over one malformed header.
fn build_tonic_metadata(headers: &HashMap<String, String>) -> tonic::metadata::MetadataMap {
    let mut metadata = tonic::metadata::MetadataMap::new();
    for (key, value) in headers {
        let parsed_key = key.parse::<tonic::metadata::MetadataKey<tonic::metadata::Ascii>>();
        let parsed_value = value.parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>();
        match (parsed_key, parsed_value) {
            (Ok(k), Ok(v)) => {
                metadata.insert(k, v);
            }
            _ => {
                tracing::warn!(key = %key, "skipping unparseable OTEL_EXPORTER_OTLP_HEADERS entry");
            }
        }
    }
    metadata
}

/// A live OTLP pipeline: one tracer, one logger provider, and one meter
/// provider, each backed by a batching/periodic exporter with a bounded
/// queue. Holding this alive for the process lifetime keeps the background
/// flush tasks running; dropping it without calling [`shutdown`](Self::shutdown)
/// simply stops future flushes (buffered data may be lost), which is an
/// acceptable startup/shutdown-ordering tradeoff, never a panic or a hang.
pub struct OtelPipeline {
    tracer_provider: SdkTracerProvider,
    logger_provider: SdkLoggerProvider,
    meter_provider: SdkMeterProvider,
    tracer: opentelemetry_sdk::trace::SdkTracer,
    meter: Meter,
}

impl OtelPipeline {
    /// Builds every signal's exporter + provider for `config`'s protocol.
    /// The only failure mode is a malformed endpoint/config caught at
    /// construction time (e.g. an endpoint string that isn't a valid URI) —
    /// an *unreachable* endpoint builds successfully and fails later, only
    /// at flush time, silently (see the module doc).
    pub fn build(config: &OtelConfig) -> Result<OtelPipeline, TelemetryError> {
        match config.protocol {
            OtelProtocol::Grpc => Self::build_grpc(config),
            OtelProtocol::HttpProtobuf => Self::build_http(config),
        }
    }

    fn build_grpc(config: &OtelConfig) -> Result<OtelPipeline, TelemetryError> {
        let resource = build_resource(config);
        let metadata = build_tonic_metadata(&config.headers);

        let mut span_builder = SpanExporter::builder()
            .with_tonic()
            .with_timeout(EXPORT_TIMEOUT)
            .with_metadata(metadata.clone());
        if let Some(endpoint) = &config.endpoint {
            span_builder = span_builder.with_endpoint(endpoint.clone());
        }
        let span_exporter = span_builder
            .build()
            .map_err(|err| TelemetryError(format!("build otlp/grpc span exporter: {err}")))?;

        let mut log_builder = LogExporter::builder()
            .with_tonic()
            .with_timeout(EXPORT_TIMEOUT)
            .with_metadata(metadata.clone());
        if let Some(endpoint) = &config.endpoint {
            log_builder = log_builder.with_endpoint(endpoint.clone());
        }
        let log_exporter = log_builder
            .build()
            .map_err(|err| TelemetryError(format!("build otlp/grpc log exporter: {err}")))?;

        let mut metric_builder = MetricExporter::builder()
            .with_tonic()
            .with_timeout(EXPORT_TIMEOUT)
            .with_metadata(metadata);
        if let Some(endpoint) = &config.endpoint {
            metric_builder = metric_builder.with_endpoint(endpoint.clone());
        }
        let metric_exporter = metric_builder
            .build()
            .map_err(|err| TelemetryError(format!("build otlp/grpc metric exporter: {err}")))?;

        Ok(Self::assemble(
            resource,
            span_exporter,
            log_exporter,
            metric_exporter,
        ))
    }

    fn build_http(config: &OtelConfig) -> Result<OtelPipeline, TelemetryError> {
        let resource = build_resource(config);

        let mut span_builder = SpanExporter::builder()
            .with_http()
            .with_timeout(EXPORT_TIMEOUT)
            .with_headers(config.headers.clone());
        if let Some(endpoint) = &config.endpoint {
            span_builder = span_builder.with_endpoint(endpoint.clone());
        }
        let span_exporter = span_builder
            .build()
            .map_err(|err| TelemetryError(format!("build otlp/http span exporter: {err}")))?;

        let mut log_builder = LogExporter::builder()
            .with_http()
            .with_timeout(EXPORT_TIMEOUT)
            .with_headers(config.headers.clone());
        if let Some(endpoint) = &config.endpoint {
            log_builder = log_builder.with_endpoint(endpoint.clone());
        }
        let log_exporter = log_builder
            .build()
            .map_err(|err| TelemetryError(format!("build otlp/http log exporter: {err}")))?;

        let mut metric_builder = MetricExporter::builder()
            .with_http()
            .with_timeout(EXPORT_TIMEOUT)
            .with_headers(config.headers.clone());
        if let Some(endpoint) = &config.endpoint {
            metric_builder = metric_builder.with_endpoint(endpoint.clone());
        }
        let metric_exporter = metric_builder
            .build()
            .map_err(|err| TelemetryError(format!("build otlp/http metric exporter: {err}")))?;

        Ok(Self::assemble(
            resource,
            span_exporter,
            log_exporter,
            metric_exporter,
        ))
    }

    /// Wires the three exporters into their providers. Each uses a batching
    /// (traces/logs) or periodic (metrics) processor with the SDK's default
    /// bounded queue — on backpressure or export failure, records are
    /// dropped, never blocked or panicked on (dead-exporter safety).
    fn assemble(
        resource: Resource,
        span_exporter: SpanExporter,
        log_exporter: LogExporter,
        metric_exporter: MetricExporter,
    ) -> OtelPipeline {
        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(span_exporter)
            .with_resource(resource.clone())
            .build();
        let tracer = tracer_provider.tracer(DEFAULT_SERVICE_NAME);

        let logger_provider = SdkLoggerProvider::builder()
            .with_batch_exporter(log_exporter)
            .with_resource(resource.clone())
            .build();

        let reader = PeriodicReader::builder(metric_exporter).build();
        let meter_provider = SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(resource)
            .build();
        let meter = meter_provider.meter(DEFAULT_SERVICE_NAME);

        OtelPipeline {
            tracer_provider,
            logger_provider,
            meter_provider,
            tracer,
            meter,
        }
    }

    /// A [`tracing_subscriber::Layer`] combining trace export (spans) and log
    /// export (events) — `.with(pipeline.tracing_layer())` onto the same
    /// registry the daemon's fmt/ring layers already install onto. Generic
    /// over the subscriber `S` so it composes at whatever position in the
    /// layer stack the caller adds it, matching every other `Layer` impl in
    /// this codebase (see `logging::LogRingLayer`).
    pub fn tracing_layer<S>(&self) -> impl Layer<S> + Send + Sync + 'static
    where
        S: tracing::Subscriber + for<'span> LookupSpan<'span> + Send + Sync + 'static,
    {
        let trace_layer = tracing_opentelemetry::layer().with_tracer(self.tracer.clone());
        let log_layer = opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(
            &self.logger_provider,
        );
        trace_layer.and_then(log_layer)
    }

    /// The meter new instruments (histograms, counters, gauges) are built
    /// from — see [`crate::duration::DurationHistogram`] for the daemon's
    /// duration/latency instrument.
    pub fn meter(&self) -> &Meter {
        &self.meter
    }

    /// Flushes and shuts down all three providers. Never panics: a provider
    /// that fails to shut down cleanly (e.g. the collector is still
    /// unreachable) is logged at `warn` and otherwise ignored.
    ///
    /// Synchronous and potentially slow: each provider's `shutdown()` can
    /// block for up to [`EXPORT_TIMEOUT`] if the configured collector is
    /// black-holed (up to ~30s total across all three run sequentially, as
    /// they are here). Callers on a Tokio worker thread MUST NOT call this
    /// directly — use [`shutdown_with_timeout`](Self::shutdown_with_timeout)
    /// instead, which moves this call off the async runtime and bounds it.
    pub fn shutdown(&self) {
        if let Err(err) = self.tracer_provider.shutdown() {
            tracing::warn!(error = %err, "otel tracer provider shutdown failed");
        }
        if let Err(err) = self.logger_provider.shutdown() {
            tracing::warn!(error = %err, "otel logger provider shutdown failed");
        }
        if let Err(err) = self.meter_provider.shutdown() {
            tracing::warn!(error = %err, "otel meter provider shutdown failed");
        }
    }

    /// Async-safe wrapper around [`shutdown`](Self::shutdown) — the daemon's
    /// actual shutdown path (see `daemon_main.rs`) calls this, never
    /// `shutdown()` directly. Runs the blocking provider-shutdown calls on
    /// the blocking thread pool via `spawn_blocking` so a Tokio worker is
    /// never occupied by them, and races the result against `budget` so a
    /// black-holed collector (up to ~30s worst case across all three
    /// providers' [`EXPORT_TIMEOUT`]) cannot stall the caller beyond it.
    ///
    /// A timed-out or panicked shutdown is logged at `warn` and otherwise
    /// swallowed — never propagated as an error, never a panic. Buffered
    /// telemetry may be lost in that case, which is the same acceptable
    /// tradeoff `shutdown()`'s own doc already describes for a bare `drop`.
    /// Consumes `self`: shutdown is a one-shot, terminal operation.
    pub async fn shutdown_with_timeout(self, budget: Duration) {
        run_with_budget(budget, move || self.shutdown()).await;
    }
}

/// Runs blocking closure `f` on the blocking thread pool, giving up after
/// `budget` if it hasn't returned by then. Split out from
/// [`OtelPipeline::shutdown_with_timeout`] so the timeout-enforcement
/// mechanism itself can be unit tested against an artificially slow closure,
/// without needing a real multi-second network stall in the test suite.
async fn run_with_budget(budget: Duration, f: impl FnOnce() + Send + 'static) {
    match tokio::time::timeout(budget, tokio::task::spawn_blocking(f)).await {
        Ok(Ok(())) => {}
        Ok(Err(join_err)) => {
            tracing::warn!(error = %join_err, "otel shutdown task panicked");
        }
        Err(_) => {
            tracing::warn!(
                budget_secs = budget.as_secs(),
                "otel shutdown exceeded its budget; abandoning flush (buffered telemetry may be lost)"
            );
        }
    }
}

/// Overall wall-clock budget for [`OtelPipeline::shutdown_with_timeout`] —
/// bounds the combined flush of all three providers well under the
/// worst-case ~30s (`EXPORT_TIMEOUT * 3` run sequentially) a black-holed
/// collector could otherwise cause, while still giving a genuinely slow but
/// live collector a real chance to drain the buffered queue.
pub const OTEL_SHUTDOWN_BUDGET: Duration = Duration::from_secs(8);

/// The single entry point: builds an OTLP pipeline from the standard
/// `OTEL_*` env vars if `enabled` (the resolved
/// `penguind.otel-telemetry` feature flag) is true. Always safe to call —
/// disabled or a build failure both simply return [`None`], logged at `warn`
/// in the failure case, never propagated as a startup error. This is the
/// license-server-graceful-degradation contract extended to telemetry
/// startup: an operator misconfiguring `OTEL_EXPORTER_OTLP_ENDPOINT` must
/// never stop the daemon from starting.
pub fn init(enabled: bool) -> Option<OtelPipeline> {
    if !enabled {
        return None;
    }
    build_or_degrade(OtelConfig::from_env())
}

/// The degrade-on-failure step of [`init`], split out so it can be unit
/// tested against a hand-built [`OtelConfig`] instead of the real process
/// environment.
fn build_or_degrade(config: OtelConfig) -> Option<OtelPipeline> {
    match OtelPipeline::build(&config) {
        Ok(pipeline) => Some(pipeline),
        Err(err) => {
            tracing::warn!(error = %err, "otel pipeline init failed, continuing without OTLP export");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_parse_defaults_to_grpc() {
        assert_eq!(OtelProtocol::parse(None), OtelProtocol::Grpc);
        assert_eq!(OtelProtocol::parse(Some("")), OtelProtocol::Grpc);
        assert_eq!(OtelProtocol::parse(Some("grpc")), OtelProtocol::Grpc);
        assert_eq!(OtelProtocol::parse(Some("bogus")), OtelProtocol::Grpc);
        // The spec's other real value, which this daemon doesn't implement,
        // must not panic or be treated as grpc's exact synonym — it still
        // falls back to grpc, but via the same "unrecognized" path as bogus.
        assert_eq!(OtelProtocol::parse(Some("http/json")), OtelProtocol::Grpc);
    }

    #[test]
    fn protocol_parse_selects_http_protobuf_exactly() {
        assert_eq!(
            OtelProtocol::parse(Some("http/protobuf")),
            OtelProtocol::HttpProtobuf
        );
        // Whitespace tolerance for a hand-edited env file.
        assert_eq!(
            OtelProtocol::parse(Some("  http/protobuf  ")),
            OtelProtocol::HttpProtobuf
        );
    }

    #[test]
    fn parse_kv_list_handles_the_empty_and_absent_cases() {
        assert!(parse_kv_list(None).is_empty());
        assert!(parse_kv_list(Some("")).is_empty());
        assert!(parse_kv_list(Some("   ")).is_empty());
    }

    #[test]
    fn parse_kv_list_parses_multiple_pairs() {
        let parsed = parse_kv_list(Some("deployment.environment=beta,team=platform"));
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.get("deployment.environment").unwrap(), "beta");
        assert_eq!(parsed.get("team").unwrap(), "platform");
    }

    #[test]
    fn parse_kv_list_splits_only_on_the_first_equals() {
        // A bearer token's base64 padding, or an embedded '=' in a value,
        // must survive intact.
        let parsed = parse_kv_list(Some("authorization=Bearer abc.def=="));
        assert_eq!(parsed.get("authorization").unwrap(), "Bearer abc.def==");
    }

    #[test]
    fn parse_kv_list_trims_whitespace_and_skips_malformed_pairs() {
        let parsed = parse_kv_list(Some(" a = b , , novalue , c=d "));
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.get("a").unwrap(), "b");
        assert_eq!(parsed.get("c").unwrap(), "d");
        assert!(!parsed.contains_key("novalue"));
    }

    #[test]
    fn config_debug_redacts_header_values() {
        let mut headers = HashMap::new();
        headers.insert(
            "authorization".to_string(),
            "Bearer super-secret".to_string(),
        );
        let config = OtelConfig {
            endpoint: Some("http://127.0.0.1:4317".to_string()),
            protocol: OtelProtocol::Grpc,
            headers,
            service_name: "penguind".to_string(),
            resource_attributes: vec![],
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(rendered.contains("1 redacted"));
    }

    /// `init(false)` must never touch the environment or build an exporter —
    /// this is the feature-flag gate's default-off path, exercised with zero
    /// `OTEL_*` vars set.
    #[test]
    fn init_disabled_returns_none() {
        assert!(init(false).is_none());
    }

    /// Dead-exporter safety: a syntactically valid but unreachable endpoint
    /// must build successfully (the tonic channel connects lazily) rather
    /// than fail startup, and using the pipeline afterwards (recording a
    /// span/metric, then shutting down) must not panic or hang. `#[tokio::test]`
    /// because the tonic exporter's channel needs a runtime context even to
    /// construct the lazy (not-yet-connecting) connection.
    #[tokio::test]
    async fn build_succeeds_and_stays_usable_for_an_unreachable_grpc_endpoint() {
        let config = OtelConfig {
            endpoint: Some("http://127.0.0.1:1".to_string()),
            protocol: OtelProtocol::Grpc,
            headers: HashMap::new(),
            service_name: "penguind-test".to_string(),
            resource_attributes: vec![],
        };
        let pipeline =
            OtelPipeline::build(&config).expect("build succeeds for an unreachable endpoint");

        let histogram = pipeline
            .meter()
            .f64_histogram("test_duration_seconds")
            .build();
        histogram.record(0.01, &[]);

        pipeline.shutdown();
    }

    /// Same guarantee for the HTTP/protobuf protocol path.
    #[test]
    fn build_succeeds_for_an_unreachable_http_endpoint() {
        let config = OtelConfig {
            endpoint: Some("http://127.0.0.1:1".to_string()),
            protocol: OtelProtocol::HttpProtobuf,
            headers: HashMap::new(),
            service_name: "penguind-test".to_string(),
            resource_attributes: vec![],
        };
        let pipeline =
            OtelPipeline::build(&config).expect("build succeeds for an unreachable endpoint");
        pipeline.shutdown();
    }

    /// Reviewer finding #7 regression test: `shutdown_with_timeout` is what
    /// the daemon's real shutdown path calls (never `shutdown()` directly —
    /// see `daemon_main.rs`), and it must return well within its budget even
    /// against a genuinely unreachable OTLP endpoint, not silently fall back
    /// to blocking the calling task for however long the SDK's own
    /// `EXPORT_TIMEOUT` takes.
    #[tokio::test]
    async fn shutdown_with_timeout_returns_promptly_for_an_unreachable_endpoint() {
        let config = OtelConfig {
            endpoint: Some("http://127.0.0.1:1".to_string()),
            protocol: OtelProtocol::Grpc,
            headers: HashMap::new(),
            service_name: "penguind-test".to_string(),
            resource_attributes: vec![],
        };
        let pipeline =
            OtelPipeline::build(&config).expect("build succeeds for an unreachable endpoint");

        let budget = Duration::from_secs(2);
        let started = std::time::Instant::now();
        pipeline.shutdown_with_timeout(budget).await;
        assert!(
            started.elapsed() < budget,
            "shutdown_with_timeout took as long as its own budget against a \
             connection-refused endpoint — the async wrapper isn't short-circuiting"
        );
    }

    /// Directly exercises the timeout-enforcement mechanism
    /// `shutdown_with_timeout` delegates to, using a blocking closure slower
    /// than its budget. Proves a black-holed collector — which would
    /// otherwise block the underlying SDK call for the full `EXPORT_TIMEOUT`
    /// (up to ~30s across all three providers) — cannot stall the caller
    /// beyond `budget`, without this test itself waiting out a real
    /// multi-second network timeout.
    #[tokio::test]
    async fn run_with_budget_gives_up_on_a_slower_blocking_call() {
        let budget = Duration::from_millis(50);
        let started = std::time::Instant::now();
        run_with_budget(budget, || std::thread::sleep(Duration::from_secs(5))).await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "run_with_budget waited for the slow blocking call instead of giving up at budget"
        );
    }

    /// A malformed (not-a-URI) endpoint is the one case that fails at build
    /// time — must return `Err`, never panic.
    #[test]
    fn build_fails_gracefully_for_a_malformed_endpoint() {
        let config = OtelConfig {
            endpoint: Some("not a url at all".to_string()),
            protocol: OtelProtocol::Grpc,
            headers: HashMap::new(),
            service_name: "penguind-test".to_string(),
            resource_attributes: vec![],
        };
        assert!(OtelPipeline::build(&config).is_err());
    }

    /// The degrade-on-failure step `init` delegates to: a malformed endpoint
    /// must yield `None`, not propagate the build error or panic — this is
    /// what daemon startup actually relies on.
    #[test]
    fn build_or_degrade_returns_none_on_build_failure() {
        let config = OtelConfig {
            endpoint: Some("not a url at all".to_string()),
            protocol: OtelProtocol::Grpc,
            headers: HashMap::new(),
            service_name: "penguind-test".to_string(),
            resource_attributes: vec![],
        };
        assert!(build_or_degrade(config).is_none());
    }

    /// `init(true)` against the real (test-harness) environment — which has
    /// no `OTEL_*` vars set — must still build cleanly using the SDK's own
    /// defaults, proving `init`'s own env-reading wiring (not just
    /// `OtelPipeline::build`) never panics on the empty-config path.
    #[tokio::test]
    async fn init_enabled_builds_cleanly_with_no_otel_env_vars_set() {
        let pipeline = init(true).expect("default config builds");
        pipeline.shutdown();
    }

    #[test]
    fn tonic_metadata_skips_unparseable_entries_without_panicking() {
        let mut headers = HashMap::new();
        headers.insert("valid-key".to_string(), "valid-value".to_string());
        // A raw control character (here, a newline) is not a legal gRPC
        // metadata value under any encoding — unlike high-bit UTF-8 bytes,
        // which `http::HeaderValue` actually accepts as opaque obs-text.
        headers.insert("bad-key".to_string(), "line one\nline two".to_string());
        let metadata = build_tonic_metadata(&headers);
        assert!(metadata.get("valid-key").is_some());
        assert!(metadata.get("bad-key").is_none());
    }
}
