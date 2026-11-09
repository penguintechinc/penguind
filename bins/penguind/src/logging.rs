//! Feeds daemon-internal `tracing` events into the shared [`LogRing`] so
//! `TailLogs` (`module: ""` = the daemon's own log) has real content, while
//! still emitting the same JSON stdout output `penguin_telemetry::Telemetry`
//! would install on its own.
//!
//! [`penguin_telemetry::Telemetry::new`] installs a global tracing
//! subscriber too, but only the *first* `set_global_default` call in a
//! process wins — every later attempt is silently ignored. [`install`] must
//! therefore run before `Telemetry::new`, so this combined subscriber (JSON
//! stdout + the ring layer + the OTel layer, when enabled) is the one that
//! actually wins the race; `Telemetry::new`'s own attempt then no-ops, while
//! its non-subscriber work (building the prometheus registry) is unaffected.
//! This is also why the OTel trace/log layer is threaded in *here* rather
//! than inside `penguin_telemetry::Telemetry` itself — it has to be part of
//! the subscriber that wins the race, not a later, discarded one.

use std::sync::Arc;
use std::time::SystemTime;

use penguin_telemetry::OtelPipeline;
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

use penguin_daemon::logring::{LogLine, LogRing};

/// Installs the process-wide tracing subscriber: JSON-formatted stdout
/// output at `level` (falling back to `info` for an unrecognised value —
/// `penguin_telemetry::Telemetry::new`, called right after this, is the
/// authoritative validator and returns a real error for a genuinely bad
/// level), a layer that appends every event to `logs` under the daemon's own
/// log source (the empty string), and — when `otel` is `Some` (the
/// `penguind.otel-telemetry` flag resolved on) — the OTLP trace/log export
/// layer from [`penguin_telemetry::otel`].
pub fn install(logs: Arc<LogRing>, level: &str, otel: Option<&OtelPipeline>) {
    let filter = parse_level_filter(level);
    let fmt_layer = tracing_subscriber::fmt::layer().json();
    let ring_layer = LogRingLayer { logs };
    let otel_layer = otel.map(OtelPipeline::tracing_layer);

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(ring_layer)
        .with(otel_layer);
    // A second install in the same process (e.g. a future call site, or a
    // test) is a no-op — there is nothing actionable to do about it here.
    let _ = subscriber.try_init();
}

/// Maps a daemon config log-level string to a [`LevelFilter`]. Unlike
/// `penguin_telemetry`'s private parser this never fails — an unrecognised
/// value falls back to `info`, since this is only ever a best-effort filter
/// ahead of the real validation `Telemetry::new` performs right after.
fn parse_level_filter(level: &str) -> LevelFilter {
    match level {
        "debug" => LevelFilter::DEBUG,
        "warn" => LevelFilter::WARN,
        "error" | "dpanic" | "panic" | "fatal" => LevelFilter::ERROR,
        _ => LevelFilter::INFO,
    }
}

/// A [`tracing_subscriber::Layer`] that appends every event's level and
/// rendered message to a [`LogRing`] source `""` (the daemon's own log),
/// backing the `TailLogs` RPC for `module: ""`. Structured fields beyond the
/// message are dropped — [`LogLine`] only carries level and message,
/// matching the daemon proto's `LogLine` wire shape.
struct LogRingLayer {
    logs: Arc<LogRing>,
}

impl<S: Subscriber> Layer<S> for LogRingLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        self.logs.append(
            "",
            LogLine {
                at: SystemTime::now(),
                level: event.metadata().level().as_str().to_lowercase(),
                message: visitor.message,
            },
        );
    }
}

/// Extracts the `message` field tracing's logging macros attach to every
/// event, discarding every other field (see [`LogRingLayer`]'s doc for why).
#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_level_filter_maps_known_values_and_defaults_unknown_to_info() {
        assert_eq!(parse_level_filter("debug"), LevelFilter::DEBUG);
        assert_eq!(parse_level_filter("info"), LevelFilter::INFO);
        assert_eq!(parse_level_filter("warn"), LevelFilter::WARN);
        assert_eq!(parse_level_filter("error"), LevelFilter::ERROR);
        assert_eq!(parse_level_filter("fatal"), LevelFilter::ERROR);
        assert_eq!(parse_level_filter("nonsense"), LevelFilter::INFO);
        assert_eq!(parse_level_filter(""), LevelFilter::INFO);
    }

    #[test]
    fn log_ring_layer_appends_the_rendered_message_and_level() {
        let logs = Arc::new(LogRing::new(4));
        let layer = LogRingLayer { logs: logs.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);

        // Scoped rather than global install: this must not fight other
        // tests in the same binary for the one-shot global subscriber slot.
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("hello from the daemon");
        });

        let backlog = logs.backlog("", 1);
        assert_eq!(backlog.len(), 1);
        assert_eq!(backlog[0].message, "hello from the daemon");
        assert_eq!(backlog[0].level, "info");
    }

    #[test]
    fn log_ring_layer_ignores_fields_other_than_message() {
        let logs = Arc::new(LogRing::new(4));
        let layer = LogRingLayer { logs: logs.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(module = "squawk", attempt = 3, "restart scheduled");
        });

        let backlog = logs.backlog("", 1);
        assert_eq!(backlog[0].message, "restart scheduled");
        assert_eq!(backlog[0].level, "warn");
    }
}
