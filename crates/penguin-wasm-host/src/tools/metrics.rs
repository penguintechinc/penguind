//! Prometheus counter + latency histogram emitted for every tool call.

use std::time::Duration;

use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry};

/// Per-call telemetry. Labels are bounded: `tool` is a declared id or
/// `unresolved` (guest-supplied names never become labels), `outcome` is a
/// fixed set.
#[derive(Clone)]
pub struct ToolMetrics {
    calls: IntCounterVec,
    latency: HistogramVec,
}

impl ToolMetrics {
    /// Registers `penguind_wasm_tool_calls_total` and
    /// `penguind_wasm_tool_call_seconds` into `registry`.
    pub fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let calls = IntCounterVec::new(
            Opts::new(
                "penguind_wasm_tool_calls_total",
                "WASM tool calls by tool and outcome",
            ),
            &["tool", "outcome"],
        )?;
        let latency = HistogramVec::new(
            HistogramOpts::new("penguind_wasm_tool_call_seconds", "WASM tool call latency"),
            &["tool", "outcome"],
        )?;
        registry.register(Box::new(calls.clone()))?;
        registry.register(Box::new(latency.clone()))?;
        Ok(Self { calls, latency })
    }

    /// Records one finished call.
    pub fn observe(&self, tool: &str, outcome: &str, elapsed: Duration) {
        self.calls.with_label_values(&[tool, outcome]).inc();
        self.latency
            .with_label_values(&[tool, outcome])
            .observe(elapsed.as_secs_f64());
    }
}
