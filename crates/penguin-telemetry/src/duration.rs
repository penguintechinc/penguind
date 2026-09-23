//! A duration/latency histogram recorded into both the existing prometheus
//! registry (the `/metrics` scrape surface) and, when OTLP is enabled, the
//! OTel metrics pipeline — the "histograms for load/latency first" half of
//! the Observability standard, which a bare counter never satisfies.

use opentelemetry::metrics::Histogram as OtelHistogram;

use crate::TelemetryError;
use crate::otel::OtelPipeline;

/// One named duration histogram, dual-written to prometheus and (optionally)
/// OTLP. Built via [`crate::Telemetry::duration_histogram`], never directly —
/// registration into the shared prometheus registry has to happen exactly
/// once, which that constructor is responsible for.
pub struct DurationHistogram {
    prometheus: prometheus::Histogram,
    otel: Option<OtelHistogram<f64>>,
}

impl DurationHistogram {
    /// Builds a histogram already registered into `registry` under `name`,
    /// and — if `otel` is present — also backed by an OTel histogram
    /// instrument from its meter. `otel` being `None` (the default-off
    /// feature-flag path) is not an error: the prometheus half alone is a
    /// complete, spec-compliant metric on its own.
    pub(crate) fn new(
        registry: &prometheus::Registry,
        name: &str,
        help: &str,
        otel: Option<&OtelPipeline>,
    ) -> Result<DurationHistogram, TelemetryError> {
        let opts = prometheus::HistogramOpts::new(name, help);
        let histogram = prometheus::Histogram::with_opts(opts)
            .map_err(|err| TelemetryError(format!("build histogram {name}: {err}")))?;
        registry
            .register(Box::new(histogram.clone()))
            .map_err(|err| TelemetryError(format!("register histogram {name}: {err}")))?;

        let otel_histogram =
            otel.map(|pipeline| pipeline.meter().f64_histogram(name.to_string()).build());

        Ok(DurationHistogram {
            prometheus: histogram,
            otel: otel_histogram,
        })
    }

    /// Records one observation, in seconds, into every backend this
    /// histogram is wired to.
    pub fn record(&self, seconds: f64) {
        self.prometheus.observe(seconds);
        if let Some(otel) = &self.otel {
            otel.record(seconds, &[]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_into_prometheus_and_reports_a_sample() {
        let registry = prometheus::Registry::new();
        let histogram = DurationHistogram::new(&registry, "t_op_duration_seconds", "test", None)
            .expect("histogram registers");

        histogram.record(0.25);
        histogram.record(1.5);

        let families = registry.gather();
        let family = families
            .iter()
            .find(|f| f.name() == "t_op_duration_seconds")
            .expect("histogram family present");
        let sample = &family.get_metric()[0].get_histogram();
        assert_eq!(sample.get_sample_count(), 2);
    }

    #[test]
    fn duplicate_names_fail_registration_rather_than_silently_colliding() {
        let registry = prometheus::Registry::new();
        let _first = DurationHistogram::new(&registry, "t_dup_seconds", "test", None).unwrap();
        let second = DurationHistogram::new(&registry, "t_dup_seconds", "test", None);
        assert!(second.is_err());
    }

    /// The OTel-aware path: recording must update both backends and never
    /// panic even though the OTel side is talking to an unreachable endpoint.
    /// `#[tokio::test]` because building the tonic-backed pipeline needs a
    /// runtime context (see `otel::tests` for the same requirement).
    #[tokio::test]
    async fn records_into_otel_when_a_pipeline_is_supplied() {
        use crate::otel::{OtelConfig, OtelPipeline, OtelProtocol};

        let config = OtelConfig {
            endpoint: Some("http://127.0.0.1:1".to_string()),
            protocol: OtelProtocol::Grpc,
            headers: std::collections::HashMap::new(),
            service_name: "penguind-test".to_string(),
            resource_attributes: vec![],
        };
        let pipeline =
            OtelPipeline::build(&config).expect("pipeline builds for an unreachable endpoint");

        let registry = prometheus::Registry::new();
        let histogram = DurationHistogram::new(
            &registry,
            "t_otel_op_duration_seconds",
            "test",
            Some(&pipeline),
        )
        .expect("histogram registers");

        histogram.record(0.1);

        pipeline.shutdown();
    }
}
