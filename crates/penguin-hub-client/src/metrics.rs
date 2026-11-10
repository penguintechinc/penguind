//! Prometheus metrics for the hub client (bridged to OTel by the daemon's
//! telemetry pipeline, alongside the `tracing` spans this crate emits).

use prometheus::{Gauge, Histogram, HistogramOpts, IntCounterVec, IntGauge, Opts, Registry};

/// Sync counters, latency histogram, verification counters and the
/// staleness gauge.
#[derive(Clone)]
pub struct HubMetrics {
    requests: IntCounterVec,
    latency: Histogram,
    verify: IntCounterVec,
    staleness: Gauge,
    modules: IntGauge,
}

impl HubMetrics {
    /// Registers every family in `registry`; a duplicate registration is an error.
    pub fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let requests = IntCounterVec::new(
            Opts::new(
                "penguind_hub_sync_requests_total",
                "Hub sync requests by result.",
            ),
            &["result"],
        )?;
        let latency = Histogram::with_opts(HistogramOpts::new(
            "penguind_hub_sync_latency_seconds",
            "Hub sync request latency.",
        ))?;
        let verify = IntCounterVec::new(
            Opts::new(
                "penguind_hub_module_verify_total",
                "Hub module verifications.",
            ),
            &["result"],
        )?;
        let staleness = Gauge::new(
            "penguind_hub_sync_staleness_seconds",
            "Seconds since the last successful hub contact.",
        )?;
        let modules = IntGauge::new(
            "penguind_hub_modules_loaded",
            "Hub-delivered modules currently loaded.",
        )?;
        registry.register(Box::new(requests.clone()))?;
        registry.register(Box::new(latency.clone()))?;
        registry.register(Box::new(verify.clone()))?;
        registry.register(Box::new(staleness.clone()))?;
        registry.register(Box::new(modules.clone()))?;
        Ok(Self {
            requests,
            latency,
            verify,
            staleness,
            modules,
        })
    }

    /// Counts one sync request outcome (`200`, `304`, `4xx`, `5xx`, `error`).
    pub fn record_request(&self, result: &str, seconds: f64) {
        self.requests.with_label_values(&[result]).inc();
        self.latency.observe(seconds);
    }

    /// Counts one module verification (`ok` / `fail`).
    pub fn record_verify(&self, ok: bool) {
        let label = if ok { "ok" } else { "fail" };
        self.verify.with_label_values(&[label]).inc();
    }

    /// Sets the staleness gauge.
    pub fn set_staleness(&self, seconds: f64) {
        self.staleness.set(seconds);
    }

    /// Sets the loaded-module gauge.
    pub fn set_modules(&self, n: usize) {
        self.modules.set(i64::try_from(n).unwrap_or(i64::MAX));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_registration_is_an_error_and_recording_works() {
        let reg = Registry::new();
        let m = HubMetrics::register(&reg).expect("first");
        assert!(HubMetrics::register(&reg).is_err());
        m.record_request("200", 0.01);
        m.record_verify(true);
        m.record_verify(false);
        m.set_staleness(7.0);
        m.set_modules(3);
        let names: Vec<String> = reg.gather().iter().map(|f| f.name().to_string()).collect();
        assert!(names.contains(&"penguind_hub_sync_staleness_seconds".to_string()));
        assert!(names.contains(&"penguind_hub_modules_loaded".to_string()));
    }
}
