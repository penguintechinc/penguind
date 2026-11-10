//! Prometheus metrics for the hub client (bridged to OTel by the daemon's
//! telemetry pipeline, alongside the `tracing` spans this crate emits).

use prometheus::{
    Gauge, Histogram, HistogramOpts, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};

use crate::tokens::TokenStoreKind;

/// Sync counters, latency histogram, verification counters and the
/// staleness gauge.
#[derive(Clone)]
pub struct HubMetrics {
    requests: IntCounterVec,
    latency: Histogram,
    verify: IntCounterVec,
    staleness: Gauge,
    modules: IntGauge,
    token_store: IntGaugeVec,
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
        let token_store = IntGaugeVec::new(
            Opts::new(
                "penguind_hub_token_store_active",
                "1 for the store holding the hub agent tokens.",
            ),
            &["store"],
        )?;
        registry.register(Box::new(token_store.clone()))?;
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
            token_store,
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

    /// Marks `kind` as the active token store (1) and every other store 0.
    pub fn set_token_store(&self, kind: TokenStoreKind) {
        for k in TokenStoreKind::ALL {
            self.token_store
                .with_label_values(&[k.label()])
                .set(i64::from(k == kind));
        }
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
        m.set_token_store(TokenStoreKind::EncryptedFile);
        let active: Vec<(String, f64)> = reg
            .gather()
            .iter()
            .filter(|f| f.name() == "penguind_hub_token_store_active")
            .flat_map(|f| {
                f.get_metric()
                    .iter()
                    .map(|m| (m.get_label()[0].value().to_string(), m.get_gauge().value()))
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(active.len(), 3);
        assert!(active.contains(&("encrypted-file".to_string(), 1.0)));
        assert!(active.contains(&("keychain".to_string(), 0.0)));
        let names: Vec<String> = reg.gather().iter().map(|f| f.name().to_string()).collect();
        assert!(names.contains(&"penguind_hub_sync_staleness_seconds".to_string()));
        assert!(names.contains(&"penguind_hub_modules_loaded".to_string()));
    }
}
