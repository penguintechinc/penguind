//! The three Prometheus collectors waddles-gateway reports, registered once in
//! `init` and genuinely updated from every code path that changes the state
//! each one describes — see [`crate::WaddlesGatewayModule::call`] for the single
//! choke point every hub request routes through, which is what lets
//! `api_requests_total`/`api_errors_total` stay accurate without every
//! command handler having to remember to touch them itself.

use penguin_sdk::{Metrics, MetricsError};
use prometheus::{Counter, Gauge, Opts};

/// Namespace/subsystem shared by every waddles-gateway collector, matching the
/// convention `penguin-module-squawk`/`penguin-module-tobogganing` already
/// use (fully-qualified names come out as `penguin_module_waddles_gateway_*`).
const NAMESPACE: &str = "penguin_module";
const SUBSYSTEM: &str = "waddles_gateway";

/// waddles-gateway's Prometheus collectors.
pub struct WaddlesGatewayMetrics {
    /// Incremented on every hub request, success or failure.
    pub api_requests_total: Counter,
    /// Incremented whenever a hub request fails — auth (401/403), any other
    /// non-2xx status, transport, or decode error.
    pub api_errors_total: Counter,
    /// Whether the module is currently running (1) or stopped (0).
    pub up: Gauge,
}

impl WaddlesGatewayMetrics {
    /// Builds all three collectors and registers each with `registerer`.
    pub fn register(registerer: &dyn Metrics) -> Result<WaddlesGatewayMetrics, MetricsError> {
        let api_requests_total = new_counter(
            "api_requests_total",
            "Total number of requests sent to the Waddles hub",
        )?;
        registerer.register(Box::new(api_requests_total.clone()))?;

        let api_errors_total = new_counter(
            "api_errors_total",
            "Total number of failed Waddles hub requests (auth, HTTP status, transport, or decode errors)",
        )?;
        registerer.register(Box::new(api_errors_total.clone()))?;

        let up = new_gauge(
            "up",
            "Whether the waddles-gateway module is running (1 = running, 0 = stopped)",
        )?;
        registerer.register(Box::new(up.clone()))?;

        Ok(WaddlesGatewayMetrics {
            api_requests_total,
            api_errors_total,
            up,
        })
    }
}

fn new_counter(name: &str, help: &str) -> Result<Counter, MetricsError> {
    let opts = Opts::new(name, help)
        .namespace(NAMESPACE)
        .subsystem(SUBSYSTEM);
    Counter::with_opts(opts).map_err(|err| MetricsError(err.to_string()))
}

fn new_gauge(name: &str, help: &str) -> Result<Gauge, MetricsError> {
    let opts = Opts::new(name, help)
        .namespace(NAMESPACE)
        .subsystem(SUBSYSTEM);
    Gauge::with_opts(opts).map_err(|err| MetricsError(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct RecordingRegisterer {
        registry: prometheus::Registry,
        names: Mutex<Vec<String>>,
    }

    impl Metrics for RecordingRegisterer {
        fn register(
            &self,
            collector: Box<dyn prometheus::core::Collector>,
        ) -> Result<(), MetricsError> {
            let desc = collector.desc()[0].fq_name.clone();
            self.registry
                .register(collector)
                .map_err(|err| MetricsError(err.to_string()))?;
            self.names.lock().unwrap().push(desc);
            Ok(())
        }
    }

    fn registerer() -> RecordingRegisterer {
        RecordingRegisterer {
            registry: prometheus::Registry::new(),
            names: Mutex::new(Vec::new()),
        }
    }

    #[test]
    fn register_wires_all_three_collectors_with_their_documented_names() {
        let reg = registerer();
        let metrics = WaddlesGatewayMetrics::register(&reg).expect("register succeeds");

        let names = reg.names.lock().unwrap().clone();
        let expected = [
            "penguin_module_waddles_gateway_api_requests_total",
            "penguin_module_waddles_gateway_api_errors_total",
            "penguin_module_waddles_gateway_up",
        ];
        for name in expected {
            assert!(names.contains(&name.to_string()), "missing {name}");
        }

        metrics.api_requests_total.inc();
        assert_eq!(metrics.api_requests_total.get(), 1.0);
    }

    #[test]
    fn up_gauge_reflects_running_state() {
        let reg = registerer();
        let metrics = WaddlesGatewayMetrics::register(&reg).unwrap();
        metrics.up.set(1.0);
        assert_eq!(metrics.up.get(), 1.0);
        metrics.up.set(0.0);
        assert_eq!(metrics.up.get(), 0.0);
    }

    #[test]
    fn registering_twice_reports_a_duplicate_error() {
        let reg = registerer();
        WaddlesGatewayMetrics::register(&reg).expect("first registration succeeds");
        let Err(err) = WaddlesGatewayMetrics::register(&reg) else {
            panic!("a second registration of the same names must fail");
        };
        assert!(!err.0.is_empty());
    }
}
