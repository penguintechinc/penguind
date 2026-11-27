//! Gathers metric families from first-party modules (squawk, tobogganing, waddlebot) and
//! verifies they match the intended Rust scheme encoded in a golden fixture.
//!
//! ## Metrics Naming Scheme (Rust vs Go Parity Divergence)
//!
//! **Rust scheme:** `penguin_module_<mod>_<name>` (Prometheus namespace/subsystem convention),
//! with NO `module=` label.
//!
//! **Go scheme (oracle):** bare `<mod>_<name>` + a const-label `module=<mod>` injected via
//! `WrapRegistererWith`.
//!
//! **Waived divergence** (PARITY §2): The Go scheme requires per-collector `WrapRegistererWith`
//! wiring for zero behavioral gain — the module identity is present either way. tikv/prometheus
//! (used by Rust) has no equivalent, so matching Go byte-for-byte would require bespoke code.
//! This test documents the Rust scheme as the intended choice for this platform.
//!
//! **Note on waddlebot:** waddlebot is Rust-only, has no Go oracle, and currently uses a
//! different naming pattern (missing the `waddlebot_` prefix on metric names). This is a
//! known inconsistency tracked as "waddlebot doubled subsystem bug" and is assigned to a
//! separate hardening track (B2); M8 does not duplicate that fix.
//!
//! All modules instantiate via their `register` method with a test registerer that
//! wraps a `prometheus::Registry`. No privileged operations (netlink/:53) are invoked.

use std::fs;
use std::path::PathBuf;

use penguin_module_squawk::metrics::SquawkMetrics;
use penguin_module_tobogganing::metrics::TobogganingMetrics;
use penguin_module_waddles_gateway::metrics::WaddlesGatewayMetrics;
use penguin_module_waddles_social::metrics::WaddlesSocialMetrics;

use penguin_sdk::{Metrics, MetricsError};
use serde::{Deserialize, Serialize};

/// A minimal representation of a metric family's identity: name and sorted label keys.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
struct MetricFamily {
    name: String,
    /// Sorted set of label-key names, excluding the value (distinguishes dimensional structure).
    label_keys: Vec<String>,
}

impl MetricFamily {
    fn from_prometheus(fq_name: &str, labels: &[String]) -> MetricFamily {
        let mut keys = labels.to_vec();
        keys.sort();
        MetricFamily {
            name: fq_name.to_string(),
            label_keys: keys,
        }
    }
}

/// Wrapper around `prometheus::Registry` that implements `Metrics` for test registration.
struct TestRegisterer {
    registry: prometheus::Registry,
}

impl TestRegisterer {
    fn new() -> TestRegisterer {
        TestRegisterer {
            registry: prometheus::Registry::new(),
        }
    }

    /// Gathers all metric families and extracts their fully-qualified names and label structures.
    fn gather_families(&self) -> Result<Vec<MetricFamily>, String> {
        let mut families = Vec::new();

        for mf in self.registry.gather() {
            let fq_name = if mf.name().is_empty() {
                continue;
            } else {
                mf.name().to_string()
            };

            if mf.metric.is_empty() {
                continue;
            }

            let metric = &mf.metric[0];
            let label_names: Vec<String> = metric
                .label
                .iter()
                .map(|lp| lp.name().to_string())
                .collect();

            families.push(MetricFamily::from_prometheus(&fq_name, &label_names));
        }

        families.sort();
        Ok(families)
    }
}

impl Metrics for TestRegisterer {
    fn register(
        &self,
        collector: Box<dyn prometheus::core::Collector>,
    ) -> Result<(), MetricsError> {
        self.registry
            .register(collector)
            .map_err(|err| MetricsError(err.to_string()))
    }
}

/// Resolves the testdata directory for golden fixtures.
fn testdata_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("testdata")
}

#[test]
fn metrics_parity() {
    let squawk_reg = TestRegisterer::new();
    let _squawk_metrics =
        SquawkMetrics::register(&squawk_reg).expect("squawk metrics registration succeeds");

    let tobogganing_reg = TestRegisterer::new();
    let _tobogganing_metrics = TobogganingMetrics::register(&tobogganing_reg)
        .expect("tobogganing metrics registration succeeds");

    let waddles_social_reg = TestRegisterer::new();
    let _waddles_social_metrics = WaddlesSocialMetrics::register(&waddles_social_reg)
        .expect("waddles-social metrics registration succeeds");

    let waddles_gateway_reg = TestRegisterer::new();
    let _waddles_gateway_metrics = WaddlesGatewayMetrics::register(&waddles_gateway_reg)
        .expect("waddles-gateway metrics registration succeeds");

    let squawk_families = squawk_reg
        .gather_families()
        .expect("squawk metric families gather succeeds");
    let tobogganing_families = tobogganing_reg
        .gather_families()
        .expect("tobogganing metric families gather succeeds");
    let waddles_social_families = waddles_social_reg
        .gather_families()
        .expect("waddles-social metric families gather succeeds");
    let waddles_gateway_families = waddles_gateway_reg
        .gather_families()
        .expect("waddles-gateway metric families gather succeeds");

    // Load the golden fixture.
    let golden_path = testdata_dir().join("metrics_parity_golden.json");
    let golden_content = fs::read_to_string(&golden_path)
        .unwrap_or_else(|err| panic!("read golden fixture {}: {err}", golden_path.display()));

    #[derive(Deserialize)]
    struct GoldenFixture {
        squawk: Vec<MetricFamily>,
        tobogganing: Vec<MetricFamily>,
        waddles_social: Vec<MetricFamily>,
        waddles_gateway: Vec<MetricFamily>,
    }

    let golden: GoldenFixture =
        serde_json::from_str(&golden_content).expect("golden fixture is valid JSON");

    // Assert each module's metric set matches the golden.
    assert_eq!(
        squawk_families, golden.squawk,
        "squawk metrics do not match golden fixture"
    );
    assert_eq!(
        tobogganing_families, golden.tobogganing,
        "tobogganing metrics do not match golden fixture"
    );
    assert_eq!(
        waddles_social_families, golden.waddles_social,
        "waddles-social metrics do not match golden fixture"
    );
    assert_eq!(
        waddles_gateway_families, golden.waddles_gateway,
        "waddles-gateway metrics do not match golden fixture"
    );
}
