//! The standard per-module registry: the four tools with real executors.

use std::sync::Arc;

use penguin_sdk::Logger;

use super::{RegistryError, ToolMetrics, ToolRegistry};
use crate::executors::{
    ConfigReadExecutor, DEFAULT_DOH_ENDPOINT, DohQueryExecutor, LoggerExecutor,
    MetricsPublishExecutor, ModuleGauges,
};

/// Everything the standard registry needs for one module.
pub struct ModuleToolContext<'a> {
    /// The module name (namespaces published metrics).
    pub module: &'a str,
    /// The module's host logger, backing the `logger` tool.
    pub logger: Arc<dyn Logger>,
    /// The module's raw YAML config, backing `config_read` (empty = none).
    pub config_yaml: &'a [u8],
    /// The daemon-wide gauge store backing `metrics_publish`; share one
    /// across runs so per-module caps persist.
    pub gauges: &'a ModuleGauges,
    /// The DoH resolver endpoint; `None` uses [`DEFAULT_DOH_ENDPOINT`].
    pub doh_endpoint: Option<&'a str>,
    /// Optional call telemetry (shared across modules, registered once).
    pub metrics: Option<ToolMetrics>,
}

/// Builds a registry over the embedded definitions with `logger`,
/// `config_read`, `metrics_publish` and `doh_query` wired. Every other
/// declared tool stays `NotImplemented`. A bad config or endpoint is an error
/// rather than a silently missing tool.
pub fn build_module_registry(ctx: ModuleToolContext<'_>) -> Result<ToolRegistry, RegistryError> {
    let mut registry = ToolRegistry::from_embedded()?;
    if let Some(metrics) = ctx.metrics {
        registry = registry.with_metrics(metrics);
    }
    registry.register(Arc::new(LoggerExecutor::new(ctx.logger)))?;
    let config = ConfigReadExecutor::new(ctx.config_yaml).map_err(RegistryError::Executor)?;
    registry.register(Arc::new(config))?;
    registry.register(Arc::new(MetricsPublishExecutor::new(
        ctx.gauges.clone(),
        ctx.module,
    )))?;
    let doh = DohQueryExecutor::new(ctx.doh_endpoint.unwrap_or(DEFAULT_DOH_ENDPOINT))
        .map_err(RegistryError::Executor)?;
    registry.register(Arc::new(doh))?;
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use penguin_sdk::LogLevel;
    use prometheus::Registry;
    use serde_json::json;

    struct Quiet;
    impl Logger for Quiet {
        fn log(&self, _l: LogLevel, _m: &str, _f: &[(&str, &str)]) {}
    }

    fn ctx<'a>(
        prom: &'a ModuleGauges,
        cfg: &'a [u8],
        doh: Option<&'a str>,
    ) -> ModuleToolContext<'a> {
        ModuleToolContext {
            module: "m",
            logger: Arc::new(Quiet),
            config_yaml: cfg,
            gauges: prom,
            doh_endpoint: doh,
            metrics: None,
        }
    }

    #[tokio::test]
    async fn wires_the_four_real_tools_and_leaves_the_rest_loud() {
        let prom = ModuleGauges::new(Registry::new());
        let reg = build_module_registry(ctx(&prom, b"a: 1\n", None)).expect("registry");
        assert!(reg.call("config_read", json!({"path":"a"})).await.is_ok());
        assert!(
            reg.call("metrics_publish", json!({"metric_name":"x","value":1}))
                .await
                .is_ok()
        );
        assert!(
            reg.call("logger", json!({"level":"INFO","message":"hi"}))
                .await
                .is_ok()
        );
        assert!(matches!(
            reg.call("http_request", json!({"method":"GET","url":"x"}))
                .await,
            Err(penguin_sdk::tools::ToolError::NotImplemented(_))
        ));
    }

    #[test]
    fn bad_config_or_endpoint_fails_construction() {
        let prom = ModuleGauges::new(Registry::new());
        assert!(matches!(
            build_module_registry(ctx(&prom, b": : not yaml [", None)),
            Err(RegistryError::Executor(_))
        ));
        assert!(matches!(
            build_module_registry(ctx(&prom, b"", Some("http://evil.example/"))),
            Err(RegistryError::Executor(_))
        ));
    }
}
