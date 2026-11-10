//! A typed convenience wrapper over [`HostServices::call_tool`].
//!
//! Module authors get named methods for the common tools instead of hand-building
//! JSON; each method uses the tool ids and argument names declared in
//! `schemas/tool_definitions.json`, so a drift between the two is caught by the
//! host's schema validation rather than silently ignored.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::host::HostServices;
use crate::tools::ToolError;

/// High-level handle a module uses to call daemon tools.
pub struct HostCapability {
    host_services: Arc<dyn HostServices>,
}

impl HostCapability {
    /// Wraps the host services handed to the module at init.
    pub fn new(host_services: Arc<dyn HostServices>) -> Self {
        Self { host_services }
    }

    /// Performs a DNS-over-HTTPS lookup (`doh_query`).
    pub async fn query_doh(&self, name: &str, query_type: &str) -> Result<Value, ToolError> {
        let args = json!({ "name": name, "query_type": query_type });
        self.host_services.call_tool("doh_query", args).await
    }

    /// Publishes a metric sample (`metrics_publish`); labels are key/value pairs.
    pub async fn push_metric(
        &self,
        metric_name: &str,
        value: f64,
        labels: Value,
    ) -> Result<(), ToolError> {
        let args = json!({ "metric_name": metric_name, "value": value, "labels": labels });
        self.host_services
            .call_tool("metrics_publish", args)
            .await?;
        Ok(())
    }

    /// Reads a module configuration value at a dot-notated path (`config_read`).
    pub async fn get_config(&self, path: &str) -> Result<Value, ToolError> {
        let args = json!({ "path": path });
        self.host_services.call_tool("config_read", args).await
    }

    /// Writes a record through the host logging facility (`logger`).
    pub async fn log(&self, level: &str, message: &str) -> Result<(), ToolError> {
        let args = json!({ "level": level, "message": message });
        self.host_services.call_tool("logger", args).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use crate::error::{MetricsError, SecretError};
    use crate::host::{
        Event, EventSink, LicenseChecker, LogLevel, Logger, Metrics, SecretStore, ToolFuture,
    };

    struct NullLogger;
    impl Logger for NullLogger {
        fn log(&self, _l: LogLevel, _m: &str, _f: &[(&str, &str)]) {}
    }
    struct NullSecrets;
    #[async_trait]
    impl SecretStore for NullSecrets {
        async fn get(&self, _k: &str) -> Result<Vec<u8>, SecretError> {
            Err(SecretError::NotFound)
        }
        async fn set(&self, _k: &str, _v: &[u8]) -> Result<(), SecretError> {
            Ok(())
        }
        async fn delete(&self, _k: &str) -> Result<(), SecretError> {
            Ok(())
        }
    }
    struct NullLicense;
    impl LicenseChecker for NullLicense {
        fn feature_enabled(&self, _k: &str) -> bool {
            false
        }
        fn tier(&self) -> String {
            String::new()
        }
    }
    struct NullMetrics;
    impl Metrics for NullMetrics {
        fn register(&self, _c: Box<dyn prometheus::core::Collector>) -> Result<(), MetricsError> {
            Ok(())
        }
    }
    struct NullEvents;
    impl EventSink for NullEvents {
        fn publish(&self, _e: Event) {}
    }

    /// Host double recording each `call_tool` and answering with a canned result.
    struct Recorder {
        calls: Mutex<Vec<(String, Value)>>,
        reply: Result<Value, ToolError>,
    }
    impl HostServices for Recorder {
        fn logger(&self) -> Arc<dyn Logger> {
            Arc::new(NullLogger)
        }
        fn secrets(&self) -> Arc<dyn SecretStore> {
            Arc::new(NullSecrets)
        }
        fn license(&self) -> Arc<dyn LicenseChecker> {
            Arc::new(NullLicense)
        }
        fn metrics(&self) -> Arc<dyn Metrics> {
            Arc::new(NullMetrics)
        }
        fn config(&self) -> Vec<u8> {
            Vec::new()
        }
        fn data_dir(&self) -> PathBuf {
            PathBuf::new()
        }
        fn events(&self) -> Arc<dyn EventSink> {
            Arc::new(NullEvents)
        }
        fn call_tool<'a>(&'a self, name: &'a str, args: Value) -> ToolFuture<'a> {
            self.calls
                .lock()
                .expect("lock")
                .push((name.to_string(), args));
            let reply = self.reply.clone();
            Box::pin(async move { reply })
        }
    }

    fn cap(reply: Result<Value, ToolError>) -> (HostCapability, Arc<Recorder>) {
        let rec = Arc::new(Recorder {
            calls: Mutex::new(Vec::new()),
            reply,
        });
        (HostCapability::new(rec.clone()), rec)
    }

    #[tokio::test]
    async fn each_method_sends_the_declared_tool_id_and_argument_names() {
        let (cap, rec) = cap(Ok(json!({"ok": true})));
        assert_eq!(
            cap.query_doh("a.test", "A").await.unwrap(),
            json!({"ok": true})
        );
        cap.push_metric("m", 1.5, json!({"k": "v"})).await.unwrap();
        assert_eq!(cap.get_config("a.b").await.unwrap(), json!({"ok": true}));
        cap.log("INFO", "hi").await.unwrap();
        let calls = rec.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                (
                    "doh_query".into(),
                    json!({"name":"a.test","query_type":"A"})
                ),
                (
                    "metrics_publish".into(),
                    json!({"metric_name":"m","value":1.5,"labels":{"k":"v"}})
                ),
                ("config_read".into(), json!({"path":"a.b"})),
                ("logger".into(), json!({"level":"INFO","message":"hi"})),
            ]
        );
    }

    #[tokio::test]
    async fn every_method_propagates_the_host_error() {
        let errors = [
            ToolError::Unavailable,
            ToolError::UnknownTool("x".into()),
            ToolError::NotImplemented("x".into()),
        ];
        for err in errors {
            let (cap, _) = cap(Err(err.clone()));
            assert_eq!(cap.query_doh("n", "A").await.unwrap_err(), err);
            assert_eq!(cap.push_metric("m", 1.0, json!({})).await.unwrap_err(), err);
            assert_eq!(cap.get_config("p").await.unwrap_err(), err);
            assert_eq!(cap.log("INFO", "m").await.unwrap_err(), err);
        }
    }

    #[tokio::test]
    async fn a_host_without_a_registry_fails_loudly_by_default() {
        struct Bare(Recorder);
        impl HostServices for Bare {
            fn logger(&self) -> Arc<dyn Logger> {
                self.0.logger()
            }
            fn secrets(&self) -> Arc<dyn SecretStore> {
                self.0.secrets()
            }
            fn license(&self) -> Arc<dyn LicenseChecker> {
                self.0.license()
            }
            fn metrics(&self) -> Arc<dyn Metrics> {
                self.0.metrics()
            }
            fn config(&self) -> Vec<u8> {
                Vec::new()
            }
            fn data_dir(&self) -> PathBuf {
                PathBuf::new()
            }
            fn events(&self) -> Arc<dyn EventSink> {
                self.0.events()
            }
        }
        let bare = Bare(Recorder {
            calls: Mutex::new(Vec::new()),
            reply: Ok(Value::Null),
        });
        let cap = HostCapability::new(Arc::new(bare));
        assert_eq!(
            cap.log("INFO", "x").await.unwrap_err(),
            ToolError::Unavailable
        );
    }
}
