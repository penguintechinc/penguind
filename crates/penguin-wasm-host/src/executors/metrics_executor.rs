//! `metrics_publish`: guest-supplied gauge samples into the daemon's prometheus registry.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use prometheus::{GaugeVec, Opts, Registry};
use serde_json::Value;

use super::ToolExecutor;

/// Most distinct metric names one module may create.
pub const MAX_METRICS: usize = 64;
/// Most label names on one metric.
pub const MAX_LABELS: usize = 8;
/// Most distinct label-value combinations (series) per metric.
pub const MAX_SERIES: usize = 256;
/// Longest accepted guest metric name, in bytes.
const MAX_NAME_LEN: usize = 96;

/// One registered gauge family plus the label schema and series seen so far.
struct Family {
    label_names: Vec<String>,
    gauge: GaugeVec,
    series: HashSet<Vec<String>>,
}

/// Backs `metrics_publish` with gauges registered in the shared registry.
/// Names are prefixed per module and every dimension is capped, because the
/// names and labels come from untrusted guest code.
pub struct MetricsPublishExecutor {
    registry: Registry,
    prefix: String,
    families: Mutex<HashMap<String, Family>>,
}

impl MetricsPublishExecutor {
    /// Creates an executor publishing under `penguind_module_<module>_`
    /// (non-alphanumerics in the module name become `_`).
    pub fn new(registry: Registry, module: &str) -> Self {
        let module: String = module
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        Self {
            registry,
            prefix: format!("penguind_module_{module}_"),
            families: Mutex::new(HashMap::new()),
        }
    }
}

/// Parses the optional `labels` object into sorted name -> value pairs;
/// only strings, numbers and booleans are accepted as values.
fn parse_labels(raw: &Value) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    let Some(map) = raw.as_object() else {
        return if raw.is_null() {
            Ok(out)
        } else {
            Err("labels must be an object".into())
        };
    };
    if map.len() > MAX_LABELS {
        return Err(format!("too many labels (max {MAX_LABELS})"));
    }
    for (key, value) in map {
        let text = match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => return Err(format!("label {key} must be a string, number or boolean")),
        };
        if text.len() > 128 {
            return Err(format!("label {key} value too long"));
        }
        out.insert(key.clone(), text);
    }
    Ok(out)
}

#[async_trait]
impl ToolExecutor for MetricsPublishExecutor {
    fn id(&self) -> &str {
        "metrics_publish"
    }

    async fn execute(&self, args: Value) -> Result<Value, String> {
        let name = args["metric_name"].as_str().unwrap_or("");
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(format!("metric_name must be 1..={MAX_NAME_LEN} bytes"));
        }
        let value = args["value"].as_f64().ok_or("value must be a number")?;
        if !value.is_finite() {
            return Err("value must be finite".into());
        }
        let labels = parse_labels(&args["labels"])?;
        let names: Vec<String> = labels.keys().cloned().collect();
        let values: Vec<String> = labels.values().cloned().collect();
        let full = format!("{}{name}", self.prefix);

        // Short synchronous critical section; nothing here awaits.
        let mut families = self
            .families
            .lock()
            .map_err(|_| "metrics state poisoned".to_string())?;
        if !families.contains_key(&full) {
            if families.len() >= MAX_METRICS {
                return Err(format!("metric limit reached (max {MAX_METRICS})"));
            }
            let refs: Vec<&str> = names.iter().map(String::as_str).collect();
            let gauge = GaugeVec::new(Opts::new(full.clone(), "Module-published gauge"), &refs)
                .map_err(|e| e.to_string())?;
            self.registry
                .register(Box::new(gauge.clone()))
                .map_err(|e| e.to_string())?;
            families.insert(
                full.clone(),
                Family {
                    label_names: names.clone(),
                    gauge,
                    series: HashSet::new(),
                },
            );
        }
        let family = families.get_mut(&full).ok_or("metric family vanished")?;
        if family.label_names != names {
            return Err(format!(
                "label names for {name} must stay {:?}",
                family.label_names
            ));
        }
        if !family.series.contains(&values) {
            if family.series.len() >= MAX_SERIES {
                return Err(format!(
                    "series limit reached for {name} (max {MAX_SERIES})"
                ));
            }
            family.series.insert(values.clone());
        }
        let refs: Vec<&str> = values.iter().map(String::as_str).collect();
        family
            .gauge
            .get_metric_with_label_values(&refs)
            .map_err(|e| e.to_string())?
            .set(value);
        Ok(Value::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn exec() -> (MetricsPublishExecutor, Registry) {
        let reg = Registry::new();
        (MetricsPublishExecutor::new(reg.clone(), "my-mod"), reg)
    }

    #[tokio::test]
    async fn publishes_a_labelled_gauge_into_the_registry() {
        let (e, reg) = exec();
        let r = e
            .execute(json!({"metric_name":"temp","value":2.5,"labels":{"zone":"a","n":1}}))
            .await;
        assert_eq!(r, Ok(Value::Null));
        let fam = reg.gather();
        let f = fam
            .iter()
            .find(|f| f.name() == "penguind_module_my_mod_temp")
            .expect("family");
        assert_eq!(f.get_metric()[0].get_gauge().value(), 2.5);
        // Updating the same series overwrites instead of adding a series.
        e.execute(json!({"metric_name":"temp","value":9,"labels":{"zone":"a","n":1}}))
            .await
            .expect("update");
        let fam = reg.gather();
        assert_eq!(fam[0].get_metric().len(), 1);
        assert_eq!(fam[0].get_metric()[0].get_gauge().value(), 9.0);
    }

    #[tokio::test]
    async fn rejects_bad_names_values_and_labels() {
        let (e, _) = exec();
        assert!(
            e.execute(json!({"metric_name":"","value":1}))
                .await
                .is_err()
        );
        assert!(
            e.execute(json!({"metric_name":"bad name!","value":1}))
                .await
                .is_err()
        );
        assert!(
            e.execute(json!({"metric_name":"x".repeat(200),"value":1}))
                .await
                .is_err()
        );
        assert!(
            e.execute(json!({"metric_name":"m","value":"s"}))
                .await
                .is_err()
        );
        assert!(
            e.execute(json!({"metric_name":"m","value":1,"labels":[1]}))
                .await
                .is_err()
        );
        assert!(
            e.execute(json!({"metric_name":"m","value":1,"labels":{"k":{"a":1}}}))
                .await
                .is_err()
        );
        assert!(
            e.execute(json!({"metric_name":"m","value":1,"labels":{"k":"v".repeat(200)}}))
                .await
                .is_err()
        );
        let many: serde_json::Map<String, Value> = (0..=MAX_LABELS)
            .map(|i| (format!("l{i}"), json!("v")))
            .collect();
        assert!(
            e.execute(json!({"metric_name":"m","value":1,"labels":many}))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn label_schema_is_fixed_per_metric() {
        let (e, _) = exec();
        e.execute(json!({"metric_name":"m","value":1,"labels":{"a":"x"}}))
            .await
            .expect("first");
        let err = e
            .execute(json!({"metric_name":"m","value":1,"labels":{"b":"x"}}))
            .await
            .expect_err("schema change");
        assert!(err.contains("label names"), "{err}");
    }

    #[tokio::test]
    async fn metric_and_series_counts_are_capped() {
        let (e, _) = exec();
        for i in 0..MAX_SERIES {
            e.execute(json!({"metric_name":"s","value":1,"labels":{"i":i}}))
                .await
                .expect("series");
        }
        assert!(
            e.execute(json!({"metric_name":"s","value":1,"labels":{"i":"overflow"}}))
                .await
                .is_err()
        );
        // An existing series is still updatable at the cap.
        assert!(
            e.execute(json!({"metric_name":"s","value":2,"labels":{"i":0}}))
                .await
                .is_ok()
        );
        let (e, _) = exec();
        for i in 0..MAX_METRICS {
            e.execute(json!({"metric_name":format!("m{i}"),"value":1}))
                .await
                .expect("metric");
        }
        assert!(
            e.execute(json!({"metric_name":"one_too_many","value":1}))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn duplicate_registration_in_a_shared_registry_is_an_error() {
        let reg = Registry::new();
        let a = MetricsPublishExecutor::new(reg.clone(), "same");
        let b = MetricsPublishExecutor::new(reg, "same");
        a.execute(json!({"metric_name":"m","value":1}))
            .await
            .expect("a");
        assert!(
            b.execute(json!({"metric_name":"m","value":1}))
                .await
                .is_err()
        );
    }
}
