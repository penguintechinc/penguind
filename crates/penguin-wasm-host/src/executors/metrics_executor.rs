//! `metrics_publish`: guest-supplied gauge samples into the daemon's prometheus registry.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

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

/// Fixed prefix for every module-published metric name.
const PREFIX: &str = "penguind_module_";
/// Constant label carrying the publishing module's id.
const MODULE_LABEL: &str = "module";
/// Longest accepted module id, in bytes.
const MAX_MODULE_LEN: usize = 128;

/// One registered gauge family plus the label schema and series seen so far.
struct Family {
    label_names: Vec<String>,
    gauge: GaugeVec,
    series: HashSet<Vec<String>>,
}

/// Gauge state shared by every run of every module over one registry.
#[derive(Default)]
struct GaugeState {
    /// Module id -> metric name -> family; outlives individual runs so the
    /// caps hold per module, not per run.
    modules: HashMap<String, HashMap<String, Family>>,
    /// Sanitized module id -> the raw id that claimed it.
    claimed: HashMap<String, String>,
}

/// The daemon-wide store behind `metrics_publish`: the shared prometheus
/// registry plus per-module caps that persist across runs. Create one per
/// registry and hand clones to every module's executor.
#[derive(Clone)]
pub struct ModuleGauges {
    registry: Registry,
    state: Arc<Mutex<GaugeState>>,
}

impl ModuleGauges {
    /// Wraps `registry`; all executors built from clones share one cap ledger.
    pub fn new(registry: Registry) -> Self {
        Self {
            registry,
            state: Arc::new(Mutex::new(GaugeState::default())),
        }
    }

    /// The wrapped prometheus registry.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

/// Whether `name` matches `^[a-z][a-z0-9_]{0,95}$` with no `__` and no
/// trailing `_`, so `<module>__<name>` splits unambiguously.
fn valid_metric_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_NAME_LEN
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
        && !name.contains("__")
        && !name.ends_with('_')
}

/// Whether `name` is an acceptable guest label name (`^[a-z][a-z0-9_]*$`,
/// at most 64 bytes, not the reserved `module` label).
fn valid_label_name(name: &str) -> bool {
    name != MODULE_LABEL && name.len() <= 64 && valid_metric_name(name)
}

/// Lowercases and maps non-alphanumerics to `_`; two ids with the same
/// sanitized form are treated as colliding.
fn sanitize(module: &str) -> String {
    module
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Backs `metrics_publish` with gauges named
/// `penguind_module_<sanitized_module>__<name>` (per-module families, so one
/// module cannot squat another's names) plus a constant `module="<id>"` label. Names, labels and every dimension are
/// validated and capped, because they come from untrusted guest code; caps
/// live in [`ModuleGauges`] so they hold across runs.
pub struct MetricsPublishExecutor {
    gauges: ModuleGauges,
    module: String,
}

impl MetricsPublishExecutor {
    /// Creates an executor publishing for `module` into `gauges`.
    pub fn new(gauges: ModuleGauges, module: &str) -> Self {
        Self {
            gauges,
            module: module.to_string(),
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
        if !valid_label_name(key) {
            return Err(format!("label name {key:?} is invalid"));
        }
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
        if !valid_metric_name(name) {
            return Err(format!(
                "metric_name must match ^[a-z][a-z0-9_]{{0,{}}}$",
                MAX_NAME_LEN - 1
            ));
        }
        if self.module.is_empty() || self.module.len() > MAX_MODULE_LEN {
            return Err("module id invalid".into());
        }
        let value = args["value"].as_f64().ok_or("value must be a number")?;
        if !value.is_finite() {
            return Err("value must be finite".into());
        }
        let labels = parse_labels(&args["labels"])?;
        let names: Vec<String> = labels.keys().cloned().collect();
        let values: Vec<String> = labels.values().cloned().collect();
        let full = format!("{PREFIX}{}__{name}", sanitize(&self.module));

        // Short synchronous critical section; nothing here awaits.
        let mut state = self
            .gauges
            .state
            .lock()
            .map_err(|_| "metrics state poisoned".to_string())?;
        let key = sanitize(&self.module);
        match state.claimed.get(&key) {
            Some(owner) if *owner != self.module => {
                return Err(format!(
                    "module id {:?} collides with {owner:?}",
                    self.module
                ));
            }
            Some(_) => {}
            None => {
                state.claimed.insert(key, self.module.clone());
            }
        }
        let families = state.modules.entry(self.module.clone()).or_default();
        if !families.contains_key(&full) {
            if families.len() >= MAX_METRICS {
                return Err(format!("metric limit reached (max {MAX_METRICS})"));
            }
            let refs: Vec<&str> = names.iter().map(String::as_str).collect();
            let opts = Opts::new(full.clone(), "Module-published gauge")
                .const_label(MODULE_LABEL, self.module.clone());
            let gauge = GaugeVec::new(opts, &refs).map_err(|e| e.to_string())?;
            self.gauges
                .registry
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
        let gauges = ModuleGauges::new(reg.clone());
        (MetricsPublishExecutor::new(gauges, "my-mod"), reg)
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
            .find(|f| f.name() == "penguind_module_my_mod__temp")
            .expect("family");
        let module = f.get_metric()[0]
            .get_label()
            .iter()
            .find(|l| l.name() == "module")
            .map(|l| l.value().to_string());
        assert_eq!(module.as_deref(), Some("my-mod"));
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
        // Two ledgers over one registry cannot both own the same series.
        let reg = Registry::new();
        let a = MetricsPublishExecutor::new(ModuleGauges::new(reg.clone()), "same");
        let b = MetricsPublishExecutor::new(ModuleGauges::new(reg), "same");
        a.execute(json!({"metric_name":"m","value":1}))
            .await
            .expect("a");
        assert!(
            b.execute(json!({"metric_name":"m","value":1}))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn metric_cap_holds_across_runs_of_one_module() {
        // regression: caps were per executor instance, so each run reset them.
        let reg = Registry::new();
        let gauges = ModuleGauges::new(reg.clone());
        for i in 0..MAX_METRICS {
            let run = MetricsPublishExecutor::new(gauges.clone(), "m");
            run.execute(json!({"metric_name":format!("g{i}"),"value":1}))
                .await
                .expect("metric");
        }
        let next_run = MetricsPublishExecutor::new(gauges.clone(), "m");
        assert!(
            next_run
                .execute(json!({"metric_name":"g_new","value":1}))
                .await
                .is_err()
        );
        // Re-publishing an existing family from a new run still works.
        assert!(
            next_run
                .execute(json!({"metric_name":"g0","value":2}))
                .await
                .is_ok()
        );
        // Another module has its own budget.
        let other = MetricsPublishExecutor::new(gauges, "other");
        assert!(
            other
                .execute(json!({"metric_name":"g_new","value":1}))
                .await
                .is_ok()
        );
        assert_eq!(reg.gather().len(), MAX_METRICS + 1);
    }

    #[tokio::test]
    async fn series_cap_holds_across_runs_of_one_module() {
        let gauges = ModuleGauges::new(Registry::new());
        for i in 0..MAX_SERIES {
            MetricsPublishExecutor::new(gauges.clone(), "m")
                .execute(json!({"metric_name":"s","value":1,"labels":{"i":i}}))
                .await
                .expect("series");
        }
        assert!(
            MetricsPublishExecutor::new(gauges, "m")
                .execute(json!({"metric_name":"s","value":1,"labels":{"i":"overflow"}}))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn module_and_metric_names_cannot_collide() {
        // regression: `a_b`+`c` and `a`+`b_c` both produced one metric name.
        let reg = Registry::new();
        let gauges = ModuleGauges::new(reg.clone());
        MetricsPublishExecutor::new(gauges.clone(), "a_b")
            .execute(json!({"metric_name":"c","value":1}))
            .await
            .expect("a_b");
        MetricsPublishExecutor::new(gauges.clone(), "a")
            .execute(json!({"metric_name":"b_c","value":2}))
            .await
            .expect("a");
        let names: Vec<String> = reg.gather().iter().map(|f| f.name().to_string()).collect();
        assert!(
            names.contains(&"penguind_module_a_b__c".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"penguind_module_a__b_c".to_string()),
            "{names:?}"
        );
        // Module ids that sanitize to the same form are rejected.
        let err = MetricsPublishExecutor::new(gauges.clone(), "a.b")
            .execute(json!({"metric_name":"x","value":1}))
            .await
            .expect_err("sanitized collision");
        assert!(err.contains("collides"), "{err}");
        assert!(
            MetricsPublishExecutor::new(gauges, "A_B")
                .execute(json!({"metric_name":"x","value":1}))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn strict_metric_and_label_names() {
        let (e, _) = exec();
        for bad in [
            "Temp", "1x", "_x", "x__y", "x_", "x-y", "x.y", "x:y", "\u{e9}",
        ] {
            assert!(
                e.execute(json!({"metric_name":bad,"value":1}))
                    .await
                    .is_err(),
                "{bad}"
            );
        }
        for bad in ["module", "Bad", "a-b", "__x"] {
            assert!(
                e.execute(json!({"metric_name":"ok","value":1,"labels":{bad:"v"}}))
                    .await
                    .is_err(),
                "{bad}"
            );
        }
        assert!(
            e.execute(json!({"metric_name":"ok_1","value":1}))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn modules_cannot_squat_each_others_metric_names() {
        // regression: a shared `penguind_module_foo` family let module A fix
        // the label schema so module B's `foo` failed to register.
        let reg = Registry::new();
        let gauges = ModuleGauges::new(reg.clone());
        MetricsPublishExecutor::new(gauges.clone(), "mod-a")
            .execute(json!({"metric_name":"foo","value":1,"labels":{"zone":"z"}}))
            .await
            .expect("a");
        MetricsPublishExecutor::new(gauges, "mod-b")
            .execute(json!({"metric_name":"foo","value":2,"labels":{"host":"h","dc":"d"}}))
            .await
            .expect("b");
        let names: Vec<String> = reg.gather().iter().map(|f| f.name().to_string()).collect();
        assert!(
            names.contains(&"penguind_module_mod_a__foo".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"penguind_module_mod_b__foo".to_string()),
            "{names:?}"
        );
    }
}
