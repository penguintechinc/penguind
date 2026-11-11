//! `config_read`: dot-path lookup into the module's schema-validated config.

use async_trait::async_trait;
use serde_json::{Value, json};

use super::ToolExecutor;

/// Backs `config_read` with the module's YAML config (already validated by the
/// daemon). Modules never read config files themselves.
pub struct ConfigReadExecutor {
    config: Value,
}

impl ConfigReadExecutor {
    /// Parses the raw YAML bytes; empty config is an empty object.
    pub fn new(yaml: &[u8]) -> Result<Self, String> {
        if yaml.is_empty() {
            return Ok(Self { config: json!({}) });
        }
        let config: Value = serde_norway::from_slice(yaml).map_err(|e| e.to_string())?;
        Ok(Self { config })
    }
}

#[async_trait]
impl ToolExecutor for ConfigReadExecutor {
    fn id(&self) -> &str {
        "config_read"
    }

    async fn execute(&self, args: Value) -> Result<Value, String> {
        let path = args["path"].as_str().unwrap_or("");
        let mut node = &self.config;
        for part in path.split('.').filter(|p| !p.is_empty()) {
            node = node
                .get(part)
                .ok_or_else(|| format!("config path not found: {path}"))?;
        }
        Ok(json!({ "path": path, "value": node }))
    }
}
