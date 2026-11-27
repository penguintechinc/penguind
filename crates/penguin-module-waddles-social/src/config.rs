//! `waddles-social`'s on-disk module configuration and the JSON Schema the
//! daemon validates it against before [`crate::WaddlesSocialModule::init`]
//! ever reads it.
//!
//! User session tokens are deliberately **not** fields here: tokens are
//! secrets read via `host.secrets()` in `init` (namespace `"waddles-social"`),
//! or held in-memory by [`crate::SessionProxy`] via `SetUserSession`.

use serde::{Deserialize, Serialize};

/// `waddles-social`'s full on-disk config shape, validated by the daemon
/// against [`CONFIG_SCHEMA`] before [`crate::WaddlesSocialModule::init`]
/// ever reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct ModuleConfig {
    pub hub: HubSection,
    /// The community UUID this module acts on (optional; empty = no active
    /// community selected yet).
    pub community_id: String,
}

/// Which Waddles hub this module talks to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct HubSection {
    pub base_url: String,
}

impl Default for HubSection {
    fn default() -> HubSection {
        HubSection {
            base_url: waddles_client::config::DEFAULT_BASE_URL.to_string(),
        }
    }
}

/// The JSON Schema the daemon validates `waddles-social.yaml` against.
pub const CONFIG_SCHEMA: &str = r#"{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "hub": {
      "type": "object",
      "properties": {
        "base_url": {
          "type": "string",
          "description": "Waddles hub API base URL",
          "default": "https://waddles.app/api/v1"
        }
      }
    },
    "community_id": {
      "type": "string",
      "description": "Active community UUID for social CLI commands",
      "default": ""
    }
  },
  "additionalProperties": false
}"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_yaml_parses_to_defaults() {
        let cfg: ModuleConfig = serde_norway::from_str("{}").unwrap();
        assert_eq!(cfg, ModuleConfig::default());
        assert_eq!(cfg.hub.base_url, "https://waddles.app/api/v1");
        assert!(cfg.community_id.is_empty());
    }

    #[test]
    fn partial_yaml_overrides_only_specified_fields() {
        let yaml = "hub:\n  base_url: \"http://127.0.0.1:8080/api/v1\"\ncommunity_id: \"11111111-1111-4111-8111-111111111111\"\n";
        let cfg: ModuleConfig = serde_norway::from_str(yaml).unwrap();
        assert_eq!(cfg.hub.base_url, "http://127.0.0.1:8080/api/v1");
        assert_eq!(cfg.community_id, "11111111-1111-4111-8111-111111111111");
    }

    #[test]
    fn schema_is_valid_json_and_compiles() {
        let schema: serde_json::Value = serde_json::from_str(CONFIG_SCHEMA).unwrap();
        let validator = jsonschema::validator_for(&schema);
        assert!(validator.is_ok(), "schema must compile");
    }

    #[test]
    fn schema_accepts_the_default_config_document() {
        let schema: serde_json::Value = serde_json::from_str(CONFIG_SCHEMA).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let instance = serde_json::to_value(ModuleConfig::default()).unwrap();
        let errors: Vec<_> = validator.iter_errors(&instance).collect();
        assert!(errors.is_empty(), "unexpected schema errors: {errors:?}");
    }

    #[test]
    fn schema_rejects_unknown_top_level_fields() {
        let schema: serde_json::Value = serde_json::from_str(CONFIG_SCHEMA).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let instance = serde_json::json!({
            "bridge": { "enabled": true }
        });
        assert!(
            validator.iter_errors(&instance).next().is_some(),
            "bridge config must be rejected by waddles-social schema"
        );
    }

    #[test]
    fn schema_defaults_match_code_defaults() {
        let schema: serde_json::Value = serde_json::from_str(CONFIG_SCHEMA).unwrap();
        let advertised_url = schema["properties"]["hub"]["properties"]["base_url"]["default"]
            .as_str()
            .unwrap();
        assert_eq!(advertised_url, ModuleConfig::default().hub.base_url);
        assert_eq!(advertised_url, waddles_client::config::DEFAULT_BASE_URL);

        let advertised_community = schema["properties"]["community_id"]["default"]
            .as_str()
            .unwrap();
        assert_eq!(advertised_community, ModuleConfig::default().community_id);
    }
}
