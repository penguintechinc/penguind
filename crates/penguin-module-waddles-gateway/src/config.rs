//! waddles-gateway's on-disk module configuration and the JSON Schema the daemon
//! validates it against before [`crate::WaddlesGatewayModule::init`] ever reads
//! it.
//!
//! The Community Access Token is deliberately **not** a field here: it is a
//! secret, read via `host.secrets()` in `init`, never from this document —
//! see that method's doc for why a config-carried value is still overridden
//! by the secret store.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// waddles-gateway's full on-disk config shape, validated by the daemon against
/// [`CONFIG_SCHEMA`] before [`crate::WaddlesGatewayModule::init`] ever reads it.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct ModuleConfig {
    pub hub: HubSection,
    /// The community UUID this module acts on. Empty (the default) is not a valid
    /// community id on the hub — `init` still builds a client against it
    /// (never fails on account of this alone; see `init`'s doc), so a
    /// misconfigured/unset value simply shows up as hub errors on first use
    /// rather than a load-time failure.
    pub community_id: String,
    pub bridge: BridgeSection,
}

/// Which hub this module talks to.
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

/// Reserved configuration for the local integration bridge — see this
/// module's doc. Every field here is read by this crate's config parser and
/// schema, but nothing in this track acts on them yet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct BridgeSection {
    pub enabled: bool,
    pub listen_tcp: String,
    pub listen_unix: String,
    pub allowed_integrations: Vec<String>,
    pub obs: ObsSection,
    pub webhooks: HashMap<String, WebhookTarget>,
}

/// OBS WebSocket adapter configuration for the bridge.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct ObsSection {
    /// Whether to enable the OBS adapter.
    pub enabled: bool,
    /// The OBS WebSocket server URL (typically `ws://127.0.0.1:4455`).
    pub url: String,
    /// The secret key name in the secrets store for the OBS password.
    pub secret_key: String,
    /// Allowlist of obs-websocket v5 requestType values permitted for remote dispatch.
    /// Empty = OBS command-out fully disabled, even if enabled=true.
    pub allowed_commands: Vec<String>,
    /// Allowlist of scene names permitted for SetCurrentProgramScene.
    /// Empty = any scene name accepted (if SetCurrentProgramScene is in allowed_commands).
    pub allowed_scenes: Vec<String>,
}

impl Default for ObsSection {
    fn default() -> ObsSection {
        ObsSection {
            enabled: false,
            url: String::new(),
            secret_key: "obs_password".to_string(),
            allowed_commands: Vec::new(),
            allowed_scenes: Vec::new(),
        }
    }
}

/// Webhook target configuration — operator-defined dispatch targets.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct WebhookTarget {
    /// The HTTP URL to POST to; never sent by the hub, operator-only.
    pub url: String,
    /// Request timeout in seconds; clamped to 30s hard ceiling.
    pub timeout_secs: u32,
    /// Optional secret store key for Bearer token auth.
    /// Empty = no auth header. Never inlined in config, always resolved at dispatch time.
    pub auth_secret_key: String,
}

impl Default for WebhookTarget {
    fn default() -> WebhookTarget {
        WebhookTarget {
            url: String::new(),
            timeout_secs: 10,
            auth_secret_key: String::new(),
        }
    }
}

/// The JSON Schema the daemon validates `waddles-gateway.yaml` against.
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
      "description": "The community UUID this module acts on",
      "default": ""
    },
    "bridge": {
      "type": "object",
      "description": "Reserved for the local integration bridge, built on a separate, later track. Unused by this module today.",
      "properties": {
        "enabled": {
          "type": "boolean",
          "description": "Enable the local integration bridge",
          "default": false
        },
        "listen_tcp": {
          "type": "string",
          "description": "TCP address the bridge listens on, when enabled",
          "default": ""
        },
        "listen_unix": {
          "type": "string",
          "description": "Unix socket path the bridge listens on, when enabled",
          "default": ""
        },
        "allowed_integrations": {
          "type": "array",
          "items": { "type": "string" },
          "description": "Local integration names permitted to connect to the bridge",
          "default": []
        },
        "obs": {
          "type": "object",
          "description": "OBS WebSocket adapter configuration",
          "properties": {
            "enabled": {
              "type": "boolean",
              "description": "Enable the OBS WebSocket adapter",
              "default": false
            },
            "url": {
              "type": "string",
              "description": "OBS WebSocket server URL (e.g., ws://127.0.0.1:4455)",
              "default": ""
            },
            "secret_key": {
              "type": "string",
              "description": "Secret store key for the OBS WebSocket password",
              "default": "obs_password"
            },
            "allowed_commands": {
              "type": "array",
              "items": { "type": "string" },
              "description": "Allowlist of obs-websocket v5 requestType values permitted for remote dispatch; empty disables command-out",
              "default": []
            },
            "allowed_scenes": {
              "type": "array",
              "items": { "type": "string" },
              "description": "Allowlist of scene names for SetCurrentProgramScene; empty allows any scene",
              "default": []
            }
          }
        },
        "webhooks": {
          "type": "object",
          "description": "Webhook targets for remote dispatch",
          "additionalProperties": {
            "type": "object",
            "properties": {
              "url": {
                "type": "string",
                "description": "HTTP URL to POST to"
              },
              "timeout_secs": {
                "type": "integer",
                "description": "Request timeout in seconds; clamped to 30s maximum",
                "default": 10
              },
              "auth_secret_key": {
                "type": "string",
                "description": "Optional secret store key for Bearer token auth",
                "default": ""
              }
            },
            "required": ["url"]
          },
          "default": {}
        }
      }
    }
  }
}"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_points_at_the_real_hub_with_no_active_community() {
        let cfg = ModuleConfig::default();
        assert_eq!(cfg.hub.base_url, waddles_client::config::DEFAULT_BASE_URL);
        assert!(cfg.community_id.is_empty());
        assert!(!cfg.bridge.enabled);
        assert!(cfg.bridge.listen_tcp.is_empty());
        assert!(cfg.bridge.listen_unix.is_empty());
        assert!(cfg.bridge.allowed_integrations.is_empty());
    }

    #[test]
    fn empty_document_deserializes_to_the_full_default() {
        let cfg: ModuleConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg, ModuleConfig::default());
    }

    #[test]
    fn partial_document_only_overrides_what_it_names() {
        let yaml = "community_id: \"11111111-1111-4111-8111-111111111111\"\n";
        let cfg: ModuleConfig = serde_norway::from_str(yaml).unwrap();
        assert_eq!(cfg.community_id, "11111111-1111-4111-8111-111111111111");
        assert_eq!(cfg.hub.base_url, waddles_client::config::DEFAULT_BASE_URL);
        assert!(!cfg.bridge.enabled);
    }

    #[test]
    fn bridge_section_round_trips_through_yaml() {
        let yaml = "bridge:\n  enabled: true\n  listen_tcp: \"127.0.0.1:9700\"\n  allowed_integrations: [\"twitch\", \"discord\"]\n";
        let cfg: ModuleConfig = serde_norway::from_str(yaml).unwrap();
        assert!(cfg.bridge.enabled);
        assert_eq!(cfg.bridge.listen_tcp, "127.0.0.1:9700");
        assert_eq!(
            cfg.bridge.allowed_integrations,
            vec!["twitch".to_string(), "discord".to_string()]
        );
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

    /// The advertised schema default must match what the code actually
    /// applies — squawk shipped a schema promising one DoH default while
    /// its code applied another; not repeating that here.
    #[test]
    fn schema_default_for_hub_base_url_matches_the_code_default() {
        let schema: serde_json::Value = serde_json::from_str(CONFIG_SCHEMA).unwrap();
        let advertised = schema["properties"]["hub"]["properties"]["base_url"]["default"]
            .as_str()
            .unwrap();
        assert_eq!(advertised, ModuleConfig::default().hub.base_url);
        assert_eq!(advertised, waddles_client::config::DEFAULT_BASE_URL);
    }

    #[test]
    fn schema_default_for_bridge_enabled_matches_the_code_default() {
        let schema: serde_json::Value = serde_json::from_str(CONFIG_SCHEMA).unwrap();
        let advertised = schema["properties"]["bridge"]["properties"]["enabled"]["default"]
            .as_bool()
            .unwrap();
        assert_eq!(advertised, ModuleConfig::default().bridge.enabled);
    }

    #[test]
    fn schema_default_for_obs_config_matches_the_code_default() {
        let schema: serde_json::Value = serde_json::from_str(CONFIG_SCHEMA).unwrap();
        let obs_schema = &schema["properties"]["bridge"]["properties"]["obs"]["properties"];

        let enabled_advertised = obs_schema["enabled"]["default"].as_bool().unwrap();
        assert_eq!(
            enabled_advertised,
            ModuleConfig::default().bridge.obs.enabled
        );

        let url_advertised = obs_schema["url"]["default"].as_str().unwrap();
        assert_eq!(url_advertised, ModuleConfig::default().bridge.obs.url);

        let secret_key_advertised = obs_schema["secret_key"]["default"].as_str().unwrap();
        assert_eq!(
            secret_key_advertised,
            ModuleConfig::default().bridge.obs.secret_key
        );

        let allowed_commands_advertised = obs_schema["allowed_commands"]["default"]
            .as_array()
            .unwrap();
        assert_eq!(
            allowed_commands_advertised.len(),
            ModuleConfig::default().bridge.obs.allowed_commands.len()
        );

        let allowed_scenes_advertised = obs_schema["allowed_scenes"]["default"].as_array().unwrap();
        assert_eq!(
            allowed_scenes_advertised.len(),
            ModuleConfig::default().bridge.obs.allowed_scenes.len()
        );
    }

    #[test]
    fn schema_default_for_webhooks_matches_the_code_default() {
        let schema: serde_json::Value = serde_json::from_str(CONFIG_SCHEMA).unwrap();
        let webhooks_advertised =
            schema["properties"]["bridge"]["properties"]["webhooks"]["default"]
                .as_object()
                .unwrap();
        assert_eq!(
            webhooks_advertised.len(),
            ModuleConfig::default().bridge.webhooks.len()
        );
    }

    #[test]
    fn schema_default_for_webhook_target_matches_the_code_default() {
        let schema: serde_json::Value = serde_json::from_str(CONFIG_SCHEMA).unwrap();
        let webhook_props = &schema["properties"]["bridge"]["properties"]["webhooks"]["additionalProperties"]
            ["properties"];

        let timeout_advertised = webhook_props["timeout_secs"]["default"].as_u64().unwrap();
        assert_eq!(
            timeout_advertised,
            WebhookTarget::default().timeout_secs as u64
        );

        let auth_secret_advertised = webhook_props["auth_secret_key"]["default"]
            .as_str()
            .unwrap();
        assert_eq!(
            auth_secret_advertised,
            WebhookTarget::default().auth_secret_key
        );
    }
}
