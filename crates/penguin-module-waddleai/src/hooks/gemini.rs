//! Google Antigravity / AGY CLI hook shim: merges WaddleAI's entries into
//! `~/.gemini/config/hooks.json`.
//!
//! This ecosystem's hooks schema is less publicly documented than Claude
//! Code's; this shim uses the straightforward shape the brief describes —
//! a flat `hooks` array of `{"id", "event", "command"}` objects — as its
//! best-known contract. A workspace-scoped `.agents/hooks.json` variant is
//! deliberately out of scope for this track (see this crate's top-level
//! doc): this installer only manages the user-level, global config, since a
//! desktop installer has no single "current workspace" to scope a
//! project-level file to.

use std::path::PathBuf;

use serde_json::{Value, json};

use super::{Ecosystem, HOOK_EVENTS, Shim, ShimError, guarded_hook_command};

/// The id prefix every entry this shim adds carries, and the sole signal
/// [`merge`](Shim::merge) uses to recognise (and replace) its own entries —
/// see that method's doc.
const ID_PREFIX: &str = "waddleai-";

/// Installs into `~/.gemini/config/hooks.json` (or a caller-supplied path
/// in tests).
pub struct GeminiShim {
    override_path: Option<PathBuf>,
}

impl GeminiShim {
    /// The real, production shim: resolves the current user's home
    /// directory at [`Shim::target_path`] time.
    pub fn new() -> GeminiShim {
        GeminiShim {
            override_path: None,
        }
    }

    /// A shim pointed at a fixed path, for tests that must never touch a
    /// real home directory.
    pub fn with_target(path: PathBuf) -> GeminiShim {
        GeminiShim {
            override_path: Some(path),
        }
    }
}

impl Default for GeminiShim {
    fn default() -> GeminiShim {
        GeminiShim::new()
    }
}

impl Shim for GeminiShim {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Gemini
    }

    fn target_path(&self) -> Result<PathBuf, ShimError> {
        if let Some(path) = &self.override_path {
            return Ok(path.clone());
        }
        let home = dirs::home_dir().ok_or(ShimError::NoHomeDir)?;
        Ok(home.join(".gemini").join("config").join("hooks.json"))
    }

    fn merge(&self, document: &mut Value) {
        // `install`'s contract (see `super::read_document`) guarantees
        // `document` is always a JSON object before `merge` ever runs —
        // provably infallible here, not a real runtime condition.
        let root = document
            .as_object_mut()
            .expect("Shim::merge contract: document is always a JSON object");

        let hooks_value = root
            .entry("hooks")
            .or_insert_with(|| Value::Array(Vec::new()));
        if !hooks_value.is_array() {
            *hooks_value = Value::Array(Vec::new());
        }
        // Just normalized above to `Value::Array` on every path —
        // infallible.
        let hooks_array = hooks_value
            .as_array_mut()
            .expect("hooks_value was just normalized to an array");

        // Idempotent: drop every entry this shim previously added (matched
        // by `id` prefix), then push one canonical, current entry per
        // event. Every other entry — added by the user or another tool —
        // is left untouched.
        hooks_array.retain(|entry| !is_waddleai_entry(entry));
        for event in HOOK_EVENTS {
            hooks_array.push(json!({
                "id": format!("{ID_PREFIX}{event}"),
                "event": event,
                "command": guarded_hook_command(event),
            }));
        }
    }
}

fn is_waddleai_entry(entry: &Value) -> bool {
    entry
        .get("id")
        .and_then(Value::as_str)
        .is_some_and(|id| id.starts_with(ID_PREFIX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_path_defaults_to_the_real_home_directory() {
        let shim = GeminiShim::new();
        let path = shim
            .target_path()
            .expect("home dir resolves in this test env");
        assert!(path.ends_with(".gemini/config/hooks.json"));
    }

    #[test]
    fn merge_adds_an_entry_per_hook_event() {
        let shim = GeminiShim::with_target(PathBuf::new());
        let mut document = json!({});
        shim.merge(&mut document);

        let hooks = document["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), HOOK_EVENTS.len());
        assert!(hooks.iter().any(|entry| entry["event"] == "pre_tool_use"));
        assert!(hooks.iter().any(|entry| entry["event"] == "post_tool_use"));
        assert!(hooks.iter().any(|entry| entry["event"] == "session_start"));
        assert!(hooks.iter().any(|entry| entry["event"] == "notification"));
    }

    #[test]
    fn merge_preserves_an_unrelated_existing_entry() {
        let shim = GeminiShim::with_target(PathBuf::new());
        let mut document = json!({
            "hooks": [{"id": "some-other-tool", "event": "pre_tool_use", "command": "other"}],
            "logLevel": "info",
        });
        shim.merge(&mut document);

        let hooks = document["hooks"].as_array().unwrap();
        assert!(hooks.iter().any(|entry| entry["id"] == "some-other-tool"));
        assert_eq!(hooks.len(), 1 + HOOK_EVENTS.len());
        assert_eq!(document["logLevel"], "info");
    }

    #[test]
    fn merge_is_idempotent() {
        let shim = GeminiShim::with_target(PathBuf::new());
        let mut document = json!({});
        shim.merge(&mut document);
        shim.merge(&mut document);

        let hooks = document["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), HOOK_EVENTS.len());
    }

    #[test]
    fn merge_normalizes_a_non_array_hooks_value_instead_of_panicking() {
        let shim = GeminiShim::with_target(PathBuf::new());
        let mut document = json!({"hooks": {"not": "an array"}});
        shim.merge(&mut document);
        assert_eq!(
            document["hooks"].as_array().unwrap().len(),
            HOOK_EVENTS.len()
        );
    }
}
