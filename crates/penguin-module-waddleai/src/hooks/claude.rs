//! Claude Code / Cortex hook shim: merges WaddleAI's `PreToolUse`/
//! `PostToolUse` entries into `~/.claude/settings.json`.
//!
//! Schema matches Claude Code's documented hooks format: `hooks.<EventName>`
//! is an array of matcher groups, each with its own `hooks` array of
//! `{"type": "command", "command": "..."}` entries. This shim only ever
//! touches matcher groups it identifies as its own (see
//! [`is_waddleai_group`]) — every other group, added by the user or another
//! tool, is left byte-for-byte alone within the merge (uninstall's
//! byte-for-byte restore, see `super::backup`, covers the rest of the
//! file).

use std::path::PathBuf;

use serde_json::{Map, Value, json};

use super::{Ecosystem, HOOK_EVENTS, Shim, ShimError, guarded_hook_command, is_hook_command};

/// Maps this crate's canonical event id (`super::HOOK_EVENTS`) to Claude
/// Code's own `PascalCase` event name.
fn claude_event_name(event: &str) -> &'static str {
    match event {
        "pre_tool_use" => "PreToolUse",
        "post_tool_use" => "PostToolUse",
        "session_start" => "SessionStart",
        "notification" => "Notification",
        other => {
            unreachable!("unknown hook event {other:?}; HOOK_EVENTS drifted from claude_event_name")
        }
    }
}

/// Installs into `~/.claude/settings.json` (or a caller-supplied path in
/// tests).
pub struct ClaudeShim {
    override_path: Option<PathBuf>,
}

impl ClaudeShim {
    /// The real, production shim: resolves the current user's home
    /// directory at [`Shim::target_path`] time.
    pub fn new() -> ClaudeShim {
        ClaudeShim {
            override_path: None,
        }
    }

    /// A shim pointed at a fixed path, for tests that must never touch a
    /// real home directory.
    pub fn with_target(path: PathBuf) -> ClaudeShim {
        ClaudeShim {
            override_path: Some(path),
        }
    }
}

impl Default for ClaudeShim {
    fn default() -> ClaudeShim {
        ClaudeShim::new()
    }
}

impl Shim for ClaudeShim {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Claude
    }

    fn target_path(&self) -> Result<PathBuf, ShimError> {
        if let Some(path) = &self.override_path {
            return Ok(path.clone());
        }
        let home = dirs::home_dir().ok_or(ShimError::NoHomeDir)?;
        Ok(home.join(".claude").join("settings.json"))
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
            .or_insert_with(|| Value::Object(Map::new()));
        if !hooks_value.is_object() {
            *hooks_value = Value::Object(Map::new());
        }
        // Just normalized above to `Value::Object` on every path —
        // infallible.
        let hooks_object = hooks_value
            .as_object_mut()
            .expect("hooks_value was just normalized to an object");

        for event in HOOK_EVENTS {
            let event_name = claude_event_name(event);
            let command = guarded_hook_command(event);

            let array_value = hooks_object
                .entry(event_name)
                .or_insert_with(|| Value::Array(Vec::new()));
            if !array_value.is_array() {
                *array_value = Value::Array(Vec::new());
            }
            // Just normalized above to `Value::Array` on every path —
            // infallible.
            let array = array_value
                .as_array_mut()
                .expect("array_value was just normalized to an array");

            // Idempotent: drop any matcher group this shim previously
            // added, then push one canonical, current entry. Every other
            // matcher group (the user's own, or another tool's) is left
            // untouched.
            array.retain(|group| !is_waddleai_group(group));
            array.push(json!({
                "matcher": "*",
                "hooks": [{"type": "command", "command": command}],
            }));
        }
    }
}

/// Whether `group` (one entry of a `PreToolUse`/`PostToolUse` array) is a
/// matcher group this shim added: its inner `hooks` array contains a
/// command this crate registered (see [`is_hook_command`]).
fn is_waddleai_group(group: &Value) -> bool {
    group
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|inner| {
            inner.iter().any(|entry| {
                entry
                    .get("command")
                    .and_then(Value::as_str)
                    .is_some_and(is_hook_command)
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_path_defaults_to_the_real_home_directory() {
        let shim = ClaudeShim::new();
        let path = shim
            .target_path()
            .expect("home dir resolves in this test env");
        assert!(path.ends_with(".claude/settings.json"));
    }

    #[test]
    fn with_target_overrides_the_default_path() {
        let shim = ClaudeShim::with_target(PathBuf::from("/tmp/fixed/settings.json"));
        assert_eq!(
            shim.target_path().unwrap(),
            PathBuf::from("/tmp/fixed/settings.json")
        );
    }

    #[test]
    fn merge_adds_all_events_to_an_empty_document() {
        let shim = ClaudeShim::with_target(PathBuf::new());
        let mut document = json!({});
        shim.merge(&mut document);

        let pre = &document["hooks"]["PreToolUse"];
        assert_eq!(pre[0]["matcher"], "*");
        assert_eq!(
            pre[0]["hooks"][0]["command"],
            guarded_hook_command("pre_tool_use")
        );
        let post = &document["hooks"]["PostToolUse"];
        assert_eq!(
            post[0]["hooks"][0]["command"],
            guarded_hook_command("post_tool_use")
        );
        let session = &document["hooks"]["SessionStart"];
        assert_eq!(
            session[0]["hooks"][0]["command"],
            guarded_hook_command("session_start")
        );
        let notif = &document["hooks"]["Notification"];
        assert_eq!(
            notif[0]["hooks"][0]["command"],
            guarded_hook_command("notification")
        );
    }

    #[test]
    fn registered_command_is_guarded_with_pdcli_so_a_missing_binary_is_a_no_op() {
        let command = guarded_hook_command("pre_tool_use");
        assert!(
            command.starts_with("command -v pdcli >/dev/null 2>&1 &&"),
            "must probe for pdcli before invoking it: {command}"
        );
        assert!(
            command.ends_with("|| true"),
            "a failing hook must not surface as an error: {command}"
        );
        assert!(command.contains(super::super::HOOK_COMMAND));
    }

    #[test]
    fn merge_upgrades_a_legacy_unguarded_entry_instead_of_duplicating_it() {
        // Anyone who installed before the guard / pdcli rename landed has
        // the bare `penguin waddleai hook` command sitting in settings.json.
        let shim = ClaudeShim::with_target(PathBuf::new());
        let mut document = json!({
            "hooks": {
                "PreToolUse": [
                    {"matcher": "*", "hooks": [
                        {"type": "command", "command": "penguin waddleai hook pre-tool-use"}
                    ]}
                ]
            }
        });
        shim.merge(&mut document);

        let pre = document["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(
            pre.len(),
            1,
            "legacy entry replaced, not duplicated: {pre:?}"
        );
        assert_eq!(
            pre[0]["hooks"][0]["command"],
            guarded_hook_command("pre_tool_use")
        );
    }

    #[test]
    fn merge_preserves_an_unrelated_existing_matcher_group() {
        let shim = ClaudeShim::with_target(PathBuf::new());
        let mut document = json!({
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "some-other-tool run"}]}
                ]
            },
            "editor.fontSize": 14,
        });
        shim.merge(&mut document);

        let pre = document["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2, "the unrelated group is kept, ours is added");
        assert_eq!(pre[0]["matcher"], "Bash");
        assert_eq!(document["editor.fontSize"], 14);
    }

    #[test]
    fn merge_is_idempotent() {
        let shim = ClaudeShim::with_target(PathBuf::new());
        let mut document = json!({});
        shim.merge(&mut document);
        shim.merge(&mut document);

        let pre = document["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(
            pre.len(),
            1,
            "merging twice must not duplicate our own group"
        );
    }

    #[test]
    fn merge_normalizes_a_non_object_hooks_value_instead_of_panicking() {
        let shim = ClaudeShim::with_target(PathBuf::new());
        let mut document = json!({"hooks": "not an object"});
        shim.merge(&mut document);
        assert!(document["hooks"]["PreToolUse"].is_array());
    }

    #[test]
    fn merge_normalizes_a_non_array_event_value_instead_of_panicking() {
        let shim = ClaudeShim::with_target(PathBuf::new());
        let mut document = json!({"hooks": {"PreToolUse": "not an array"}});
        shim.merge(&mut document);
        assert_eq!(document["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }
}
