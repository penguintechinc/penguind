//! Per-ecosystem hook shim installation: merges a WaddleAI hook entry into
//! an editor/agent's own JSON config file, and — on uninstall — restores
//! that file to its exact pre-install bytes.
//!
//! # Why byte-for-byte restore, not JSON-diff removal
//!
//! `~/.claude/settings.json`, `~/.gemini/config/hooks.json`, and VS Code's
//! `settings.json` are user-owned files that certainly carry unrelated
//! content already — other hooks, editor preferences, extension settings.
//! The safest uninstall this crate can offer is not "parse the file again
//! and delete our entry" (which re-serializes the *whole* file through
//! `serde_json` and so can reformat or reorder content this crate never
//! touched) but "put back the exact bytes that were there before install
//! ever touched the file" — [`backup::snapshot`] records those bytes (or
//! "the file did not exist") before the first write, and [`uninstall`]
//! replays them verbatim. See [`backup`]'s doc for the on-disk format.
//!
//! Every write goes through [`fsutil::write_atomic`] (or, for uninstall's
//! restore, the same primitive used indirectly via [`std::fs::write`] only
//! after the atomic rename path fails to apply — see [`uninstall`]): a temp
//! file in the same directory, then a rename, so a reader (the editor, the
//! agent process) never observes a half-written config.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

pub mod claude;
pub mod gemini;
pub mod vscode;

mod backup;

/// The hook events every ecosystem shim wires up, matching
/// `waddleai/services/management/app/api/v1/hooks.py` (`HOOK_EVENTS`).
pub const HOOK_EVENTS: [&str; 4] = [
    "pre_tool_use",
    "post_tool_use",
    "session_start",
    "notification",
];

/// Normalizes a CLI or stdin event name (supporting both canonical
/// snake_case and legacy hyphenated aliases) to the wire format expected by
/// WaddleAI (`HOOK_EVENTS`).
pub fn normalize_event(event: &str) -> Option<&'static str> {
    match event {
        "pre_tool_use" | "pre-tool-use" => Some("pre_tool_use"),
        "post_tool_use" | "post-tool-use" => Some("post_tool_use"),
        "session_start" | "session-start" => Some("session_start"),
        "notification" => Some("notification"),
        _ => None,
    }
}

/// Whether `event` is a telemetry-only event routed to
/// `POST /api/v1/hooks/telemetry` rather than `POST /api/v1/hooks/evaluate`.
pub fn is_telemetry_event(event: &str) -> bool {
    matches!(event, "post_tool_use" | "session_start" | "notification")
}

/// The CLI binary name invoked by installed hook shims.
pub const CLI_BINARY: &str = "pdcli";

/// The base CLI invocation every shim registers; each ecosystem module
/// appends one of [`HOOK_EVENTS`]. Matches `crate::commands`'s `hook`
/// subcommand.
pub const HOOK_COMMAND: &str = "pdcli waddleai hook";

/// Legacy CLI invocation prior to the `penguin` -> `pdcli` binary rename;
/// recognized by [`is_hook_command`] so re-installing upgrades old shims
/// cleanly without duplicating entries.
const LEGACY_HOOK_COMMAND: &str = "penguin waddleai hook";

/// Builds the shell command a shim actually registers for `event`.
///
/// Wrapped in a `command -v` guard so the hook degrades to a silent no-op
/// when the `pdcli` binary is absent.
pub fn guarded_hook_command(event: &str) -> String {
    build_guarded_command(CLI_BINARY, &format!("{HOOK_COMMAND} {event}"))
}

/// Builds `command -v {probe} >/dev/null 2>&1 && exec {command} || true`.
///
/// Split out from [`guarded_hook_command`] purely so tests can substitute a
/// controllable `probe`/`command` pair for the real `penguin` binary and
/// [`HOOK_COMMAND`], and assert on the resulting exit code without depending
/// on `penguin` actually being installed in the test environment.
fn build_guarded_command(probe: &str, command: &str) -> String {
    format!("command -v {probe} >/dev/null 2>&1 && exec {command} || true")
}

/// Whether `command` is one this crate registered, in either the current
/// (`pdcli`), legacy (`penguin`), bare, or guarded form.
pub fn is_hook_command(command: &str) -> bool {
    command.contains(HOOK_COMMAND) || command.contains(LEGACY_HOOK_COMMAND)
}

/// One ecosystem this crate can install a hook shim for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    /// Claude Code: `~/.claude/settings.json`.
    Claude,
    /// Cortex: `~/.claude/settings.json`.
    Cortex,
    /// Google Antigravity / AGY CLI: `~/.gemini/config/hooks.json`.
    Gemini,
    /// VS Code: the user `settings.json`.
    VsCode,
}

impl Ecosystem {
    /// The canonical WaddleAI wire identifier (`HOOK_ECOSYSTEMS` in
    /// `waddleai/services/management/app/api/v1/hooks.py`).
    pub fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Claude => "claude-code",
            Ecosystem::Cortex => "cortex",
            Ecosystem::Gemini => "antigravity",
            Ecosystem::VsCode => "vscode",
        }
    }

    /// Parses canonical wire names (`claude-code`, `cortex`, `antigravity`,
    /// `vscode`) as well as legacy CLI aliases (`claude`, `gemini`).
    pub fn parse(value: &str) -> Option<Ecosystem> {
        match value {
            "claude-code" | "claude" => Some(Ecosystem::Claude),
            "cortex" => Some(Ecosystem::Cortex),
            "antigravity" | "gemini" => Some(Ecosystem::Gemini),
            "vscode" => Some(Ecosystem::VsCode),
            _ => None,
        }
    }

    /// Every known ecosystem, in a fixed display order.
    pub fn all() -> [Ecosystem; 4] {
        [
            Ecosystem::Claude,
            Ecosystem::Cortex,
            Ecosystem::Gemini,
            Ecosystem::VsCode,
        ]
    }
}

/// Everything ecosystem-specific about installing a hook shim: where its
/// config file lives, and how to merge this module's entry into it.
/// [`claude::ClaudeShim`], [`gemini::GeminiShim`], and [`vscode::VsCodeShim`]
/// each implement this against their own real file shape.
pub trait Shim {
    /// Which ecosystem this is — used for backup file naming and reports.
    fn ecosystem(&self) -> Ecosystem;

    /// The absolute path to the config file this shim installs into.
    fn target_path(&self) -> Result<PathBuf, ShimError>;

    /// Merges this module's hook entry into `document` (parsed from the
    /// target file, or an empty object if the file did not exist / was
    /// empty). Must be idempotent: merging twice produces the same result
    /// as merging once, so repeated `install` calls (e.g. after an
    /// operator re-runs it, or a version bump changes the merged command)
    /// never accumulate duplicate entries.
    fn merge(&self, document: &mut Value);
}

/// Everything that can go wrong installing, uninstalling, or reporting on a
/// [`Shim`].
#[derive(Debug, thiserror::Error)]
pub enum ShimError {
    /// The platform's home directory couldn't be resolved.
    #[error("could not resolve the user's home directory")]
    NoHomeDir,
    /// The platform's user config directory couldn't be resolved.
    #[error("could not resolve the user's config directory")]
    NoConfigDir,
    /// The target file's top-level JSON value is not an object, so merging
    /// a keyed entry into it is undefined — refusing rather than guessing
    /// how to coerce it.
    #[error("{0}: top-level JSON value is not an object")]
    NotAnObject(PathBuf),
    /// The target file exists but isn't valid JSON.
    #[error("{path}: invalid JSON: {source}")]
    InvalidJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    /// A filesystem operation failed.
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// [`uninstall`] was called for an ecosystem with no recorded install.
    #[error("{0}: not installed")]
    NotInstalled(String),
}

/// The result of one [`install`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    /// The config file that was written.
    pub target_path: PathBuf,
    /// `true` if this call took a fresh backup (a genuinely new install);
    /// `false` if a backup already existed and only the merge was
    /// refreshed.
    pub freshly_installed: bool,
}

/// The result of one [`uninstall`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallReport {
    /// The config file that was restored (or removed, if it did not exist
    /// before install).
    pub target_path: PathBuf,
}

/// Whether a shim is currently installed, per [`backup_dir`]'s records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimStatus {
    pub ecosystem: Ecosystem,
    pub target_path: PathBuf,
    pub installed: bool,
}

/// Installs `shim`: takes a byte-for-byte backup of its target file on the
/// first call only (see [`backup::snapshot`]), then merges
/// [`Shim::merge`]'s entry into the (possibly freshly-created) document and
/// writes it back atomically.
pub fn install(backup_dir: &Path, shim: &dyn Shim) -> Result<InstallReport, ShimError> {
    let target = shim.target_path()?;
    let ecosystem = shim.ecosystem().as_str();
    let freshly_installed = !backup::exists(backup_dir, ecosystem);

    backup::snapshot(backup_dir, ecosystem, &target).map_err(|source| ShimError::Io {
        path: target.clone(),
        source,
    })?;

    let mut document = read_document(&target)?;
    shim.merge(&mut document);
    write_document(&target, &document)?;

    Ok(InstallReport {
        target_path: target,
        freshly_installed,
    })
}

/// Uninstalls `shim`: restores its target file to the exact bytes
/// [`install`] backed up (or removes the file entirely, if it did not exist
/// before install), then clears the backup. Errors with
/// [`ShimError::NotInstalled`] if no backup is on record — this crate
/// refuses to guess at removing an entry it has no proof it ever added.
pub fn uninstall(backup_dir: &Path, shim: &dyn Shim) -> Result<UninstallReport, ShimError> {
    let target = shim.target_path()?;
    let ecosystem = shim.ecosystem().as_str();

    let loaded = backup::load(backup_dir, ecosystem).map_err(|source| ShimError::Io {
        path: target.clone(),
        source,
    })?;
    let Some(backup) = loaded else {
        return Err(ShimError::NotInstalled(ecosystem.to_string()));
    };

    match backup.original {
        Some(bytes) => {
            crate::fsutil::write_atomic(&target, &bytes).map_err(|source| ShimError::Io {
                path: target.clone(),
                source,
            })?;
        }
        None => remove_if_present(&target)?,
    }

    backup::clear(backup_dir, ecosystem).map_err(|source| ShimError::Io {
        path: target.clone(),
        source,
    })?;

    Ok(UninstallReport {
        target_path: target,
    })
}

/// Reports whether `shim` is currently installed.
pub fn status(backup_dir: &Path, shim: &dyn Shim) -> Result<ShimStatus, ShimError> {
    let target = shim.target_path()?;
    Ok(ShimStatus {
        ecosystem: shim.ecosystem(),
        installed: backup::exists(backup_dir, shim.ecosystem().as_str()),
        target_path: target,
    })
}

/// Reads `path` as a JSON object, treating a missing or empty file as an
/// empty object (the state a brand-new config file starts from).
fn read_document(path: &Path) -> Result<Value, ShimError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Value::Object(Map::new()));
        }
        Err(source) => {
            return Err(ShimError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if bytes.is_empty() {
        return Ok(Value::Object(Map::new()));
    }

    let document: Value =
        serde_json::from_slice(&bytes).map_err(|source| ShimError::InvalidJson {
            path: path.to_path_buf(),
            source,
        })?;
    if !document.is_object() {
        return Err(ShimError::NotAnObject(path.to_path_buf()));
    }
    Ok(document)
}

/// Pretty-prints `document` and writes it to `path` atomically.
fn write_document(path: &Path, document: &Value) -> Result<(), ShimError> {
    let mut bytes = serde_json::to_vec_pretty(document).map_err(|err| ShimError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, err),
    })?;
    bytes.push(b'\n');
    crate::fsutil::write_atomic(path, &bytes).map_err(|source| ShimError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn remove_if_present(path: &Path) -> Result<(), ShimError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ShimError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test-only [`Shim`] with a caller-supplied fixed target path, so
    /// these tests exercise the merge/backup/restore engine without
    /// touching a real home directory.
    struct FixedShim {
        target: PathBuf,
        marker: &'static str,
    }

    impl Shim for FixedShim {
        fn ecosystem(&self) -> Ecosystem {
            Ecosystem::Claude
        }

        fn target_path(&self) -> Result<PathBuf, ShimError> {
            Ok(self.target.clone())
        }

        fn merge(&self, document: &mut Value) {
            let object = document.as_object_mut().expect("document is an object");
            object.insert(self.marker.to_string(), Value::Bool(true));
        }
    }

    #[test]
    fn ecosystem_round_trips_and_accepts_legacy_aliases() {
        for eco in Ecosystem::all() {
            assert_eq!(Ecosystem::parse(eco.as_str()), Some(eco));
        }
        assert_eq!(Ecosystem::parse("claude"), Some(Ecosystem::Claude));
        assert_eq!(Ecosystem::parse("gemini"), Some(Ecosystem::Gemini));
        assert_eq!(Ecosystem::parse("bogus"), None);
    }

    #[test]
    fn normalize_event_accepts_canonical_and_hyphenated_aliases() {
        assert_eq!(normalize_event("pre_tool_use"), Some("pre_tool_use"));
        assert_eq!(normalize_event("pre-tool-use"), Some("pre_tool_use"));
        assert_eq!(normalize_event("post_tool_use"), Some("post_tool_use"));
        assert_eq!(normalize_event("post-tool-use"), Some("post_tool_use"));
        assert_eq!(normalize_event("session_start"), Some("session_start"));
        assert_eq!(normalize_event("session-start"), Some("session_start"));
        assert_eq!(normalize_event("notification"), Some("notification"));
        assert_eq!(normalize_event("unknown"), None);
    }

    /// The whole point of [`guarded_hook_command`]'s `exec` (see its doc):
    /// once the probe succeeds, the hook's own exit code -- allow, deny, or
    /// unavailable -- must reach the calling ecosystem unmodified, because
    /// that exit code is the actual enforcement mechanism. Uses `true`/
    /// `false`/a nested `sh -c` in place of `penguin`/[`HOOK_COMMAND`] so
    /// this doesn't depend on `penguin` actually being on the test
    /// environment's PATH.
    #[test]
    fn guarded_command_propagates_the_hook_s_real_exit_code_when_the_probe_is_present() {
        let cases: [(&str, &str, i32); 3] = [
            ("allow", "true", 0),
            ("deny", "false", 1),
            ("unavailable", "sh -c 'exit 2'", 2),
        ];
        for (label, hook, want) in cases {
            let shell = build_guarded_command("true", hook);
            let status = std::process::Command::new("sh")
                .arg("-c")
                .arg(&shell)
                .status()
                .expect("sh spawns");
            assert_eq!(
                status.code(),
                Some(want),
                "{label}: guarded command {shell:?} did not propagate the hook's exit code"
            );
        }
    }

    /// The one case that must NOT propagate as a block: the probe binary
    /// itself isn't reachable (a PATH gap, not a policy decision), so the
    /// guard must fail open regardless of what the never-invoked hook
    /// command would have returned.
    #[test]
    fn guarded_command_does_not_block_when_the_probe_binary_is_absent() {
        let shell = build_guarded_command("definitely-not-a-real-binary-xyz", "false");
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(&shell)
            .status()
            .expect("sh spawns");
        assert_eq!(
            status.code(),
            Some(0),
            "a missing probe binary must degrade to a silent allow: {shell:?}"
        );
    }

    /// [`guarded_hook_command`] itself (not just the lower-level helper)
    /// must retain the shape exit-code propagation depends on: `exec`
    /// directly into the real hook invocation, with nothing wrapping it in
    /// a subshell that would mask its exit status.
    #[test]
    fn guarded_hook_command_execs_directly_into_the_hook_invocation() {
        let command = guarded_hook_command("pre-tool-use");
        assert!(
            command.contains(&format!("&& exec {HOOK_COMMAND} pre-tool-use")),
            "must exec directly into the hook command, not wrap it: {command}"
        );
    }

    #[test]
    fn install_on_a_missing_file_creates_it_with_only_the_merged_entry() {
        let dir = tempfile::tempdir().unwrap();
        let backup_dir = dir.path().join("backups");
        let target = dir.path().join("settings.json");
        let shim = FixedShim {
            target: target.clone(),
            marker: "waddleai",
        };

        let report = install(&backup_dir, &shim).expect("install succeeds");
        assert!(report.freshly_installed);
        assert_eq!(report.target_path, target);

        let written: Value = serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(written, serde_json::json!({"waddleai": true}));
    }

    /// The literal scenario from this track's brief: a settings file with
    /// pre-existing unrelated keys must keep them after install, and
    /// uninstall must restore the file byte-for-byte.
    #[test]
    fn install_merges_into_a_file_with_unrelated_keys_and_uninstall_restores_it_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let backup_dir = dir.path().join("backups");
        let target = dir.path().join("settings.json");
        let original_bytes =
            b"{\n  \"editor.fontSize\": 14,\n  \"someOtherTool\": {\"enabled\": true}\n}\n";
        std::fs::write(&target, original_bytes).unwrap();
        let shim = FixedShim {
            target: target.clone(),
            marker: "waddleai",
        };

        install(&backup_dir, &shim).expect("install succeeds");

        let merged: Value = serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(merged["editor.fontSize"], 14);
        assert_eq!(merged["someOtherTool"]["enabled"], true);
        assert_eq!(merged["waddleai"], true);

        uninstall(&backup_dir, &shim).expect("uninstall succeeds");

        let restored = std::fs::read(&target).unwrap();
        assert_eq!(
            restored, original_bytes,
            "uninstall must restore the exact original bytes"
        );
    }

    #[test]
    fn install_is_idempotent_and_does_not_duplicate_the_merged_entry() {
        let dir = tempfile::tempdir().unwrap();
        let backup_dir = dir.path().join("backups");
        let target = dir.path().join("settings.json");
        let shim = FixedShim {
            target: target.clone(),
            marker: "waddleai",
        };

        let first = install(&backup_dir, &shim).unwrap();
        let second = install(&backup_dir, &shim).unwrap();
        assert!(first.freshly_installed);
        assert!(
            !second.freshly_installed,
            "a second install reuses the existing backup"
        );

        let written: Value = serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(written, serde_json::json!({"waddleai": true}));
    }

    #[test]
    fn uninstall_of_a_never_installed_file_did_not_exist_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let backup_dir = dir.path().join("backups");
        let target = dir.path().join("settings.json");
        let shim = FixedShim {
            target: target.clone(),
            marker: "waddleai",
        };

        install(&backup_dir, &shim).expect("install succeeds");
        assert!(target.exists());

        uninstall(&backup_dir, &shim).expect("uninstall succeeds");
        assert!(
            !target.exists(),
            "a file WaddleAI created must be removed, not left empty"
        );
    }

    #[test]
    fn uninstall_without_a_prior_install_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let backup_dir = dir.path().join("backups");
        let target = dir.path().join("settings.json");
        let shim = FixedShim {
            target,
            marker: "waddleai",
        };

        let err = uninstall(&backup_dir, &shim).expect_err("must fail with no backup on record");
        assert!(matches!(err, ShimError::NotInstalled(_)));
    }

    #[test]
    fn status_reports_installed_only_after_install_and_not_after_uninstall() {
        let dir = tempfile::tempdir().unwrap();
        let backup_dir = dir.path().join("backups");
        let target = dir.path().join("settings.json");
        let shim = FixedShim {
            target,
            marker: "waddleai",
        };

        assert!(!status(&backup_dir, &shim).unwrap().installed);
        install(&backup_dir, &shim).unwrap();
        assert!(status(&backup_dir, &shim).unwrap().installed);
        uninstall(&backup_dir, &shim).unwrap();
        assert!(!status(&backup_dir, &shim).unwrap().installed);
    }

    #[test]
    fn install_rejects_a_target_whose_top_level_value_is_not_an_object() {
        let dir = tempfile::tempdir().unwrap();
        let backup_dir = dir.path().join("backups");
        let target = dir.path().join("settings.json");
        std::fs::write(&target, b"[1, 2, 3]").unwrap();
        let shim = FixedShim {
            target,
            marker: "waddleai",
        };

        let err = install(&backup_dir, &shim).expect_err("a top-level array must be rejected");
        assert!(matches!(err, ShimError::NotAnObject(_)));
    }

    #[test]
    fn install_rejects_invalid_json_rather_than_clobbering_it() {
        let dir = tempfile::tempdir().unwrap();
        let backup_dir = dir.path().join("backups");
        let target = dir.path().join("settings.json");
        std::fs::write(&target, b"{ not valid json").unwrap();
        let shim = FixedShim {
            target,
            marker: "waddleai",
        };

        let err = install(&backup_dir, &shim).expect_err("malformed JSON must be rejected");
        assert!(matches!(err, ShimError::InvalidJson { .. }));
    }

    /// Concurrency smoke test: several ecosystems installing into the same
    /// `backup_dir` must not collide on each other's backup files.
    #[test]
    fn multiple_ecosystems_keep_independent_backups() {
        let dir = tempfile::tempdir().unwrap();
        let backup_dir = dir.path().join("backups");
        let claude_target = dir.path().join("claude.json");
        let vscode_target = dir.path().join("vscode.json");
        std::fs::write(&claude_target, b"{\"a\":1}").unwrap();
        std::fs::write(&vscode_target, b"{\"b\":2}").unwrap();

        struct NamedShim {
            ecosystem: Ecosystem,
            target: PathBuf,
        }
        impl Shim for NamedShim {
            fn ecosystem(&self) -> Ecosystem {
                self.ecosystem
            }
            fn target_path(&self) -> Result<PathBuf, ShimError> {
                Ok(self.target.clone())
            }
            fn merge(&self, document: &mut Value) {
                document
                    .as_object_mut()
                    .unwrap()
                    .insert("waddleai".to_string(), Value::Bool(true));
            }
        }

        let claude_shim = NamedShim {
            ecosystem: Ecosystem::Claude,
            target: claude_target.clone(),
        };
        let vscode_shim = NamedShim {
            ecosystem: Ecosystem::VsCode,
            target: vscode_target.clone(),
        };

        install(&backup_dir, &claude_shim).unwrap();
        install(&backup_dir, &vscode_shim).unwrap();
        uninstall(&backup_dir, &claude_shim).unwrap();

        assert_eq!(std::fs::read(&claude_target).unwrap(), b"{\"a\":1}");
        let vscode_doc: Value =
            serde_json::from_slice(&std::fs::read(&vscode_target).unwrap()).unwrap();
        assert_eq!(vscode_doc["waddleai"], true);
    }
}
