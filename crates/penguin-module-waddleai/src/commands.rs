//! waddleai's CLI command tree (pure data — see [`command_tree`]) and its
//! [`dispatch`] handlers.
//!
//! # No secret or sensitive payload is ever a literal CLI argument
//!
//! Every leaf command that would otherwise need a secret (`key set`'s
//! virtual key) or a sensitive payload (`hook <event>`'s event JSON, which
//! carries absolute file paths and full command lines) declares
//! `max_args: 0` — clap rejects any literal shell token for it outright
//! (see `penguin_cli_core::tree::args_positional`). The value still reaches
//! [`dispatch`] through `args`, but only via `bins/penguin`'s piped-stdin
//! fallback (`penguin_cli_core::dispatch::apply_stdin_fallback`, wired in
//! `cmd_dispatch`) — never a literal argument a shell would record in
//! history or expose in the process list for the command's lifetime.
//! `key set` additionally accepts `--key-file <path>`: a file *path* is not
//! sensitive, so passing one as a flag is fine — only the file's *contents*
//! are secret, and those are read directly, daemon-side.
//!
//! This is also protocol-correct, not just a hygiene fix: Claude Code and
//! Google Antigravity/AGY both deliver a hook's event payload to the
//! invoked command on **stdin** — a shim piping the JSON as a literal
//! argument would already be violating the upstream contract.
//!
//! # `hook <pre-tool-use|post-tool-use>`
//!
//! This is the actual hot-path command every installed shim invokes (see
//! `crate::hooks::HOOK_COMMAND`) — the one place this module's added
//! latency is directly on an agent's critical path (see
//! `crate::metrics`'s doc on `hook_evaluation_latency_seconds`), so
//! [`hook_command`] times the *entire* handler, not just the WaddleAI round
//! trip.
//!
//! Exit codes carry the enforcement: `0` for
//! [`crate::module::HookOutcome::Allow`], nonzero for
//! [`crate::module::HookOutcome::Deny`] and
//! [`crate::module::HookOutcome::Unavailable`] alike. That "no live
//! decision means block" default is each ecosystem's *own* hook contract
//! (a nonzero exit from a `PreToolUse` hook blocks the tool call in Claude
//! Code, and the equivalent holds for the others) — this crate supplies the
//! exit code, never a bespoke allow/deny rule of its own.

use std::collections::HashMap;
use std::time::Instant;

use serde::Serialize;
use serde_json::{Value, json};

use penguin_sdk::{CommandResult, CommandSpec, FlagSpec, FlagType, ModuleError};

use crate::hooks::Ecosystem;
use crate::module::{DecisionSource, HookOutcome, WaddleAiModule};

/// Declares waddleai's full command tree.
pub fn command_tree() -> Vec<CommandSpec> {
    vec![
        CommandSpec {
            name: "status".to_string(),
            use_line: "status".to_string(),
            short: "Show WaddleAI connectivity, auth, hook, and denylist status".to_string(),
            flags: vec![json_flag()],
            ..Default::default()
        },
        CommandSpec {
            name: "key".to_string(),
            use_line: "key".to_string(),
            short: "Manage the WaddleAI virtual key".to_string(),
            subcommands: vec![
                CommandSpec {
                    name: "set".to_string(),
                    use_line: "set".to_string(),
                    short: "Set the virtual key from stdin or --key-file (never a CLI argument)"
                        .to_string(),
                    // No positional: a secret must never be a literal shell
                    // token (shell history, `ps`) — see this module's
                    // top-level doc. Piped stdin
                    // (`echo "$KEY" | penguin waddleai key set`) or
                    // `--key-file <path>` are the only two channels.
                    flags: vec![json_flag(), key_file_flag()],
                    min_args: 0,
                    max_args: 0,
                    ..Default::default()
                },
                CommandSpec {
                    name: "status".to_string(),
                    use_line: "status".to_string(),
                    short: "Show whether a virtual key is set (masked hint only)".to_string(),
                    flags: vec![json_flag()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        CommandSpec {
            name: "hooks".to_string(),
            use_line: "hooks".to_string(),
            short: "Install, remove, and report on per-ecosystem hook shims".to_string(),
            subcommands: vec![
                CommandSpec {
                    name: "list".to_string(),
                    use_line: "list".to_string(),
                    short: "List every ecosystem shim and its install state".to_string(),
                    flags: vec![json_flag()],
                    ..Default::default()
                },
                CommandSpec {
                    name: "install".to_string(),
                    use_line: "install <claude-code|cortex|antigravity|vscode>".to_string(),
                    short: "Install a hook shim, merging into the ecosystem's own config"
                        .to_string(),
                    flags: vec![json_flag()],
                    min_args: 1,
                    max_args: 1,
                    tray: true,
                    ..Default::default()
                },
                CommandSpec {
                    name: "uninstall".to_string(),
                    use_line: "uninstall <claude-code|cortex|antigravity|vscode>".to_string(),
                    short: "Uninstall a hook shim, restoring the config byte-for-byte".to_string(),
                    flags: vec![json_flag()],
                    min_args: 1,
                    max_args: 1,
                    tray: true,
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        CommandSpec {
            name: "denylist".to_string(),
            use_line: "denylist".to_string(),
            short: "Manage the cached Tier-1 denylist snapshot".to_string(),
            subcommands: vec![
                CommandSpec {
                    name: "sync".to_string(),
                    use_line: "sync".to_string(),
                    short: "Fetch a fresh denylist snapshot from WaddleAI now".to_string(),
                    flags: vec![json_flag()],
                    ..Default::default()
                },
                CommandSpec {
                    name: "status".to_string(),
                    use_line: "status".to_string(),
                    short: "Show the cached denylist's size and staleness".to_string(),
                    flags: vec![json_flag()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        CommandSpec {
            name: "hook".to_string(),
            use_line: "hook".to_string(),
            short: "Evaluate one normalized agent-hook event (invoked by installed shims)"
                .to_string(),
            subcommands: vec![
                CommandSpec {
                    name: "pre_tool_use".to_string(),
                    use_line: "pre_tool_use".to_string(),
                    short: "Evaluate a pre_tool_use event (payload read from stdin)".to_string(),
                    // No positional: matches the real upstream hook
                    // contract (Claude Code/Antigravity deliver the event
                    // payload on the invoked command's stdin, not as an
                    // argument) and keeps payload content — absolute paths,
                    // full command lines — out of shell history/`ps`.
                    min_args: 0,
                    max_args: 0,
                    ..Default::default()
                },
                CommandSpec {
                    name: "post_tool_use".to_string(),
                    use_line: "post_tool_use".to_string(),
                    short: "Forward a post_tool_use telemetry event (payload read from stdin)"
                        .to_string(),
                    min_args: 0,
                    max_args: 0,
                    ..Default::default()
                },
                CommandSpec {
                    name: "session_start".to_string(),
                    use_line: "session_start".to_string(),
                    short: "Forward a session_start telemetry event (payload read from stdin)"
                        .to_string(),
                    min_args: 0,
                    max_args: 0,
                    ..Default::default()
                },
                CommandSpec {
                    name: "notification".to_string(),
                    use_line: "notification".to_string(),
                    short: "Forward a notification telemetry event (payload read from stdin)"
                        .to_string(),
                    min_args: 0,
                    max_args: 0,
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
    ]
}

fn json_flag() -> FlagSpec {
    FlagSpec {
        name: "json".to_string(),
        shorthand: String::new(),
        usage: "Output as JSON".to_string(),
        default: "false".to_string(),
        flag_type: FlagType::Bool,
    }
}

fn key_file_flag() -> FlagSpec {
    FlagSpec {
        name: "key-file".to_string(),
        shorthand: String::new(),
        usage: "Read the virtual key from this file's contents (the path itself is not secret)"
            .to_string(),
        default: String::new(),
        flag_type: FlagType::String,
    }
}

/// The single entry point [`crate::module::WaddleAiModule::dispatch`]
/// delegates to. Always returns `Ok` — a bad command, bad arguments, or a
/// failed WaddleAI call is reported as a nonzero-`exit_code`
/// [`CommandResult`], not a [`ModuleError`]; the latter is reserved for a
/// supervisor-level contract violation, which nothing in this router can
/// produce.
pub(crate) async fn dispatch(
    module: &WaddleAiModule,
    path: &[String],
    flags: &HashMap<String, String>,
    args: &[String],
) -> Result<CommandResult, ModuleError> {
    let Some(command) = path.first() else {
        return Ok(usage_result("waddleai: no command specified"));
    };
    let as_json = json_requested(flags);
    let result = match command.as_str() {
        "status" => cmd_status(module, as_json).await,
        "key" => dispatch_key(module, path, flags, args, as_json).await,
        "hooks" => dispatch_hooks(module, path, args, as_json).await,
        "denylist" => dispatch_denylist(module, path, as_json).await,
        "hook" => hook_command(module, path, args).await,
        other => unknown_command(other),
    };
    Ok(result)
}

fn usage_result(message: impl Into<String>) -> CommandResult {
    CommandResult {
        output: message.into(),
        json: Vec::new(),
        exit_code: 1,
    }
}

fn unknown_command(name: &str) -> CommandResult {
    usage_result(format!("waddleai: unknown command '{name}'"))
}

fn unknown_subcommand(name: &str) -> CommandResult {
    usage_result(format!("Unknown subcommand: {name}"))
}

fn json_requested(flags: &HashMap<String, String>) -> bool {
    flags.get("json").map(String::as_str) == Some("true")
}

/// Builds a successful [`CommandResult`]: `text` for the default human
/// rendering, `value` (always serialised into `json`) for `--json`.
fn success(as_json: bool, text: String, value: &impl Serialize) -> CommandResult {
    let json = serde_json::to_vec(value).unwrap_or_default();
    let output = if as_json {
        serde_json::to_string_pretty(value).unwrap_or_default()
    } else {
        text
    };
    CommandResult {
        output,
        json,
        exit_code: 0,
    }
}

fn parse_ecosystem(raw: &str) -> Result<Ecosystem, CommandResult> {
    Ecosystem::parse(raw).ok_or_else(|| {
        usage_result(format!(
            "invalid ecosystem '{raw}': expected claude, gemini, or vscode"
        ))
    })
}

// ── status ────────────────────────────────────────────────────────────

async fn cmd_status(module: &WaddleAiModule, as_json: bool) -> CommandResult {
    use penguin_sdk::Module;
    let status = match module.status().await {
        Ok(status) => status,
        Err(err) => return usage_result(format!("status failed: {err}")),
    };

    let mut text = format!("State: {}\n", status.state.as_str());
    let mut keys: Vec<&String> = status.detail.keys().collect();
    keys.sort();
    for key in &keys {
        text.push_str(&format!("  {key}: {}\n", status.detail[*key]));
    }

    success(as_json, text, &status.detail)
}

// ── key ───────────────────────────────────────────────────────────────

async fn dispatch_key(
    module: &WaddleAiModule,
    path: &[String],
    flags: &HashMap<String, String>,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    match path.get(1).map(String::as_str) {
        Some("set") => key_set(module, flags, args, as_json).await,
        Some("status") => key_status(module, as_json),
        Some(other) => unknown_subcommand(other),
        None => usage_result("Usage: waddleai key {set|status}"),
    }
}

/// `waddleai key set [--key-file <path>]`. The value comes from exactly one
/// of two channels, never a literal CLI argument (see this module's
/// top-level doc): `--key-file`'s file contents (wins if given), or `args`
/// — populated only via `bins/penguin`'s piped-stdin fallback
/// (`penguin_cli_core::dispatch::apply_stdin_fallback`), never a shell
/// token clap would have accepted directly (`key.set`'s `CommandSpec`
/// declares `max_args: 0`). Neither present is a clear usage error, not a
/// panic or a silent no-op.
async fn key_set(
    module: &WaddleAiModule,
    flags: &HashMap<String, String>,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    let value = match flags.get("key-file") {
        Some(path) if !path.is_empty() => match read_key_file(path) {
            Ok(value) => value,
            Err(err) => return usage_result(format!("failed to read --key-file {path}: {err}")),
        },
        _ => match args.first() {
            Some(value) => value.clone(),
            None => {
                return usage_result(
                    "no virtual key provided: pipe it on stdin (e.g. `echo \"$KEY\" | penguin \
                     waddleai key set`) or pass --key-file <path>",
                );
            }
        },
    };
    if value.is_empty() {
        return usage_result("virtual key must not be empty");
    }
    match module.set_virtual_key(value).await {
        Ok(()) => success(
            as_json,
            format!("virtual key set: {}", module.masked_key()),
            &json!({"key": module.masked_key()}),
        ),
        Err(err) => usage_result(format!("failed to set virtual key: {err}")),
    }
}

/// Reads `path`'s contents as the virtual key, trimming exactly one
/// trailing newline — a text file's or `echo "$KEY" >file`'s customary EOL
/// — the same way `penguin_cli_core::dispatch::apply_stdin_fallback` trims
/// piped stdin, so `--key-file` and stdin behave identically regardless of
/// which channel produced the value.
fn read_key_file(path: &str) -> std::io::Result<String> {
    let raw = std::fs::read_to_string(path)?;
    Ok(raw.strip_suffix('\n').unwrap_or(&raw).to_string())
}

fn key_status(module: &WaddleAiModule, as_json: bool) -> CommandResult {
    let present = module.key_present();
    let masked = module.masked_key();
    let text = if present {
        format!("virtual key set: {masked}")
    } else {
        "no virtual key set".to_string()
    };
    success(as_json, text, &json!({"present": present, "key": masked}))
}

// ── hooks ─────────────────────────────────────────────────────────────

async fn dispatch_hooks(
    module: &WaddleAiModule,
    path: &[String],
    args: &[String],
    as_json: bool,
) -> CommandResult {
    match path.get(1).map(String::as_str) {
        Some("list") => hooks_list(module, as_json),
        Some("install") => hooks_install(module, args, as_json),
        Some("uninstall") => hooks_uninstall(module, args, as_json),
        Some(other) => unknown_subcommand(other),
        None => {
            usage_result("Usage: waddleai hooks {list|install <ecosystem>|uninstall <ecosystem>}")
        }
    }
}

#[derive(Serialize)]
struct HookStatusJson {
    ecosystem: String,
    target_path: String,
    installed: bool,
}

fn hooks_list(module: &WaddleAiModule, as_json: bool) -> CommandResult {
    let mut rows = Vec::new();
    let mut lines = Vec::new();
    for ecosystem in Ecosystem::all() {
        match module.hook_status(ecosystem) {
            Ok(status) => {
                lines.push(format!(
                    "{}: {} ({})",
                    ecosystem.as_str(),
                    if status.installed {
                        "installed"
                    } else {
                        "not installed"
                    },
                    status.target_path.display(),
                ));
                rows.push(HookStatusJson {
                    ecosystem: ecosystem.as_str().to_string(),
                    target_path: status.target_path.display().to_string(),
                    installed: status.installed,
                });
            }
            Err(err) => lines.push(format!("{}: error ({err})", ecosystem.as_str())),
        }
    }
    success(as_json, lines.join("\n"), &rows)
}

fn hooks_install(module: &WaddleAiModule, args: &[String], as_json: bool) -> CommandResult {
    let Some(raw) = args.first() else {
        return usage_result("Usage: waddleai hooks install <claude|gemini|vscode>");
    };
    let ecosystem = match parse_ecosystem(raw) {
        Ok(ecosystem) => ecosystem,
        Err(result) => return result,
    };
    match module.install_hook(ecosystem) {
        Ok(report) => success(
            as_json,
            format!(
                "{} hook installed at {}",
                ecosystem.as_str(),
                report.target_path.display()
            ),
            &json!({
                "ecosystem": ecosystem.as_str(),
                "target_path": report.target_path.display().to_string(),
                "freshly_installed": report.freshly_installed,
            }),
        ),
        Err(err) => usage_result(format!("install failed: {err}")),
    }
}

fn hooks_uninstall(module: &WaddleAiModule, args: &[String], as_json: bool) -> CommandResult {
    let Some(raw) = args.first() else {
        return usage_result("Usage: waddleai hooks uninstall <claude|gemini|vscode>");
    };
    let ecosystem = match parse_ecosystem(raw) {
        Ok(ecosystem) => ecosystem,
        Err(result) => return result,
    };
    match module.uninstall_hook(ecosystem) {
        Ok(report) => success(
            as_json,
            format!(
                "{} hook uninstalled, {} restored",
                ecosystem.as_str(),
                report.target_path.display()
            ),
            &json!({
                "ecosystem": ecosystem.as_str(),
                "target_path": report.target_path.display().to_string(),
            }),
        ),
        Err(err) => usage_result(format!("uninstall failed: {err}")),
    }
}

// ── denylist ──────────────────────────────────────────────────────────

async fn dispatch_denylist(
    module: &WaddleAiModule,
    path: &[String],
    as_json: bool,
) -> CommandResult {
    match path.get(1).map(String::as_str) {
        Some("sync") => denylist_sync(module, as_json).await,
        Some("status") => denylist_status(module, as_json),
        Some(other) => unknown_subcommand(other),
        None => usage_result("Usage: waddleai denylist {sync|status}"),
    }
}

async fn denylist_sync(module: &WaddleAiModule, as_json: bool) -> CommandResult {
    match module.sync_denylist().await {
        Ok(cache) => success(
            as_json,
            format!("denylist synced: {} entries", cache.entries.len()),
            &json!({"entries": cache.entries.len(), "version": cache.version}),
        ),
        Err(err) => usage_result(format!("denylist sync failed: {err}")),
    }
}

fn denylist_status(module: &WaddleAiModule, as_json: bool) -> CommandResult {
    let cache = module.denylist_snapshot();
    let max_age = std::time::Duration::from_secs(module.config().denylist.max_age_secs);
    let now = std::time::SystemTime::now();
    let stale = cache.is_stale(now, max_age);
    let synced_at = cache
        .synced_at_unix
        .map(|secs| secs.to_string())
        .unwrap_or_else(|| "never".to_string());

    let text = format!(
        "entries: {}\nlast_synced: {synced_at}\nstale: {stale}",
        cache.entries.len()
    );
    success(
        as_json,
        text,
        &json!({
            "entries": cache.entries.len(),
            "version": cache.version,
            "last_synced": synced_at,
            "stale": stale,
        }),
    )
}

// ── hook ──────────────────────────────────────────────────────────────

/// `waddleai hook <pre-tool-use|post-tool-use> <payload-json>`. See this
/// module's top-level doc for the exit-code contract and the argv-transit
/// caveat.
async fn hook_command(module: &WaddleAiModule, path: &[String], args: &[String]) -> CommandResult {
    let Some(raw_event) = path.get(1).map(String::as_str) else {
        return usage_result(
            "Usage: waddleai hook {pre_tool_use|post_tool_use|session_start|notification} (payload piped on stdin)",
        );
    };
    let Some(event) = crate::hooks::normalize_event(raw_event) else {
        return unknown_subcommand(raw_event);
    };
    // `args` here was populated only by `bins/penguin`'s piped-stdin
    // fallback — `hook.<event>`'s `CommandSpec` declares `max_args: 0`, so
    // this was never a literal shell token. Empty means either nothing was
    // piped, or the shim invoking this command didn't pipe anything —
    // either way, a clear usage error, not a crash.
    let Some(raw_payload) = args.first() else {
        return usage_result(format!(
            "no payload provided on stdin for `waddleai hook {event}`"
        ));
    };
    let payload: Value = match serde_json::from_str(raw_payload) {
        Ok(payload) => payload,
        Err(err) => return usage_result(format!("invalid JSON payload: {err}")),
    };

    // Determine the ecosystem from the payload's own `ecosystem` field
    // (populated by the installed shim's command — see `crate::hooks`);
    // an unrecognised or missing value falls back to a generic label so
    // metrics still record the invocation rather than being dropped.
    let ecosystem = payload
        .get("ecosystem")
        .and_then(Value::as_str)
        .and_then(Ecosystem::parse)
        .unwrap_or(Ecosystem::Claude);

    let started = Instant::now();
    let outcome = module.evaluate_hook_event(ecosystem, event, &payload).await;
    let elapsed = started.elapsed();
    module
        .metrics()
        .hook_evaluation_latency_seconds
        .observe(elapsed.as_secs_f64());

    match outcome {
        HookOutcome::Allow { reason } => CommandResult {
            output: serde_json::to_string(&json!({"decision": "allow", "reason": reason}))
                .unwrap_or_default(),
            json: serde_json::to_vec(&json!({"decision": "allow", "reason": reason}))
                .unwrap_or_default(),
            exit_code: 0,
        },
        HookOutcome::Deny {
            reason,
            rule_id,
            source,
        } => {
            let source_str = match source {
                DecisionSource::Live => "live",
                DecisionSource::CachedDenylist => "cached_denylist",
            };
            let value = json!({
                "decision": "deny",
                "reason": reason,
                "rule_id": rule_id,
                "source": source_str,
            });
            CommandResult {
                output: serde_json::to_string(&value).unwrap_or_default(),
                json: serde_json::to_vec(&value).unwrap_or_default(),
                exit_code: 1,
            }
        }
        HookOutcome::Ask { reason, rule_id } => {
            let value = json!({
                "decision": "ask",
                "reason": reason,
                "rule_id": rule_id,
            });
            CommandResult {
                output: serde_json::to_string(&value).unwrap_or_default(),
                json: serde_json::to_vec(&value).unwrap_or_default(),
                exit_code: 2,
            }
        }
        HookOutcome::Redirect {
            reason,
            rule_id,
            redirect_model,
            active_skills,
        } => {
            let value = json!({
                "decision": "redirect",
                "reason": reason,
                "rule_id": rule_id,
                "redirect_model": redirect_model,
                "active_skills": active_skills,
            });
            CommandResult {
                output: serde_json::to_string(&value).unwrap_or_default(),
                json: serde_json::to_vec(&value).unwrap_or_default(),
                exit_code: 0,
            }
        }
        HookOutcome::Unavailable { reason } => {
            let value = json!({"decision": "unavailable", "reason": reason});
            CommandResult {
                output: serde_json::to_string(&value).unwrap_or_default(),
                json: serde_json::to_vec(&value).unwrap_or_default(),
                exit_code: 2,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeHost, MockResponse, MockServer};
    use std::sync::Arc;

    fn config_bytes(base_url: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"server": {"base_url": base_url}})).unwrap()
    }

    async fn init_module(server: &MockServer) -> WaddleAiModule {
        use penguin_sdk::{Module, SecretStore};
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.secrets
            .set("virtual_key", b"wa-testkey")
            .await
            .unwrap();
        host.config = config_bytes(&server.base_url);
        let module = WaddleAiModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");
        module
    }

    #[test]
    fn command_tree_declares_every_top_level_command() {
        let tree = command_tree();
        let names: Vec<&str> = tree.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["status", "key", "hooks", "denylist", "hook"]);
    }

    #[test]
    fn hooks_install_and_uninstall_are_tray_commands() {
        let tree = command_tree();
        let hooks = tree.iter().find(|c| c.name == "hooks").unwrap();
        let install = hooks
            .subcommands
            .iter()
            .find(|c| c.name == "install")
            .unwrap();
        assert!(install.tray);
        let list = hooks.subcommands.iter().find(|c| c.name == "list").unwrap();
        assert!(!list.tray);
    }

    #[tokio::test]
    async fn dispatch_no_command_is_a_nonzero_exit() {
        let server = MockServer::start().await;
        let module = init_module(&server).await;
        let result = module_dispatch(&module, &[], &HashMap::new(), &[]).await;
        assert_ne!(result.exit_code, 0);
        server.stop().await;
    }

    #[tokio::test]
    async fn dispatch_unknown_command_is_a_nonzero_exit() {
        let server = MockServer::start().await;
        let module = init_module(&server).await;
        let result = module_dispatch(&module, &["bogus".to_string()], &HashMap::new(), &[]).await;
        assert_ne!(result.exit_code, 0);
        server.stop().await;
    }

    #[tokio::test]
    async fn key_set_then_status_reports_a_masked_hint_never_the_raw_value() {
        let server = MockServer::start().await;
        let module = init_module(&server).await;

        // `args` here is exactly what `bins/penguin`'s piped-stdin fallback
        // (`penguin_cli_core::dispatch::apply_stdin_fallback`) would have
        // produced from `echo "$KEY" | penguin waddleai key set` — never a
        // literal shell token, since `key.set`'s `CommandSpec` declares
        // `max_args: 0` (see `command_tree_declares_no_positional_for_any_
        // secret_or_payload_command` below).
        let result = module_dispatch(
            &module,
            &["key".to_string(), "set".to_string()],
            &HashMap::new(),
            &["wa-brandnewsecretvalue".to_string()],
        )
        .await;
        assert_eq!(result.exit_code, 0);
        assert!(!result.output.contains("brandnewsecretvalue"));

        let status = module_dispatch(
            &module,
            &["key".to_string(), "status".to_string()],
            &HashMap::new(),
            &[],
        )
        .await;
        assert!(status.output.contains("****"));
        assert!(!status.output.contains("brandnewsecretvalue"));

        server.stop().await;
    }

    #[tokio::test]
    async fn key_set_reads_the_key_from_key_file_and_trims_its_trailing_newline() {
        let server = MockServer::start().await;
        let module = init_module(&server).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.txt");
        std::fs::write(&path, "wa-fromfile\n").unwrap();

        let mut flags = HashMap::new();
        flags.insert("key-file".to_string(), path.display().to_string());
        let result = module_dispatch(
            &module,
            &["key".to_string(), "set".to_string()],
            &flags,
            &[],
        )
        .await;
        assert_eq!(result.exit_code, 0, "{}", result.output);
        assert!(!result.output.contains("fromfile"));
        assert!(module.key_present());
        assert_eq!(module.masked_key(), "****file");

        server.stop().await;
    }

    #[tokio::test]
    async fn key_set_with_neither_key_file_nor_piped_stdin_is_a_clear_usage_error() {
        let server = MockServer::start().await;
        // `init_module` seeds an initial key so `key_present()` starts
        // `true` here — the assertion that matters is that a `key set`
        // with neither channel leaves that original key untouched rather
        // than silently clearing or corrupting it.
        let module = init_module(&server).await;
        let masked_before = module.masked_key();

        let result = module_dispatch(
            &module,
            &["key".to_string(), "set".to_string()],
            &HashMap::new(),
            &[],
        )
        .await;
        assert_eq!(result.exit_code, 1);
        assert!(result.output.contains("no virtual key provided"));
        assert_eq!(module.masked_key(), masked_before);

        server.stop().await;
    }

    #[tokio::test]
    async fn key_set_reports_a_clear_error_for_a_missing_key_file() {
        let server = MockServer::start().await;
        let module = init_module(&server).await;

        let mut flags = HashMap::new();
        flags.insert(
            "key-file".to_string(),
            "/nonexistent/path/key.txt".to_string(),
        );
        let result = module_dispatch(
            &module,
            &["key".to_string(), "set".to_string()],
            &flags,
            &[],
        )
        .await;
        assert_eq!(result.exit_code, 1);
        assert!(result.output.contains("failed to read --key-file"));

        server.stop().await;
    }

    /// The literal regression this track's follow-up fix exists for: no
    /// command that carries a secret (`key.set`) or a sensitive payload
    /// (`hook.pre-tool-use`/`hook.post-tool-use`) may accept it as a
    /// positional CLI argument — `max_args: 0` is what makes clap reject a
    /// typed shell token outright (`penguin_cli_core::tree::
    /// args_positional`), which is the actual security boundary; the
    /// `--key-file`/piped-stdin fallback tests above prove the remaining
    /// channels still work.
    #[test]
    fn no_command_accepts_a_secret_or_sensitive_payload_positionally() {
        let tree = command_tree();
        let key = tree.iter().find(|c| c.name == "key").unwrap();
        let key_set = key.subcommands.iter().find(|c| c.name == "set").unwrap();
        assert_eq!(
            key_set.max_args, 0,
            "key set must not accept a positional value"
        );
        assert_eq!(key_set.min_args, 0);

        let hook = tree.iter().find(|c| c.name == "hook").unwrap();
        for event in [
            "pre_tool_use",
            "post_tool_use",
            "session_start",
            "notification",
        ] {
            let spec = hook.subcommands.iter().find(|c| c.name == event).unwrap();
            assert_eq!(
                spec.max_args, 0,
                "{event} must not accept a positional payload"
            );
            assert_eq!(spec.min_args, 0);
        }
    }

    #[tokio::test]
    async fn hooks_install_writes_the_shim_and_list_reports_it() {
        let server = MockServer::start().await;
        let module = init_module(&server).await;
        // Safety: this dispatches the real `hooks install claude` path, so
        // it MUST route the shim's target file through the test-only
        // override seam (`WaddleAiModule::set_hook_target_dir_for_test`) —
        // never the default `ClaudeShim::new()`, which resolves the
        // developer's real `~/.claude/settings.json`.
        let hook_target_dir = tempfile::tempdir().unwrap();
        module.set_hook_target_dir_for_test(hook_target_dir.path().to_path_buf());

        let result = module_dispatch(
            &module,
            &["hooks".to_string(), "install".to_string()],
            &HashMap::new(),
            &["claude".to_string()],
        )
        .await;
        assert_eq!(result.exit_code, 0, "{}", result.output);

        // Proves the override seam was actually exercised, not merely
        // configured: the shim's config file must exist under the
        // overridden directory (and nowhere else) with the merged hook
        // entry in it.
        let written_path = hook_target_dir.path().join("claude-settings.json");
        let written = std::fs::read_to_string(&written_path).unwrap_or_else(|err| {
            panic!(
                "expected the shim to write {}: {err}",
                written_path.display()
            )
        });
        assert!(
            written.contains("PreToolUse"),
            "written config must contain the merged hook entry: {written}"
        );

        let list = module_dispatch(
            &module,
            &["hooks".to_string(), "list".to_string()],
            &HashMap::new(),
            &[],
        )
        .await;
        assert!(list.output.contains("claude-code: installed"));
        assert!(
            list.output
                .contains(&hook_target_dir.path().display().to_string()),
            "list must report the overridden path, confirming no real path was ever touched: {}",
            list.output
        );

        server.stop().await;
    }

    #[tokio::test]
    async fn hooks_install_rejects_an_unknown_ecosystem() {
        let server = MockServer::start().await;
        let module = init_module(&server).await;

        let result = module_dispatch(
            &module,
            &["hooks".to_string(), "install".to_string()],
            &HashMap::new(),
            &["notaneco".to_string()],
        )
        .await;
        assert_eq!(result.exit_code, 1);
        assert!(result.output.contains("invalid ecosystem"));

        server.stop().await;
    }

    #[tokio::test]
    async fn denylist_sync_then_status_reflects_the_new_snapshot() {
        let server = MockServer::start().await;
        server
            .respond(
                "GET",
                "/hooks/policy",
                MockResponse::json(
                    200,
                    r#"{"denylist_patterns":[".env*",".git/**"],"updated_at":"2026-11-27T00:00:00Z"}"#,
                ),
            )
            .await;
        let module = init_module(&server).await;

        let sync = module_dispatch(
            &module,
            &["denylist".to_string(), "sync".to_string()],
            &HashMap::new(),
            &[],
        )
        .await;
        assert_eq!(sync.exit_code, 0);

        let status = module_dispatch(
            &module,
            &["denylist".to_string(), "status".to_string()],
            &HashMap::new(),
            &[],
        )
        .await;
        assert!(status.output.contains("entries: 2"));
        assert!(status.output.contains("stale: false"));

        server.stop().await;
    }

    #[tokio::test]
    async fn hook_command_allows_on_a_live_allow_decision() {
        let server = MockServer::start().await;
        server
            .respond(
                "POST",
                "/hooks/evaluate",
                MockResponse::json(200, r#"{"decision":"allow","reason":"ok"}"#),
            )
            .await;
        let module = init_module(&server).await;

        let result = module_dispatch(
            &module,
            &["hook".to_string(), "pre-tool-use".to_string()],
            &HashMap::new(),
            &["{}".to_string()],
        )
        .await;
        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("\"allow\""));

        server.stop().await;
    }

    #[tokio::test]
    async fn hook_command_handles_redirect_and_ask_decisions() {
        let server = MockServer::start().await;
        server
            .respond(
                "POST",
                "/hooks/evaluate",
                MockResponse::json(
                    200,
                    r#"{"decision":"redirect","reason":"use local","redirect_model":"qwen2.5:7b","active_skills":["git"]}"#,
                ),
            )
            .await;
        let module = init_module(&server).await;

        let redirect_res = module_dispatch(
            &module,
            &["hook".to_string(), "pre_tool_use".to_string()],
            &HashMap::new(),
            &[r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#.to_string()],
        )
        .await;
        assert_eq!(redirect_res.exit_code, 0);
        assert!(redirect_res.output.contains("\"redirect\""));
        assert!(redirect_res.output.contains("qwen2.5:7b"));

        server.stop().await;

        let ask_server = MockServer::start().await;
        ask_server
            .respond(
                "POST",
                "/hooks/evaluate",
                MockResponse::json(200, r#"{"decision":"ask","reason":"confirm?"}"#),
            )
            .await;
        let ask_module = init_module(&ask_server).await;
        let ask_res = module_dispatch(
            &ask_module,
            &["hook".to_string(), "pre_tool_use".to_string()],
            &HashMap::new(),
            &[r#"{"tool_name":"Bash","tool_input":{"command":"rm foo"}}"#.to_string()],
        )
        .await;
        assert_eq!(ask_res.exit_code, 2);
        assert!(ask_res.output.contains("\"ask\""));

        ask_server.stop().await;
    }

    #[tokio::test]
    async fn hook_command_rejects_invalid_json_with_a_usage_error_not_a_crash() {
        let server = MockServer::start().await;
        let module = init_module(&server).await;

        let result = module_dispatch(
            &module,
            &["hook".to_string(), "pre-tool-use".to_string()],
            &HashMap::new(),
            &["not json".to_string()],
        )
        .await;
        assert_eq!(result.exit_code, 1);
        assert!(result.output.contains("invalid JSON"));

        server.stop().await;
    }

    /// The other half of the stdin-only contract: `hook.<event>` declares
    /// `max_args: 0`, so `args` is only ever non-empty when
    /// `bins/penguin`'s piped-stdin fallback actually had content to
    /// forward (see `no_command_accepts_a_secret_or_sensitive_payload_
    /// positionally`) — an empty `args` (nothing piped, or a TTY) must be a
    /// clear usage error, never a panic or a silent allow.
    #[tokio::test]
    async fn hook_command_with_no_piped_payload_is_a_clear_usage_error() {
        let server = MockServer::start().await;
        let module = init_module(&server).await;

        let result = module_dispatch(
            &module,
            &["hook".to_string(), "pre-tool-use".to_string()],
            &HashMap::new(),
            &[],
        )
        .await;
        assert_eq!(result.exit_code, 1);
        assert!(result.output.contains("no payload provided on stdin"));

        server.stop().await;
    }

    #[tokio::test]
    async fn hook_command_records_evaluation_latency() {
        let server = MockServer::start().await;
        server
            .respond(
                "POST",
                "/hooks/evaluate",
                MockResponse::json(200, r#"{"decision":"allow","reason":"ok"}"#),
            )
            .await;
        let module = init_module(&server).await;

        module_dispatch(
            &module,
            &["hook".to_string(), "pre-tool-use".to_string()],
            &HashMap::new(),
            &["{}".to_string()],
        )
        .await;

        assert_eq!(
            module
                .metrics()
                .hook_evaluation_latency_seconds
                .get_sample_count(),
            1
        );

        server.stop().await;
    }

    /// Thin wrapper so tests read like `module.dispatch(...)` without
    /// pulling `penguin_sdk::Module` into every single test.
    async fn module_dispatch(
        module: &WaddleAiModule,
        path: &[String],
        flags: &HashMap<String, String>,
        args: &[String],
    ) -> CommandResult {
        dispatch(module, path, flags, args).await.unwrap()
    }
}
