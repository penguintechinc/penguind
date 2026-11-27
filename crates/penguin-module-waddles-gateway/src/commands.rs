//! waddlebot's CLI command tree (pure data — see [`command_tree`]) and its
//! [`dispatch`] handlers: a full read-and-write surface over every endpoint
//! `waddles-client` exposes.
//!
//! Every handler here funnels its hub call through
//! [`crate::WaddlesGatewayModule::call`], so `waddlebot_api_requests_total`/
//! `waddlebot_api_errors_total` stay accurate with no per-handler
//! bookkeeping. `workflow`/`loyalty` are opaque JSON proxies on the hub side
//! (see `waddles_client::client::WaddlesClient`'s own doc), so those
//! handlers pretty-print the raw `serde_json::Value` rather than shaping a
//! schema that does not exist.
//!
//! # Secrets in output
//!
//! A Community Access Token is a secret. `token create`/`token rotate` are
//! the only two commands that ever see one in plaintext (the hub shows it
//! exactly once, at mint time) — [`mask_secret`] runs on that value before
//! it reaches `output` *or* `json`, so neither field, nor any log derived
//! from them, ever carries the live token. This is distinct from
//! `browser-sources list`'s `token` field, which is a per-overlay OBS
//! source key meant to be pasted verbatim into OBS (the whole point of the
//! command) rather than a login credential — see [`browser_sources_list`]'s
//! doc.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;
use serde_json::{Value, json};

use penguin_sdk::{CommandResult, CommandSpec, FlagSpec, FlagType, ModuleError, Status};
use waddles_client::WaddlesError;
use waddles_client::models::{
    Announcement, MusicSettings, MusicSettingsUpdate, NewAnnouncement, NewRadioStation,
};

use crate::mask::mask_secret;
use crate::module::WaddlesGatewayModule;

/// Declares waddlebot's full command tree: one top-level command per
/// resource area, nested subcommands for anything with more than one
/// action — the same shape `penguin-module-squawk`'s `forward`/`cache`
/// trees and `penguin-module-tobogganing`'s flat tree both use, picked per
/// command based on how many actions the resource actually has.
pub fn command_tree() -> Vec<CommandSpec> {
    vec![
        CommandSpec {
            name: "status".to_string(),
            use_line: "status".to_string(),
            short: "Show hub connectivity, auth, and active community".to_string(),
            flags: vec![json_flag()],
            ..Default::default()
        },
        CommandSpec {
            name: "auth".to_string(),
            use_line: "auth".to_string(),
            short: "Inspect Community Access Token (CAT) authentication state".to_string(),
            subcommands: vec![CommandSpec {
                name: "status".to_string(),
                use_line: "status".to_string(),
                short: "Check CAT presence and live hub auth probe".to_string(),
                flags: vec![json_flag()],
                ..Default::default()
            }],
            ..Default::default()
        },
        CommandSpec {
            name: "bridge".to_string(),
            use_line: "bridge".to_string(),
            short: "Inspect the local OBS/streamer bridge and mint per-script tokens".to_string(),
            subcommands: vec![
                CommandSpec {
                    name: "status".to_string(),
                    use_line: "status".to_string(),
                    short: "Show bridge running state and bound transports".to_string(),
                    flags: vec![json_flag()],
                    ..Default::default()
                },
                CommandSpec {
                    name: "mint".to_string(),
                    use_line: "mint <integration>".to_string(),
                    short: "Mint a local bearer token for an allowed integration".to_string(),
                    flags: vec![json_flag()],
                    min_args: 1,
                    max_args: 1,
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        CommandSpec {
            name: "community".to_string(),
            use_line: "community".to_string(),
            short: "Manage the active community".to_string(),
            subcommands: vec![
                CommandSpec {
                    name: "list".to_string(),
                    use_line: "list".to_string(),
                    short: "List communities this token can act on".to_string(),
                    flags: vec![json_flag()],
                    ..Default::default()
                },
                CommandSpec {
                    name: "use".to_string(),
                    use_line: "use <id>".to_string(),
                    short: "Switch the active community".to_string(),
                    flags: vec![json_flag()],
                    min_args: 1,
                    max_args: 1,
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        CommandSpec {
            name: "music".to_string(),
            use_line: "music".to_string(),
            short: "Manage community music settings, providers, and radio stations".to_string(),
            subcommands: vec![
                CommandSpec {
                    name: "settings".to_string(),
                    use_line: "settings".to_string(),
                    short: "Show music settings, or update the fields given as flags".to_string(),
                    flags: vec![
                        json_flag(),
                        string_flag("default-provider", "Default music provider"),
                        bool_flag("autoplay", "Enable autoplay"),
                        int_flag("volume-limit", "Maximum volume level"),
                        bool_flag("require-dj-approval", "Require DJ approval for requests"),
                        bool_flag("active", "Enable the music module"),
                        string_flag("allowed-genres", "Comma-separated allowed genres"),
                        string_flag("blocked-artists", "Comma-separated blocked artists"),
                    ],
                    ..Default::default()
                },
                CommandSpec {
                    name: "provider".to_string(),
                    use_line: "provider".to_string(),
                    short: "Manage connected music providers".to_string(),
                    subcommands: vec![
                        CommandSpec {
                            name: "list".to_string(),
                            use_line: "list".to_string(),
                            short: "List connected music providers".to_string(),
                            flags: vec![json_flag()],
                            ..Default::default()
                        },
                        CommandSpec {
                            name: "disconnect".to_string(),
                            use_line: "disconnect <name>".to_string(),
                            short: "Disconnect a music provider".to_string(),
                            flags: vec![json_flag()],
                            min_args: 1,
                            max_args: 1,
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
                CommandSpec {
                    name: "station".to_string(),
                    use_line: "station".to_string(),
                    short: "Manage the community's radio stations".to_string(),
                    subcommands: vec![
                        CommandSpec {
                            name: "list".to_string(),
                            use_line: "list".to_string(),
                            short: "List radio stations".to_string(),
                            flags: vec![
                                json_flag(),
                                int_flag("page", "Page number"),
                                int_flag("limit", "Results per page"),
                            ],
                            ..Default::default()
                        },
                        CommandSpec {
                            name: "add".to_string(),
                            use_line: "add".to_string(),
                            short: "Add a radio station".to_string(),
                            flags: vec![
                                json_flag(),
                                string_flag("name", "Station name (required)"),
                                string_flag("url", "Stream URL (required)"),
                                string_flag("description", "Station description"),
                                string_flag("genre", "Station genre"),
                                bool_flag("active", "Mark the station active"),
                            ],
                            ..Default::default()
                        },
                        CommandSpec {
                            name: "remove".to_string(),
                            use_line: "remove <id>".to_string(),
                            short: "Remove a radio station".to_string(),
                            flags: vec![json_flag()],
                            min_args: 1,
                            max_args: 1,
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        CommandSpec {
            name: "browser-sources".to_string(),
            use_line: "browser-sources".to_string(),
            short: "Manage OBS browser-source overlay URLs".to_string(),
            subcommands: vec![
                CommandSpec {
                    name: "list".to_string(),
                    use_line: "list".to_string(),
                    short: "List browser-source URLs".to_string(),
                    flags: vec![json_flag()],
                    ..Default::default()
                },
                CommandSpec {
                    name: "regenerate".to_string(),
                    use_line: "regenerate".to_string(),
                    short: "Regenerate browser-source URL tokens".to_string(),
                    flags: vec![
                        json_flag(),
                        string_flag(
                            "source-type",
                            "Regenerate only this source type; omit for all",
                        ),
                    ],
                    tray: true,
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        CommandSpec {
            name: "token".to_string(),
            use_line: "token".to_string(),
            short: "Manage Community Access Tokens (CATs)".to_string(),
            subcommands: vec![
                CommandSpec {
                    name: "list".to_string(),
                    use_line: "list".to_string(),
                    short: "List issued CATs (never their secret values)".to_string(),
                    flags: vec![json_flag()],
                    ..Default::default()
                },
                CommandSpec {
                    name: "scopes".to_string(),
                    use_line: "scopes".to_string(),
                    short: "List permission scopes a CAT can be minted with".to_string(),
                    flags: vec![json_flag()],
                    ..Default::default()
                },
                CommandSpec {
                    name: "create".to_string(),
                    use_line: "create <name>".to_string(),
                    short: "Mint a new CAT (shown once, masked)".to_string(),
                    flags: vec![
                        json_flag(),
                        string_flag("scopes", "Comma-separated permission scopes"),
                        string_flag("expires-at", "ISO-8601 expiry"),
                    ],
                    min_args: 1,
                    max_args: 1,
                    ..Default::default()
                },
                CommandSpec {
                    name: "revoke".to_string(),
                    use_line: "revoke <id>".to_string(),
                    short: "Revoke a CAT".to_string(),
                    flags: vec![json_flag()],
                    min_args: 1,
                    max_args: 1,
                    ..Default::default()
                },
                CommandSpec {
                    name: "rotate".to_string(),
                    use_line: "rotate <id>".to_string(),
                    short: "Revoke a CAT and mint its replacement (shown once, masked)".to_string(),
                    flags: vec![
                        json_flag(),
                        string_flag("name", "Name for the replacement CAT (required)"),
                        string_flag("scopes", "Comma-separated permission scopes"),
                        string_flag("expires-at", "ISO-8601 expiry"),
                    ],
                    min_args: 1,
                    max_args: 1,
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        CommandSpec {
            name: "announce".to_string(),
            use_line: "announce".to_string(),
            short: "Manage community announcements".to_string(),
            subcommands: vec![
                CommandSpec {
                    name: "list".to_string(),
                    use_line: "list".to_string(),
                    short: "List announcements".to_string(),
                    flags: vec![
                        json_flag(),
                        string_flag("status", "Filter by draft/published/archived"),
                    ],
                    ..Default::default()
                },
                CommandSpec {
                    name: "show".to_string(),
                    use_line: "show <id>".to_string(),
                    short: "Show one announcement".to_string(),
                    flags: vec![json_flag()],
                    min_args: 1,
                    max_args: 1,
                    ..Default::default()
                },
                CommandSpec {
                    name: "create".to_string(),
                    use_line: "create".to_string(),
                    short: "Create an announcement".to_string(),
                    flags: vec![
                        json_flag(),
                        string_flag("title", "Title (required)"),
                        string_flag("content", "Content (required)"),
                        string_flag("type", "Announcement type"),
                        bool_flag("pinned", "Pin the announcement"),
                        string_flag("status", "Initial status"),
                    ],
                    ..Default::default()
                },
                CommandSpec {
                    name: "publish".to_string(),
                    use_line: "publish <id>".to_string(),
                    short: "Publish a draft announcement".to_string(),
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
            name: "workflow".to_string(),
            use_line: "workflow".to_string(),
            short: "Manage community workflows (opaque JSON passthrough)".to_string(),
            subcommands: vec![
                CommandSpec {
                    name: "list".to_string(),
                    use_line: "list".to_string(),
                    short: "List workflows".to_string(),
                    flags: vec![json_flag()],
                    ..Default::default()
                },
                CommandSpec {
                    name: "show".to_string(),
                    use_line: "show <id>".to_string(),
                    short: "Show one workflow".to_string(),
                    flags: vec![json_flag()],
                    min_args: 1,
                    max_args: 1,
                    ..Default::default()
                },
                CommandSpec {
                    name: "create".to_string(),
                    use_line: "create <payload-json>".to_string(),
                    short: "Create a workflow from a raw JSON payload".to_string(),
                    flags: vec![json_flag()],
                    min_args: 1,
                    max_args: 1,
                    ..Default::default()
                },
                CommandSpec {
                    name: "update".to_string(),
                    use_line: "update <id> <payload-json>".to_string(),
                    short: "Update a workflow with a raw JSON payload".to_string(),
                    flags: vec![json_flag()],
                    min_args: 2,
                    max_args: 2,
                    ..Default::default()
                },
                CommandSpec {
                    name: "delete".to_string(),
                    use_line: "delete <id>".to_string(),
                    short: "Delete a workflow".to_string(),
                    flags: vec![json_flag()],
                    min_args: 1,
                    max_args: 1,
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        CommandSpec {
            name: "loyalty".to_string(),
            use_line: "loyalty".to_string(),
            short: "Manage the community's loyalty program (opaque JSON passthrough)".to_string(),
            subcommands: vec![
                CommandSpec {
                    name: "config".to_string(),
                    use_line: "config [payload-json]".to_string(),
                    short: "Show, or update with a raw JSON payload, the loyalty config"
                        .to_string(),
                    flags: vec![json_flag()],
                    min_args: 0,
                    max_args: 1,
                    ..Default::default()
                },
                CommandSpec {
                    name: "adjust".to_string(),
                    use_line: "adjust <user_id> <payload-json>".to_string(),
                    short: "Adjust a user's loyalty balance with a raw JSON payload".to_string(),
                    flags: vec![json_flag()],
                    min_args: 2,
                    max_args: 2,
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

fn string_flag(name: &str, usage: &str) -> FlagSpec {
    FlagSpec {
        name: name.to_string(),
        shorthand: String::new(),
        usage: usage.to_string(),
        default: String::new(),
        flag_type: FlagType::String,
    }
}

fn bool_flag(name: &str, usage: &str) -> FlagSpec {
    FlagSpec {
        name: name.to_string(),
        shorthand: String::new(),
        usage: usage.to_string(),
        default: "false".to_string(),
        flag_type: FlagType::Bool,
    }
}

fn int_flag(name: &str, usage: &str) -> FlagSpec {
    FlagSpec {
        name: name.to_string(),
        shorthand: String::new(),
        usage: usage.to_string(),
        default: "0".to_string(),
        flag_type: FlagType::Int,
    }
}

/// The single entry point [`crate::module::WaddlesGatewayModule::dispatch`]
/// delegates to. Always returns `Ok` — a bad command, bad arguments, or a
/// failed hub call is reported as a nonzero-`exit_code` [`CommandResult`],
/// not a [`ModuleError`]; the latter is reserved for a supervisor-level
/// contract violation, which nothing in this router can produce.
pub(crate) async fn dispatch(
    module: &WaddlesGatewayModule,
    path: &[String],
    flags: &HashMap<String, String>,
    args: &[String],
) -> Result<CommandResult, ModuleError> {
    let Some(command) = path.first() else {
        return Ok(usage_result("waddles-gateway: no command specified"));
    };
    let as_json = json_requested(flags);
    let result = match command.as_str() {
        "status" => cmd_status(module, as_json).await,
        "auth" => dispatch_auth(module, path, as_json).await,
        "bridge" => dispatch_bridge(module, path, args, as_json),
        "community" => dispatch_community(module, path, args, as_json).await,
        "music" => dispatch_music(module, path, flags, args, as_json).await,
        "browser-sources" => dispatch_browser_sources(module, path, flags, as_json).await,
        "token" => dispatch_token(module, path, flags, args, as_json).await,
        "announce" => dispatch_announce(module, path, flags, args, as_json).await,
        "workflow" => dispatch_workflow(module, path, args, as_json).await,
        "loyalty" => dispatch_loyalty(module, path, args, as_json).await,
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
    usage_result(format!("waddles-gateway: unknown command '{name}'"))
}

fn unknown_subcommand(name: &str) -> CommandResult {
    usage_result(format!("Unknown subcommand: {name}"))
}

fn hub_error(context: &str, err: WaddlesError) -> CommandResult {
    usage_result(format!("{context}: {err}"))
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

/// Pretty-prints an opaque hub `Value` — used by every `workflow`/`loyalty`
/// handler, where there is no fixed schema to summarise, so the JSON
/// rendering *is* the human rendering regardless of `--json`.
fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

fn csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn parse_id(raw: &str) -> Option<i64> {
    raw.parse().ok()
}

// ── status ────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct StatusJson<'a> {
    state: &'a str,
    detail: BTreeMap<&'a String, &'a String>,
}

/// `waddlebot status [--json]`.
async fn cmd_status(module: &WaddlesGatewayModule, as_json: bool) -> CommandResult {
    use penguin_sdk::Module;
    let status = match module.status().await {
        Ok(status) => status,
        Err(err) => return usage_result(format!("status failed: {err}")),
    };

    if as_json {
        let payload = StatusJson {
            state: status.state.as_str(),
            detail: status.detail.iter().collect(),
        };
        let json = serde_json::to_vec(&payload).unwrap_or_default();
        return CommandResult {
            output: String::from_utf8_lossy(&json).into_owned(),
            json,
            exit_code: 0,
        };
    }

    CommandResult {
        output: format_status_text(&status),
        json: Vec::new(),
        exit_code: 0,
    }
}

fn format_status_text(status: &Status) -> String {
    let mut output = format!("State: {}\n", status.state.as_str());
    let mut keys: Vec<&String> = status.detail.keys().collect();
    keys.sort();
    for key in keys {
        output.push_str(&format!("  {key}: {}\n", status.detail[key]));
    }
    output
}

// ── auth ──────────────────────────────────────────────────────────────

async fn dispatch_auth(
    module: &WaddlesGatewayModule,
    path: &[String],
    as_json: bool,
) -> CommandResult {
    match path.get(1).map(String::as_str) {
        Some("status") => cmd_status(module, as_json).await,
        Some(other) => unknown_subcommand(other),
        None => usage_result("Usage: waddles-gateway auth status"),
    }
}

// ── bridge ────────────────────────────────────────────────────────────

fn dispatch_bridge(
    module: &WaddlesGatewayModule,
    path: &[String],
    args: &[String],
    as_json: bool,
) -> CommandResult {
    match path.get(1).map(String::as_str) {
        Some("status") => {
            let (running, tcp, unix) = module.bridge_status();
            let tcp_str = tcp.map(|a| a.to_string()).unwrap_or_default();
            let unix_str = unix.map(|p| p.display().to_string()).unwrap_or_default();
            let text = format!("running={running} tcp={tcp_str} unix={unix_str}");
            success(
                as_json,
                text,
                &json!({
                    "running": running,
                    "tcp": if tcp_str.is_empty() { Value::Null } else { Value::String(tcp_str) },
                    "unix": if unix_str.is_empty() { Value::Null } else { Value::String(unix_str) },
                }),
            )
        }
        Some("mint") => {
            let Some(integration) = args.first() else {
                return usage_result("Usage: waddles-gateway bridge mint <integration>");
            };
            match module.mint_bridge_token(integration) {
                Some(token) => success(
                    as_json,
                    format!("integration={integration} token={token}"),
                    &json!({
                        "integration": integration,
                        "token": token,
                    }),
                ),
                None => usage_result(format!(
                    "cannot mint token for '{integration}': bridge not running or integration not allowed"
                )),
            }
        }
        Some(other) => unknown_subcommand(other),
        None => usage_result("Usage: waddles-gateway bridge {status|mint <integration>}"),
    }
}

// ── community ─────────────────────────────────────────────────────────

async fn dispatch_community(
    module: &WaddlesGatewayModule,
    path: &[String],
    args: &[String],
    as_json: bool,
) -> CommandResult {
    match path.get(1).map(String::as_str) {
        Some("list") => community_list(module, as_json).await,
        Some("use") => community_use(module, args, as_json).await,
        Some(other) => unknown_subcommand(other),
        None => usage_result("Usage: waddlebot community {list|use <id>}"),
    }
}

async fn community_list(module: &WaddlesGatewayModule, as_json: bool) -> CommandResult {
    let client = module.client();
    match module.call(client.list_my_communities()).await {
        Ok(communities) => {
            let text = if communities.is_empty() {
                "no communities".to_string()
            } else {
                communities
                    .iter()
                    .map(|c| format!("{} {} role={}", c.id, c.display_name, c.role))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            let value: Vec<Value> = communities
                .iter()
                .map(|c| {
                    json!({
                        "id": c.id, "name": c.name, "display_name": c.display_name,
                        "role": c.role, "member_count": c.member_count,
                    })
                })
                .collect();
            success(as_json, text, &value)
        }
        Err(err) => hub_error("list communities failed", err),
    }
}

async fn community_use(
    module: &WaddlesGatewayModule,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    let Some(raw_id) = args.first() else {
        return usage_result("Usage: waddlebot community use <id>");
    };
    if !waddles_client::config::is_valid_uuid(raw_id) {
        return usage_result(format!("invalid community id: {raw_id}"));
    }
    match module.set_community(raw_id) {
        Ok(()) => success(
            as_json,
            format!("active community set to {raw_id}"),
            &json!({"community_id": raw_id}),
        ),
        Err(err) => usage_result(format!("failed to switch community: {err}")),
    }
}

// ── music ─────────────────────────────────────────────────────────────

async fn dispatch_music(
    module: &WaddlesGatewayModule,
    path: &[String],
    flags: &HashMap<String, String>,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    match path.get(1).map(String::as_str) {
        Some("settings") => music_settings(module, flags, as_json).await,
        Some("provider") => dispatch_music_provider(module, path, args, as_json).await,
        Some("station") => dispatch_music_station(module, path, flags, args, as_json).await,
        Some(other) => unknown_subcommand(other),
        None => usage_result("Usage: waddlebot music {settings|provider|station}"),
    }
}

fn music_settings_json(s: &MusicSettings) -> Value {
    json!({
        "default_provider": s.default_provider, "autoplay_enabled": s.autoplay_enabled,
        "volume_limit": s.volume_limit, "allowed_genres": s.allowed_genres,
        "blocked_artists": s.blocked_artists, "require_dj_approval": s.require_dj_approval,
        "is_active": s.is_active,
    })
}

fn format_music_settings(s: &MusicSettings) -> String {
    format!(
        "default_provider={} autoplay={} volume_limit={} dj_approval={} active={}",
        s.default_provider.as_deref().unwrap_or("none"),
        s.autoplay_enabled,
        s.volume_limit,
        s.require_dj_approval,
        s.is_active,
    )
}

/// `waddlebot music settings [--json] [update flags...]`: a bare call
/// fetches the current settings; any of the update flags present sends a
/// partial `PUT` carrying only the fields the caller actually set (`--json`
/// never counts as an update field).
async fn music_settings(
    module: &WaddlesGatewayModule,
    flags: &HashMap<String, String>,
    as_json: bool,
) -> CommandResult {
    let update_requested = flags.keys().any(|key| key != "json");
    let client = module.client();

    let result = if update_requested {
        let mut update = MusicSettingsUpdate::default();
        if let Some(v) = flags.get("default-provider") {
            update.default_provider = Some(v.clone());
        }
        if let Some(v) = flags.get("autoplay") {
            update.autoplay_enabled = v.parse().ok();
        }
        if let Some(v) = flags.get("volume-limit") {
            update.volume_limit = v.parse().ok();
        }
        if let Some(v) = flags.get("require-dj-approval") {
            update.require_dj_approval = v.parse().ok();
        }
        if let Some(v) = flags.get("active") {
            update.is_active = v.parse().ok();
        }
        if let Some(v) = flags.get("allowed-genres") {
            update.allowed_genres = Some(csv(v));
        }
        if let Some(v) = flags.get("blocked-artists") {
            update.blocked_artists = Some(csv(v));
        }
        module.call(client.update_music_settings(&update)).await
    } else {
        module.call(client.get_music_settings()).await
    };

    match result {
        Ok(settings) => success(
            as_json,
            format_music_settings(&settings),
            &music_settings_json(&settings),
        ),
        Err(err) => hub_error("music settings failed", err),
    }
}

async fn dispatch_music_provider(
    module: &WaddlesGatewayModule,
    path: &[String],
    args: &[String],
    as_json: bool,
) -> CommandResult {
    match path.get(2).map(String::as_str) {
        Some("list") => music_provider_list(module, as_json).await,
        Some("disconnect") => music_provider_disconnect(module, args, as_json).await,
        Some(other) => unknown_subcommand(other),
        None => usage_result("Usage: waddlebot music provider {list|disconnect <name>}"),
    }
}

async fn music_provider_list(module: &WaddlesGatewayModule, as_json: bool) -> CommandResult {
    let client = module.client();
    match module.call(client.list_music_providers()).await {
        Ok(providers) => {
            let text = if providers.is_empty() {
                "no music providers".to_string()
            } else {
                providers
                    .iter()
                    .map(|p| {
                        format!(
                            "{} connected={} active={}",
                            p.provider_name, p.is_connected, p.is_active
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            let value: Vec<Value> = providers
                .iter()
                .map(|p| {
                    json!({
                        "provider_name": p.provider_name, "is_connected": p.is_connected,
                        "is_active": p.is_active,
                    })
                })
                .collect();
            success(as_json, text, &value)
        }
        Err(err) => hub_error("list music providers failed", err),
    }
}

async fn music_provider_disconnect(
    module: &WaddlesGatewayModule,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    let Some(name) = args.first() else {
        return usage_result("Usage: waddlebot music provider disconnect <name>");
    };
    let client = module.client();
    match module.call(client.disconnect_music_provider(name)).await {
        Ok(message) => success(as_json, message.clone(), &json!({"message": message})),
        Err(err) => hub_error("disconnect music provider failed", err),
    }
}

async fn dispatch_music_station(
    module: &WaddlesGatewayModule,
    path: &[String],
    flags: &HashMap<String, String>,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    match path.get(2).map(String::as_str) {
        Some("list") => music_station_list(module, flags, as_json).await,
        Some("add") => music_station_add(module, flags, as_json).await,
        Some("remove") => music_station_remove(module, args, as_json).await,
        Some(other) => unknown_subcommand(other),
        None => usage_result("Usage: waddlebot music station {list|add|remove <id>}"),
    }
}

async fn music_station_list(
    module: &WaddlesGatewayModule,
    flags: &HashMap<String, String>,
    as_json: bool,
) -> CommandResult {
    let page = flags.get("page").and_then(|v| v.parse::<u32>().ok());
    let limit = flags.get("limit").and_then(|v| v.parse::<u32>().ok());
    let client = module.client();
    match module.call(client.list_radio_stations(page, limit)).await {
        Ok(list) => {
            let text = if list.stations.is_empty() {
                "no radio stations".to_string()
            } else {
                list.stations
                    .iter()
                    .map(|s| format!("{} {} ({})", s.id, s.name, s.url))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            let value = json!({
                "pagination": {
                    "page": list.pagination.page, "limit": list.pagination.limit,
                    "total": list.pagination.total, "pages": list.pagination.pages,
                },
                "stations": list.stations.iter().map(|s| json!({
                    "id": s.id, "name": s.name, "url": s.url, "genre": s.genre,
                    "is_active": s.is_active,
                })).collect::<Vec<_>>(),
            });
            success(as_json, text, &value)
        }
        Err(err) => hub_error("list radio stations failed", err),
    }
}

async fn music_station_add(
    module: &WaddlesGatewayModule,
    flags: &HashMap<String, String>,
    as_json: bool,
) -> CommandResult {
    let Some(name) = flags.get("name") else {
        return usage_result(
            "Usage: waddlebot music station add --name N --url U [--description D] [--genre G] [--active]",
        );
    };
    let Some(url) = flags.get("url") else {
        return usage_result(
            "Usage: waddlebot music station add --name N --url U [--description D] [--genre G] [--active]",
        );
    };
    let description = flags.get("description").map(String::as_str);
    let genre = flags.get("genre").map(String::as_str);
    let is_active = flags.get("active").map(|v| v == "true");
    let station = NewRadioStation {
        name,
        url,
        description,
        genre,
        is_active,
    };
    let client = module.client();
    match module.call(client.add_radio_station(&station)).await {
        Ok(s) => success(
            as_json,
            format!("radio station created: {} ({})", s.id, s.name),
            &json!({
                "id": s.id, "name": s.name, "url": s.url, "genre": s.genre,
                "is_active": s.is_active,
            }),
        ),
        Err(err) => hub_error("add radio station failed", err),
    }
}

async fn music_station_remove(
    module: &WaddlesGatewayModule,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    let Some(raw_id) = args.first() else {
        return usage_result("Usage: waddlebot music station remove <id>");
    };
    let Some(id) = parse_id(raw_id) else {
        return usage_result(format!("invalid station id: {raw_id}"));
    };
    let client = module.client();
    match module.call(client.remove_radio_station(id)).await {
        Ok(message) => success(as_json, message.clone(), &json!({"message": message})),
        Err(err) => hub_error("remove radio station failed", err),
    }
}

// ── browser-sources ──────────────────────────────────────────────────

async fn dispatch_browser_sources(
    module: &WaddlesGatewayModule,
    path: &[String],
    flags: &HashMap<String, String>,
    as_json: bool,
) -> CommandResult {
    match path.get(1).map(String::as_str) {
        Some("list") => browser_sources_list(module, as_json).await,
        Some("regenerate") => browser_sources_regenerate(module, flags, as_json).await,
        Some(other) => unknown_subcommand(other),
        None => usage_result("Usage: waddlebot browser-sources {list|regenerate}"),
    }
}

/// `waddlebot browser-sources list [--json]`. The `token` in each source is
/// a per-overlay OBS source key embedded in `url` — showing it is the
/// command's entire purpose (operators paste the URL into OBS), unlike a
/// CAT, which is never echoed unmasked. See this module's top-level doc.
async fn browser_sources_list(module: &WaddlesGatewayModule, as_json: bool) -> CommandResult {
    let client = module.client();
    match module.call(client.list_browser_sources()).await {
        Ok(sources) => {
            let text = if sources.is_empty() {
                "no browser sources".to_string()
            } else {
                sources
                    .iter()
                    .map(|s| format!("{}: {} (active={})", s.source_type, s.url, s.is_active))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            let value: Vec<Value> = sources
                .iter()
                .map(|s| {
                    json!({
                        "source_type": s.source_type, "url": s.url, "token": s.token,
                        "is_active": s.is_active,
                    })
                })
                .collect();
            success(as_json, text, &value)
        }
        Err(err) => hub_error("list browser sources failed", err),
    }
}

async fn browser_sources_regenerate(
    module: &WaddlesGatewayModule,
    flags: &HashMap<String, String>,
    as_json: bool,
) -> CommandResult {
    let source_type = flags.get("source-type").map(String::as_str);
    let client = module.client();
    match module
        .call(client.regenerate_browser_sources(source_type))
        .await
    {
        Ok(message) => success(as_json, message.clone(), &json!({"message": message})),
        Err(err) => hub_error("regenerate browser sources failed", err),
    }
}

// ── token ─────────────────────────────────────────────────────────────

async fn dispatch_token(
    module: &WaddlesGatewayModule,
    path: &[String],
    flags: &HashMap<String, String>,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    match path.get(1).map(String::as_str) {
        Some("list") => token_list(module, as_json).await,
        Some("scopes") => token_scopes(module, as_json).await,
        Some("create") => token_create(module, flags, args, as_json).await,
        Some("revoke") => token_revoke(module, args, as_json).await,
        Some("rotate") => token_rotate(module, flags, args, as_json).await,
        Some(other) => unknown_subcommand(other),
        None => usage_result(
            "Usage: waddlebot token {list|scopes|create <name>|revoke <id>|rotate <id>}",
        ),
    }
}

async fn token_list(module: &WaddlesGatewayModule, as_json: bool) -> CommandResult {
    let client = module.client();
    match module.call(client.list_cats()).await {
        Ok(list) => {
            let text = if list.tokens.is_empty() {
                format!("no tokens (quota {}, used {})", list.quota, list.used)
            } else {
                let mut lines: Vec<String> = list
                    .tokens
                    .iter()
                    .map(|t| {
                        format!(
                            "{} {} scopes=[{}] revoked={}",
                            t.id,
                            t.name,
                            t.scopes.join(","),
                            t.is_revoked
                        )
                    })
                    .collect();
                lines.push(format!("quota {} used {}", list.quota, list.used));
                lines.join("\n")
            };
            let value = json!({
                "quota": list.quota, "used": list.used,
                "tokens": list.tokens.iter().map(|t| json!({
                    "id": t.id, "name": t.name, "scopes": t.scopes,
                    "is_revoked": t.is_revoked, "expires_at": t.expires_at,
                })).collect::<Vec<_>>(),
            });
            success(as_json, text, &value)
        }
        Err(err) => hub_error("list tokens failed", err),
    }
}

async fn token_scopes(module: &WaddlesGatewayModule, as_json: bool) -> CommandResult {
    let client = module.client();
    match module.call(client.list_scopes()).await {
        Ok(scopes) => {
            let text = if scopes.is_empty() {
                "no scopes".to_string()
            } else {
                scopes
                    .iter()
                    .map(|s| format!("{} - {}", s.scope_key, s.display_name))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            let value: Vec<Value> = scopes
                .iter()
                .map(|s| {
                    json!({
                        "scope_key": s.scope_key, "display_name": s.display_name,
                        "category": s.category,
                    })
                })
                .collect();
            success(as_json, text, &value)
        }
        Err(err) => hub_error("list scopes failed", err),
    }
}

/// `waddlebot token create <name> [--scopes a,b] [--expires-at TIME]`. The
/// hub shows the plaintext CAT exactly once, in this response — but it is
/// masked before it ever reaches `output` or `json`; see this module's
/// top-level doc.
async fn token_create(
    module: &WaddlesGatewayModule,
    flags: &HashMap<String, String>,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    let Some(name) = args.first() else {
        return usage_result(
            "Usage: waddlebot token create <name> [--scopes a,b] [--expires-at TIME]",
        );
    };
    let scopes = flags.get("scopes").map(|v| csv(v)).unwrap_or_default();
    let expires_at = flags.get("expires-at").map(String::as_str);
    let client = module.client();
    match module
        .call(client.create_cat(name, &scopes, expires_at))
        .await
    {
        Ok(new_token) => {
            let masked = mask_secret(&new_token.token);
            success(
                as_json,
                format!("token created: {masked} ({})", new_token.message),
                &json!({"token": masked, "message": new_token.message}),
            )
        }
        Err(err) => hub_error("create token failed", err),
    }
}

async fn token_revoke(
    module: &WaddlesGatewayModule,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    let Some(raw_id) = args.first() else {
        return usage_result("Usage: waddlebot token revoke <id>");
    };
    let Some(id) = parse_id(raw_id) else {
        return usage_result(format!("invalid token id: {raw_id}"));
    };
    let client = module.client();
    match module.call(client.revoke_cat(id)).await {
        Ok(message) => success(as_json, message.clone(), &json!({"message": message})),
        Err(err) => hub_error("revoke token failed", err),
    }
}

/// `waddlebot token rotate <id> --name NEW [--scopes a,b] [--expires-at TIME]`.
/// Same masking rule as [`token_create`].
async fn token_rotate(
    module: &WaddlesGatewayModule,
    flags: &HashMap<String, String>,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    let Some(raw_id) = args.first() else {
        return usage_result("Usage: waddlebot token rotate <id> --name NEW_NAME");
    };
    let Some(id) = parse_id(raw_id) else {
        return usage_result(format!("invalid token id: {raw_id}"));
    };
    let Some(name) = flags.get("name") else {
        return usage_result(
            "Usage: waddlebot token rotate <id> --name NEW_NAME [--scopes a,b] [--expires-at TIME]",
        );
    };
    let scopes = flags.get("scopes").map(|v| csv(v)).unwrap_or_default();
    let expires_at = flags.get("expires-at").map(String::as_str);
    let client = module.client();
    match module
        .call(client.rotate_cat(id, name, &scopes, expires_at))
        .await
    {
        Ok(new_token) => {
            let masked = mask_secret(&new_token.token);
            success(
                as_json,
                format!("token rotated: {masked} ({})", new_token.message),
                &json!({"token": masked, "message": new_token.message}),
            )
        }
        Err(err) => hub_error("rotate token failed", err),
    }
}

// ── announce ──────────────────────────────────────────────────────────

async fn dispatch_announce(
    module: &WaddlesGatewayModule,
    path: &[String],
    flags: &HashMap<String, String>,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    match path.get(1).map(String::as_str) {
        Some("list") => announce_list(module, flags, as_json).await,
        Some("show") => announce_show(module, args, as_json).await,
        Some("create") => announce_create(module, flags, as_json).await,
        Some("publish") => announce_publish(module, args, as_json).await,
        Some(other) => unknown_subcommand(other),
        None => usage_result("Usage: waddlebot announce {list|show <id>|create|publish <id>}"),
    }
}

fn announcement_json(a: &Announcement) -> Value {
    json!({
        "id": a.id, "title": a.title, "content": a.content, "status": a.status,
        "announcement_type": a.announcement_type, "is_pinned": a.is_pinned,
        "published_at": a.published_at, "archived_at": a.archived_at,
    })
}

async fn announce_list(
    module: &WaddlesGatewayModule,
    flags: &HashMap<String, String>,
    as_json: bool,
) -> CommandResult {
    let status = flags.get("status").map(String::as_str);
    let client = module.client();
    match module.call(client.list_announcements(status)).await {
        Ok(list) => {
            let text = if list.announcements.is_empty() {
                "no announcements".to_string()
            } else {
                list.announcements
                    .iter()
                    .map(|a| {
                        format!(
                            "{} [{}] {} (pinned={})",
                            a.id, a.status, a.title, a.is_pinned
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            let value = json!({
                "pagination": {
                    "page": list.pagination.page, "limit": list.pagination.limit,
                    "total": list.pagination.total, "total_pages": list.pagination.total_pages,
                },
                "announcements": list.announcements.iter().map(announcement_json).collect::<Vec<_>>(),
            });
            success(as_json, text, &value)
        }
        Err(err) => hub_error("list announcements failed", err),
    }
}

async fn announce_show(
    module: &WaddlesGatewayModule,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    let Some(raw_id) = args.first() else {
        return usage_result("Usage: waddlebot announce show <id>");
    };
    let Some(id) = parse_id(raw_id) else {
        return usage_result(format!("invalid announcement id: {raw_id}"));
    };
    let client = module.client();
    match module.call(client.get_announcement(id)).await {
        Ok(a) => success(
            as_json,
            format!("{}: {}\n{}", a.id, a.title, a.content),
            &announcement_json(&a),
        ),
        Err(err) => hub_error("show announcement failed", err),
    }
}

async fn announce_create(
    module: &WaddlesGatewayModule,
    flags: &HashMap<String, String>,
    as_json: bool,
) -> CommandResult {
    let Some(title) = flags.get("title") else {
        return usage_result(
            "Usage: waddlebot announce create --title T --content C [--type TYPE] [--pinned] [--status STATUS]",
        );
    };
    let Some(content) = flags.get("content") else {
        return usage_result(
            "Usage: waddlebot announce create --title T --content C [--type TYPE] [--pinned] [--status STATUS]",
        );
    };
    let announcement_type = flags.get("type").map(String::as_str);
    let is_pinned = flags.get("pinned").map(|v| v == "true");
    let status = flags.get("status").map(String::as_str);
    let new_announcement = NewAnnouncement {
        title,
        content,
        announcement_type,
        is_pinned,
        status,
    };
    let client = module.client();
    match module
        .call(client.create_announcement(&new_announcement))
        .await
    {
        Ok(a) => success(
            as_json,
            format!("announcement created: {} ({})", a.id, a.title),
            &announcement_json(&a),
        ),
        Err(err) => hub_error("create announcement failed", err),
    }
}

async fn announce_publish(
    module: &WaddlesGatewayModule,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    let Some(raw_id) = args.first() else {
        return usage_result("Usage: waddlebot announce publish <id>");
    };
    let Some(id) = parse_id(raw_id) else {
        return usage_result(format!("invalid announcement id: {raw_id}"));
    };
    let client = module.client();
    match module.call(client.publish_announcement(id)).await {
        Ok(a) => success(
            as_json,
            format!("announcement {} published", a.id),
            &announcement_json(&a),
        ),
        Err(err) => hub_error("publish announcement failed", err),
    }
}

// ── workflow (opaque JSON) ───────────────────────────────────────────

async fn dispatch_workflow(
    module: &WaddlesGatewayModule,
    path: &[String],
    args: &[String],
    as_json: bool,
) -> CommandResult {
    match path.get(1).map(String::as_str) {
        Some("list") => workflow_list(module, as_json).await,
        Some("show") => workflow_show(module, args, as_json).await,
        Some("create") => workflow_create(module, args, as_json).await,
        Some("update") => workflow_update(module, args, as_json).await,
        Some("delete") => workflow_delete(module, args, as_json).await,
        Some(other) => unknown_subcommand(other),
        None => usage_result(
            "Usage: waddlebot workflow {list|show <id>|create <json>|update <id> <json>|delete <id>}",
        ),
    }
}

fn parse_json_payload(raw: &str) -> Result<Value, CommandResult> {
    serde_json::from_str(raw).map_err(|err| usage_result(format!("invalid JSON payload: {err}")))
}

async fn workflow_list(module: &WaddlesGatewayModule, as_json: bool) -> CommandResult {
    let client = module.client();
    match module.call(client.list_workflows()).await {
        Ok(value) => success(as_json, pretty(&value), &value),
        Err(err) => hub_error("list workflows failed", err),
    }
}

async fn workflow_show(
    module: &WaddlesGatewayModule,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    let Some(id) = args.first() else {
        return usage_result("Usage: waddlebot workflow show <id>");
    };
    let client = module.client();
    match module.call(client.get_workflow(id)).await {
        Ok(value) => success(as_json, pretty(&value), &value),
        Err(err) => hub_error("show workflow failed", err),
    }
}

async fn workflow_create(
    module: &WaddlesGatewayModule,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    let Some(raw_payload) = args.first() else {
        return usage_result("Usage: waddlebot workflow create <payload-json>");
    };
    let payload = match parse_json_payload(raw_payload) {
        Ok(payload) => payload,
        Err(result) => return result,
    };
    let client = module.client();
    match module.call(client.create_workflow(&payload)).await {
        Ok(value) => success(as_json, pretty(&value), &value),
        Err(err) => hub_error("create workflow failed", err),
    }
}

async fn workflow_update(
    module: &WaddlesGatewayModule,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    let (Some(id), Some(raw_payload)) = (args.first(), args.get(1)) else {
        return usage_result("Usage: waddlebot workflow update <id> <payload-json>");
    };
    let payload = match parse_json_payload(raw_payload) {
        Ok(payload) => payload,
        Err(result) => return result,
    };
    let client = module.client();
    match module.call(client.update_workflow(id, &payload)).await {
        Ok(value) => success(as_json, pretty(&value), &value),
        Err(err) => hub_error("update workflow failed", err),
    }
}

async fn workflow_delete(
    module: &WaddlesGatewayModule,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    let Some(id) = args.first() else {
        return usage_result("Usage: waddlebot workflow delete <id>");
    };
    let client = module.client();
    match module.call(client.delete_workflow(id)).await {
        Ok(value) => success(as_json, pretty(&value), &value),
        Err(err) => hub_error("delete workflow failed", err),
    }
}

// ── loyalty (opaque JSON) ────────────────────────────────────────────

async fn dispatch_loyalty(
    module: &WaddlesGatewayModule,
    path: &[String],
    args: &[String],
    as_json: bool,
) -> CommandResult {
    match path.get(1).map(String::as_str) {
        Some("config") => loyalty_config(module, args, as_json).await,
        Some("adjust") => loyalty_adjust(module, args, as_json).await,
        Some(other) => unknown_subcommand(other),
        None => usage_result(
            "Usage: waddlebot loyalty {config [payload-json]|adjust <user_id> <payload-json>}",
        ),
    }
}

/// `waddlebot loyalty config [payload-json]`: no payload reads the current
/// config, a payload sends it as a `PUT`.
async fn loyalty_config(
    module: &WaddlesGatewayModule,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    let client = module.client();
    if let Some(raw_payload) = args.first() {
        let payload = match parse_json_payload(raw_payload) {
            Ok(payload) => payload,
            Err(result) => return result,
        };
        return match module.call(client.update_loyalty_config(&payload)).await {
            Ok(value) => success(as_json, pretty(&value), &value),
            Err(err) => hub_error("update loyalty config failed", err),
        };
    }
    match module.call(client.get_loyalty_config()).await {
        Ok(value) => success(as_json, pretty(&value), &value),
        Err(err) => hub_error("get loyalty config failed", err),
    }
}

async fn loyalty_adjust(
    module: &WaddlesGatewayModule,
    args: &[String],
    as_json: bool,
) -> CommandResult {
    let (Some(raw_user_id), Some(raw_payload)) = (args.first(), args.get(1)) else {
        return usage_result("Usage: waddlebot loyalty adjust <user_id> <payload-json>");
    };
    if raw_user_id.trim().is_empty() {
        return usage_result(format!("invalid user id: {raw_user_id}"));
    }
    let payload = match parse_json_payload(raw_payload) {
        Ok(payload) => payload,
        Err(result) => return result,
    };
    let client = module.client();
    match module
        .call(client.adjust_loyalty_balance(raw_user_id, &payload))
        .await
    {
        Ok(value) => success(as_json, pretty(&value), &value),
        Err(err) => hub_error("adjust loyalty balance failed", err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeHost, MockHub, MockResponse};
    use penguin_sdk::{Module, SecretStore};
    use std::sync::Arc;

    const TEST_COMMUNITY_UUID: &str = "11111111-1111-4111-8111-111111111111";

    fn config_bytes(hub_base_url: &str, community_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "hub": {"base_url": hub_base_url},
            "community_id": community_id,
        }))
        .unwrap()
    }

    async fn init_module(hub: &MockHub) -> WaddlesGatewayModule {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.secrets
            .set("cat", b"wdl_c_supersecrettoken")
            .await
            .unwrap();
        host.config = config_bytes(&hub.base_url, TEST_COMMUNITY_UUID);
        let module = WaddlesGatewayModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");
        module
    }

    #[test]
    fn command_tree_declares_every_top_level_command() {
        let tree = command_tree();
        let names: Vec<&str> = tree.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "status",
                "auth",
                "bridge",
                "community",
                "music",
                "browser-sources",
                "token",
                "announce",
                "workflow",
                "loyalty",
            ]
        );
    }

    #[test]
    fn regenerate_and_publish_are_the_only_tray_commands() {
        let tree = command_tree();
        let browser_sources = tree.iter().find(|c| c.name == "browser-sources").unwrap();
        let regenerate = browser_sources
            .subcommands
            .iter()
            .find(|c| c.name == "regenerate")
            .unwrap();
        assert!(regenerate.tray);
        let list = browser_sources
            .subcommands
            .iter()
            .find(|c| c.name == "list")
            .unwrap();
        assert!(!list.tray);

        let announce = tree.iter().find(|c| c.name == "announce").unwrap();
        let publish = announce
            .subcommands
            .iter()
            .find(|c| c.name == "publish")
            .unwrap();
        assert!(publish.tray);
    }

    #[test]
    fn every_leaf_command_declares_a_json_flag() {
        fn assert_leaves_have_json(specs: &[CommandSpec]) {
            for spec in specs {
                if spec.subcommands.is_empty() {
                    assert!(
                        spec.flags.iter().any(|f| f.name == "json"),
                        "{} is missing --json",
                        spec.name
                    );
                } else {
                    assert_leaves_have_json(&spec.subcommands);
                }
            }
        }
        assert_leaves_have_json(&command_tree());
    }

    #[tokio::test]
    async fn dispatch_status_reports_state_as_json() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/communities/my",
            MockResponse::json(200, r#"{"success":true,"communities":[]}"#),
        )
        .await;
        let module = init_module(&hub).await;

        let mut flags = HashMap::new();
        flags.insert("json".to_string(), "true".to_string());
        let result = dispatch(&module, &["status".to_string()], &flags, &[])
            .await
            .unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(!result.json.is_empty());
        assert!(result.output.contains("\"state\""));

        hub.stop().await;
    }

    #[tokio::test]
    async fn community_list_hits_the_hub_and_formats_output() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/communities/my",
            MockResponse::json(
                200,
                r#"{"success":true,"communities":[{"id":"11111111-1111-4111-8111-111111111111","name":"c","displayName":"Community","role":"admin"}]}"#,
            ),
        )
        .await;
        let module = init_module(&hub).await;

        let result = dispatch(
            &module,
            &["community".to_string(), "list".to_string()],
            &HashMap::new(),
            &[],
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("Community"));

        hub.stop().await;
    }

    #[tokio::test]
    async fn community_use_rejects_an_invalid_uuid() {
        let hub = MockHub::start().await;
        let module = init_module(&hub).await;

        let result = dispatch(
            &module,
            &["community".to_string(), "use".to_string()],
            &HashMap::new(),
            &["not-a-uuid".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, 1);
        assert!(result.output.contains("invalid community id"));

        let ok = dispatch(
            &module,
            &["community".to_string(), "use".to_string()],
            &HashMap::new(),
            &["22222222-2222-4222-8222-222222222222".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(ok.exit_code, 0);
        assert_eq!(
            module.community_id(),
            "22222222-2222-4222-8222-222222222222"
        );

        hub.stop().await;
    }

    #[tokio::test]
    async fn music_settings_with_no_flags_sends_a_get() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/admin/11111111-1111-4111-8111-111111111111/music/settings",
            MockResponse::json(
                200,
                r#"{"success":true,"settings":{"id":1,"communityId":"11111111-1111-4111-8111-111111111111","autoplayEnabled":true,"volumeLimit":80,"requireDjApproval":false,"isActive":true}}"#,
            ),
        )
        .await;
        let module = init_module(&hub).await;

        let result = dispatch(
            &module,
            &["music".to_string(), "settings".to_string()],
            &HashMap::new(),
            &[],
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(
            hub.request_count(
                "GET",
                "/admin/11111111-1111-4111-8111-111111111111/music/settings"
            )
            .await,
            1
        );
        assert_eq!(
            hub.request_count(
                "PUT",
                "/admin/11111111-1111-4111-8111-111111111111/music/settings"
            )
            .await,
            0
        );

        hub.stop().await;
    }

    #[tokio::test]
    async fn music_settings_with_a_flag_sends_a_put_carrying_only_that_field() {
        let hub = MockHub::start().await;
        hub.respond(
            "PUT",
            "/admin/11111111-1111-4111-8111-111111111111/music/settings",
            MockResponse::json(
                200,
                r#"{"success":true,"settings":{"id":1,"communityId":"11111111-1111-4111-8111-111111111111","autoplayEnabled":true,"volumeLimit":50,"requireDjApproval":false,"isActive":true}}"#,
            ),
        )
        .await;
        let module = init_module(&hub).await;

        let mut flags = HashMap::new();
        flags.insert("volume-limit".to_string(), "50".to_string());
        let result = dispatch(
            &module,
            &["music".to_string(), "settings".to_string()],
            &flags,
            &[],
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, 0);

        let requests = hub.requests().await;
        let put = requests
            .iter()
            .find(|r| r.method == "PUT")
            .expect("a PUT was sent");
        let body = put.json_body();
        assert_eq!(body["volumeLimit"], 50);
        assert!(
            body.get("autoplayEnabled").is_none(),
            "unset fields must be omitted"
        );

        hub.stop().await;
    }

    #[tokio::test]
    async fn browser_sources_regenerate_is_wired_to_the_hub() {
        let hub = MockHub::start().await;
        hub.respond(
            "POST",
            "/admin/11111111-1111-4111-8111-111111111111/browser-sources/regenerate",
            MockResponse::json(200, r#"{"success":true,"message":"regenerated"}"#),
        )
        .await;
        let module = init_module(&hub).await;

        let result = dispatch(
            &module,
            &["browser-sources".to_string(), "regenerate".to_string()],
            &HashMap::new(),
            &[],
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("regenerated"));

        hub.stop().await;
    }

    /// The critical secret-hygiene test: a freshly minted CAT must never
    /// appear unmasked in either `output` or `json`.
    #[tokio::test]
    async fn token_create_never_prints_the_raw_cat() {
        let hub = MockHub::start().await;
        let raw_token = "wdl_c_ABSOLUTELY_SECRET_VALUE_1234";
        hub.respond(
            "POST",
            "/admin/11111111-1111-4111-8111-111111111111/tokens/cats",
            MockResponse::json(
                200,
                format!(r#"{{"token":"{raw_token}","message":"created"}}"#),
            ),
        )
        .await;
        let module = init_module(&hub).await;

        let result = dispatch(
            &module,
            &["token".to_string(), "create".to_string()],
            &HashMap::new(),
            &["new-token".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(!result.output.contains(raw_token));
        let json_text = String::from_utf8_lossy(&result.json);
        assert!(!json_text.contains(raw_token));
        assert!(result.output.contains("****"));

        hub.stop().await;
    }

    #[tokio::test]
    async fn token_rotate_never_prints_the_raw_cat() {
        let hub = MockHub::start().await;
        hub.respond(
            "DELETE",
            "/admin/11111111-1111-4111-8111-111111111111/tokens/cats/5",
            MockResponse::json(200, r#"{"message":"revoked"}"#),
        )
        .await;
        let raw_token = "wdl_c_ANOTHER_SECRET_VALUE_5678";
        hub.respond(
            "POST",
            "/admin/11111111-1111-4111-8111-111111111111/tokens/cats",
            MockResponse::json(
                200,
                format!(r#"{{"token":"{raw_token}","message":"rotated"}}"#),
            ),
        )
        .await;
        let module = init_module(&hub).await;

        let mut flags = HashMap::new();
        flags.insert("name".to_string(), "replacement".to_string());
        let result = dispatch(
            &module,
            &["token".to_string(), "rotate".to_string()],
            &flags,
            &["5".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(!result.output.contains(raw_token));
        assert!(!String::from_utf8_lossy(&result.json).contains(raw_token));

        hub.stop().await;
    }

    #[tokio::test]
    async fn token_rotate_without_a_name_flag_is_a_usage_error() {
        let hub = MockHub::start().await;
        let module = init_module(&hub).await;
        let result = dispatch(
            &module,
            &["token".to_string(), "rotate".to_string()],
            &HashMap::new(),
            &["5".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, 1);
        assert!(result.output.contains("Usage"));
        hub.stop().await;
    }

    #[tokio::test]
    async fn announce_create_then_publish_round_trip() {
        let hub = MockHub::start().await;
        hub.respond(
            "POST",
            "/admin/11111111-1111-4111-8111-111111111111/announcements",
            MockResponse::json(
                200,
                r#"{"data":{"id":9,"communityId":"11111111-1111-4111-8111-111111111111","title":"Hi","content":"Body","announcementType":"general","status":"draft","isPinned":false}}"#,
            ),
        )
        .await;
        hub.respond(
            "POST",
            "/admin/11111111-1111-4111-8111-111111111111/announcements/9/publish",
            MockResponse::json(
                200,
                r#"{"data":{"id":9,"communityId":"11111111-1111-4111-8111-111111111111","title":"Hi","content":"Body","announcementType":"general","status":"published","isPinned":false}}"#,
            ),
        )
        .await;
        let module = init_module(&hub).await;

        let mut flags = HashMap::new();
        flags.insert("title".to_string(), "Hi".to_string());
        flags.insert("content".to_string(), "Body".to_string());
        let created = dispatch(
            &module,
            &["announce".to_string(), "create".to_string()],
            &flags,
            &[],
        )
        .await
        .unwrap();
        assert_eq!(created.exit_code, 0);

        let published = dispatch(
            &module,
            &["announce".to_string(), "publish".to_string()],
            &HashMap::new(),
            &["9".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(published.exit_code, 0);
        assert!(published.output.contains("published"));

        hub.stop().await;
    }

    #[tokio::test]
    async fn workflow_create_rejects_invalid_json_without_calling_the_hub() {
        let hub = MockHub::start().await;
        let module = init_module(&hub).await;

        let result = dispatch(
            &module,
            &["workflow".to_string(), "create".to_string()],
            &HashMap::new(),
            &["{not valid json".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, 1);
        assert!(result.output.contains("invalid JSON"));
        assert_eq!(hub.requests().await.len(), 0);

        hub.stop().await;
    }

    #[tokio::test]
    async fn workflow_show_pretty_prints_the_opaque_payload() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/admin/11111111-1111-4111-8111-111111111111/workflows/wf-1",
            MockResponse::json(200, r#"{"id":"wf-1","steps":[{"type":"trigger"}]}"#),
        )
        .await;
        let module = init_module(&hub).await;

        let result = dispatch(
            &module,
            &["workflow".to_string(), "show".to_string()],
            &HashMap::new(),
            &["wf-1".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("wf-1"));
        assert!(result.output.contains('\n'), "must be pretty-printed");

        hub.stop().await;
    }

    #[tokio::test]
    async fn loyalty_config_with_no_payload_is_a_get_with_a_payload_is_a_put() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/admin/11111111-1111-4111-8111-111111111111/loyalty/config",
            MockResponse::json(200, r#"{"pointsPerMessage":1}"#),
        )
        .await;
        hub.respond(
            "PUT",
            "/admin/11111111-1111-4111-8111-111111111111/loyalty/config",
            MockResponse::json(200, r#"{"pointsPerMessage":2}"#),
        )
        .await;
        let module = init_module(&hub).await;

        let get_result = dispatch(
            &module,
            &["loyalty".to_string(), "config".to_string()],
            &HashMap::new(),
            &[],
        )
        .await
        .unwrap();
        assert_eq!(get_result.exit_code, 0);

        let put_result = dispatch(
            &module,
            &["loyalty".to_string(), "config".to_string()],
            &HashMap::new(),
            &[r#"{"pointsPerMessage":2}"#.to_string()],
        )
        .await
        .unwrap();
        assert_eq!(put_result.exit_code, 0);

        assert_eq!(
            hub.request_count(
                "GET",
                "/admin/11111111-1111-4111-8111-111111111111/loyalty/config"
            )
            .await,
            1
        );
        assert_eq!(
            hub.request_count(
                "PUT",
                "/admin/11111111-1111-4111-8111-111111111111/loyalty/config"
            )
            .await,
            1
        );

        hub.stop().await;
    }

    #[tokio::test]
    async fn loyalty_adjust_parses_user_id_and_payload() {
        let hub = MockHub::start().await;
        hub.respond(
            "PUT",
            "/admin/11111111-1111-4111-8111-111111111111/loyalty/user/discord_42/balance",
            MockResponse::json(200, r#"{"balance":150}"#),
        )
        .await;
        let module = init_module(&hub).await;

        let result = dispatch(
            &module,
            &["loyalty".to_string(), "adjust".to_string()],
            &HashMap::new(),
            &["discord_42".to_string(), r#"{"delta":50}"#.to_string()],
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("150"));

        hub.stop().await;
    }

    #[tokio::test]
    async fn unknown_top_level_command_is_a_nonzero_exit() {
        let hub = MockHub::start().await;
        let module = init_module(&hub).await;
        let result = dispatch(&module, &["bogus".to_string()], &HashMap::new(), &[])
            .await
            .unwrap();
        assert_eq!(result.exit_code, 1);
        hub.stop().await;
    }

    #[tokio::test]
    async fn unknown_subcommand_is_a_nonzero_exit() {
        let hub = MockHub::start().await;
        let module = init_module(&hub).await;
        let result = dispatch(
            &module,
            &["music".to_string(), "bogus".to_string()],
            &HashMap::new(),
            &[],
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, 1);
        hub.stop().await;
    }

    #[tokio::test]
    async fn a_successful_call_increments_the_requests_metric() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/communities/my",
            MockResponse::json(200, r#"{"success":true,"communities":[]}"#),
        )
        .await;
        let module = init_module(&hub).await;
        let before = module.metrics().api_requests_total.get();

        dispatch(
            &module,
            &["community".to_string(), "list".to_string()],
            &HashMap::new(),
            &[],
        )
        .await
        .unwrap();

        assert_eq!(module.metrics().api_requests_total.get(), before + 1.0);
        assert_eq!(module.metrics().api_errors_total.get(), 0.0);

        hub.stop().await;
    }

    #[tokio::test]
    async fn a_failed_call_increments_the_errors_metric() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/communities/my",
            MockResponse::json(401, r#"{"error":"unauthorized"}"#),
        )
        .await;
        let module = init_module(&hub).await;

        let result = dispatch(
            &module,
            &["community".to_string(), "list".to_string()],
            &HashMap::new(),
            &[],
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, 1);
        assert_eq!(module.metrics().api_errors_total.get(), 1.0);

        hub.stop().await;
    }
}
