//! `pdcli hub ...` — pure request shaping, response parsing and rendering for
//! the hub-api admin surface (`services/hub-api/openapi/v1.yaml`).
//!
//! Nothing here performs I/O: the clap subtree, the mapping from parsed
//! arguments to an HTTP request, the `{status,data,meta}` envelope parser,
//! the OIDC device-flow form/response handling, the signed-module checks and
//! the table/JSON rendering are all functions over data. `bins/pdcli` owns
//! the HTTP transport, the OS keychain and stdin/stdout.

use std::fmt;

use base64::Engine as _;
use clap::{Arg, ArgAction, ArgMatches, Command};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use url::Url;

/// Environment variable consulted when `--hub-url` is absent.
pub const HUB_URL_ENV: &str = "PDCLI_HUB_URL";
/// Environment variable consulted when `hub login --issuer` is absent.
pub const ISSUER_ENV: &str = "PDCLI_OIDC_ISSUER";
/// Environment variable consulted when `hub login --client-id` is absent.
pub const CLIENT_ID_ENV: &str = "PDCLI_OIDC_CLIENT_ID";
/// OIDC client id used when neither flag nor env var supplies one.
pub const DEFAULT_CLIENT_ID: &str = "pdcli";
/// Every scope the admin CLI can exercise, requested at login.
pub const LOGIN_SCOPES: &str = "openid offline_access hub:groups:read hub:groups:write \
hub:agents:read hub:agents:write hub:modules:read hub:modules:write hub:flags:read \
hub:flags:write hub:bootstrap:read hub:bootstrap:write";
/// Prefix of every admin API path in the contract.
const API_PREFIX: &str = "/api/v1";
/// Domain-separation header of the minisign-signed module message.
const SIGNED_MESSAGE_HEADER: &str = "penguin-wasm-module/v1";
/// Hub-side upload ceiling (ModuleUpload.binary, 64 MiB) checked before upload.
pub const MAX_MODULE_BYTES: usize = 64 * 1024 * 1024;
/// Device-flow grant type (RFC 8628).
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Every way a hub command can fail; each maps to a clear message and a
/// non-zero exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubError {
    /// Bad arguments or inputs (exit 2).
    Usage(String),
    /// Missing or invalid configuration (hub URL, issuer).
    Config(String),
    /// No usable credentials.
    Auth(String),
    /// The hub answered with a non-2xx status.
    Api {
        /// HTTP status code.
        status: u16,
        /// Human-readable message built from the problem details.
        message: String,
    },
    /// Network / TLS failure before an HTTP status was received.
    Transport(String),
    /// The hub answered 2xx but not in the contracted shape.
    Protocol(String),
    /// Module signature missing, malformed or not verifying.
    Signature(String),
    /// Local file or keychain failure.
    Io(String),
}

impl HubError {
    /// Process exit code for this error: 2 for usage, 1 otherwise.
    pub fn exit_code(&self) -> u8 {
        match self {
            HubError::Usage(_) => 2,
            _ => 1,
        }
    }
}

impl fmt::Display for HubError {
    /// Renders the message shown to the operator after `pdcli: hub: `.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HubError::Usage(m) => write!(f, "{m}"),
            HubError::Config(m) => write!(f, "configuration error: {m}"),
            HubError::Auth(m) => write!(f, "{m}"),
            HubError::Api { message, .. } => write!(f, "{message}"),
            HubError::Transport(m) => write!(f, "cannot reach hub: {m}"),
            HubError::Protocol(m) => write!(f, "unexpected hub response: {m}"),
            HubError::Signature(m) => write!(f, "signature error: {m}"),
            HubError::Io(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for HubError {}

/// HTTP method of a shaped request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// GET.
    Get,
    /// POST.
    Post,
    /// PUT.
    Put,
    /// PATCH.
    Patch,
    /// DELETE.
    Delete,
}

impl Method {
    /// Upper-case method token for the transport.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }
}

/// Request body variants the hub contract uses.
#[derive(Debug, Clone, PartialEq)]
pub enum Body {
    /// No body.
    Empty,
    /// `application/json`.
    Json(Value),
    /// `application/x-www-form-urlencoded` (OIDC endpoints).
    Form(String),
    /// `multipart/form-data` with its full content type (boundary included).
    Multipart {
        /// Content-Type header value.
        content_type: String,
        /// Encoded body.
        bytes: Vec<u8>,
    },
}

/// A fully shaped HTTP request, independent of any HTTP library.
#[derive(Debug, Clone, PartialEq)]
pub struct HubRequest {
    /// HTTP method.
    pub method: Method,
    /// Path relative to the hub URL, or an absolute URL (OIDC endpoints).
    pub path: String,
    /// Query parameters, in order.
    pub query: Vec<(String, String)>,
    /// Body.
    pub body: Body,
}

impl HubRequest {
    /// Builds a body-less request with no query parameters.
    fn new(method: Method, path: String) -> HubRequest {
        HubRequest {
            method,
            path,
            query: Vec::new(),
            body: Body::Empty,
        }
    }

    /// Attaches a JSON body.
    fn json(mut self, value: Value) -> HubRequest {
        self.body = Body::Json(value);
        self
    }

    /// Resolves the request against `base` into the final URL, query included.
    pub fn url(&self, base: &Url) -> Result<Url, HubError> {
        let mut url = if self.path.starts_with("https://") || self.path.starts_with("http://") {
            Url::parse(&self.path)
                .map_err(|e| HubError::Config(format!("bad URL {}: {e}", self.path)))?
        } else {
            let mut joined = base.clone();
            let prefix = base.path().trim_end_matches('/');
            joined.set_path(&format!("{prefix}{}", self.path));
            joined
        };
        if !self.query.is_empty() {
            url.query_pairs_mut().extend_pairs(self.query.iter());
        }
        Ok(url)
    }
}

/// What a response's `data` describes — selects the table columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Group or page of groups.
    Group,
    /// Agent or page of agents.
    Agent,
    /// Module version or page of module versions.
    Module,
    /// Bootstrap token (agent enrollment credential).
    BootstrapToken,
    /// Group module assignments.
    Assignment,
    /// A ConfigPolicy document.
    Policy,
    /// Hub flag.
    Flag,
    /// Group membership set.
    Members,
    /// Audit events.
    Audit,
    /// No content expected (204).
    Done,
}

/// Target of a policy-changing command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyTarget {
    /// A per-agent override (`PUT /agents/{id}/override`).
    Agent(String),
    /// A group policy (`PATCH /groups/{id}`).
    Group(String),
}

/// A parsed `pdcli hub ...` invocation.
#[derive(Debug, Clone, PartialEq)]
pub enum HubAction {
    /// OIDC device-flow login.
    Login {
        /// Issuer flag, if given.
        issuer: Option<String>,
        /// Client id flag, if given.
        client_id: Option<String>,
    },
    /// Remove the stored token.
    Logout,
    /// Show the stored token's identity claims.
    Whoami,
    /// A single API call.
    Call(HubRequest, Kind),
    /// `module publish`: needs the wasm and manifest files read first.
    Publish {
        /// WASM file path.
        wasm: String,
        /// Signed manifest JSON path.
        manifest: String,
        /// Optional minisign public key file for local verification.
        pubkey: Option<String>,
    },
    /// `config set`: needs the policy file read first.
    ConfigSet {
        /// Agent override or group policy.
        target: PolicyTarget,
        /// Policy JSON path.
        file: String,
    },
    /// `limits set`: read-modify-write of the target's `limits`.
    LimitsSet {
        /// Agent override or group policy.
        target: PolicyTarget,
        /// Limits fields to set.
        limits: Map<String, Value>,
    },
}

/// Numeric `limits` fields with their contract bounds.
const LIMIT_FIELDS: [(&str, u64, u64); 6] = [
    ("max_memory_mb", 1, u64::MAX),
    ("max_fuel", 1, u64::MAX),
    ("max_tool_calls_per_min", 1, u64::MAX),
    ("max_concurrent_instances", 1, u64::MAX),
    ("poll_interval_s", 60, 86_400),
    ("max_stale_s", 300, u64::MAX),
];

/// Builds the `hub` subtree grafted onto the static root.
pub fn build_hub_command() -> Command {
    Command::new("hub")
        .about("Manage the penguind hub (admin)")
        .subcommand_required(true)
        .arg(
            Arg::new("hub-url")
                .long("hub-url")
                .global(true)
                .num_args(1)
                .help("hub base URL (default: $PDCLI_HUB_URL)"),
        )
        .subcommand(
            Command::new("login")
                .about("Log in via OIDC device flow; token stored in the OS keychain")
                .arg(opt(
                    "issuer",
                    "OIDC issuer URL (default: $PDCLI_OIDC_ISSUER)",
                ))
                .arg(opt(
                    "client-id",
                    "OIDC client id (default: $PDCLI_OIDC_CLIENT_ID or pdcli)",
                )),
        )
        .subcommand(Command::new("logout").about("Remove the stored hub token"))
        .subcommand(Command::new("whoami").about("Show the logged-in identity"))
        .subcommand(
            Command::new("module")
                .about("Signed WASM modules")
                .subcommand_required(true)
                .subcommand(
                    paged(Command::new("list").about("List module versions"))
                        .arg(opt("module-id", "filter by module id"))
                        .arg(opt("status", "available|yanked")),
                )
                .subcommand(
                    Command::new("show")
                        .about("Show a module version")
                        .arg(pos("id")),
                )
                .subcommand(
                    Command::new("publish")
                        .about("Upload a wasm file with its pre-signed manifest")
                        .arg(pos("wasm"))
                        .arg(opt("manifest", "signed manifest JSON").required(true))
                        .arg(opt("pubkey", "minisign public key file to verify locally")),
                )
                .subcommand(
                    Command::new("revoke")
                        .about("Yank a module version")
                        .arg(pos("id")),
                ),
        )
        .subcommand(
            Command::new("agent")
                .about("Enrolled agents")
                .subcommand_required(true)
                .subcommand(
                    paged(Command::new("list").about("List agents"))
                        .arg(opt("group", "filter by group id"))
                        .arg(opt("status", "active|stale|revoked")),
                )
                .subcommand(Command::new("show").about("Show an agent").arg(pos("id")))
                .subcommand(
                    Command::new("create")
                        .about("Mint a one-time enrollment token for a new agent")
                        .arg(opt("group", "group to join (repeatable)").action(ArgAction::Append))
                        .arg(
                            opt("ttl", "token lifetime in seconds (60..604800)")
                                .value_parser(clap::value_parser!(u64).range(60..=604_800)),
                        ),
                )
                .subcommand(
                    Command::new("disable")
                        .about("Revoke an agent")
                        .arg(pos("id")),
                )
                .subcommand(
                    Command::new("token")
                        .about("Enrollment tokens")
                        .subcommand_required(true)
                        .subcommand(paged(Command::new("list").about("List enrollment tokens")))
                        .subcommand(
                            Command::new("revoke")
                                .about("Revoke an enrollment token")
                                .arg(pos("id")),
                        ),
                ),
        )
        .subcommand(
            Command::new("group")
                .about("Agent groups")
                .subcommand_required(true)
                .subcommand(
                    paged(Command::new("list").about("List groups"))
                        .arg(opt("name-prefix", "filter by name prefix")),
                )
                .subcommand(
                    Command::new("create")
                        .about("Create a group")
                        .arg(pos("name"))
                        .arg(opt("description", "description")),
                )
                .subcommand(Command::new("show").about("Show a group").arg(pos("id")))
                .subcommand(
                    Command::new("edit")
                        .about("Rename or re-describe a group")
                        .arg(pos("id"))
                        .arg(opt("name", "new name"))
                        .arg(opt("description", "new description")),
                )
                .subcommand(
                    Command::new("delete")
                        .about("Delete a group")
                        .arg(pos("id")),
                )
                .subcommand(
                    Command::new("members")
                        .about("Replace a group's members")
                        .arg(pos("id"))
                        .arg(
                            Arg::new("agents")
                                .num_args(0..)
                                .help("agent ids (none = empty group)"),
                        ),
                ),
        )
        .subcommand(
            Command::new("assign")
                .about("Show or replace a group's module assignments")
                .arg(pos("group"))
                .arg(Arg::new("modules").num_args(0..).help("module version ids"))
                .arg(flag("clear", "remove every assignment")),
        )
        .subcommand(
            Command::new("config")
                .about("Agent overrides and group policies")
                .subcommand_required(true)
                .subcommand(
                    Command::new("show")
                        .about("Show an agent's effective config")
                        .arg(pos("agent")),
                )
                .subcommand(
                    target_args(Command::new("set").about("Replace an override or group policy"))
                        .arg(opt("file", "ConfigPolicy JSON file").required(true)),
                )
                .subcommand(
                    Command::new("clear")
                        .about("Clear an agent override")
                        .arg(pos("agent")),
                ),
        )
        .subcommand(
            Command::new("flags")
                .about("Restrict-only hub feature flags")
                .subcommand_required(true)
                .subcommand(
                    paged(Command::new("list").about("List flags"))
                        .arg(opt("group", "filter by group id")),
                )
                .subcommand(
                    Command::new("set")
                        .about("Create or update a flag")
                        .arg(pos("key"))
                        .arg(
                            opt("enabled", "true = defer to license, false = force off")
                                .required(true)
                                .value_parser(clap::value_parser!(bool)),
                        )
                        .arg(opt("group", "scope to a group (default: tenant)")),
                )
                .subcommand(Command::new("delete").about("Delete a flag").arg(pos("id"))),
        )
        .subcommand(
            Command::new("limits")
                .about("Numeric ceilings")
                .subcommand_required(true)
                .subcommand(limit_args(target_args(
                    Command::new("set").about("Set limits on an agent or group"),
                ))),
        )
        .subcommand(
            paged(Command::new("audit").about("List hub audit events"))
                .arg(opt("since", "RFC 3339 lower bound")),
        )
}

/// A required positional argument.
fn pos(id: &'static str) -> Arg {
    Arg::new(id).required(true).num_args(1)
}

/// An optional `--id <value>` argument.
fn opt(id: &'static str, help: &'static str) -> Arg {
    Arg::new(id).long(id).num_args(1).help(help)
}

/// A boolean `--id` switch.
fn flag(id: &'static str, help: &'static str) -> Arg {
    Arg::new(id)
        .long(id)
        .num_args(0)
        .action(ArgAction::SetTrue)
        .help(help)
}

/// Adds `--limit`/`--cursor` paging arguments.
fn paged(cmd: Command) -> Command {
    cmd.arg(opt("limit", "page size").value_parser(clap::value_parser!(u32).range(1..=500)))
        .arg(opt("cursor", "cursor from a previous page"))
}

/// Adds the mutually exclusive, required `--agent`/`--group` target.
fn target_args(cmd: Command) -> Command {
    cmd.arg(opt("agent", "agent id").conflicts_with("group"))
        .arg(opt("group", "group id"))
        .group(
            clap::ArgGroup::new("target")
                .args(["agent", "group"])
                .required(true),
        )
}

/// Adds one `--<limit>` argument per contract limits field.
fn limit_args(mut cmd: Command) -> Command {
    for (name, min, max) in LIMIT_FIELDS {
        let id = name.replace('_', "-");
        cmd = cmd.arg(
            Arg::new(name)
                .long(id)
                .num_args(1)
                .value_parser(clap::value_parser!(u64).range(min..=max)),
        );
    }
    cmd
}

/// Resolves the hub base URL from the flag or env var; requires https except
/// for loopback hosts (local development and tests).
pub fn resolve_hub_url(flag: Option<&str>, env: Option<&str>) -> Result<Url, HubError> {
    let raw = flag
        .or(env)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            HubError::Config(format!("no hub URL: pass --hub-url or set {HUB_URL_ENV}"))
        })?;
    let url = Url::parse(raw.trim())
        .map_err(|e| HubError::Config(format!("invalid hub URL {raw:?}: {e}")))?;
    require_secure(&url)?;
    Ok(url)
}

/// Rejects non-https URLs unless they point at a loopback host.
pub fn require_secure(url: &Url) -> Result<(), HubError> {
    let loopback = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    match url.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        other => Err(HubError::Config(format!(
            "{url} uses {other}; only https is allowed (http for loopback only)"
        ))),
    }
}

/// Checks that `id` is a canonical UUID before it becomes a path segment.
pub fn validate_uuid(field: &str, id: &str) -> Result<(), HubError> {
    let bytes = id.as_bytes();
    let ok = bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    if ok {
        Ok(())
    } else {
        Err(HubError::Usage(format!(
            "{field} must be a UUID, got {id:?}"
        )))
    }
}

/// Fetches a string argument by id.
fn s(m: &ArgMatches, id: &str) -> Option<String> {
    m.get_one::<String>(id).cloned()
}

/// Fetches a required string argument (clap guarantees presence).
fn req(m: &ArgMatches, id: &str) -> Result<String, HubError> {
    s(m, id).ok_or_else(|| HubError::Usage(format!("missing <{id}>")))
}

/// Fetches a required UUID argument and validates it.
fn req_uuid(m: &ArgMatches, id: &str) -> Result<String, HubError> {
    let v = req(m, id)?;
    validate_uuid(id, &v)?;
    Ok(v)
}

/// Fetches an optional UUID argument and validates it.
fn opt_uuid(m: &ArgMatches, id: &str) -> Result<Option<String>, HubError> {
    match s(m, id) {
        Some(v) => {
            validate_uuid(id, &v)?;
            Ok(Some(v))
        }
        None => Ok(None),
    }
}

/// Appends `--limit`/`--cursor` to the query.
fn page_query(m: &ArgMatches, q: &mut Vec<(String, String)>) {
    if let Some(l) = m.get_one::<u32>("limit") {
        q.push(("limit".into(), l.to_string()));
    }
    if let Some(c) = s(m, "cursor") {
        q.push(("cursor".into(), c));
    }
}

/// Maps a named status to its contract int enum code.
fn status_code(name: &str, table: &[(&str, u8)]) -> Result<String, HubError> {
    table
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, c)| c.to_string())
        .ok_or_else(|| {
            let names: Vec<&str> = table.iter().map(|(n, _)| *n).collect();
            HubError::Usage(format!("status must be one of {}", names.join("|")))
        })
}

/// Reads the target of a `--agent`/`--group` command.
fn policy_target(m: &ArgMatches) -> Result<PolicyTarget, HubError> {
    if let Some(a) = opt_uuid(m, "agent")? {
        return Ok(PolicyTarget::Agent(a));
    }
    match opt_uuid(m, "group")? {
        Some(g) => Ok(PolicyTarget::Group(g)),
        None => Err(HubError::Usage(
            "one of --agent or --group is required".into(),
        )),
    }
}

/// Turns the `hub` subcommand's matches into an action.
pub fn parse_action(hub: &ArgMatches) -> Result<HubAction, HubError> {
    let (name, m) = hub
        .subcommand()
        .ok_or_else(|| HubError::Usage("missing hub subcommand".into()))?;
    let call = |r: HubRequest, k: Kind| Ok(HubAction::Call(r, k));
    let p = |rest: &str| format!("{API_PREFIX}{rest}");
    match name {
        "login" => Ok(HubAction::Login {
            issuer: s(m, "issuer"),
            client_id: s(m, "client-id"),
        }),
        "logout" => Ok(HubAction::Logout),
        "whoami" => Ok(HubAction::Whoami),
        "module" => {
            let (sub, m) = sub_of(m)?;
            match sub {
                "list" => {
                    let mut r = HubRequest::new(Method::Get, p("/modules"));
                    page_query(m, &mut r.query);
                    if let Some(id) = s(m, "module-id") {
                        validate_module_name(&id)?;
                        r.query.push(("module_id".into(), id));
                    }
                    if let Some(st) = s(m, "status") {
                        r.query.push((
                            "status".into(),
                            status_code(&st, &[("available", 1), ("yanked", 2)])?,
                        ));
                    }
                    call(r, Kind::Module)
                }
                "show" => call(
                    HubRequest::new(Method::Get, p(&format!("/modules/{}", req_uuid(m, "id")?))),
                    Kind::Module,
                ),
                "publish" => Ok(HubAction::Publish {
                    wasm: req(m, "wasm")?,
                    manifest: req(m, "manifest")?,
                    pubkey: s(m, "pubkey"),
                }),
                "revoke" => call(
                    HubRequest::new(
                        Method::Patch,
                        p(&format!("/modules/{}", req_uuid(m, "id")?)),
                    )
                    .json(json!({"status": 2})),
                    Kind::Module,
                ),
                other => unknown(other),
            }
        }
        "agent" => {
            let (sub, m) = sub_of(m)?;
            match sub {
                "list" => {
                    let mut r = HubRequest::new(Method::Get, p("/agents"));
                    page_query(m, &mut r.query);
                    if let Some(g) = opt_uuid(m, "group")? {
                        r.query.push(("group_id".into(), g));
                    }
                    if let Some(st) = s(m, "status") {
                        r.query.push((
                            "status".into(),
                            status_code(&st, &[("active", 1), ("stale", 2), ("revoked", 3)])?,
                        ));
                    }
                    call(r, Kind::Agent)
                }
                "show" => call(
                    HubRequest::new(Method::Get, p(&format!("/agents/{}", req_uuid(m, "id")?))),
                    Kind::Agent,
                ),
                "create" => {
                    let mut body = Map::new();
                    let groups: Vec<String> = m
                        .get_many::<String>("group")
                        .map(|v| v.cloned().collect())
                        .unwrap_or_default();
                    for g in &groups {
                        validate_uuid("group", g)?;
                    }
                    if !groups.is_empty() {
                        body.insert("group_ids".into(), json!(groups));
                    }
                    if let Some(t) = m.get_one::<u64>("ttl") {
                        body.insert("ttl_s".into(), json!(t));
                    }
                    call(
                        HubRequest::new(Method::Post, p("/bootstrap-tokens"))
                            .json(Value::Object(body)),
                        Kind::BootstrapToken,
                    )
                }
                "disable" => call(
                    HubRequest::new(
                        Method::Delete,
                        p(&format!("/agents/{}", req_uuid(m, "id")?)),
                    ),
                    Kind::Done,
                ),
                "token" => {
                    let (sub, m) = sub_of(m)?;
                    match sub {
                        "list" => {
                            let mut r = HubRequest::new(Method::Get, p("/bootstrap-tokens"));
                            page_query(m, &mut r.query);
                            call(r, Kind::BootstrapToken)
                        }
                        "revoke" => call(
                            HubRequest::new(
                                Method::Delete,
                                p(&format!("/bootstrap-tokens/{}", req_uuid(m, "id")?)),
                            ),
                            Kind::Done,
                        ),
                        other => unknown(other),
                    }
                }
                other => unknown(other),
            }
        }
        "group" => {
            let (sub, m) = sub_of(m)?;
            match sub {
                "list" => {
                    let mut r = HubRequest::new(Method::Get, p("/groups"));
                    page_query(m, &mut r.query);
                    if let Some(np) = s(m, "name-prefix") {
                        r.query.push(("name_prefix".into(), np));
                    }
                    call(r, Kind::Group)
                }
                "create" => {
                    let name = req(m, "name")?;
                    check_len("name", &name, 1, 128)?;
                    let mut body = json!({ "name": name });
                    if let Some(d) = s(m, "description") {
                        check_len("description", &d, 0, 1024)?;
                        body["description"] = json!(d);
                    }
                    call(
                        HubRequest::new(Method::Post, p("/groups")).json(body),
                        Kind::Group,
                    )
                }
                "show" => call(
                    HubRequest::new(Method::Get, p(&format!("/groups/{}", req_uuid(m, "id")?))),
                    Kind::Group,
                ),
                "edit" => {
                    let id = req_uuid(m, "id")?;
                    let mut body = Map::new();
                    if let Some(n) = s(m, "name") {
                        check_len("name", &n, 1, 128)?;
                        body.insert("name".into(), json!(n));
                    }
                    if let Some(d) = s(m, "description") {
                        check_len("description", &d, 0, 1024)?;
                        body.insert("description".into(), json!(d));
                    }
                    if body.is_empty() {
                        return Err(HubError::Usage(
                            "group edit needs --name and/or --description".into(),
                        ));
                    }
                    call(
                        HubRequest::new(Method::Patch, p(&format!("/groups/{id}")))
                            .json(Value::Object(body)),
                        Kind::Group,
                    )
                }
                "delete" => call(
                    HubRequest::new(
                        Method::Delete,
                        p(&format!("/groups/{}", req_uuid(m, "id")?)),
                    ),
                    Kind::Done,
                ),
                "members" => {
                    let id = req_uuid(m, "id")?;
                    let agents = uuids(m, "agents")?;
                    call(
                        HubRequest::new(Method::Put, p(&format!("/groups/{id}/members")))
                            .json(json!({ "agent_ids": agents })),
                        Kind::Members,
                    )
                }
                other => unknown(other),
            }
        }
        "assign" => {
            let group = req_uuid(m, "group")?;
            let modules = uuids(m, "modules")?;
            let path = p(&format!("/groups/{group}/modules"));
            let clear = m.get_flag("clear");
            if clear && !modules.is_empty() {
                return Err(HubError::Usage(
                    "--clear cannot be combined with module ids".into(),
                ));
            }
            if modules.is_empty() && !clear {
                return call(HubRequest::new(Method::Get, path), Kind::Assignment);
            }
            let body: Vec<Value> = modules
                .iter()
                .map(|id| json!({ "module_version_id": id }))
                .collect();
            call(
                HubRequest::new(Method::Put, path).json(Value::Array(body)),
                Kind::Assignment,
            )
        }
        "config" => {
            let (sub, m) = sub_of(m)?;
            match sub {
                "show" => call(
                    HubRequest::new(
                        Method::Get,
                        p(&format!("/agents/{}", req_uuid(m, "agent")?)),
                    ),
                    Kind::Agent,
                ),
                "set" => Ok(HubAction::ConfigSet {
                    target: policy_target(m)?,
                    file: req(m, "file")?,
                }),
                "clear" => call(
                    HubRequest::new(
                        Method::Delete,
                        p(&format!("/agents/{}/override", req_uuid(m, "agent")?)),
                    ),
                    Kind::Done,
                ),
                other => unknown(other),
            }
        }
        "flags" => {
            let (sub, m) = sub_of(m)?;
            match sub {
                "list" => {
                    let mut r = HubRequest::new(Method::Get, p("/flags"));
                    page_query(m, &mut r.query);
                    if let Some(g) = opt_uuid(m, "group")? {
                        r.query.push(("group_id".into(), g));
                    }
                    call(r, Kind::Flag)
                }
                "set" => {
                    let key = req(m, "key")?;
                    validate_flag_key(&key)?;
                    let enabled = *m
                        .get_one::<bool>("enabled")
                        .ok_or_else(|| HubError::Usage("--enabled is required".into()))?;
                    let body = match opt_uuid(m, "group")? {
                        Some(g) => {
                            json!({ "key": key, "enabled": enabled, "scope": 2, "group_id": g })
                        }
                        None => json!({ "key": key, "enabled": enabled, "scope": 1 }),
                    };
                    call(
                        HubRequest::new(Method::Put, p("/flags")).json(body),
                        Kind::Flag,
                    )
                }
                "delete" => call(
                    HubRequest::new(Method::Delete, p(&format!("/flags/{}", req_uuid(m, "id")?))),
                    Kind::Done,
                ),
                other => unknown(other),
            }
        }
        "limits" => {
            let (sub, m) = sub_of(m)?;
            match sub {
                "set" => {
                    let target = policy_target(m)?;
                    let mut limits = Map::new();
                    for (name, _, _) in LIMIT_FIELDS {
                        if let Some(v) = m.get_one::<u64>(name) {
                            limits.insert(name.into(), json!(v));
                        }
                    }
                    if limits.is_empty() {
                        return Err(HubError::Usage(
                            "limits set needs at least one --max-*/--poll-interval-s flag".into(),
                        ));
                    }
                    Ok(HubAction::LimitsSet { target, limits })
                }
                other => unknown(other),
            }
        }
        "audit" => {
            let mut r = HubRequest::new(Method::Get, p("/audit-events"));
            page_query(m, &mut r.query);
            if let Some(since) = s(m, "since") {
                r.query.push(("since".into(), since));
            }
            call(r, Kind::Audit)
        }
        other => unknown(other),
    }
}

/// Returns the nested subcommand, or a usage error.
fn sub_of(m: &ArgMatches) -> Result<(&str, &ArgMatches), HubError> {
    m.subcommand()
        .ok_or_else(|| HubError::Usage("missing subcommand".into()))
}

/// Usage error for an unrecognised subcommand.
fn unknown<T>(name: &str) -> Result<T, HubError> {
    Err(HubError::Usage(format!("unknown hub subcommand {name:?}")))
}

/// Collects and validates a multi-valued UUID positional.
fn uuids(m: &ArgMatches, id: &str) -> Result<Vec<String>, HubError> {
    let vals: Vec<String> = m
        .get_many::<String>(id)
        .map(|v| v.cloned().collect())
        .unwrap_or_default();
    for v in &vals {
        validate_uuid(id, v)?;
    }
    Ok(vals)
}

/// Enforces the contract's string length bounds (in characters).
fn check_len(field: &str, v: &str, min: usize, max: usize) -> Result<(), HubError> {
    let n = v.chars().count();
    if n < min || n > max {
        return Err(HubError::Usage(format!(
            "{field} must be {min}..={max} characters"
        )));
    }
    Ok(())
}

/// Validates `ModuleName` (`^[a-z][a-z0-9-]{1,62}$`).
pub fn validate_module_name(id: &str) -> Result<(), HubError> {
    let b = id.as_bytes();
    let ok = (2..=63).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-');
    if ok {
        Ok(())
    } else {
        Err(HubError::Usage(format!("invalid module id {id:?}")))
    }
}

/// Validates `SemVer` (`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`).
pub fn validate_semver(v: &str) -> Result<(), HubError> {
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    let core_ok = parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    let pre_ok = pre.is_none_or(|p| {
        !p.is_empty()
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    });
    if core_ok && pre_ok {
        Ok(())
    } else {
        Err(HubError::Usage(format!("invalid version {v:?}")))
    }
}

/// Validates a flag key (`^[a-z0-9-]+\.[a-z0-9.-]+$`).
pub fn validate_flag_key(k: &str) -> Result<(), HubError> {
    let allowed = |s: &str, dot: bool| {
        !s.is_empty()
            && s.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || (dot && b == b'.')
            })
    };
    let ok = k
        .split_once('.')
        .is_some_and(|(a, b)| allowed(a, false) && allowed(b, true));
    if ok {
        Ok(())
    } else {
        Err(HubError::Usage(format!(
            "flag key must look like product.feature, got {k:?}"
        )))
    }
}

/// The pre-signed manifest accompanying a wasm upload.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct SignedManifest {
    /// Module id (`id` or `module_id`).
    #[serde(alias = "module_id")]
    pub id: String,
    /// SemVer version.
    pub version: String,
    /// Optional sha256 hex; when present it must match the wasm.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Minisign signature text over [`signed_message`].
    #[serde(default)]
    pub signature: Option<String>,
}

/// Lower-case hex sha256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The exact message the offline signer signs (plan: Signing).
pub fn signed_message(id: &str, version: &str, sha256: &str) -> String {
    format!("{SIGNED_MESSAGE_HEADER}\nid={id}\nversion={version}\nsha256={sha256}\n")
}

/// Verifies a minisign `signature` over the module message with `pubkey`
/// (minisign public key file text or bare base64 key).
pub fn verify_signature(pubkey: &str, signature: &str, message: &str) -> Result<(), HubError> {
    let trimmed = pubkey.trim();
    let pk = minisign_verify::PublicKey::decode(trimmed)
        .or_else(|_| minisign_verify::PublicKey::from_base64(trimmed))
        .map_err(|_| HubError::Signature("malformed minisign public key".into()))?;
    let sig = minisign_verify::Signature::decode(signature)
        .map_err(|_| HubError::Signature("malformed minisign signature in manifest".into()))?;
    pk.verify(message.as_bytes(), &sig, false).map_err(|_| {
        HubError::Signature("manifest signature does not verify against --pubkey".into())
    })
}

/// Validates the manifest against the wasm, optionally verifies the
/// signature locally, and shapes the multipart upload. Fails fast when the
/// signature is missing — the hub never signs.
pub fn build_publish(
    wasm: &[u8],
    manifest_json: &str,
    pubkey: Option<&str>,
) -> Result<HubRequest, HubError> {
    if wasm.is_empty() {
        return Err(HubError::Usage("wasm file is empty".into()));
    }
    if wasm.len() > MAX_MODULE_BYTES {
        return Err(HubError::Usage(format!(
            "wasm file exceeds {MAX_MODULE_BYTES} bytes"
        )));
    }
    if !wasm.starts_with(b"\0asm") {
        return Err(HubError::Usage(
            "file is not a WebAssembly module (bad magic)".into(),
        ));
    }
    let manifest: SignedManifest = serde_json::from_str(manifest_json)
        .map_err(|e| HubError::Usage(format!("invalid manifest JSON: {e}")))?;
    let signature = manifest
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            HubError::Signature(
                "manifest has no signature; sign it offline before publishing".into(),
            )
        })?;
    validate_module_name(&manifest.id)?;
    validate_semver(&manifest.version)?;
    let digest = sha256_hex(wasm);
    if let Some(declared) = &manifest.sha256
        && !declared.eq_ignore_ascii_case(&digest)
    {
        return Err(HubError::Signature(format!(
            "manifest sha256 {declared} does not match wasm sha256 {digest}"
        )));
    }
    if let Some(pk) = pubkey {
        verify_signature(
            pk,
            signature,
            &signed_message(&manifest.id, &manifest.version, &digest),
        )?;
    }
    let boundary = format!("pdcli-{}", &digest[..32]);
    let fields = [
        ("module_id", manifest.id.as_str()),
        ("version", manifest.version.as_str()),
        ("sha256", digest.as_str()),
        ("signature", signature),
    ];
    let bytes = multipart_body(
        &boundary,
        &fields,
        (
            "binary",
            &format!("{}-{}.wasm", manifest.id, manifest.version),
            "application/wasm",
            wasm,
        ),
    );
    Ok(HubRequest {
        method: Method::Post,
        path: format!("{API_PREFIX}/modules"),
        query: Vec::new(),
        body: Body::Multipart {
            content_type: format!("multipart/form-data; boundary={boundary}"),
            bytes,
        },
    })
}

/// Encodes a `multipart/form-data` body with text fields and one file part.
pub fn multipart_body(
    boundary: &str,
    fields: &[(&str, &str)],
    file: (&str, &str, &str, &[u8]),
) -> Vec<u8> {
    let mut out = Vec::with_capacity(file.3.len() + 1024);
    for (name, value) in fields {
        out.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    let (name, filename, ctype, bytes) = file;
    out.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {ctype}\r\n\r\n").as_bytes(),
    );
    out.extend_from_slice(bytes);
    out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    out
}

/// Shapes `config set`: agent override (PUT) or group policy (PATCH).
pub fn build_config_set(target: &PolicyTarget, policy_json: &str) -> Result<HubRequest, HubError> {
    let policy: Value = serde_json::from_str(policy_json)
        .map_err(|e| HubError::Usage(format!("invalid policy JSON: {e}")))?;
    if !policy.is_object() {
        return Err(HubError::Usage(
            "policy must be a JSON object (ConfigPolicy)".into(),
        ));
    }
    Ok(policy_write(target, policy))
}

/// The write request for a full policy document on `target`.
fn policy_write(target: &PolicyTarget, policy: Value) -> HubRequest {
    match target {
        PolicyTarget::Agent(id) => {
            HubRequest::new(Method::Put, format!("{API_PREFIX}/agents/{id}/override")).json(policy)
        }
        PolicyTarget::Group(id) => {
            HubRequest::new(Method::Patch, format!("{API_PREFIX}/groups/{id}"))
                .json(json!({ "policy": policy }))
        }
    }
}

/// The read request whose `data` holds `target`'s current policy.
pub fn policy_read(target: &PolicyTarget) -> HubRequest {
    match target {
        PolicyTarget::Agent(id) => {
            HubRequest::new(Method::Get, format!("{API_PREFIX}/agents/{id}"))
        }
        PolicyTarget::Group(id) => {
            HubRequest::new(Method::Get, format!("{API_PREFIX}/groups/{id}"))
        }
    }
}

/// Merges `limits` into the current policy (read from the GET `data`) and
/// shapes the write, preserving every other policy field.
pub fn build_limits_write(
    target: &PolicyTarget,
    current: &Value,
    limits: &Map<String, Value>,
) -> HubRequest {
    let field = match target {
        PolicyTarget::Agent(_) => "override",
        PolicyTarget::Group(_) => "policy",
    };
    let mut policy = match current.get(field) {
        Some(Value::Object(o)) => Value::Object(o.clone()),
        _ => json!({}),
    };
    let mut merged = match policy.get("limits") {
        Some(Value::Object(o)) => o.clone(),
        _ => Map::new(),
    };
    for (k, v) in limits {
        merged.insert(k.clone(), v.clone());
    }
    policy["limits"] = Value::Object(merged);
    policy_write(target, policy)
}

/// Parses a hub response: 2xx yields the envelope's `data` (Null for 204);
/// anything else becomes a [`HubError::Api`] with a clear message.
pub fn parse_response(status: u16, body: &[u8]) -> Result<Value, HubError> {
    if (200..300).contains(&status) {
        if status == 204 || body.iter().all(u8::is_ascii_whitespace) {
            return Ok(Value::Null);
        }
        let v: Value = serde_json::from_slice(body)
            .map_err(|e| HubError::Protocol(format!("invalid JSON: {e}")))?;
        return match v.get("status").and_then(Value::as_str) {
            Some("success") => v
                .get("data")
                .cloned()
                .ok_or_else(|| HubError::Protocol("envelope has no data".into())),
            _ => Err(HubError::Protocol(
                "missing {status: success} envelope".into(),
            )),
        };
    }
    let problem = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("data").cloned());
    let title = problem
        .as_ref()
        .and_then(|p| p.get("title"))
        .and_then(Value::as_str);
    let detail = problem
        .as_ref()
        .and_then(|p| p.get("detail"))
        .and_then(Value::as_str);
    let reason = match (title, detail) {
        (Some(t), Some(d)) => format!("{t}: {d}"),
        (Some(t), None) => t.to_string(),
        (None, Some(d)) => d.to_string(),
        (None, None) => String::from("no details"),
    };
    let hint = match status {
        401 => "not logged in or token expired; run `pdcli hub login`",
        403 => "permission denied (missing hub scope or tenant mismatch)",
        404 => "not found",
        409 => "conflict",
        410 => "gone",
        412 => "precondition failed (resource changed)",
        413 => "upload too large",
        422 => "rejected by hub validation",
        429 => "rate limited; retry later",
        500..=599 => "hub server error",
        _ => "request failed",
    };
    Err(HubError::Api {
        status,
        message: format!("{hint} (HTTP {status}): {reason}"),
    })
}

/// Columns rendered for each kind: (header, JSON field).
fn columns(kind: Kind) -> &'static [(&'static str, &'static str)] {
    match kind {
        Kind::Group => &[
            ("ID", "id"),
            ("NAME", "name"),
            ("AGENTS", "agent_count"),
            ("UPDATED", "updated_at"),
        ],
        Kind::Agent => &[
            ("ID", "id"),
            ("STATUS", "status"),
            ("PLATFORM", "platform"),
            ("VERSION", "agent_version"),
            ("LAST SEEN", "last_seen_at"),
        ],
        Kind::Module => &[
            ("ID", "id"),
            ("MODULE", "module_id"),
            ("VERSION", "version"),
            ("STATUS", "status"),
            ("SIZE", "size_bytes"),
        ],
        Kind::BootstrapToken => &[
            ("ID", "id"),
            ("EXPIRES", "expires_at"),
            ("USED", "used"),
            ("TOKEN", "token"),
        ],
        Kind::Assignment => &[
            ("MODULE VERSION", "module_version_id"),
            ("MODULE", "module_id"),
            ("VERSION", "version"),
        ],
        Kind::Flag => &[
            ("ID", "id"),
            ("KEY", "key"),
            ("ENABLED", "enabled"),
            ("SCOPE", "scope"),
            ("GROUP", "group_id"),
        ],
        Kind::Audit => &[
            ("TIME", "timestamp"),
            ("ACTOR", "actor_id"),
            ("ACTION", "action"),
            ("RESOURCE", "resource_id"),
        ],
        Kind::Policy | Kind::Members | Kind::Done => &[],
    }
}

/// Human label for an int enum code in a given column.
fn enum_label(kind: Kind, field: &str, v: &Value) -> Option<&'static str> {
    let code = v.as_i64()?;
    let table: &[&str] = match (kind, field) {
        (Kind::Agent, "status") => &["active", "stale", "revoked"],
        (Kind::Agent, "platform") => &["linux", "macos", "windows"],
        (Kind::Module, "status") => &["available", "yanked"],
        (Kind::Flag, "scope") => &["tenant", "group"],
        _ => return None,
    };
    usize::try_from(code - 1)
        .ok()
        .and_then(|i| table.get(i).copied())
}

/// Plain-text cell for a JSON value.
fn cell(kind: Kind, field: &str, v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "-".into(),
        Some(v) => {
            if let Some(l) = enum_label(kind, field, v) {
                return l.into();
            }
            match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            }
        }
    }
}

/// Renders a response `data` as pretty JSON (`--json`) or a table / key list.
pub fn render(kind: Kind, data: &Value, as_json: bool) -> String {
    if as_json {
        let v = if data.is_null() {
            json!({ "ok": true })
        } else {
            data.clone()
        };
        return serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string());
    }
    if data.is_null() {
        return "ok".into();
    }
    let rows: Option<&Vec<Value>> = data
        .as_array()
        .or_else(|| data.get("items").and_then(Value::as_array));
    let cols = columns(kind);
    let mut out = match rows {
        Some(rows) if !cols.is_empty() => table(kind, cols, rows),
        _ => key_values(kind, data),
    };
    if let Some(c) = data.get("next_cursor").and_then(Value::as_str) {
        out.push_str(&format!("\nnext page: --cursor {c}"));
    }
    out
}

/// Aligned table of `rows`.
fn table(kind: Kind, cols: &[(&str, &str)], rows: &[Value]) -> String {
    if rows.is_empty() {
        return "(none)".into();
    }
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| cols.iter().map(|(_, f)| cell(kind, f, r.get(*f))).collect())
        .collect();
    let widths: Vec<usize> = cols
        .iter()
        .enumerate()
        .map(|(i, (h, _))| {
            cells
                .iter()
                .map(|r| r[i].chars().count())
                .max()
                .unwrap_or(0)
                .max(h.len())
        })
        .collect();
    let line = |vals: Vec<&str>| {
        vals.iter()
            .zip(&widths)
            .map(|(v, w)| format!("{v:<w$}"))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };
    let mut lines = vec![line(cols.iter().map(|(h, _)| *h).collect())];
    for r in &cells {
        lines.push(line(r.iter().map(String::as_str).collect()));
    }
    lines.join("\n")
}

/// `key: value` lines for a single object.
fn key_values(kind: Kind, data: &Value) -> String {
    match data.as_object() {
        Some(obj) => obj
            .iter()
            .map(|(k, v)| match v {
                Value::Object(_) | Value::Array(_) => format!("{k}: {v}"),
                _ => format!("{k}: {}", cell(kind, k, Some(v))),
            })
            .collect::<Vec<_>>()
            .join("\n"),
        None => data.to_string(),
    }
}

/// OIDC discovery fields the device flow needs.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct OidcDiscovery {
    /// RFC 8628 device authorization endpoint.
    pub device_authorization_endpoint: String,
    /// Token endpoint.
    pub token_endpoint: String,
}

/// Discovery document URL for `issuer`.
pub fn discovery_url(issuer: &str) -> Result<Url, HubError> {
    let url = Url::parse(&format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    ))
    .map_err(|e| HubError::Config(format!("invalid issuer {issuer:?}: {e}")))?;
    require_secure(&url)?;
    Ok(url)
}

/// Parses and checks a discovery document (both endpoints must be secure).
pub fn parse_discovery(body: &[u8]) -> Result<OidcDiscovery, HubError> {
    let d: OidcDiscovery = serde_json::from_slice(body).map_err(|e| {
        HubError::Protocol(format!("OIDC discovery lacks device flow endpoints: {e}"))
    })?;
    for u in [&d.device_authorization_endpoint, &d.token_endpoint] {
        let parsed =
            Url::parse(u).map_err(|e| HubError::Protocol(format!("bad OIDC endpoint {u}: {e}")))?;
        require_secure(&parsed)?;
    }
    Ok(d)
}

/// RFC 8628 device authorization response.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DeviceAuthorization {
    /// Opaque device code polled with.
    pub device_code: String,
    /// Code the user types.
    pub user_code: String,
    /// Where the user goes.
    pub verification_uri: String,
    /// Pre-filled verification link, if offered.
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    /// Seconds until the codes expire.
    pub expires_in: u64,
    /// Minimum poll interval in seconds (default 5).
    #[serde(default = "default_interval")]
    pub interval: u64,
}

/// RFC 8628 default polling interval.
fn default_interval() -> u64 {
    5
}

/// Form-encodes key/value pairs.
fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// Shapes the device authorization request.
pub fn device_authorization_request(endpoint: &str, client_id: &str) -> HubRequest {
    HubRequest {
        method: Method::Post,
        path: endpoint.into(),
        query: Vec::new(),
        body: Body::Form(form(&[("client_id", client_id), ("scope", LOGIN_SCOPES)])),
    }
}

/// Shapes one device-code token poll.
pub fn device_token_request(endpoint: &str, client_id: &str, device_code: &str) -> HubRequest {
    HubRequest {
        method: Method::Post,
        path: endpoint.into(),
        query: Vec::new(),
        body: Body::Form(form(&[
            ("grant_type", DEVICE_GRANT),
            ("device_code", device_code),
            ("client_id", client_id),
        ])),
    }
}

/// Shapes a refresh-token grant.
pub fn refresh_request(endpoint: &str, client_id: &str, refresh_token: &str) -> HubRequest {
    HubRequest {
        method: Method::Post,
        path: endpoint.into(),
        query: Vec::new(),
        body: Body::Form(form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ])),
    }
}

/// Credentials persisted in the OS keychain (never a plaintext file).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredToken {
    /// Bearer access token.
    pub access_token: String,
    /// Refresh token, if issued.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Unix seconds when the access token expires.
    pub expires_at: u64,
    /// Token endpoint used for refresh.
    pub token_endpoint: String,
    /// OIDC client id used for refresh.
    pub client_id: String,
}

impl fmt::Debug for StoredToken {
    /// Never prints token material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredToken")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl StoredToken {
    /// True when the access token expires within 30 seconds of `now`.
    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_add(30) >= self.expires_at
    }
}

/// Outcome of one token-endpoint poll.
#[derive(Debug, Clone, PartialEq)]
pub enum PollOutcome {
    /// Tokens issued.
    Token(StoredToken),
    /// User has not approved yet.
    Pending,
    /// Poll more slowly (+5 s).
    SlowDown,
}

/// Interprets a token-endpoint response (device poll or refresh).
pub fn parse_token_response(
    status: u16,
    body: &[u8],
    token_endpoint: &str,
    client_id: &str,
    now: u64,
) -> Result<PollOutcome, HubError> {
    let v: Value = serde_json::from_slice(body)
        .map_err(|e| HubError::Protocol(format!("token endpoint returned invalid JSON: {e}")))?;
    if (200..300).contains(&status) {
        let access = v
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| HubError::Protocol("token response has no access_token".into()))?;
        let expires_in = v.get("expires_in").and_then(Value::as_u64).unwrap_or(3600);
        return Ok(PollOutcome::Token(StoredToken {
            access_token: access.into(),
            refresh_token: v
                .get("refresh_token")
                .and_then(Value::as_str)
                .map(String::from),
            expires_at: now.saturating_add(expires_in),
            token_endpoint: token_endpoint.into(),
            client_id: client_id.into(),
        }));
    }
    match v.get("error").and_then(Value::as_str) {
        Some("authorization_pending") => Ok(PollOutcome::Pending),
        Some("slow_down") => Ok(PollOutcome::SlowDown),
        Some("access_denied") => Err(HubError::Auth(
            "login denied by the identity provider".into(),
        )),
        Some("expired_token") => Err(HubError::Auth(
            "device code expired; run `pdcli hub login` again".into(),
        )),
        Some("invalid_grant") => Err(HubError::Auth(
            "session no longer valid; run `pdcli hub login`".into(),
        )),
        Some(other) => Err(HubError::Auth(format!("identity provider error: {other}"))),
        None => Err(HubError::Auth(format!(
            "token endpoint returned HTTP {status}"
        ))),
    }
}

/// Decodes (without verifying — display only) a JWT's claims.
pub fn decode_claims(jwt: &str) -> Result<Value, HubError> {
    let payload = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| HubError::Auth("stored token is not a JWT".into()))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| HubError::Auth("stored token payload is not base64url".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| HubError::Auth("stored token payload is not JSON".into()))
}

/// The `whoami` view: identity claims only, never the token itself.
pub fn whoami_view(claims: &Value, hub: &Url) -> Value {
    let pick = |k: &str| claims.get(k).cloned().unwrap_or(Value::Null);
    json!({
        "hub": hub.as_str(),
        "sub": pick("sub"),
        "tenant": pick("tenant"),
        "scope": pick("scope"),
        "iss": pick("iss"),
        "exp": pick("exp"),
    })
}

/// Keychain account name for the token belonging to `hub`.
pub fn keychain_account(hub: &Url) -> String {
    format!(
        "{}{}",
        hub.origin().ascii_serialization(),
        hub.path().trim_end_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: &str = "0b7f3c2e-1d4a-4c8e-9a6b-2f1e3d4c5b6a";
    const A: &str = "1c8e4d3f-2e5b-4d9f-8b7c-3a2f4e5d6c7b";
    const SPEC: &str = include_str!("../../../services/hub-api/openapi/v1.yaml");

    fn action(args: &[&str]) -> Result<HubAction, HubError> {
        let mut full = vec!["pdcli", "hub"];
        full.extend_from_slice(args);
        let m = crate::tree::build_static_root()
            .try_get_matches_from(full)
            .expect("parse");
        let (_, hub) = m.subcommand().expect("hub");
        parse_action(hub)
    }

    fn req(args: &[&str]) -> (HubRequest, Kind) {
        match action(args).expect("action") {
            HubAction::Call(r, k) => (r, k),
            other => panic!("expected call, got {other:?}"),
        }
    }

    /// Path template in the contract for a concrete path.
    fn in_spec(path: &str) -> bool {
        let templ: String = path
            .split('/')
            .map(|seg| {
                if seg.len() == 36 && validate_uuid("x", seg).is_ok() {
                    "{}"
                } else {
                    seg
                }
            })
            .collect::<Vec<_>>()
            .join("/");
        SPEC.lines()
            .filter_map(|l| l.strip_prefix("  /").and_then(|l| l.strip_suffix(':')))
            .any(|p| {
                let p = format!("/{p}");
                let norm: String = p
                    .split('/')
                    .map(|s| if s.starts_with('{') { "{}" } else { s })
                    .collect::<Vec<_>>()
                    .join("/");
                norm == templ
            })
    }

    fn norm(path: &str) -> String {
        path.split('/')
            .map(|s| {
                if validate_uuid("x", s).is_ok() {
                    "{}"
                } else {
                    s
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    #[test]
    fn shapes_requests_against_contract() {
        let cases: &[(&[&str], Method, &str)] = &[
            (
                &["module", "list", "--status", "yanked", "--limit", "5"],
                Method::Get,
                "/api/v1/modules",
            ),
            (&["module", "show", G], Method::Get, "/api/v1/modules/{}"),
            (
                &["module", "revoke", G],
                Method::Patch,
                "/api/v1/modules/{}",
            ),
            (
                &["agent", "list", "--group", G, "--status", "stale"],
                Method::Get,
                "/api/v1/agents",
            ),
            (&["agent", "show", A], Method::Get, "/api/v1/agents/{}"),
            (
                &["agent", "create", "--group", G, "--ttl", "600"],
                Method::Post,
                "/api/v1/bootstrap-tokens",
            ),
            (
                &["agent", "disable", A],
                Method::Delete,
                "/api/v1/agents/{}",
            ),
            (
                &["agent", "token", "list"],
                Method::Get,
                "/api/v1/bootstrap-tokens",
            ),
            (
                &["agent", "token", "revoke", G],
                Method::Delete,
                "/api/v1/bootstrap-tokens/{}",
            ),
            (
                &["group", "list", "--name-prefix", "ops"],
                Method::Get,
                "/api/v1/groups",
            ),
            (
                &["group", "create", "ops", "--description", "d"],
                Method::Post,
                "/api/v1/groups",
            ),
            (&["group", "show", G], Method::Get, "/api/v1/groups/{}"),
            (
                &["group", "edit", G, "--name", "x"],
                Method::Patch,
                "/api/v1/groups/{}",
            ),
            (&["group", "delete", G], Method::Delete, "/api/v1/groups/{}"),
            (
                &["group", "members", G, A],
                Method::Put,
                "/api/v1/groups/{}/members",
            ),
            (&["assign", G, A], Method::Put, "/api/v1/groups/{}/modules"),
            (&["assign", G], Method::Get, "/api/v1/groups/{}/modules"),
            (
                &["assign", G, "--clear"],
                Method::Put,
                "/api/v1/groups/{}/modules",
            ),
            (&["config", "show", A], Method::Get, "/api/v1/agents/{}"),
            (
                &["config", "clear", A],
                Method::Delete,
                "/api/v1/agents/{}/override",
            ),
            (
                &["flags", "list", "--group", G],
                Method::Get,
                "/api/v1/flags",
            ),
            (
                &["flags", "set", "penguind.hub-api", "--enabled", "false"],
                Method::Put,
                "/api/v1/flags",
            ),
            (&["flags", "delete", G], Method::Delete, "/api/v1/flags/{}"),
        ];
        for &(args, method, templ) in cases {
            let (r, _) = req(args);
            assert_eq!(r.method, method, "{args:?}");
            assert_eq!(norm(&r.path), templ, "{args:?}");
            assert!(in_spec(&r.path), "{} not in v1.yaml", r.path);
        }
    }

    #[test]
    fn audit_path_is_flagged_as_outside_contract() {
        let (r, k) = req(&["audit"]);
        assert_eq!((r.path.as_str(), k), ("/api/v1/audit-events", Kind::Audit));
        // Contract gap: no audit endpoint in v1.yaml yet; flip when added.
        assert!(!in_spec(&r.path));
    }

    #[test]
    fn bodies_match_schemas() {
        assert_eq!(
            req(&["module", "revoke", G]).0.body,
            Body::Json(json!({"status": 2}))
        );
        assert_eq!(
            req(&["agent", "create", "--group", G, "--ttl", "600"])
                .0
                .body,
            Body::Json(json!({"group_ids": [G], "ttl_s": 600}))
        );
        assert_eq!(
            req(&["group", "members", G, A]).0.body,
            Body::Json(json!({"agent_ids": [A]}))
        );
        assert_eq!(
            req(&["group", "members", G]).0.body,
            Body::Json(json!({"agent_ids": []}))
        );
        assert_eq!(
            req(&["assign", G, A]).0.body,
            Body::Json(json!([{"module_version_id": A}]))
        );
        assert_eq!(req(&["assign", G, "--clear"]).0.body, Body::Json(json!([])));
        assert_eq!(
            req(&[
                "flags",
                "set",
                "penguind.hub-api",
                "--enabled",
                "true",
                "--group",
                G
            ])
            .0
            .body,
            Body::Json(
                json!({"key": "penguind.hub-api", "enabled": true, "scope": 2, "group_id": G})
            )
        );
        let (r, _) = req(&[
            "module",
            "list",
            "--status",
            "yanked",
            "--limit",
            "5",
            "--cursor",
            "c1",
            "--module-id",
            "waddleai",
        ]);
        let q: Vec<(&str, &str)> = r
            .query
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        assert_eq!(
            q,
            vec![
                ("limit", "5"),
                ("cursor", "c1"),
                ("module_id", "waddleai"),
                ("status", "2")
            ]
        );
        let (r, _) = req(&["agent", "list", "--status", "revoked"]);
        assert_eq!(r.query, vec![("status".to_string(), "3".to_string())]);
    }

    #[test]
    fn rejects_bad_input() {
        let cases: &[&[&str]] = &[
            &["module", "show", "1"],
            &["group", "show", "../../etc"],
            &["module", "list", "--status", "gone"],
            &["group", "edit", G],
            &["flags", "set", "NoDot", "--enabled", "true"],
            &["assign", G, A, "--clear"],
            &["limits", "set", "--group", G],
            &["group", "create", ""],
        ];
        for args in cases {
            let e = action(args).expect_err("must fail");
            assert_eq!(e.exit_code(), 2, "{args:?}: {e}");
        }
    }

    #[test]
    fn tree_rejects_bad_args() {
        let cases: &[&[&str]] = &[
            &[
                "hub",
                "limits",
                "set",
                "--poll-interval-s",
                "10",
                "--group",
                G,
            ],
            &[
                "hub",
                "limits",
                "set",
                "--max-fuel",
                "1",
                "--agent",
                A,
                "--group",
                G,
            ],
            &["hub", "module", "publish", "x.wasm"],
            &["hub"],
        ];
        for args in cases {
            let mut full = vec!["pdcli"];
            full.extend_from_slice(args);
            assert!(
                crate::tree::build_static_root()
                    .try_get_matches_from(full)
                    .is_err(),
                "{args:?}"
            );
        }
    }

    #[test]
    fn tree_has_every_command_and_global_flags() {
        let root = crate::tree::build_static_root();
        let hub = root.find_subcommand("hub").expect("hub");
        for name in [
            "login", "logout", "whoami", "module", "agent", "group", "assign", "config", "flags",
            "limits", "audit",
        ] {
            assert!(hub.find_subcommand(name).is_some(), "missing {name}");
        }
        let m = root
            .try_get_matches_from([
                "pdcli",
                "hub",
                "--hub-url",
                "https://h",
                "agent",
                "token",
                "list",
                "--json",
            ])
            .expect("parse");
        assert!(m.get_flag("json"));
        let (_, h) = m.subcommand().expect("hub");
        assert_eq!(
            h.get_one::<String>("hub-url").map(String::as_str),
            Some("https://h")
        );
    }

    #[test]
    fn non_request_actions() {
        assert_eq!(action(&["logout"]), Ok(HubAction::Logout));
        assert_eq!(action(&["whoami"]), Ok(HubAction::Whoami));
        assert_eq!(
            action(&["login", "--issuer", "https://i"]),
            Ok(HubAction::Login {
                issuer: Some("https://i".into()),
                client_id: None
            })
        );
        assert_eq!(
            action(&["config", "set", "--group", G, "--file", "p.json"]),
            Ok(HubAction::ConfigSet {
                target: PolicyTarget::Group(G.into()),
                file: "p.json".into()
            })
        );
        let Ok(HubAction::LimitsSet { target, limits }) = action(&[
            "limits",
            "set",
            "--agent",
            A,
            "--max-fuel",
            "9",
            "--poll-interval-s",
            "60",
        ]) else {
            panic!("limits")
        };
        assert_eq!(target, PolicyTarget::Agent(A.into()));
        assert_eq!(
            Value::Object(limits),
            json!({"max_fuel": 9, "poll_interval_s": 60})
        );
        assert!(matches!(
            action(&["module", "publish", "m.wasm", "--manifest", "m.json"]),
            Ok(HubAction::Publish { pubkey: None, .. })
        ));
    }

    #[test]
    fn hub_url_resolution() {
        let cases: &[(Option<&str>, Option<&str>, bool)] = &[
            (Some("https://hub.example"), None, true),
            (None, Some("https://hub.example"), true),
            (None, None, false),
            (Some("http://hub.example"), None, false),
            (Some("http://127.0.0.1:8080"), None, true),
            (Some("ftp://x"), None, false),
            (Some("not a url"), None, false),
        ];
        for &(flag, env, ok) in cases {
            assert_eq!(resolve_hub_url(flag, env).is_ok(), ok, "{flag:?} {env:?}");
        }
    }

    #[test]
    fn url_joins_base_path_and_query() {
        let base = Url::parse("https://h.example/prefix/").expect("url");
        let mut r = HubRequest::new(Method::Get, "/api/v1/groups".into());
        r.query.push(("name_prefix".into(), "a b".into()));
        assert_eq!(
            r.url(&base).expect("url").as_str(),
            "https://h.example/prefix/api/v1/groups?name_prefix=a+b"
        );
        let abs = HubRequest::new(Method::Post, "https://idp.example/token".into());
        assert_eq!(
            abs.url(&base).expect("url").as_str(),
            "https://idp.example/token"
        );
    }

    #[test]
    fn module_names_and_semvers() {
        for (v, ok) in [
            ("waddleai", true),
            ("a", false),
            ("Waddle", false),
            ("9abc", false),
        ] {
            assert_eq!(validate_module_name(v).is_ok(), ok, "{v}");
        }
        for (v, ok) in [
            ("1.2.3", true),
            ("1.2.3-rc.1", true),
            ("1.2", false),
            ("1.2.x", false),
            ("1.2.3-", false),
        ] {
            assert_eq!(validate_semver(v).is_ok(), ok, "{v}");
        }
    }

    fn sign(msg: &str) -> (String, String) {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().expect("kp");
        let sig = minisign::sign(
            Some(&kp.pk),
            &kp.sk,
            std::io::Cursor::new(msg.as_bytes()),
            None,
            None,
        )
        .expect("sign");
        (kp.pk.to_box().expect("pk").into_string(), sig.to_string())
    }

    const WASM: &[u8] = b"\0asm\x01\0\0\0";

    fn manifest(sig: Option<&str>, sha: Option<&str>) -> String {
        json!({"id": "waddleai", "version": "1.0.0", "sha256": sha, "signature": sig}).to_string()
    }

    #[test]
    fn publish_fails_fast_without_signature() {
        for m in [manifest(None, None), manifest(Some("  "), None)] {
            assert!(matches!(
                build_publish(WASM, &m, None),
                Err(HubError::Signature(_))
            ));
        }
    }

    #[test]
    fn publish_verifies_locally_and_shapes_multipart() {
        let digest = sha256_hex(WASM);
        let (pk, sig) = sign(&signed_message("waddleai", "1.0.0", &digest));
        let r =
            build_publish(WASM, &manifest(Some(&sig), Some(&digest)), Some(&pk)).expect("publish");
        assert_eq!(
            (r.method, r.path.as_str()),
            (Method::Post, "/api/v1/modules")
        );
        assert!(in_spec(&r.path));
        let Body::Multipart {
            content_type,
            bytes,
        } = r.body
        else {
            panic!("multipart")
        };
        let boundary = content_type
            .strip_prefix("multipart/form-data; boundary=")
            .expect("boundary");
        let text = String::from_utf8_lossy(&bytes);
        for field in ["module_id", "version", "sha256", "signature", "binary"] {
            assert!(text.contains(&format!("name=\"{field}\"")), "{field}");
        }
        assert!(text.contains(&digest));
        assert!(text.ends_with(&format!("--{boundary}--\r\n")));
        assert!(bytes.windows(WASM.len()).any(|w| w == WASM));
    }

    #[test]
    fn publish_rejects_wrong_key_bad_sha_and_non_wasm() {
        let digest = sha256_hex(WASM);
        let (_, sig) = sign(&signed_message("waddleai", "1.0.0", &digest));
        let (other_pk, _) = sign("x");
        assert!(matches!(
            build_publish(WASM, &manifest(Some(&sig), None), Some(&other_pk)),
            Err(HubError::Signature(_))
        ));
        let bad = "0".repeat(64);
        assert!(matches!(
            build_publish(WASM, &manifest(Some(&sig), Some(&bad)), None),
            Err(HubError::Signature(_))
        ));
        assert!(matches!(
            build_publish(b"MZ", &manifest(Some(&sig), None), None),
            Err(HubError::Usage(_))
        ));
        assert!(matches!(
            build_publish(WASM, "{", None),
            Err(HubError::Usage(_))
        ));
        assert!(matches!(
            build_publish(WASM, &manifest(Some(&sig), None), Some("junk")),
            Err(HubError::Signature(_))
        ));
        // Without --pubkey a present signature is accepted; the hub verifies.
        assert!(build_publish(WASM, &manifest(Some(&sig), None), None).is_ok());
    }

    #[test]
    fn limits_merge_preserves_other_policy_fields() {
        let current = json!({"policy": {"allowed_tools": ["a"], "limits": {"max_fuel": 1, "max_memory_mb": 64}}});
        let mut l = Map::new();
        l.insert("max_fuel".into(), json!(5));
        let r = build_limits_write(&PolicyTarget::Group(G.into()), &current, &l);
        assert_eq!(r.method, Method::Patch);
        assert_eq!(
            r.body,
            Body::Json(
                json!({"policy": {"allowed_tools": ["a"], "limits": {"max_fuel": 5, "max_memory_mb": 64}}})
            )
        );
        let r = build_limits_write(&PolicyTarget::Agent(A.into()), &json!({"id": A}), &l);
        assert_eq!(
            (r.method, r.path.clone()),
            (Method::Put, format!("/api/v1/agents/{A}/override"))
        );
        assert_eq!(r.body, Body::Json(json!({"limits": {"max_fuel": 5}})));
        assert_eq!(
            policy_read(&PolicyTarget::Agent(A.into())).path,
            format!("/api/v1/agents/{A}")
        );
    }

    #[test]
    fn config_set_requires_object() {
        assert!(build_config_set(&PolicyTarget::Agent(A.into()), "[1]").is_err());
        let r = build_config_set(&PolicyTarget::Group(G.into()), r#"{"allowed_tools":null}"#)
            .expect("ok");
        assert_eq!(
            r.body,
            Body::Json(json!({"policy": {"allowed_tools": null}}))
        );
    }

    #[test]
    fn maps_http_errors() {
        let cases: &[(u16, &str)] = &[
            (401, "pdcli hub login"),
            (403, "permission denied"),
            (404, "not found"),
            (409, "conflict"),
            (413, "too large"),
            (422, "validation"),
            (429, "rate limited"),
            (503, "server error"),
        ];
        for &(status, needle) in cases {
            let body = json!({"status": "error", "data": {"type": "about:blank", "title": "T", "status": status, "code": 7, "detail": "D"}, "meta": {"version": 1, "timestamp": "2026-11-10T00:00:00Z"}});
            let e = parse_response(status, body.to_string().as_bytes()).expect_err("err");
            let msg = e.to_string();
            assert!(
                msg.contains(needle) && msg.contains("T: D") && msg.contains(&status.to_string()),
                "{msg}"
            );
            assert_eq!(e.exit_code(), 1);
            assert!(
                parse_response(status, b"<html>")
                    .expect_err("err")
                    .to_string()
                    .contains("no details")
            );
        }
    }

    #[test]
    fn parses_success_envelopes() {
        let body = json!({"status": "success", "data": {"items": [], "next_cursor": null}, "meta": {"version": 1, "timestamp": "t"}});
        assert_eq!(
            parse_response(200, body.to_string().as_bytes()),
            Ok(json!({"items": [], "next_cursor": null}))
        );
        assert_eq!(parse_response(204, b""), Ok(Value::Null));
        assert!(matches!(
            parse_response(200, b"{\"items\":[]}"),
            Err(HubError::Protocol(_))
        ));
        assert!(matches!(
            parse_response(200, b"nope"),
            Err(HubError::Protocol(_))
        ));
    }

    #[test]
    fn renders_tables_and_json() {
        let data = json!({"items": [{"id": A, "status": 2, "platform": 1, "agent_version": "1.0.0", "last_seen_at": null}], "next_cursor": "n2"});
        let t = render(Kind::Agent, &data, false);
        assert!(t.starts_with("ID"));
        assert!(
            t.contains("stale") && t.contains("linux") && t.contains("--cursor n2"),
            "{t}"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&render(Kind::Agent, &data, true)).expect("json"),
            data
        );
        assert_eq!(render(Kind::Done, &Value::Null, false), "ok");
        assert_eq!(
            render(Kind::Done, &Value::Null, true).replace(char::is_whitespace, ""),
            "{\"ok\":true}"
        );
        assert_eq!(render(Kind::Group, &json!({"items": []}), false), "(none)");
        let one = render(Kind::Module, &json!({"id": G, "status": 1}), false);
        assert!(one.contains("status: available"), "{one}");
        let arr = render(
            Kind::Assignment,
            &json!([{"module_version_id": G, "module_id": "m", "version": "1.0.0"}]),
            false,
        );
        assert!(arr.contains("MODULE VERSION") && arr.contains(G));
    }

    #[test]
    fn device_flow_shaping_and_polling() {
        let r = device_authorization_request("https://idp/device", "pdcli");
        let Body::Form(f) = &r.body else {
            panic!("form")
        };
        assert!(f.contains("client_id=pdcli") && f.contains("hub%3Amodules%3Awrite"));
        let Body::Form(f) = device_token_request("https://idp/t", "pdcli", "dc").body else {
            panic!("form")
        };
        assert!(
            f.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code")
                && f.contains("device_code=dc")
        );
        let Body::Form(f) = refresh_request("https://idp/t", "pdcli", "rt").body else {
            panic!("form")
        };
        assert!(f.contains("grant_type=refresh_token"));

        assert_eq!(
            parse_token_response(400, br#"{"error":"authorization_pending"}"#, "t", "c", 0),
            Ok(PollOutcome::Pending)
        );
        assert_eq!(
            parse_token_response(400, br#"{"error":"slow_down"}"#, "t", "c", 0),
            Ok(PollOutcome::SlowDown)
        );
        for e in ["access_denied", "expired_token", "invalid_grant", "weird"] {
            let body = json!({"error": e}).to_string();
            assert!(matches!(
                parse_token_response(400, body.as_bytes(), "t", "c", 0),
                Err(HubError::Auth(_))
            ));
        }
        let Ok(PollOutcome::Token(t)) = parse_token_response(
            200,
            br#"{"access_token":"a","refresh_token":"r","expires_in":60}"#,
            "t",
            "c",
            100,
        ) else {
            panic!("token")
        };
        assert_eq!((t.expires_at, t.refresh_token.as_deref()), (160, Some("r")));
        assert!(!t.is_expired(100) && t.is_expired(131));
        assert!(!format!("{t:?}").contains('a') || !format!("{t:?}").contains("\"a\""));
        assert!(parse_token_response(200, br#"{}"#, "t", "c", 0).is_err());

        let d: DeviceAuthorization = serde_json::from_str(r#"{"device_code":"d","user_code":"U","verification_uri":"https://v","expires_in":600}"#).expect("da");
        assert_eq!(d.interval, 5);
        assert!(parse_discovery(br#"{"device_authorization_endpoint":"https://i/d","token_endpoint":"https://i/t"}"#).is_ok());
        assert!(
            parse_discovery(
                br#"{"device_authorization_endpoint":"http://i/d","token_endpoint":"https://i/t"}"#
            )
            .is_err()
        );
        assert!(parse_discovery(br#"{"token_endpoint":"https://i/t"}"#).is_err());
        assert_eq!(
            discovery_url("https://i/realm/").expect("u").as_str(),
            "https://i/realm/.well-known/openid-configuration"
        );
    }

    #[test]
    fn whoami_decodes_claims_without_leaking_token() {
        let claims = json!({"sub": A, "tenant": "t1", "scope": "hub:groups:read", "exp": 9});
        let jwt = format!(
            "h.{}.s",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let hub = Url::parse("https://hub.example/").expect("u");
        let v = whoami_view(&decode_claims(&jwt).expect("claims"), &hub);
        assert_eq!(v["tenant"], "t1");
        assert!(!v.to_string().contains(&jwt));
        assert!(decode_claims("opaque").is_err());
        assert!(decode_claims("a.!!!.c").is_err());
        assert_eq!(keychain_account(&hub), "https://hub.example");
    }
}
