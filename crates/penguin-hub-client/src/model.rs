//! Wire types for the agent routes of `services/hub-api/openapi/v1.yaml`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The `{status, data, meta}` envelope; `meta` is ignored on read.
#[derive(Debug, Deserialize)]
pub struct Envelope<T> {
    /// `success` or `error`.
    pub status: String,
    /// Payload, or an RFC 9457 problem object on error.
    pub data: T,
}

/// RFC 9457 problem details as the hub renders them inside `data`.
#[derive(Debug, Default, Deserialize)]
pub struct Problem {
    /// Stable hub error code.
    #[serde(default)]
    pub code: Option<i64>,
    /// Short title.
    #[serde(default)]
    pub title: String,
    /// Human detail.
    #[serde(default)]
    pub detail: Option<String>,
}

/// `TokenResponse` from enroll / token refresh.
#[derive(Deserialize)]
pub struct TokenResponse {
    /// Agent public id (UUID).
    pub agent_id: String,
    /// Machine JWT, at most one hour.
    pub access_token: String,
    /// Seconds until the access token expires.
    pub expires_in: u64,
    /// Single-use rotating refresh token.
    pub refresh_token: String,
}

/// `EnrollRequest`.
#[derive(Serialize)]
pub struct EnrollRequest<'a> {
    /// 1 linux, 2 macos, 3 windows.
    pub platform: u8,
    /// Agent semver.
    pub agent_version: &'a str,
}

/// `RefreshRequest`.
#[derive(Serialize)]
pub struct RefreshRequest<'a> {
    /// The current refresh token.
    pub refresh_token: &'a str,
}

/// `Limits`: absent means no hub ceiling.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubLimits {
    /// Memory ceiling in MiB.
    #[serde(default)]
    pub max_memory_mb: Option<u64>,
    /// Fuel ceiling.
    #[serde(default)]
    pub max_fuel: Option<u64>,
    /// Tool-call ceiling (applied to the per-run call budget).
    #[serde(default)]
    pub max_tool_calls_per_min: Option<u64>,
    /// Concurrency ceiling (informational; the host runs modules one-shot).
    #[serde(default)]
    pub max_concurrent_instances: Option<u64>,
    /// Poll interval the hub asks for.
    #[serde(default)]
    pub poll_interval_s: Option<u64>,
    /// Staleness bound the hub asks for.
    #[serde(default)]
    pub max_stale_s: Option<u64>,
}

/// `ConfigPolicy`, plus the optional `allowed_dns` narrowing list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubPolicy {
    /// `None` = hub imposes no tool restriction (local ceiling decides).
    #[serde(default)]
    pub allowed_tools: Option<Vec<String>>,
    /// Hub-side numeric ceilings.
    #[serde(default)]
    pub limits: HubLimits,
    /// `None` = no DNS restriction from the hub; `Some` can only narrow.
    #[serde(default)]
    pub allowed_dns: Option<Vec<String>>,
    /// Opaque per-module settings (never secrets); carried, not interpreted.
    #[serde(default)]
    pub settings: serde_json::Value,
}

/// `ModuleManifest` as delivered in a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestWire {
    /// Module id.
    pub id: String,
    /// Module semver.
    pub version: String,
    /// Lowercase-hex sha256 of the binary.
    pub sha256: String,
    /// Minisign signature text.
    pub signature: String,
    /// Absolute hub URL of the binary.
    pub binary_url: String,
}

/// `SyncBundle`: the agent's desired state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncBundle {
    /// Agent public id.
    pub agent_id: String,
    /// RFC 3339 generation time.
    pub generated_at: String,
    /// Merged hub policy.
    #[serde(default)]
    pub policy: HubPolicy,
    /// Hub flag restrictions; effective = license && hub.
    #[serde(default)]
    pub flags: BTreeMap<String, bool>,
    /// Modules the agent should run.
    #[serde(default)]
    pub modules: Vec<ManifestWire>,
    /// Requested poll interval.
    pub poll_interval_s: u64,
    /// Staleness bound.
    pub max_stale_s: u64,
}

/// One module's outcome inside a [`StatusReport`].
#[derive(Debug, Clone, Serialize)]
pub struct ModuleStatus {
    /// Module id.
    pub id: String,
    /// Module version.
    pub version: String,
    /// Whether it is loaded.
    pub loaded: bool,
    /// Failure code when not loaded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<i64>,
}

/// `StatusReport`.
#[derive(Debug, Serialize)]
pub struct StatusReport {
    /// ETag of the bundle this report is about.
    pub applied_etag: String,
    /// 1 applied, 2 partial, 3 rejected.
    pub result: u8,
    /// Agent semver.
    pub agent_version: String,
    /// Per-module outcomes.
    pub modules: Vec<ModuleStatus>,
}

/// Module failure codes reported in `error_code`.
pub mod error_code {
    /// Signature or digest verification failed (or malformed fields/version).
    pub const VERIFY: i64 = 1;
    /// The binary could not be fetched.
    pub const FETCH: i64 = 2;
    /// Version lower than the highest already verified for this id.
    pub const ROLLBACK: i64 = 3;
    /// The host refused or failed to load/run it.
    pub const LOAD: i64 = 4;
    /// Local policy (flag) denies it.
    pub const POLICY: i64 = 5;
    /// The bundle listed the id twice.
    pub const DUPLICATE: i64 = 6;
}
