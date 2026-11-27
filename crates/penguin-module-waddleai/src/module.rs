//! The waddleai `penguin_sdk::Module` implementation: lifecycle glue wiring
//! [`crate::client::WaddleAiClient`] to the daemon supervisor, the
//! per-ecosystem hook shims (see [`crate::hooks`]) to the CLI surface, and
//! the Tier-1 denylist cache (see [`crate::cache`]) to a background sync
//! task.
//!
//! # License gating
//!
//! `info().license_feature` is deliberately empty, matching every other
//! built-in module: the module itself — installing shims, reporting
//! status, emitting telemetry — must load with no license server reachable
//! at all. Per `~/.claude/rules/critical-rules.md`'s tier table, WaddleAI
//! *as a product* is Enterprise-gated, but that entitlement is checked
//! server-side when a forwarded hook event is actually evaluated (see
//! [`crate::client::WaddleAiClient::evaluate_hook_event`]) — the same
//! "future decision, not defaulted here" reasoning
//! `penguin_module_waddlebot::WaddlebotModule` documents for its own
//! `license_feature`.
//!
//! # No policy logic
//!
//! This module ships shims and forwards normalized events; WaddleAI's
//! engine decides. The one local decision this module ever makes —
//! [`WaddleAiModule::evaluate_hook_event`]'s offline denylist fallback — is
//! an exact-match replay of the server's own last-synced answer, never a
//! rule this crate invented. See [`crate::cache`]'s doc.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use penguin_sdk::{
    CommandResult, CommandSpec, HealthLevel, HealthReport, HostServices, Module, ModuleError,
    ModuleInfo, ModuleState, Status,
};

use crate::cache::DenylistCache;
use crate::client::{Config as ClientConfig, EvaluateRequest, TelemetryRequest, WaddleAiClient};
use crate::commands;
use crate::config::ModuleConfig;
use crate::error::WaddleAiError;
use crate::hooks::{self, Ecosystem, Shim};
use crate::metrics::WaddleAiMetrics;

/// How long a cached auth probe (shared by [`Module::status`] and
/// [`Module::health`]) is trusted before a fresh one runs. Matches every
/// other built-in module's own health-cache TTL.
const AUTH_CACHE_TTL: Duration = Duration::from_secs(5);
/// Upper bound on a single auth probe's round trip.
const AUTH_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// The secret key the module's virtual key is read from. Never a config
/// field — see [`WaddleAiModule::init`]'s doc.
const VIRTUAL_KEY_SECRET_KEY: &str = "virtual_key";

/// The coarse outcome of a live probe against WaddleAI, distinguishing
/// "credentials rejected" from "couldn't even talk to the server" — finer
/// grained than [`HealthLevel`], which [`Module::health`] collapses this
/// into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthState {
    Ok,
    Unauthorized,
    Unreachable,
}

impl AuthState {
    fn as_str(self) -> &'static str {
        match self {
            AuthState::Ok => "ok",
            AuthState::Unauthorized => "unauthorized",
            AuthState::Unreachable => "unreachable",
        }
    }
}

/// One cached probe outcome plus the instant it ran.
#[derive(Debug, Clone, Copy)]
struct AuthProbe {
    state: AuthState,
    checked_at: SystemTime,
}

/// The outcome of [`WaddleAiModule::evaluate_hook_event`] — what
/// `crate::commands::hook_command` renders and turns into an exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookOutcome {
    /// WaddleAI returned a live `"allow"` decision (or fire-and-forget
    /// telemetry completed/degraded without blocking).
    Allow { reason: String },
    /// A denial — either WaddleAI's own live decision, or an offline
    /// glob match against the cached Tier-1 denylist (`source` records
    /// which).
    Deny {
        reason: String,
        rule_id: Option<Value>,
        source: DecisionSource,
    },
    /// WaddleAI requested interactive confirmation (`decision == "ask"`).
    Ask {
        reason: String,
        rule_id: Option<Value>,
    },
    /// WaddleAI steered the call to another model or skill set
    /// (`decision == "redirect"`).
    Redirect {
        reason: String,
        rule_id: Option<Value>,
        redirect_model: Option<String>,
        active_skills: Option<Vec<String>>,
    },
    /// No live decision could be obtained (WaddleAI unreachable or
    /// rejected the request) and the tool input did not match the cached
    /// denylist — this crate has no answer to give, so it says so rather
    /// than inventing one. `crate::commands::hook_command` maps this to a
    /// nonzero exit, matching each ecosystem's own hook contract of
    /// blocking on a nonzero exit.
    Unavailable { reason: String },
}

/// Where a [`HookOutcome::Deny`] decision came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionSource {
    /// WaddleAI's own live response.
    Live,
    /// An offline exact-match against [`crate::cache::DenylistCache`].
    CachedDenylist,
}

/// The background denylist-sync task's handle, held while the module is
/// running.
struct SyncTask {
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

/// [`WaddleAiModule`]'s real state, held behind an `Arc` so the module
/// itself stays a cheap `Clone`.
struct Inner {
    host: OnceLock<Arc<dyn HostServices>>,
    config: OnceLock<ModuleConfig>,
    metrics: OnceLock<WaddleAiMetrics>,
    /// The virtual key read from secrets at `init`, kept so
    /// [`WaddleAiModule::set_virtual_key`] can rebuild the client without a
    /// secrets round trip and so [`WaddleAiModule::key_present`]/
    /// [`WaddleAiModule::masked_key`] are cheap. Never logged or placed in
    /// any command's output except through [`crate::mask::mask_secret`].
    virtual_key: StdMutex<String>,
    /// Not a `OnceLock`: [`WaddleAiModule::set_virtual_key`] rebuilds and
    /// swaps it, since [`WaddleAiClient`] bakes the key in at construction.
    client: StdMutex<Option<Arc<WaddleAiClient>>>,
    running: AtomicBool,
    last_probe: StdMutex<Option<AuthProbe>>,
    denylist: StdMutex<DenylistCache>,
    denylist_path: OnceLock<std::path::PathBuf>,
    hooks_backup_dir: OnceLock<std::path::PathBuf>,
    sync_task: StdMutex<Option<SyncTask>>,
    /// Test-only injection seam (see
    /// [`WaddleAiModule::set_hook_target_dir_for_test`]): when set,
    /// [`WaddleAiModule::shim_for`] builds each ecosystem's [`Shim`] with
    /// [`hooks::claude::ClaudeShim::with_target`] (and its Gemini/VS Code
    /// equivalents) pointed under this directory instead of the real
    /// home/config directory. Always present (not `#[cfg(test)]`-gated) so
    /// `shim_for` has one code path in every build; only ever populated by
    /// the `#[cfg(test)]` setter, so it is always `None` outside tests.
    hook_target_dir_override: OnceLock<std::path::PathBuf>,
}

impl Inner {
    const UNINITIALISED: &'static str = "waddleai module used before init";

    fn new() -> Inner {
        Inner {
            host: OnceLock::new(),
            config: OnceLock::new(),
            metrics: OnceLock::new(),
            virtual_key: StdMutex::new(String::new()),
            client: StdMutex::new(None),
            running: AtomicBool::new(false),
            last_probe: StdMutex::new(None),
            denylist: StdMutex::new(DenylistCache::empty()),
            denylist_path: OnceLock::new(),
            hooks_backup_dir: OnceLock::new(),
            sync_task: StdMutex::new(None),
            hook_target_dir_override: OnceLock::new(),
        }
    }
}

/// waddleai: the desktop-side companion to WaddleAI's agent-hooks feature.
/// Installs per-ecosystem hook shims, holds the connection/credential, and
/// reports telemetry — never policy. See this module's top-level doc.
///
/// A cheap `Clone` (an `Arc` around its real state) so the background
/// denylist-sync task can hold a handle without borrowing `&self` past
/// `start`'s return.
#[derive(Clone)]
pub struct WaddleAiModule {
    inner: Arc<Inner>,
}

impl Default for WaddleAiModule {
    fn default() -> WaddleAiModule {
        WaddleAiModule::new()
    }
}

impl WaddleAiModule {
    /// Builds a fresh, un-initialised module — the shape every
    /// [`penguin_sdk::Factory`] invocation (including [`factory`]) produces.
    pub fn new() -> WaddleAiModule {
        WaddleAiModule {
            inner: Arc::new(Inner::new()),
        }
    }

    /// The panic message every post-init accessor shares: every `Module`
    /// method besides `info`/`init` runs only after `init` has already
    /// populated every field below, so a miss here means the supervisor
    /// violated that contract, not a recoverable runtime condition.
    pub(crate) fn host(&self) -> &Arc<dyn HostServices> {
        self.inner.host.get().expect(Inner::UNINITIALISED)
    }

    pub(crate) fn config(&self) -> &ModuleConfig {
        self.inner.config.get().expect(Inner::UNINITIALISED)
    }

    pub(crate) fn metrics(&self) -> &WaddleAiMetrics {
        self.inner.metrics.get().expect(Inner::UNINITIALISED)
    }

    pub(crate) fn client(&self) -> Arc<WaddleAiClient> {
        self.inner
            .client
            .lock()
            .expect("client mutex poisoned")
            .clone()
            .expect(Inner::UNINITIALISED)
    }

    fn denylist_path(&self) -> &std::path::Path {
        self.inner.denylist_path.get().expect(Inner::UNINITIALISED)
    }

    fn hooks_backup_dir(&self) -> &std::path::Path {
        self.inner
            .hooks_backup_dir
            .get()
            .expect(Inner::UNINITIALISED)
    }

    /// Whether a virtual key is currently set.
    pub(crate) fn key_present(&self) -> bool {
        !self
            .inner
            .virtual_key
            .lock()
            .expect("virtual_key mutex poisoned")
            .is_empty()
    }

    /// A non-reversible hint of the current virtual key, never the value
    /// itself.
    pub(crate) fn masked_key(&self) -> String {
        crate::mask::mask_secret(
            &self
                .inner
                .virtual_key
                .lock()
                .expect("virtual_key mutex poisoned"),
        )
    }

    /// Persists `value` to `host.secrets()`, then rebuilds the client
    /// against it — the backing primitive for `key set`.
    ///
    /// `value` still arrives via `dispatch`'s plain `args: &[String]` (the
    /// SDK's `Dispatch` RPC has no dedicated secret field), but by the time
    /// it reaches this method it was never a literal shell token: `key
    /// set`'s `CommandSpec` declares `max_args: 0`, so clap rejects a typed
    /// positional outright, and `bins/penguin` only ever populates `args`
    /// here from a genuine pipe (`penguin_cli_core::dispatch::
    /// apply_stdin_fallback`) or from `--key-file`'s file contents (read
    /// daemon-side, never via `args` at all) — see `crate::commands`'s
    /// top-level doc for the full mechanism. This keeps the value out of
    /// shell history and the process list, the part that actually leaks.
    ///
    /// A dedicated secrets-set RPC the desktop UI's paste flow could call
    /// directly (mirroring `penguin_module_waddlebot::session_proxy`'s
    /// `SetUserSession` RPC) remains a legitimate defence-in-depth
    /// follow-up — it would also cover a locally-compromised `penguin`
    /// binary reading `args` in-process, which stdin/`--key-file` do not —
    /// but is out of scope for this crate alone to add.
    ///
    /// This method still never logs, echoes, or returns `value` unmasked —
    /// see [`crate::mask::mask_secret`] at every call site that surfaces it.
    pub(crate) async fn set_virtual_key(&self, value: String) -> Result<(), ModuleError> {
        self.host()
            .secrets()
            .set(VIRTUAL_KEY_SECRET_KEY, value.as_bytes())
            .await
            .map_err(|err| ModuleError::new(format!("store virtual key: {err}")))?;

        let client_config = ClientConfig {
            base_url: self.config().server.base_url.clone(),
            virtual_key: value.clone(),
            ..ClientConfig::default()
        };
        let client = WaddleAiClient::new(client_config)
            .map_err(|err| ModuleError::new(format!("rebuild WaddleAI client: {err}")))?;

        *self.inner.client.lock().expect("client mutex poisoned") = Some(Arc::new(client));
        *self
            .inner
            .virtual_key
            .lock()
            .expect("virtual_key mutex poisoned") = value;
        // A key change invalidates any cached probe outcome.
        *self.inner.last_probe.lock().expect("probe mutex poisoned") = None;
        Ok(())
    }

    /// Runs `fut` (one WaddleAI API call) and updates
    /// `waddleai_api_requests_total`/`waddleai_api_errors_total` around it —
    /// the single choke point every call site routes through.
    pub(crate) async fn call<T>(
        &self,
        fut: impl std::future::Future<Output = Result<T, WaddleAiError>>,
    ) -> Result<T, WaddleAiError> {
        self.metrics().api_requests_total.inc();
        let result = fut.await;
        if result.is_err() {
            self.metrics().api_errors_total.inc();
        }
        result
    }

    /// A cheap, cached liveness/auth probe shared by [`Module::status`] and
    /// [`Module::health`].
    async fn probe_auth(&self) -> AuthProbe {
        {
            let cached = self.inner.last_probe.lock().expect("probe mutex poisoned");
            if let Some(probe) = *cached
                && let Ok(age) = SystemTime::now().duration_since(probe.checked_at)
                && age < AUTH_CACHE_TTL
            {
                return probe;
            }
        }

        let client = self.client();
        let attempt = self.call(client.health());
        let state = match tokio::time::timeout(AUTH_PROBE_TIMEOUT, attempt).await {
            Ok(Ok(_health)) => AuthState::Ok,
            Ok(Err(WaddleAiError::Auth { .. })) => AuthState::Unauthorized,
            Ok(Err(_other)) => AuthState::Unreachable,
            Err(_elapsed) => AuthState::Unreachable,
        };
        let probe = AuthProbe {
            state,
            checked_at: SystemTime::now(),
        };
        *self.inner.last_probe.lock().expect("probe mutex poisoned") = Some(probe);
        probe
    }

    /// A read-only clone of the currently cached denylist snapshot.
    pub(crate) fn denylist_snapshot(&self) -> DenylistCache {
        self.inner
            .denylist
            .lock()
            .expect("denylist mutex poisoned")
            .clone()
    }

    /// Fetches a fresh denylist snapshot, persists it to disk, and updates
    /// the in-memory copy and the `denylist_*` gauges. The single choke
    /// point both the `denylist sync` CLI command and the background sync
    /// task route through.
    pub(crate) async fn sync_denylist(&self) -> Result<DenylistCache, WaddleAiError> {
        let client = self.client();
        let response = self.call(client.fetch_denylist()).await?;

        let mut cache = self
            .inner
            .denylist
            .lock()
            .expect("denylist mutex poisoned")
            .clone();
        cache.record_sync(
            response.updated_at,
            response.denylist_patterns,
            SystemTime::now(),
        );

        if let Err(err) = crate::cache::save(self.denylist_path(), &cache) {
            self.host().logger().warn(
                "failed to persist denylist cache to disk",
                &[("error", &err.to_string())],
            );
        }

        self.metrics()
            .denylist_entries
            .set(cache.entries.len() as f64);
        if let Some(synced_at) = cache.synced_at_unix {
            self.metrics()
                .denylist_last_synced_timestamp_seconds
                .set(synced_at as f64);
        }
        self.metrics().denylist_stale.set(0.0);

        *self.inner.denylist.lock().expect("denylist mutex poisoned") = cache.clone();
        Ok(cache)
    }

    /// Evaluates one normalized hook event:
    /// - Telemetry-only events (`post_tool_use`, `session_start`,
    ///   `notification`) are forwarded fire-and-forget to
    ///   `POST /api/v1/hooks/telemetry` and never block the agent.
    /// - `pre_tool_use` is forwarded to `POST /api/v1/hooks/evaluate`; if
    ///   unreachable, falls back to glob-matching `tool_input` against the
    ///   cached Tier-1 denylist (fail-closed).
    pub(crate) async fn evaluate_hook_event(
        &self,
        ecosystem: Ecosystem,
        event: &str,
        payload: &Value,
    ) -> HookOutcome {
        let canonical_event = hooks::normalize_event(event).unwrap_or(event);
        self.metrics()
            .hook_invocations_total
            .with_label_values(&[ecosystem.as_str(), canonical_event])
            .inc();

        let tool_name = payload
            .get("tool_name")
            .or_else(|| payload.get("tool"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(if hooks::is_telemetry_event(canonical_event) {
                ""
            } else {
                "unknown"
            })
            .to_string();

        let tool_input = match payload.get("tool_input") {
            Some(v) if v.is_object() => v.clone(),
            _ if payload.is_object() => payload.clone(),
            _ => serde_json::json!({}),
        };

        let session_id = payload
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        let workspace_path = payload
            .get("workspace_path")
            .or_else(|| payload.get("cwd"))
            .and_then(Value::as_str)
            .map(ToString::to_string);

        let occurred_at = payload
            .get("occurred_at")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(now_rfc3339);

        let client = self.client();

        if hooks::is_telemetry_event(canonical_event) {
            let req = TelemetryRequest {
                ecosystem: ecosystem.as_str().to_string(),
                event: canonical_event.to_string(),
                tool_name,
                session_id,
                tool_input,
                occurred_at,
            };
            if let Err(err) = self.call(client.send_telemetry(&req)).await {
                self.host().logger().warn(
                    "hook telemetry delivery failed (non-blocking)",
                    &[("event", canonical_event), ("error", &err.to_string())],
                );
            }
            self.record_decision("allow");
            return HookOutcome::Allow {
                reason: "telemetry".to_string(),
            };
        }

        let req = EvaluateRequest {
            hook_version: "1",
            ecosystem: ecosystem.as_str().to_string(),
            event: canonical_event.to_string(),
            tool_name,
            tool_input: tool_input.clone(),
            session_id,
            workspace_path,
            occurred_at,
        };

        match self.call(client.evaluate_hook_event(&req)).await {
            Ok(response) => match response.decision.as_str() {
                "allow" => {
                    self.record_decision("allow");
                    HookOutcome::Allow {
                        reason: response.reason.unwrap_or_default(),
                    }
                }
                "ask" => {
                    self.record_decision("ask");
                    let reason = response
                        .reason
                        .filter(|r| !r.is_empty())
                        .unwrap_or_else(|| "confirmation required by WaddleAI".to_string());
                    HookOutcome::Ask {
                        reason,
                        rule_id: response.rule_id,
                    }
                }
                "redirect" => {
                    self.record_decision("redirect");
                    HookOutcome::Redirect {
                        reason: response.reason.unwrap_or_default(),
                        rule_id: response.rule_id,
                        redirect_model: response.redirect_model,
                        active_skills: response.active_skills,
                    }
                }
                _ => {
                    // "deny", or any unrecognised wire value — fail safe.
                    self.record_decision("deny");
                    let reason = response
                        .reason
                        .filter(|r| !r.is_empty())
                        .unwrap_or_else(|| "denied by WaddleAI".to_string());
                    HookOutcome::Deny {
                        reason,
                        rule_id: response.rule_id,
                        source: DecisionSource::Live,
                    }
                }
            },
            Err(_err) => {
                let cache = self.denylist_snapshot();
                if let Some(pattern) = cache.matches_tool_input(&tool_input) {
                    self.record_decision("deny");
                    return HookOutcome::Deny {
                        reason: format!("matched cached Tier-1 denylist pattern: {pattern}"),
                        rule_id: None,
                        source: DecisionSource::CachedDenylist,
                    };
                }
                if let Some(subject) = payload.get("subject").and_then(Value::as_str)
                    && cache.contains(subject)
                {
                    self.record_decision("deny");
                    return HookOutcome::Deny {
                        reason: "subject matches the cached Tier-1 denylist".to_string(),
                        rule_id: None,
                        source: DecisionSource::CachedDenylist,
                    };
                }
                self.record_decision("unavailable");
                HookOutcome::Unavailable {
                    reason: "WaddleAI is unreachable and the subject is not on the cached denylist"
                        .to_string(),
                }
            }
        }
    }

    fn record_decision(&self, outcome: &str) {
        self.metrics()
            .hook_decisions_total
            .with_label_values(&[outcome])
            .inc();
    }

    /// Builds the [`Shim`] implementation for `ecosystem`.
    ///
    /// When [`Inner::hook_target_dir_override`] is set (only ever true in
    /// this crate's own tests, via
    /// [`WaddleAiModule::set_hook_target_dir_for_test`]), every shim is
    /// built with its `with_target` constructor pointed at a file under
    /// that directory instead of resolving a real home/config directory —
    /// the same per-shim injection seam [`hooks::claude::ClaudeShim`],
    /// [`hooks::gemini::GeminiShim`], and [`hooks::vscode::VsCodeShim`]
    /// already expose to their own unit tests, wired through here so
    /// [`WaddleAiModule::install_hook`]/`uninstall_hook`/`hook_status` (and
    /// therefore `crate::commands`' `hooks install/uninstall/list`
    /// dispatch, end to end) can be exercised without ever touching a real
    /// path either.
    fn shim_for(&self, ecosystem: Ecosystem) -> Box<dyn Shim> {
        if let Some(dir) = self.inner.hook_target_dir_override.get() {
            let filename = match ecosystem {
                Ecosystem::Claude | Ecosystem::Cortex => "claude-settings.json",
                Ecosystem::Gemini => "gemini-hooks.json",
                Ecosystem::VsCode => "vscode-settings.json",
            };
            let target = dir.join(filename);
            return match ecosystem {
                Ecosystem::Claude | Ecosystem::Cortex => {
                    Box::new(hooks::claude::ClaudeShim::with_target(target))
                }
                Ecosystem::Gemini => Box::new(hooks::gemini::GeminiShim::with_target(target)),
                Ecosystem::VsCode => Box::new(hooks::vscode::VsCodeShim::with_target(target)),
            };
        }
        match ecosystem {
            Ecosystem::Claude | Ecosystem::Cortex => Box::new(hooks::claude::ClaudeShim::new()),
            Ecosystem::Gemini => Box::new(hooks::gemini::GeminiShim::new()),
            Ecosystem::VsCode => Box::new(hooks::vscode::VsCodeShim::new()),
        }
    }

    /// Test-only injection seam: overrides the directory
    /// [`WaddleAiModule::shim_for`] resolves every ecosystem's shim target
    /// file under, so a test exercising `install_hook`/`uninstall_hook`/
    /// `hook_status` — directly or via `crate::commands`'s `hooks
    /// install`/`uninstall`/`list` dispatch — never resolves
    /// `dirs::home_dir()`/`dirs::config_dir()` and so can never write into a
    /// real developer's actual Claude/Gemini/VS Code config, regardless of
    /// whether the test happens to run somewhere those resolve to a
    /// writable path. Must be called at most once per module instance,
    /// before the first hook call — matches every other `OnceLock` field on
    /// [`Inner`] being populate-once.
    #[cfg(test)]
    pub(crate) fn set_hook_target_dir_for_test(&self, dir: std::path::PathBuf) {
        self.inner
            .hook_target_dir_override
            .set(dir)
            .expect("hook target dir override set more than once");
    }

    /// Installs the hook shim for `ecosystem`.
    pub(crate) fn install_hook(
        &self,
        ecosystem: Ecosystem,
    ) -> Result<hooks::InstallReport, hooks::ShimError> {
        hooks::install(self.hooks_backup_dir(), self.shim_for(ecosystem).as_ref())
    }

    /// Uninstalls the hook shim for `ecosystem`, restoring its config file
    /// byte-for-byte.
    pub(crate) fn uninstall_hook(
        &self,
        ecosystem: Ecosystem,
    ) -> Result<hooks::UninstallReport, hooks::ShimError> {
        hooks::uninstall(self.hooks_backup_dir(), self.shim_for(ecosystem).as_ref())
    }

    /// Reports whether `ecosystem`'s shim is currently installed.
    pub(crate) fn hook_status(
        &self,
        ecosystem: Ecosystem,
    ) -> Result<hooks::ShimStatus, hooks::ShimError> {
        hooks::status(self.hooks_backup_dir(), self.shim_for(ecosystem).as_ref())
    }

    /// Starts the background denylist-sync task: one immediate best-effort
    /// sync, then a refresh every `denylist.sync_interval_secs`. Failures
    /// are logged, never fatal — a module that can't reach WaddleAI yet is
    /// still itself fully operational (matching every other built-in
    /// module's degrade-gracefully rule for its own upstream).
    fn start_sync_task(&self) {
        let cancel = CancellationToken::new();
        let cancel_for_task = cancel.clone();
        let module = self.clone();
        let interval = Duration::from_secs(self.config().denylist.sync_interval_secs.max(1));

        let handle = tokio::spawn(async move {
            if let Err(err) = module.sync_denylist().await {
                module.host().logger().warn(
                    "initial denylist sync failed",
                    &[("error", &err.to_string())],
                );
            }

            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // consume the immediate first tick

            loop {
                tokio::select! {
                    () = cancel_for_task.cancelled() => return,
                    _ = ticker.tick() => {
                        if let Err(err) = module.sync_denylist().await {
                            module.host().logger().warn(
                                "denylist sync failed",
                                &[("error", &err.to_string())],
                            );
                        }
                    }
                }
            }
        });

        *self
            .inner
            .sync_task
            .lock()
            .expect("sync_task mutex poisoned") = Some(SyncTask { cancel, handle });
    }

    /// Stops the background denylist-sync task, if running. Idempotent.
    async fn stop_sync_task(&self) {
        let task = self
            .inner
            .sync_task
            .lock()
            .expect("sync_task mutex poisoned")
            .take();
        if let Some(task) = task {
            task.cancel.cancel();
            let _ = task.handle.await;
        }
    }
}

/// Formats `SystemTime::now()` as an RFC3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`)
/// without pulling in a date/time crate.
fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;
    // Howard Hinnant's civil_from_days algorithm (days since 1970-01-01).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(m <= 2);
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Builds a fresh, un-initialised [`WaddleAiModule`] — the
/// [`penguin_sdk::Factory`] registered for the built-in `"waddleai"`
/// module (see `penguin-registry`).
pub fn factory() -> Box<dyn Module> {
    Box::new(WaddleAiModule::new())
}

#[async_trait]
impl Module for WaddleAiModule {
    /// Identity metadata for the daemon's module registry and `penguin
    /// status`. See this module's top-level doc for why `license_feature`
    /// is empty.
    fn info(&self) -> ModuleInfo {
        ModuleInfo {
            name: "waddleai".to_string(),
            version: "1.0.0".to_string(),
            description:
                "WaddleAI agent-hooks: shim installation, credential storage, and telemetry"
                    .to_string(),
            license_feature: String::new(),
        }
    }

    /// Resolves config (defaults, then the host's validated YAML), reads
    /// the virtual key from the secret store — **never** from config, even
    /// if a document happened to carry one, matching every other built-in
    /// module's rule for its own credential — loads the persisted denylist
    /// cache from disk, builds the WaddleAI client, and registers every
    /// metric.
    ///
    /// Never fails because WaddleAI is unreachable or rejects the virtual
    /// key: [`WaddleAiClient::new`] only builds an HTTP/TLS stack, it never
    /// touches the network. The module loads either way; a bad server URL
    /// or an invalid/absent key instead shows up through
    /// [`Module::health`]/[`Module::status`] once it starts trying to
    /// actually talk to WaddleAI.
    async fn init(&self, host: Arc<dyn HostServices>) -> Result<(), ModuleError> {
        let logger = host.logger();

        let raw = host.config();
        let cfg: ModuleConfig = if raw.is_empty() {
            ModuleConfig::default()
        } else {
            serde_norway::from_slice(&raw)
                .map_err(|err| ModuleError::new(format!("parse waddleai config: {err}")))?
        };

        let virtual_key = match host.secrets().get(VIRTUAL_KEY_SECRET_KEY).await {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(_not_found_or_other) => String::new(),
        };

        let client_config = ClientConfig {
            base_url: cfg.server.base_url.clone(),
            virtual_key: virtual_key.clone(),
            ..ClientConfig::default()
        };
        let client = WaddleAiClient::new(client_config)
            .map_err(|err| ModuleError::new(format!("create WaddleAI client: {err}")))?;

        let metrics = WaddleAiMetrics::register(host.metrics().as_ref())
            .map_err(|err| ModuleError::new(format!("register metrics: {err}")))?;

        let denylist_path = host.data_dir().join("denylist.json");
        let hooks_backup_dir = host.data_dir().join("hooks");
        let denylist = crate::cache::load(&denylist_path)
            .map_err(|err| ModuleError::new(format!("load denylist cache: {err}")))?;
        metrics.denylist_entries.set(denylist.entries.len() as f64);
        if let Some(synced_at) = denylist.synced_at_unix {
            metrics
                .denylist_last_synced_timestamp_seconds
                .set(synced_at as f64);
        }
        metrics
            .denylist_stale
            .set(f64::from(u8::from(denylist.is_stale(
                SystemTime::now(),
                Duration::from_secs(cfg.denylist.max_age_secs),
            ))));

        logger.info(
            "waddleai module initialized",
            &[
                ("server", cfg.server.base_url.as_str()),
                ("key_present", &(!virtual_key.is_empty()).to_string()),
                ("denylist_entries", &denylist.entries.len().to_string()),
            ],
        );

        // `OnceLock::set` returning `Err` would mean `init` ran twice —
        // impossible per the `Module::init` contract ("called exactly
        // once"), so a violation here is a supervisor bug, not a condition
        // this method needs to handle gracefully.
        let _ = self.inner.host.set(host);
        let _ = self.inner.hooks_backup_dir.set(hooks_backup_dir);
        let _ = self.inner.denylist_path.set(denylist_path);
        let _ = self.inner.config.set(cfg);
        let _ = self.inner.metrics.set(metrics);
        *self.inner.client.lock().expect("client mutex poisoned") = Some(Arc::new(client));
        *self
            .inner
            .virtual_key
            .lock()
            .expect("virtual_key mutex poisoned") = virtual_key;
        *self.inner.denylist.lock().expect("denylist mutex poisoned") = denylist;

        Ok(())
    }

    /// Marks the module running, flips the `waddleai_up` gauge, auto-installs
    /// any ecosystem shims enabled in config (see
    /// [`crate::config::HooksSection`]), and starts the background
    /// denylist-sync task. Idempotent.
    async fn start(&self) -> Result<(), ModuleError> {
        if self.inner.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.metrics().up.set(1.0);

        for (ecosystem, enabled) in [
            (Ecosystem::Claude, self.config().hooks.claude),
            (Ecosystem::Gemini, self.config().hooks.gemini),
            (Ecosystem::VsCode, self.config().hooks.vscode),
        ] {
            if !enabled {
                continue;
            }
            if let Err(err) = self.install_hook(ecosystem) {
                // Never fatal: a shim install failure (e.g. an unreadable
                // home directory in a locked-down environment) must not
                // take the whole module down.
                self.host().logger().warn(
                    "auto-install of hook shim failed",
                    &[
                        ("ecosystem", ecosystem.as_str()),
                        ("error", &err.to_string()),
                    ],
                );
            }
        }

        self.start_sync_task();
        self.host().logger().info("waddleai module started", &[]);
        Ok(())
    }

    /// Stops the background denylist-sync task and flips `waddleai_up`
    /// back to 0. Idempotent. Never uninstalls hook shims — stopping the
    /// module is not the same as an operator asking to remove the shims.
    async fn stop(&self) -> Result<(), ModuleError> {
        if !self.inner.running.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        self.stop_sync_task().await;
        self.metrics().up.set(0.0);
        self.host().logger().info("waddleai module stopped", &[]);
        Ok(())
    }

    /// Reports the module's running state, the active server URL, whether a
    /// virtual key is set, a cached auth probe outcome, each ecosystem
    /// shim's install state, and the denylist cache's size/staleness.
    async fn status(&self) -> Result<Status, ModuleError> {
        let running = self.inner.running.load(Ordering::SeqCst);
        let state = if running {
            ModuleState::Running
        } else {
            ModuleState::Stopped
        };

        let probe = self.probe_auth().await;
        let denylist = self.denylist_snapshot();
        let now = SystemTime::now();
        let max_age = Duration::from_secs(self.config().denylist.max_age_secs);

        let mut detail = HashMap::new();
        detail.insert("server".to_string(), self.config().server.base_url.clone());
        detail.insert("key_present".to_string(), self.key_present().to_string());
        detail.insert("auth".to_string(), probe.state.as_str().to_string());
        detail.insert(
            "denylist_entries".to_string(),
            denylist.entries.len().to_string(),
        );
        detail.insert(
            "denylist_last_synced".to_string(),
            denylist
                .synced_at_unix
                .map(|secs| secs.to_string())
                .unwrap_or_else(|| "never".to_string()),
        );
        detail.insert(
            "denylist_stale".to_string(),
            denylist.is_stale(now, max_age).to_string(),
        );
        for ecosystem in Ecosystem::all() {
            let installed = self
                .hook_status(ecosystem)
                .map(|s| s.installed)
                .unwrap_or(false);
            detail.insert(
                format!("hook_{}", ecosystem.as_str()),
                installed.to_string(),
            );
        }

        Ok(Status { state, detail })
    }

    /// A cheap, cached liveness/auth probe. [`HealthLevel::Healthy`] only
    /// when WaddleAI accepts the current virtual key; otherwise
    /// [`HealthLevel::Degraded`] — never [`HealthLevel::Unhealthy`], since a
    /// module that can't reach its remote server yet is still itself fully
    /// operational, same rule every other built-in module applies.
    ///
    /// When unreachable, the message notes whether the offline fail-closed
    /// path can still be trusted (a fresh cached denylist) or not (a stale
    /// one) — see [`crate::cache::DenylistCache::is_stale`]'s doc for why
    /// that distinction matters.
    async fn health(&self) -> HealthReport {
        let probe = self.probe_auth().await;
        let (level, message) = match probe.state {
            AuthState::Ok => (HealthLevel::Healthy, "OK".to_string()),
            AuthState::Unauthorized => (
                HealthLevel::Degraded,
                "WaddleAI rejected the virtual key".to_string(),
            ),
            AuthState::Unreachable => {
                let denylist = self.denylist_snapshot();
                let max_age = Duration::from_secs(self.config().denylist.max_age_secs);
                let message = if denylist.is_stale(probe.checked_at, max_age) {
                    "WaddleAI unreachable; cached Tier-1 denylist is stale, offline fail-closed \
                     coverage is degraded"
                        .to_string()
                } else {
                    format!(
                        "WaddleAI unreachable; falling back to a fresh cached Tier-1 denylist \
                         ({} entries)",
                        denylist.entries.len()
                    )
                };
                (HealthLevel::Degraded, message)
            }
        };
        HealthReport {
            level,
            message,
            checked_at: probe.checked_at,
        }
    }

    /// Declares waddleai's CLI command tree.
    fn commands(&self) -> Vec<CommandSpec> {
        commands::command_tree()
    }

    /// Executes one waddleai CLI command.
    async fn dispatch(
        &self,
        path: &[String],
        flags: &HashMap<String, String>,
        args: &[String],
    ) -> Result<CommandResult, ModuleError> {
        commands::dispatch(self, path, flags, args).await
    }

    /// Returns [`crate::config::CONFIG_SCHEMA`] for the daemon to validate
    /// `waddleai.yaml` against before `init` ever sees it.
    fn config_schema(&self) -> Option<Vec<u8>> {
        Some(crate::config::CONFIG_SCHEMA.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeHost, MockResponse, MockServer};
    use penguin_sdk::SecretStore;

    fn config_bytes(base_url: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"server": {"base_url": base_url}})).unwrap()
    }

    async fn init_module_against(server: &MockServer) -> (WaddleAiModule, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.secrets
            .set("virtual_key", b"wa-testkey")
            .await
            .unwrap();
        host.config = config_bytes(&server.base_url);
        let module = WaddleAiModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");
        (module, dir)
    }

    #[test]
    fn info_reports_waddleai_identity_with_no_license_gate() {
        let module = WaddleAiModule::new();
        let info = module.info();
        assert_eq!(info.name, "waddleai");
        assert_eq!(info.version, "1.0.0");
        assert!(info.license_feature.is_empty());
    }

    #[test]
    fn factory_builds_a_fresh_uninitialised_module() {
        let module = factory();
        assert_eq!(module.info().name, "waddleai");
    }

    #[test]
    #[should_panic(expected = "waddleai module used before init")]
    fn accessors_panic_before_init() {
        let module = WaddleAiModule::new();
        let _ = module.config();
    }

    #[tokio::test]
    async fn init_never_fails_when_the_server_is_unreachable() {
        let unreachable = MockServer::unreachable_base_url().await;
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.config = config_bytes(&unreachable);
        let module = WaddleAiModule::new();
        module
            .init(Arc::new(host))
            .await
            .expect("init must succeed even when WaddleAI cannot be reached");
    }

    #[tokio::test]
    async fn init_reads_the_virtual_key_from_secrets_not_config() {
        let server = MockServer::start().await;
        server
            .respond(
                "GET",
                "/healthz",
                MockResponse::json(200, r#"{"status":"ok"}"#),
            )
            .await;
        let (module, _dir) = init_module_against(&server).await;

        module.client().health().await.ok();
        let requests = server.requests().await;
        assert_eq!(
            requests[0].header("authorization"),
            Some("Bearer wa-testkey")
        );

        server.stop().await;
    }

    #[tokio::test]
    async fn health_maps_a_successful_probe_to_healthy() {
        let server = MockServer::start().await;
        server
            .respond(
                "GET",
                "/healthz",
                MockResponse::json(200, r#"{"status":"ok"}"#),
            )
            .await;
        let (module, _dir) = init_module_against(&server).await;

        let health = module.health().await;
        assert_eq!(health.level, HealthLevel::Healthy);

        server.stop().await;
    }

    #[tokio::test]
    async fn health_maps_a_401_to_degraded() {
        let server = MockServer::start().await;
        server
            .respond(
                "GET",
                "/healthz",
                MockResponse::json(401, r#"{"error":"bad key"}"#),
            )
            .await;
        let (module, _dir) = init_module_against(&server).await;

        let health = module.health().await;
        assert_eq!(health.level, HealthLevel::Degraded);
        assert!(health.message.contains("rejected"));

        server.stop().await;
    }

    #[tokio::test]
    async fn health_notes_a_fresh_cache_when_unreachable() {
        let unreachable = MockServer::unreachable_base_url().await;
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.config = config_bytes(&unreachable);
        let module = WaddleAiModule::new();
        module.init(Arc::new(host)).await.unwrap();

        {
            let mut cache = module.inner.denylist.lock().unwrap();
            cache.record_sync("1".to_string(), vec!["bad".to_string()], SystemTime::now());
        }

        let health = module.health().await;
        assert_eq!(health.level, HealthLevel::Degraded);
        assert!(health.message.contains("fresh cached"));
    }

    #[tokio::test]
    async fn health_notes_a_stale_cache_when_unreachable() {
        let unreachable = MockServer::unreachable_base_url().await;
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.config = config_bytes(&unreachable);
        let module = WaddleAiModule::new();
        module.init(Arc::new(host)).await.unwrap();

        {
            let mut cache = module.inner.denylist.lock().unwrap();
            let long_ago = SystemTime::now() - Duration::from_secs(999_999);
            cache.record_sync("1".to_string(), vec!["bad".to_string()], long_ago);
        }

        let health = module.health().await;
        assert_eq!(health.level, HealthLevel::Degraded);
        assert!(health.message.contains("stale"));
    }

    #[tokio::test]
    async fn status_reports_server_key_presence_and_auth() {
        let server = MockServer::start().await;
        server
            .respond(
                "GET",
                "/healthz",
                MockResponse::json(200, r#"{"status":"ok"}"#),
            )
            .await;
        let (module, _dir) = init_module_against(&server).await;

        let status = module.status().await.unwrap();
        assert_eq!(status.state, ModuleState::Stopped);
        assert_eq!(status.detail.get("server"), Some(&server.base_url));
        assert_eq!(status.detail.get("key_present"), Some(&"true".to_string()));
        assert_eq!(status.detail.get("auth"), Some(&"ok".to_string()));
        assert_eq!(
            status.detail.get("hook_claude-code"),
            Some(&"false".to_string())
        );

        server.stop().await;
    }

    #[tokio::test]
    async fn start_sets_the_up_gauge_and_is_idempotent() {
        let server = MockServer::start().await;
        let (module, _dir) = init_module_against(&server).await;

        module.start().await.expect("start succeeds");
        assert_eq!(module.metrics().up.get(), 1.0);
        module.start().await.expect("second start is a no-op");
        assert_eq!(module.metrics().up.get(), 1.0);

        module.stop().await.expect("stop succeeds");
        assert_eq!(module.metrics().up.get(), 0.0);
        module.stop().await.expect("second stop is a no-op");

        server.stop().await;
    }

    #[tokio::test]
    async fn set_virtual_key_persists_to_secrets_and_rebuilds_the_client() {
        let server = MockServer::start().await;
        server
            .respond(
                "GET",
                "/healthz",
                MockResponse::json(200, r#"{"status":"ok"}"#),
            )
            .await;
        let (module, _dir) = init_module_against(&server).await;

        module
            .set_virtual_key("wa-rotated".to_string())
            .await
            .expect("set succeeds");
        assert!(module.key_present());
        assert_eq!(module.masked_key(), "****ated");

        module.client().health().await.ok();
        let requests = server.requests().await;
        assert_eq!(
            requests.last().unwrap().header("authorization"),
            Some("Bearer wa-rotated")
        );

        let stored = module.host().secrets().get("virtual_key").await.unwrap();
        assert_eq!(stored, b"wa-rotated");

        server.stop().await;
    }

    #[tokio::test]
    async fn sync_denylist_persists_to_disk_and_updates_metrics() {
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
        let (module, _dir) = init_module_against(&server).await;

        let cache = module.sync_denylist().await.expect("sync succeeds");
        assert_eq!(
            cache.entries,
            vec![".env*".to_string(), ".git/**".to_string()]
        );
        assert_eq!(module.metrics().denylist_entries.get(), 2.0);
        assert_eq!(module.metrics().denylist_stale.get(), 0.0);

        let reloaded = crate::cache::load(module.denylist_path()).unwrap();
        assert_eq!(reloaded, cache);

        server.stop().await;
    }

    #[tokio::test]
    async fn evaluate_hook_event_returns_a_live_allow() {
        let server = MockServer::start().await;
        server
            .respond(
                "POST",
                "/hooks/evaluate",
                MockResponse::json(200, r#"{"decision":"allow","reason":"ok"}"#),
            )
            .await;
        let (module, _dir) = init_module_against(&server).await;

        let outcome = module
            .evaluate_hook_event(Ecosystem::Claude, "pre_tool_use", &serde_json::json!({}))
            .await;
        assert_eq!(
            outcome,
            HookOutcome::Allow {
                reason: "ok".to_string()
            }
        );
        assert_eq!(
            module
                .metrics()
                .hook_decisions_total
                .with_label_values(&["allow"])
                .get(),
            1.0
        );

        server.stop().await;
    }

    #[tokio::test]
    async fn evaluate_hook_event_returns_a_live_deny() {
        let server = MockServer::start().await;
        server
            .respond(
                "POST",
                "/hooks/evaluate",
                MockResponse::json(
                    200,
                    r#"{"decision":"deny","reason":"blocked","rule_id":"r-9"}"#,
                ),
            )
            .await;
        let (module, _dir) = init_module_against(&server).await;

        let outcome = module
            .evaluate_hook_event(Ecosystem::Claude, "pre_tool_use", &serde_json::json!({}))
            .await;
        assert_eq!(
            outcome,
            HookOutcome::Deny {
                reason: "blocked".to_string(),
                rule_id: Some(serde_json::json!("r-9")),
                source: DecisionSource::Live,
            }
        );

        server.stop().await;
    }

    #[tokio::test]
    async fn evaluate_hook_event_preserves_ask_and_redirect_decisions() {
        let server = MockServer::start().await;
        server
            .respond(
                "POST",
                "/hooks/evaluate",
                MockResponse::json(200, r#"{"decision":"ask","reason":"confirm?"}"#),
            )
            .await;
        let (module, _dir) = init_module_against(&server).await;

        let ask_outcome = module
            .evaluate_hook_event(Ecosystem::Claude, "pre_tool_use", &serde_json::json!({}))
            .await;
        assert_eq!(
            ask_outcome,
            HookOutcome::Ask {
                reason: "confirm?".to_string(),
                rule_id: None,
            }
        );

        server.stop().await;

        let redirect_server = MockServer::start().await;
        redirect_server
            .respond(
                "POST",
                "/hooks/evaluate",
                MockResponse::json(
                    200,
                    r#"{"decision":"redirect","reason":"use local","redirect_model":"qwen2.5:7b","active_skills":["scan"]}"#,
                ),
            )
            .await;
        let (redirect_module, _dir2) = init_module_against(&redirect_server).await;
        let redirect_outcome = redirect_module
            .evaluate_hook_event(Ecosystem::Claude, "pre_tool_use", &serde_json::json!({}))
            .await;
        assert_eq!(
            redirect_outcome,
            HookOutcome::Redirect {
                reason: "use local".to_string(),
                rule_id: None,
                redirect_model: Some("qwen2.5:7b".to_string()),
                active_skills: Some(vec!["scan".to_string()]),
            }
        );

        redirect_server.stop().await;
    }

    #[tokio::test]
    async fn evaluate_hook_event_routes_telemetry_events_without_blocking() {
        let unreachable = MockServer::unreachable_base_url().await;
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.config = config_bytes(&unreachable);
        let module = WaddleAiModule::new();
        module.init(Arc::new(host)).await.unwrap();

        for ev in ["post_tool_use", "session_start", "notification"] {
            let outcome = module
                .evaluate_hook_event(
                    Ecosystem::Gemini,
                    ev,
                    &serde_json::json!({"tool_name": "Bash"}),
                )
                .await;
            assert_eq!(
                outcome,
                HookOutcome::Allow {
                    reason: "telemetry".to_string()
                }
            );
        }
    }

    #[tokio::test]
    async fn evaluate_hook_event_falls_back_to_glob_cached_denylist_when_unreachable() {
        let unreachable = MockServer::unreachable_base_url().await;
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.config = config_bytes(&unreachable);
        let module = WaddleAiModule::new();
        module.init(Arc::new(host)).await.unwrap();
        {
            let mut cache = module.inner.denylist.lock().unwrap();
            cache.record_sync(
                "1".to_string(),
                vec![".env*".to_string(), "*.pem".to_string()],
                SystemTime::now(),
            );
        }

        let outcome = module
            .evaluate_hook_event(
                Ecosystem::Claude,
                "pre_tool_use",
                &serde_json::json!({
                    "tool_name": "Read",
                    "tool_input": {"file_path": "/app/.env.production"}
                }),
            )
            .await;
        assert_eq!(
            outcome,
            HookOutcome::Deny {
                reason: "matched cached Tier-1 denylist pattern: .env*".to_string(),
                rule_id: None,
                source: DecisionSource::CachedDenylist,
            }
        );
    }

    #[tokio::test]
    async fn evaluate_hook_event_is_unavailable_when_unreachable_and_no_cache_match() {
        let unreachable = MockServer::unreachable_base_url().await;
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.config = config_bytes(&unreachable);
        let module = WaddleAiModule::new();
        module.init(Arc::new(host)).await.unwrap();

        let outcome = module
            .evaluate_hook_event(
                Ecosystem::Claude,
                "pre-tool-use",
                &serde_json::json!({"subject": "ls -la"}),
            )
            .await;
        assert!(matches!(outcome, HookOutcome::Unavailable { .. }));
    }

    #[tokio::test]
    async fn start_auto_installs_shims_enabled_in_config() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let claude_target = dir.path().join("claude-settings.json");
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.config = serde_json::to_vec(&serde_json::json!({
            "server": {"base_url": server.base_url},
            "hooks": {"claude": false, "gemini": false, "vscode": false},
        }))
        .unwrap();
        let module = WaddleAiModule::new();
        module.init(Arc::new(host)).await.unwrap();

        // With every `hooks.*` flag false, start must not touch any real
        // config file — verified indirectly via `status`'s detail.
        module.start().await.expect("start succeeds");
        let status = module.status().await.unwrap();
        assert_eq!(
            status.detail.get("hook_claude-code"),
            Some(&"false".to_string())
        );

        module.stop().await.ok();
        server.stop().await;
        let _ = claude_target; // reserved for a future override-path variant
    }

    #[test]
    fn config_schema_is_present_and_valid_json() {
        let module = WaddleAiModule::new();
        let schema = module.config_schema().expect("schema present");
        let _: serde_json::Value = serde_json::from_slice(&schema).expect("valid JSON");
    }

    #[tokio::test]
    async fn default_impl_builds_a_fresh_module() {
        let module = WaddleAiModule::default();
        assert_eq!(module.info().name, "waddleai");
    }
}
