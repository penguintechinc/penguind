//! The `waddles-social` `penguin_sdk::Module` implementation: lifecycle glue
//! wiring [`waddles_client::WaddlesClient`] and [`crate::session_proxy::SessionProxy`]
//! to the daemon supervisor and to [`crate::commands`]'s social/session CLI surface.
//!
//! # Scope
//!
//! `waddles-social` owns the Discord-like desktop social client session
//! (`penguin.desktop.v1.SessionProxy`) and user-scoped social/community CLI
//! commands (`auth`, `communities`, `status`, `health`). Local TCP/WS bridge
//! listeners, OBS adapters, and Community Access Token (`wdl_c_`) admin
//! commands live in `penguin-module-waddles-gateway`.
//!
//! # License gating
//!
//! `info().license_feature` is deliberately empty, matching
//! `penguin-module-squawk` and `penguin-module-tobogganing`: the module loads
//! with no license server reachable.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use penguin_sdk::{
    CommandResult, CommandSpec, HealthLevel, HealthReport, HostServices, Module, ModuleError,
    ModuleInfo, ModuleState, Status,
};

use waddles_client::{WaddlesClient, WaddlesConfig, WaddlesError};

use crate::commands;
use crate::config::ModuleConfig;
use crate::metrics::WaddlesSocialMetrics;

/// Secrets namespace assigned to this module by the daemon host.
pub const SECRETS_NAMESPACE: &str = "waddles-social";

/// Primary secret key for the user's hub access token (JWT).
pub(crate) const ACCESS_TOKEN_SECRET_KEY: &str = "access_token";
/// Legacy/alternate secret key checked if `access_token` is absent.
pub(crate) const FALLBACK_TOKEN_SECRET_KEY: &str = "token";

/// Global registry for the `waddles-social` module's session proxy.
/// Stored here so the daemon service (`penguin.desktop.v1.SessionProxy`) can
/// access it without downcasting `dyn Module`. Populated during `Module::init`.
static SESSION_PROXY_REGISTRY: OnceLock<StdMutex<Option<Arc<crate::session_proxy::SessionProxy>>>> =
    OnceLock::new();

/// Get or initialize the session proxy registry.
/// Public so the daemon service can access it.
pub fn get_session_proxy_registry()
-> &'static StdMutex<Option<Arc<crate::session_proxy::SessionProxy>>> {
    SESSION_PROXY_REGISTRY.get_or_init(|| StdMutex::new(None))
}

/// How long a cached auth probe (shared by [`Module::status`] and
/// [`Module::health`]) is trusted before a fresh one runs.
const AUTH_CACHE_TTL: Duration = Duration::from_secs(5);
/// Upper bound on a single auth probe's round trip.
const AUTH_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Coarse outcome of a live probe against the hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthState {
    Ok,
    Unauthorized,
    Unreachable,
}

impl AuthState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            AuthState::Ok => "ok",
            AuthState::Unauthorized => "unauthorized",
            AuthState::Unreachable => "unreachable",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthProbe {
    pub(crate) state: AuthState,
    pub(crate) checked_at: SystemTime,
}

struct Inner {
    host: OnceLock<Arc<dyn HostServices>>,
    config: OnceLock<ModuleConfig>,
    client: StdMutex<Option<Arc<WaddlesClient>>>,
    token: StdMutex<String>,
    community_id: StdMutex<String>,
    metrics: OnceLock<WaddlesSocialMetrics>,
    running: AtomicBool,
    last_probe: StdMutex<Option<AuthProbe>>,
    session_proxy: OnceLock<Arc<crate::session_proxy::SessionProxy>>,
}

impl Inner {
    const UNINITIALISED: &'static str = "waddles-social module used before init";

    fn new() -> Inner {
        Inner {
            host: OnceLock::new(),
            config: OnceLock::new(),
            client: StdMutex::new(None),
            token: StdMutex::new(String::new()),
            community_id: StdMutex::new(String::new()),
            metrics: OnceLock::new(),
            running: AtomicBool::new(false),
            last_probe: StdMutex::new(None),
            session_proxy: OnceLock::new(),
        }
    }
}

/// `waddles-social`: desktop social client module and `SessionProxy` host
/// for the Waddles hub.
#[derive(Clone)]
pub struct WaddlesSocialModule {
    inner: Arc<Inner>,
}

impl Default for WaddlesSocialModule {
    fn default() -> WaddlesSocialModule {
        WaddlesSocialModule::new()
    }
}

impl WaddlesSocialModule {
    /// Builds a fresh, un-initialised module.
    pub fn new() -> WaddlesSocialModule {
        WaddlesSocialModule {
            inner: Arc::new(Inner::new()),
        }
    }

    pub(crate) fn host(&self) -> &Arc<dyn HostServices> {
        self.inner.host.get().expect(Inner::UNINITIALISED)
    }

    pub(crate) fn config(&self) -> &ModuleConfig {
        self.inner.config.get().expect(Inner::UNINITIALISED)
    }

    pub(crate) fn metrics(&self) -> &WaddlesSocialMetrics {
        self.inner.metrics.get().expect(Inner::UNINITIALISED)
    }

    /// Returns the active [`WaddlesClient`]. Call fresh per operation rather than
    /// caching across awaits, as `auth set-token` / `communities use` rebuild it.
    pub(crate) fn client(&self) -> Arc<WaddlesClient> {
        self.inner
            .client
            .lock()
            .expect("client mutex poisoned")
            .clone()
            .expect(Inner::UNINITIALISED)
    }

    /// Returns the active community UUID (empty string if none selected).
    pub(crate) fn community_id(&self) -> String {
        self.inner
            .community_id
            .lock()
            .expect("community_id mutex poisoned")
            .clone()
    }

    /// Returns the current in-memory user token (empty string if unset).
    pub(crate) fn token(&self) -> String {
        self.inner
            .token
            .lock()
            .expect("token mutex poisoned")
            .clone()
    }

    /// Returns the module's [`SessionProxy`] instance once initialized.
    pub fn session_proxy(&self) -> Option<Arc<crate::session_proxy::SessionProxy>> {
        self.inner.session_proxy.get().cloned()
    }

    /// Rebuilds the hub client with a new `community_id`, keeping the current
    /// hub URL and user token.
    pub(crate) fn set_community(&self, community_id: String) -> Result<(), ModuleError> {
        let token = self.token();
        let hub_config = WaddlesConfig {
            base_url: self.config().hub.base_url.clone(),
            community_id: community_id.clone(),
            token,
            ..WaddlesConfig::default()
        };
        let client = WaddlesClient::new(hub_config)
            .map_err(|err| ModuleError::new(format!("rebuild hub client: {err}")))?;
        *self.inner.client.lock().expect("client mutex poisoned") = Some(Arc::new(client));
        *self
            .inner
            .community_id
            .lock()
            .expect("community_id mutex poisoned") = community_id;
        Ok(())
    }

    /// Rebuilds the hub client with a new user token and invalidates the
    /// cached auth probe.
    pub(crate) fn set_token(&self, token: String) -> Result<(), ModuleError> {
        let community_id = self.community_id();
        let hub_config = WaddlesConfig {
            base_url: self.config().hub.base_url.clone(),
            community_id,
            token: token.clone(),
            ..WaddlesConfig::default()
        };
        let client = WaddlesClient::new(hub_config)
            .map_err(|err| ModuleError::new(format!("rebuild hub client: {err}")))?;
        *self.inner.client.lock().expect("client mutex poisoned") = Some(Arc::new(client));
        *self.inner.token.lock().expect("token mutex poisoned") = token;
        *self.inner.last_probe.lock().expect("probe mutex poisoned") = None;
        Ok(())
    }

    /// Runs `fut` (one hub call) and updates `api_requests_total` /
    /// `api_errors_total` around it.
    pub(crate) async fn call<T>(
        &self,
        fut: impl std::future::Future<Output = Result<T, WaddlesError>>,
    ) -> Result<T, WaddlesError> {
        self.metrics().api_requests_total.inc();
        let result = fut.await;
        if result.is_err() {
            self.metrics().api_errors_total.inc();
        }
        result
    }

    /// Cheap, cached liveness/auth probe shared by [`Module::status`],
    /// [`Module::health`], and CLI `status`/`health`/`auth status`.
    pub(crate) async fn probe_auth(&self) -> AuthProbe {
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
        let attempt = self.call(client.list_my_communities());
        let state = match tokio::time::timeout(AUTH_PROBE_TIMEOUT, attempt).await {
            Ok(Ok(_communities)) => AuthState::Ok,
            Ok(Err(WaddlesError::Auth { .. })) => AuthState::Unauthorized,
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
}

/// Builds a fresh, un-initialised [`WaddlesSocialModule`] — the
/// [`penguin_sdk::Factory`] registered for `"waddles-social"`.
pub fn factory() -> Box<dyn Module> {
    Box::new(WaddlesSocialModule::new())
}

async fn read_initial_token(host: &dyn HostServices) -> String {
    if let Ok(bytes) = host.secrets().get(ACCESS_TOKEN_SECRET_KEY).await {
        return String::from_utf8_lossy(&bytes).into_owned();
    }
    if let Ok(bytes) = host.secrets().get(FALLBACK_TOKEN_SECRET_KEY).await {
        return String::from_utf8_lossy(&bytes).into_owned();
    }
    String::new()
}

#[async_trait]
impl Module for WaddlesSocialModule {
    fn info(&self) -> ModuleInfo {
        ModuleInfo {
            name: SECRETS_NAMESPACE.to_string(),
            version: "1.0.0".to_string(),
            description: "Waddles desktop social client and session proxy".to_string(),
            license_feature: String::new(),
        }
    }

    async fn init(&self, host: Arc<dyn HostServices>) -> Result<(), ModuleError> {
        let logger = host.logger();

        let raw = host.config();
        let cfg: ModuleConfig = if raw.is_empty() {
            ModuleConfig::default()
        } else {
            serde_norway::from_slice(&raw)
                .map_err(|err| ModuleError::new(format!("parse waddles-social config: {err}")))?
        };

        let token = read_initial_token(host.as_ref()).await;

        let hub_config = WaddlesConfig {
            base_url: cfg.hub.base_url.clone(),
            community_id: cfg.community_id.clone(),
            token: token.clone(),
            ..WaddlesConfig::default()
        };
        let client = WaddlesClient::new(hub_config)
            .map_err(|err| ModuleError::new(format!("create hub client: {err}")))?;

        let metrics = WaddlesSocialMetrics::register(host.metrics().as_ref())
            .map_err(|err| ModuleError::new(format!("register metrics: {err}")))?;

        let session_proxy = Arc::new(crate::session_proxy::SessionProxy::new());

        logger.info(
            "waddles-social module initialized",
            &[
                ("hub", cfg.hub.base_url.as_str()),
                ("community_id", cfg.community_id.as_str()),
                ("token_present", &(!token.is_empty()).to_string()),
            ],
        );

        *self.inner.client.lock().expect("client mutex poisoned") = Some(Arc::new(client));
        *self.inner.token.lock().expect("token mutex poisoned") = token;
        *self
            .inner
            .community_id
            .lock()
            .expect("community_id mutex poisoned") = cfg.community_id.clone();

        let _ = self.inner.host.set(host);
        let _ = self.inner.config.set(cfg);
        let _ = self.inner.metrics.set(metrics);
        let _ = self.inner.session_proxy.set(session_proxy.clone());

        let registry = get_session_proxy_registry();
        *registry.lock().expect("proxy registry mutex poisoned") = Some(session_proxy);

        Ok(())
    }

    async fn start(&self) -> Result<(), ModuleError> {
        if self.inner.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.metrics().up.set(1.0);
        self.host()
            .logger()
            .info("waddles-social module started", &[]);
        Ok(())
    }

    async fn stop(&self) -> Result<(), ModuleError> {
        if !self.inner.running.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        self.metrics().up.set(0.0);
        self.host()
            .logger()
            .info("waddles-social module stopped", &[]);
        Ok(())
    }

    async fn status(&self) -> Result<Status, ModuleError> {
        let running = self.inner.running.load(Ordering::SeqCst);
        let state = if running {
            ModuleState::Running
        } else {
            ModuleState::Stopped
        };

        let probe = self.probe_auth().await;
        let mut detail = HashMap::new();
        detail.insert("hub".to_string(), self.config().hub.base_url.clone());
        detail.insert("community".to_string(), self.community_id());
        detail.insert("auth".to_string(), probe.state.as_str().to_string());

        Ok(Status { state, detail })
    }

    async fn health(&self) -> HealthReport {
        let probe = self.probe_auth().await;
        let (level, message) = match probe.state {
            AuthState::Ok => (HealthLevel::Healthy, "OK".to_string()),
            AuthState::Unauthorized => (
                HealthLevel::Degraded,
                "hub rejected credentials".to_string(),
            ),
            AuthState::Unreachable => (HealthLevel::Degraded, "hub unreachable".to_string()),
        };
        HealthReport {
            level,
            message,
            checked_at: probe.checked_at,
        }
    }

    fn commands(&self) -> Vec<CommandSpec> {
        commands::command_tree()
    }

    async fn dispatch(
        &self,
        path: &[String],
        flags: &HashMap<String, String>,
        args: &[String],
    ) -> Result<CommandResult, ModuleError> {
        commands::dispatch(self, path, flags, args).await
    }

    fn config_schema(&self) -> Option<Vec<u8>> {
        Some(crate::config::CONFIG_SCHEMA.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeHost, MockHub, MockResponse};
    use penguin_sdk::SecretStore;

    const TEST_COMMUNITY_ID: &str = "11111111-1111-4111-8111-111111111111";

    fn config_bytes(hub_base_url: &str, community_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "hub": {"base_url": hub_base_url},
            "community_id": community_id,
        }))
        .unwrap()
    }

    async fn init_module_against(hub: &MockHub, community_id: &str) -> WaddlesSocialModule {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.secrets
            .set(ACCESS_TOKEN_SECRET_KEY, b"jwt_test_token_1234")
            .await
            .unwrap();
        host.config = config_bytes(&hub.base_url, community_id);
        let module = WaddlesSocialModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");
        module
    }

    #[test]
    fn info_reports_waddles_social_identity_with_no_license_gate() {
        let module = WaddlesSocialModule::new();
        let info = module.info();
        assert_eq!(info.name, "waddles-social");
        assert_eq!(info.version, "1.0.0");
        assert!(info.license_feature.is_empty());
        assert!(!info.description.is_empty());
    }

    #[test]
    fn factory_builds_a_fresh_uninitialised_module() {
        let module = factory();
        assert_eq!(module.info().name, "waddles-social");
    }

    #[test]
    #[should_panic(expected = "waddles-social module used before init")]
    fn accessors_panic_before_init() {
        let module = WaddlesSocialModule::new();
        let _ = module.config();
    }

    #[tokio::test]
    async fn init_never_fails_when_the_hub_is_unreachable() {
        let unreachable = MockHub::unreachable_base_url().await;
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.config = config_bytes(&unreachable, TEST_COMMUNITY_ID);
        let module = WaddlesSocialModule::new();
        module
            .init(Arc::new(host))
            .await
            .expect("init must succeed even when the hub cannot be reached");
    }

    #[tokio::test]
    async fn init_reads_access_token_from_secrets_and_registers_session_proxy() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/communities/my",
            MockResponse::json(200, r#"{"success":true,"communities":[]}"#),
        )
        .await;

        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.secrets
            .set(ACCESS_TOKEN_SECRET_KEY, b"jwt_from_secret")
            .await
            .unwrap();
        host.config = config_bytes(&hub.base_url, TEST_COMMUNITY_ID);
        let module = WaddlesSocialModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");

        assert!(module.session_proxy().is_some());
        assert!(
            get_session_proxy_registry()
                .lock()
                .expect("registry mutex")
                .is_some()
        );

        module.client().list_my_communities().await.ok();
        let requests = hub.requests().await;
        assert_eq!(
            requests[0].header("authorization"),
            Some("Bearer jwt_from_secret")
        );

        hub.stop().await;
    }

    #[tokio::test]
    async fn init_falls_back_to_legacy_token_secret_key() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/communities/my",
            MockResponse::json(200, r#"{"success":true,"communities":[]}"#),
        )
        .await;

        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.secrets
            .set(FALLBACK_TOKEN_SECRET_KEY, b"jwt_fallback")
            .await
            .unwrap();
        host.config = config_bytes(&hub.base_url, "");
        let module = WaddlesSocialModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");

        module.client().list_my_communities().await.ok();
        let requests = hub.requests().await;
        assert_eq!(
            requests[0].header("authorization"),
            Some("Bearer jwt_fallback")
        );

        hub.stop().await;
    }

    #[tokio::test]
    async fn start_and_stop_are_idempotent_and_flip_up_gauge() {
        let hub = MockHub::start().await;
        let module = init_module_against(&hub, TEST_COMMUNITY_ID).await;

        assert_eq!(module.metrics().up.get(), 0.0);
        module.start().await.unwrap();
        assert_eq!(module.metrics().up.get(), 1.0);
        module.start().await.unwrap();
        assert_eq!(module.metrics().up.get(), 1.0);

        module.stop().await.unwrap();
        assert_eq!(module.metrics().up.get(), 0.0);
        module.stop().await.unwrap();
        assert_eq!(module.metrics().up.get(), 0.0);

        hub.stop().await;
    }

    #[tokio::test]
    async fn health_maps_probe_states_correctly() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/communities/my",
            MockResponse::json(200, r#"{"success":true,"communities":[]}"#),
        )
        .await;
        let module = init_module_against(&hub, TEST_COMMUNITY_ID).await;
        let report = module.health().await;
        assert_eq!(report.level, HealthLevel::Healthy);
        assert_eq!(report.message, "OK");

        // Second call within TTL uses cache (no additional HTTP request).
        let cached = module.health().await;
        assert_eq!(cached.checked_at, report.checked_at);
        assert_eq!(hub.requests().await.len(), 1);
        hub.stop().await;

        let hub_401 = MockHub::start().await;
        hub_401
            .respond(
                "GET",
                "/communities/my",
                MockResponse::json(401, r#"{"error":"unauthorized"}"#),
            )
            .await;
        let module_401 = init_module_against(&hub_401, TEST_COMMUNITY_ID).await;
        let report_401 = module_401.health().await;
        assert_eq!(report_401.level, HealthLevel::Degraded);
        assert_eq!(report_401.message, "hub rejected credentials");
        hub_401.stop().await;
    }

    #[tokio::test]
    async fn status_reports_running_state_and_detail() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/communities/my",
            MockResponse::json(200, r#"{"success":true,"communities":[]}"#),
        )
        .await;
        let module = init_module_against(&hub, TEST_COMMUNITY_ID).await;
        module.start().await.unwrap();

        let status = module.status().await.unwrap();
        assert_eq!(status.state, ModuleState::Running);
        assert_eq!(status.detail.get("hub"), Some(&hub.base_url));
        assert_eq!(
            status.detail.get("community"),
            Some(&TEST_COMMUNITY_ID.to_string())
        );
        assert_eq!(status.detail.get("auth"), Some(&"ok".to_string()));

        hub.stop().await;
    }
}
