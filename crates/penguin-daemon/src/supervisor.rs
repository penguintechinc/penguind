//! The module lifecycle state machine, ported from
//! `go-client/internal/daemon/supervisor.go` (+ `dispatch.go`).
//!
//! See the `lib.rs` module doc for the full list of deliberate divergences
//! from the Go reference; the ones this file implements are annotated inline
//! at the point they apply.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use penguin_sdk::{
    CommandResult, CommandSpec, Event, EventType, Factory, HealthLevel, HealthReport, Module,
    ModuleError, ModuleInfo, ModuleState, Status,
};

use crate::broker::EventBroker;
use crate::external::{ExternalLoadError, ExternalLoader};
use crate::host::HostFactory;
use crate::state::PersistedState;

/// An error from a supervisor operation.
///
/// [`SupervisorError::UnknownModule`] is kept distinct from
/// [`SupervisorError::NotLoaded`] — a name absent from the registry entirely
/// versus a registered module that simply isn't loaded — so the gRPC layer
/// can map the two differently (`NOT_FOUND` for the former; Go's Rust
/// equivalent conflates both, since it never carries a registry to tell them
/// apart).
#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    /// `name` is not in the module registry at all.
    #[error("unknown module: {0}")]
    UnknownModule(String),
    /// `name` is registered but not currently loaded.
    #[error("module not loaded: {0}")]
    NotLoaded(String),
    /// `name` resolved to an external plugin, but loading it failed —
    /// manifest, verification, or process-launch error. Kept distinct from
    /// [`SupervisorError::UnknownModule`]: this is a real, retryable
    /// failure for a plugin that does exist, not a "no such module" miss.
    #[error("failed to load external plugin: {0}")]
    ExternalLoad(String),
    /// A module lifecycle or dispatch call itself failed.
    #[error("{0}")]
    Module(#[from] ModuleError),
}

/// Construction parameters for a [`Supervisor`].
pub struct SupervisorConfig {
    /// Every module the daemon can load, keyed by its own name.
    pub registry: BTreeMap<String, Factory>,
    /// Builds the [`penguin_sdk::HostServices`] handed to a module at load
    /// time.
    pub host_factory: Arc<dyn HostFactory>,
    /// The single event broker shared with the daemon's `WatchEvents`
    /// subscribers.
    pub broker: Arc<EventBroker>,
    /// Directory the enabled-set (`enabled.json`) is persisted under.
    pub state_dir: PathBuf,
    /// Restart attempts allowed before a module parks in `failed`. `0` means
    /// "use the default" ([`crate::backoff::MAX_RESTARTS`]).
    pub max_restarts: u32,
    /// How often a loaded module's `health()` is polled.
    pub health_interval: Duration,
    /// How long a module must run before a subsequent failure resets its
    /// restart budget (divergence: see the module doc).
    pub stability_window: Duration,
    /// Resolves a name the builtin registry doesn't recognise into an
    /// external plugin. `None` disables external plugin loading entirely —
    /// every name not in `registry` stays [`SupervisorError::UnknownModule`],
    /// same as before external loading existed.
    pub external: Option<Arc<dyn ExternalLoader>>,
}

/// One module's live lifecycle bookkeeping.
///
/// Only [`ModuleState::Running`], [`ModuleState::Degraded`], and
/// [`ModuleState::Failed`] are ever written to `state` here —
/// [`ModuleState::Disabled`] is synthesized in [`Supervisor::list`] for any
/// registered name absent from the loaded map, and `Stopped` is published as
/// an event but never retained (the entry is removed in the same locked step
/// that would otherwise store it).
struct LoadedModule {
    /// The running instance, shared so the health-poll task can hold its own
    /// handle without contending with lifecycle calls made under the lock.
    instance: Arc<dyn Module>,
    state: ModuleState,
    /// Consecutive restart attempts since the last stability-window reset.
    restart_attempt: u32,
    /// When the current instance last (re)started; the stability-window
    /// reset compares this against `now` on the next failure.
    started_at: Instant,
    /// Monotonic load order, used to stop modules in true LIFO order on
    /// shutdown rather than Go's alphabetical-descending approximation.
    load_seq: u64,
    /// Cancels this module's health-poll task; triggered on stop, unload,
    /// shutdown, and restart. Cancellation is fire-and-forget, matching Go's
    /// `cancelCtx()`, which likewise never waits for the goroutine to exit.
    health_cancel: CancellationToken,
}

/// State protected by one lock, mirroring Go's single `sync.RWMutex` guarding
/// both `loaded` and `persisted` — keeping them under one guard is what makes
/// a `Load`/`Unload` on the same name fully serialized end to end, including
/// the enabled-set persist at the end of each.
struct Shared {
    loaded: HashMap<String, LoadedModule>,
    persisted: PersistedState,
}

/// Fields shared across every clone of a [`Supervisor`] handle.
struct Inner {
    registry: BTreeMap<String, Factory>,
    /// Identity metadata for every registered module, resolved once at
    /// construction from a throwaway instance (mirrors Go's `New`, which
    /// likewise builds each factory once just to read `Info()`).
    module_infos: BTreeMap<String, ModuleInfo>,
    host_factory: Arc<dyn HostFactory>,
    broker: Arc<EventBroker>,
    state_dir: PathBuf,
    max_restarts: u32,
    health_interval: Duration,
    stability_window: Duration,
    /// See [`SupervisorConfig::external`].
    external: Option<Arc<dyn ExternalLoader>>,
    shared: RwLock<Shared>,
    /// Cancelled on `shutdown`; scheduled restarts select on this so a
    /// daemon shutdown abandons pending backoffs instead of restarting a
    /// module the operator just asked to stop.
    life_token: CancellationToken,
    load_seq: AtomicU64,
}

/// Drives every module's `init`/`start`/`stop` lifecycle, persists the
/// user-enabled set, fans status changes out through the shared
/// [`EventBroker`], and restarts modules that crash or report unhealthy.
///
/// Cheap to clone — every clone shares the same underlying state, which is
/// what lets the health-poll and scheduled-restart background tasks hold
/// their own handle.
#[derive(Clone)]
pub struct Supervisor {
    inner: Arc<Inner>,
}

impl Supervisor {
    /// Builds a fresh supervisor. Loads nothing; call [`Supervisor::start_enabled`]
    /// on daemon boot to restore the persisted enabled-set.
    pub fn new(cfg: SupervisorConfig) -> Supervisor {
        let mut module_infos = BTreeMap::new();
        for (name, factory) in &cfg.registry {
            module_infos.insert(name.clone(), factory().info());
        }

        let max_restarts = if cfg.max_restarts == 0 {
            crate::backoff::MAX_RESTARTS
        } else {
            cfg.max_restarts
        };

        let inner = Inner {
            registry: cfg.registry,
            module_infos,
            host_factory: cfg.host_factory,
            broker: cfg.broker,
            state_dir: cfg.state_dir,
            max_restarts,
            health_interval: cfg.health_interval,
            stability_window: cfg.stability_window,
            external: cfg.external,
            shared: RwLock::new(Shared {
                loaded: HashMap::new(),
                persisted: PersistedState::default(),
            }),
            life_token: CancellationToken::new(),
            load_seq: AtomicU64::new(0),
        };
        Supervisor {
            inner: Arc::new(inner),
        }
    }

    /// Loads and starts `name`. Idempotent: a module already loaded returns
    /// its current state without re-running `init`/`start`.
    ///
    /// On success the module is added to the persisted enabled-set (best
    /// effort — a save failure is logged, not returned). On failure the
    /// module is left unloaded and the name stays retryable.
    pub async fn load(&self, name: &str) -> Result<ModuleState, SupervisorError> {
        let mut shared = self.inner.shared.write().await;
        if let Some(existing) = shared.loaded.get(name) {
            return Ok(existing.state);
        }
        let module = self.instantiate(name).await?;

        self.inner
            .broker
            .publish(state_event(name, ModuleState::Initializing));

        let schema = module.config_schema();
        let host = self.inner.host_factory.host_for(name, schema.as_deref());

        if let Err(err) = module.init(host.clone()).await {
            stop_failed_instance(&module, name).await;
            self.inner
                .broker
                .publish(error_event(name, &err.to_string()));
            self.inner
                .broker
                .publish(state_event(name, ModuleState::Disabled));
            return Err(SupervisorError::Module(err));
        }

        if let Err(err) = module.start().await {
            stop_failed_instance(&module, name).await;
            self.inner
                .broker
                .publish(error_event(name, &err.to_string()));
            self.inner
                .broker
                .publish(state_event(name, ModuleState::Disabled));
            return Err(SupervisorError::Module(err));
        }

        // Divergence: publish `running` only after `start` actually succeeds.
        self.inner
            .broker
            .publish(state_event(name, ModuleState::Running));

        let load_seq = self.inner.load_seq.fetch_add(1, Ordering::Relaxed);
        let health_cancel = CancellationToken::new();
        self.spawn_health_poll(name.to_string(), module.clone(), health_cancel.clone());

        shared.loaded.insert(
            name.to_string(),
            LoadedModule {
                instance: module,
                state: ModuleState::Running,
                restart_attempt: 0,
                started_at: Instant::now(),
                load_seq,
                health_cancel,
            },
        );

        shared.persisted.add(name);
        if let Err(err) = shared.persisted.save(&self.inner.state_dir) {
            tracing::warn!(module = name, error = %err, "failed to persist enabled-set");
        }

        Ok(ModuleState::Running)
    }

    /// Stops and disables `name`. Idempotent: a module that isn't loaded is a
    /// no-op, regardless of whether the name is even registered (matching
    /// Go, which only ever checks the loaded set here).
    ///
    /// Unlike [`Supervisor::shutdown`], this removes the name from the
    /// persisted enabled-set (best effort) — unload is the sole operator
    /// action that makes a module stay gone across a restart.
    pub async fn unload(&self, name: &str) -> Result<(), SupervisorError> {
        let mut shared = self.inner.shared.write().await;
        if !shared.loaded.contains_key(name) {
            return Ok(());
        }
        self.stop_locked(&mut shared.loaded, name).await;

        shared.persisted.remove(name);
        if let Err(err) = shared.persisted.save(&self.inner.state_dir) {
            tracing::warn!(module = name, error = %err, "failed to persist enabled-set");
        }
        Ok(())
    }

    /// Loads every module in the persisted enabled-set. Called on daemon
    /// startup to restore previous state; a per-module load failure is
    /// logged and collected rather than aborting the rest of the boot.
    pub async fn start_enabled(&self) -> Vec<(String, SupervisorError)> {
        let persisted = match PersistedState::load(&self.inner.state_dir) {
            Ok(state) => state,
            Err(err) => {
                tracing::warn!(error = %err, "failed to load persisted state; starting with nothing enabled");
                PersistedState::default()
            }
        };
        let names: Vec<String> = persisted.iter().cloned().collect();
        {
            let mut shared = self.inner.shared.write().await;
            shared.persisted = persisted;
        }

        let mut failures = Vec::new();
        for name in names {
            if let Err(err) = self.load(&name).await {
                tracing::warn!(module = %name, error = %err, "failed to load persisted module");
                failures.push((name, err));
            }
        }
        failures
    }

    /// Stops every loaded module in true reverse load order (LIFO) and
    /// abandons any pending scheduled restart. Deliberately never touches the
    /// persisted enabled-set — a daemon restart must bring back exactly what
    /// was loaded before, and only [`Supervisor::unload`] may shrink that set.
    pub async fn shutdown(&self) {
        self.inner.life_token.cancel();
        let mut shared = self.inner.shared.write().await;

        let mut order: Vec<(String, u64)> = shared
            .loaded
            .iter()
            .map(|(name, module)| (name.clone(), module.load_seq))
            .collect();
        order.sort_by_key(|(_name, load_seq)| std::cmp::Reverse(*load_seq));

        for (name, _load_seq) in order {
            self.stop_locked(&mut shared.loaded, &name).await;
        }
    }

    /// Snapshots every module the operator could see: every *registered*
    /// (builtin) module, loaded or not — an unloaded name reports the
    /// synthesized [`ModuleState::Disabled`], never actually stored — plus
    /// every currently loaded *external* module.
    ///
    /// External modules have no registry entry to enumerate ahead of time
    /// (see [`Inner::external`]), so unlike a builtin they only ever appear
    /// here while loaded — there is no "disabled" row for a plugin the
    /// operator hasn't loaded yet, since this crate has no way to know it
    /// exists until [`Supervisor::load`] resolves it. The `bool` in each
    /// entry is `true` for an external module, `false` for a builtin one.
    pub async fn list(&self) -> Vec<(ModuleInfo, ModuleState, bool)> {
        let shared = self.inner.shared.read().await;
        let mut out = Vec::with_capacity(self.inner.module_infos.len() + shared.loaded.len());
        for (name, info) in &self.inner.module_infos {
            let state = shared
                .loaded
                .get(name)
                .map(|module| module.state)
                .unwrap_or(ModuleState::Disabled);
            out.push((info.clone(), state, false));
        }
        for (name, module) in &shared.loaded {
            if self.inner.module_infos.contains_key(name) {
                continue; // already emitted above, as a builtin
            }
            out.push((module.instance.info(), module.state, true));
        }
        out
    }

    /// Returns `name`'s self-reported [`Status`], or an error distinguishing
    /// "not registered" from "registered but not loaded".
    pub async fn status(&self, name: &str) -> Result<Status, SupervisorError> {
        let module = self.loaded_module_or_err(name).await?;
        module.status().await.map_err(SupervisorError::Module)
    }

    /// Returns `name`'s current [`HealthReport`].
    pub async fn health(&self, name: &str) -> Result<HealthReport, SupervisorError> {
        let module = self.loaded_module_or_err(name).await?;
        Ok(module.health().await)
    }

    /// Returns `name`'s declared command tree.
    pub async fn commands(&self, name: &str) -> Result<Vec<CommandSpec>, SupervisorError> {
        let module = self.loaded_module_or_err(name).await?;
        Ok(module.commands())
    }

    /// Executes a CLI command against `name`.
    pub async fn dispatch(
        &self,
        name: &str,
        path: &[String],
        flags: &HashMap<String, String>,
        args: &[String],
    ) -> Result<CommandResult, SupervisorError> {
        let module = self.loaded_module_or_err(name).await?;
        module
            .dispatch(path, flags, args)
            .await
            .map_err(SupervisorError::Module)
    }

    /// Proxy a user-session HTTP request through the `waddles-social` module.
    pub async fn proxy_request(
        &self,
        module_name: &str,
        req: penguin_module_waddles_social::session_proxy::HttpRequest,
    ) -> Result<penguin_module_waddles_social::session_proxy::HttpResponse, SupervisorError> {
        if module_name != "waddles-social" {
            return Err(SupervisorError::UnknownModule(module_name.to_string()));
        }

        let shared = self.inner.shared.read().await;
        let _loaded = shared
            .loaded
            .get("waddles-social")
            .ok_or_else(|| SupervisorError::NotLoaded("waddles-social".to_string()))?;
        drop(shared);

        let registry = penguin_module_waddles_social::get_session_proxy_registry();
        let proxy = registry
            .lock()
            .expect("proxy registry poisoned")
            .clone()
            .ok_or_else(|| SupervisorError::NotLoaded("waddles-social".to_string()))?;

        proxy
            .forward_request(req)
            .await
            .map_err(|e| SupervisorError::Module(ModuleError::new(e.to_string())))
    }

    /// Set the user session on the `waddles-social` module for hub proxy operations.
    pub async fn set_user_session(
        &self,
        module_name: &str,
        access_token: String,
        refresh_token: Option<String>,
        hub_base_url: String,
    ) -> Result<(), SupervisorError> {
        if module_name != "waddles-social" {
            return Err(SupervisorError::UnknownModule(module_name.to_string()));
        }

        let shared = self.inner.shared.read().await;
        let _loaded = shared
            .loaded
            .get("waddles-social")
            .ok_or_else(|| SupervisorError::NotLoaded("waddles-social".to_string()))?;
        drop(shared);

        let registry = penguin_module_waddles_social::get_session_proxy_registry();
        let proxy = registry
            .lock()
            .expect("proxy registry poisoned")
            .clone()
            .ok_or_else(|| SupervisorError::NotLoaded("waddles-social".to_string()))?;

        proxy
            .set_session(access_token, refresh_token, hub_base_url)
            .map_err(|e| SupervisorError::Module(ModuleError::new(e.to_string())))
    }

    /// Execute a bridge action (OBS command or webhook) through the `waddles-gateway` module.
    pub async fn execute_bridge_action(
        &self,
        module_name: &str,
        req: penguin_module_waddles_gateway::bridge_action::BridgeActionRequest,
    ) -> Result<penguin_module_waddles_gateway::bridge_action::BridgeActionResponse, SupervisorError>
    {
        if module_name != "waddles-gateway" {
            return Err(SupervisorError::UnknownModule(module_name.to_string()));
        }

        let shared = self.inner.shared.read().await;
        let _loaded = shared
            .loaded
            .get("waddles-gateway")
            .ok_or_else(|| SupervisorError::NotLoaded("waddles-gateway".to_string()))?;
        drop(shared);

        let registry = penguin_module_waddles_gateway::get_bridge_action_registry();
        let executor = registry
            .lock()
            .expect("bridge action registry poisoned")
            .clone()
            .ok_or_else(|| SupervisorError::NotLoaded("waddles-gateway".to_string()))?;

        executor
            .execute(req)
            .await
            .map_err(|e| SupervisorError::Module(ModuleError::new(e.to_string())))
    }

    /// Records a crash or unhealthy reading for `name` and either schedules a
    /// backoff restart or, once [`Inner::max_restarts`] is reached, parks the
    /// module in [`ModuleState::Failed`] with no further restart scheduled.
    ///
    /// Divergence: the restart budget resets to zero before incrementing if
    /// the module has been running longer than the stability window, so a
    /// module that ran fine for a while gets a fresh budget instead of
    /// `max_restarts` being a lifetime total for the process (Go's bug).
    pub async fn report_failure(&self, name: &str, reason: &str) {
        let mut shared = self.inner.shared.write().await;
        let Some(module) = shared.loaded.get_mut(name) else {
            return;
        };

        // This instance is either about to be parked or replaced by a
        // restart — either way, its own health-poll loop has nothing useful
        // left to observe. Cancelling it here (rather than only when a
        // restart actually completes) stops a persistently-unhealthy
        // instance from reporting a fresh "failure" on every remaining poll
        // tick during the backoff wait, which would blow through the restart
        // budget before the scheduled restart ever fires.
        module.health_cancel.cancel();

        if module.started_at.elapsed() >= self.inner.stability_window {
            module.restart_attempt = 0;
        }
        module.restart_attempt += 1;
        let attempt = module.restart_attempt;

        if attempt >= self.inner.max_restarts {
            module.state = ModuleState::Failed;
            self.inner
                .broker
                .publish(state_event(name, ModuleState::Failed));
            self.inner.broker.publish(error_event(
                name,
                &format!("max restarts ({}) exceeded", self.inner.max_restarts),
            ));
            return;
        }

        module.state = ModuleState::Degraded;
        let mut fields = HashMap::new();
        fields.insert("reason".to_string(), reason.to_string());
        self.inner
            .broker
            .publish(state_event_with_fields(name, ModuleState::Degraded, fields));

        // Restarts use the supervisor's lifetime token, never a request's: a
        // CLI call that triggered this report ending must not cancel a
        // pending restart.
        let delay = crate::backoff::delay_for_random(attempt - 1);
        let supervisor = self.clone();
        let name_owned = name.to_string();
        let token = self.inner.life_token.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(delay) => supervisor.perform_scheduled_restart(&name_owned).await,
                _ = token.cancelled() => {}
            }
        });
    }

    /// Boxes a recursive call back into [`Supervisor::report_failure`].
    ///
    /// `perform_scheduled_restart`'s failure branches call `report_failure`,
    /// which itself spawns a task that (eventually) calls
    /// `perform_scheduled_restart` again. Plain `.await` on that direct call
    /// does not type-check: each function's opaque `async fn` return type
    /// would need to structurally embed the other's, unboundedly. Erasing the
    /// recursive call to a boxed trait object breaks the cycle — its type is
    /// the fixed-size `Pin<Box<dyn Future + Send>>` rather than an opaque type
    /// requiring further expansion.
    fn boxed_report_failure<'a>(
        &'a self,
        name: &'a str,
        reason: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(self.report_failure(name, reason))
    }

    /// Resolves a live module handle for a status/health/commands/dispatch
    /// call, distinguishing an unregistered name from a registered-but-
    /// unloaded one.
    ///
    /// Checks the loaded map first, *then* the registry — not the other way
    /// around — because an external plugin is never in `registry` at all
    /// (only the builtin factories are), so a registry-first check would
    /// wrongly report `UnknownModule` for an external plugin that is
    /// actually loaded and running.
    async fn loaded_module_or_err(&self, name: &str) -> Result<Arc<dyn Module>, SupervisorError> {
        let shared = self.inner.shared.read().await;
        if let Some(module) = shared.loaded.get(name) {
            return Ok(module.instance.clone());
        }
        if self.inner.registry.contains_key(name) {
            return Err(SupervisorError::NotLoaded(name.to_string()));
        }
        Err(SupervisorError::UnknownModule(name.to_string()))
    }

    /// Resolves a fresh, un-initialised instance for `name`: the builtin
    /// registry first, falling back to [`Inner::external`] only when `name`
    /// is not registered. Shared by [`Supervisor::load`] and
    /// [`Supervisor::perform_scheduled_restart`] so a module that came from
    /// the external loader is restarted through the exact same resolution
    /// path it was first loaded through, rather than the restart path only
    /// ever knowing about the fixed builtin registry.
    async fn instantiate(&self, name: &str) -> Result<Arc<dyn Module>, SupervisorError> {
        if let Some(factory) = self.inner.registry.get(name).copied() {
            return Ok(Arc::from(factory()));
        }
        let Some(external) = self.inner.external.as_ref() else {
            return Err(SupervisorError::UnknownModule(name.to_string()));
        };
        match external.load(name).await {
            Ok(module) => Ok(Arc::from(module)),
            Err(ExternalLoadError::NotFound(_)) => {
                Err(SupervisorError::UnknownModule(name.to_string()))
            }
            Err(ExternalLoadError::Load(message)) => Err(SupervisorError::ExternalLoad(message)),
        }
    }

    /// Stops one loaded module and removes it from the loaded map, without
    /// touching the persisted enabled-set. Callers must already hold the
    /// write lock on `loaded` (mirrors Go's `stopLocked`).
    async fn stop_locked(&self, loaded: &mut HashMap<String, LoadedModule>, name: &str) {
        let Some(module) = loaded.get(name) else {
            return;
        };
        let instance = module.instance.clone();
        module.health_cancel.cancel();

        self.inner
            .broker
            .publish(state_event(name, ModuleState::Stopping));
        if let Err(err) = instance.stop().await {
            tracing::warn!(module = name, error = %err, "error stopping module");
        }

        self.inner
            .broker
            .publish(state_event(name, ModuleState::Stopped));
        loaded.remove(name);
    }

    /// Re-initializes and restarts a module after its backoff delay elapses.
    ///
    /// On success the module's old (already-stopped) instance is replaced and
    /// `started_at` resets, carrying `restart_attempt` forward unchanged (the
    /// stability-window reset only happens lazily, on the *next* failure — see
    /// [`Supervisor::report_failure`]). On failure the stale entry is left in
    /// place and this recurses into `report_failure`, exactly like Go's
    /// `scheduleRestart`.
    async fn perform_scheduled_restart(&self, name: &str) {
        let mut shared = self.inner.shared.write().await;
        let Some(existing) = shared.loaded.get(name) else {
            return;
        };
        let old_instance = existing.instance.clone();
        let restart_attempt = existing.restart_attempt;
        let load_seq = existing.load_seq;
        existing.health_cancel.cancel();

        if let Err(err) = old_instance.stop().await {
            tracing::warn!(module = name, error = %err, "error stopping failed module before restart");
        }

        // Re-resolves through the same builtin-or-external path `load` uses
        // (see `instantiate`'s doc comment), rather than only ever
        // consulting the fixed builtin registry — a name that was loaded
        // via the external loader must be restartable too, not silently
        // dropped on its first crash.
        let module = match self.instantiate(name).await {
            Ok(module) => module,
            Err(err) => {
                drop(shared);
                self.inner.broker.publish(error_event(
                    name,
                    &format!("restart instantiation failed: {err}"),
                ));
                self.boxed_report_failure(name, "restart instantiation failed")
                    .await;
                return;
            }
        };

        self.inner
            .broker
            .publish(state_event(name, ModuleState::Initializing));
        let schema = module.config_schema();
        let host = self.inner.host_factory.host_for(name, schema.as_deref());

        if let Err(err) = module.init(host.clone()).await {
            stop_failed_instance(&module, name).await;
            drop(shared);
            self.inner
                .broker
                .publish(error_event(name, &format!("restart init failed: {err}")));
            self.boxed_report_failure(name, "restart init failed").await;
            return;
        }
        if let Err(err) = module.start().await {
            stop_failed_instance(&module, name).await;
            drop(shared);
            self.inner
                .broker
                .publish(error_event(name, &format!("restart start failed: {err}")));
            self.boxed_report_failure(name, "restart start failed")
                .await;
            return;
        }

        self.inner
            .broker
            .publish(state_event(name, ModuleState::Running));

        let health_cancel = CancellationToken::new();
        self.spawn_health_poll(name.to_string(), module.clone(), health_cancel.clone());

        shared.loaded.insert(
            name.to_string(),
            LoadedModule {
                instance: module,
                state: ModuleState::Running,
                restart_attempt,
                started_at: Instant::now(),
                load_seq,
                health_cancel,
            },
        );
    }

    /// Spawns the per-module health-poll loop: every `health_interval`, probes
    /// `module.health()` and drives state transitions. Cancelled via `cancel`
    /// on stop/unload/shutdown/restart.
    ///
    /// Divergence: Go never calls `ReportFailure` at all, so its whole
    /// backoff/restart machine is unreachable dead code; this loop is what
    /// makes crash detection real.
    fn spawn_health_poll(&self, name: String, module: Arc<dyn Module>, cancel: CancellationToken) {
        let supervisor = self.clone();
        let interval = self.inner.health_interval;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {
                        supervisor.poll_health_once(&name, &module).await;
                    }
                    _ = cancel.cancelled() => break,
                }
            }
        });
    }

    /// Runs one health probe and drives the matching state transition.
    async fn poll_health_once(&self, name: &str, module: &Arc<dyn Module>) {
        let report = module.health().await;
        match report.level {
            HealthLevel::Unhealthy => self.report_failure(name, &report.message).await,
            HealthLevel::Degraded => self.mark_degraded(name).await,
            HealthLevel::Healthy => self.restore_running_if_degraded(name).await,
        }
    }

    /// Marks a running module `degraded` without touching its restart budget
    /// — a health-observed degradation is not a crash, so no restart is
    /// scheduled.
    async fn mark_degraded(&self, name: &str) {
        let mut shared = self.inner.shared.write().await;
        let Some(module) = shared.loaded.get_mut(name) else {
            return;
        };
        if module.state == ModuleState::Degraded {
            return;
        }
        module.state = ModuleState::Degraded;
        self.inner
            .broker
            .publish(state_event(name, ModuleState::Degraded));
    }

    /// Restores a module from `degraded` back to `running` once a health
    /// probe reports healthy again.
    async fn restore_running_if_degraded(&self, name: &str) {
        let mut shared = self.inner.shared.write().await;
        let Some(module) = shared.loaded.get_mut(name) else {
            return;
        };
        if module.state != ModuleState::Degraded {
            return;
        }
        module.state = ModuleState::Running;
        self.inner
            .broker
            .publish(state_event(name, ModuleState::Running));
    }
}

/// Best-effort cleanup for an instance whose `init` or `start` just failed:
/// `stop()` is what tears down an external plugin's child process, and
/// nothing else on this failure path ever calls it — without this, a
/// plugin whose binary launched fine but whose `init`/`start` RPC failed
/// would leak its process. Safe to call unconditionally per the
/// `Module::stop` contract ("must be idempotent"): a builtin module that
/// never started any background work simply no-ops.
async fn stop_failed_instance(module: &Arc<dyn Module>, name: &str) {
    if let Err(err) = module.stop().await {
        tracing::warn!(module = name, error = %err, "error stopping module after failed load");
    }
}

/// Builds a `StateChanged` event with no extra context fields.
fn state_event(name: &str, state: ModuleState) -> Event {
    state_event_with_fields(name, state, HashMap::new())
}

/// Builds a `StateChanged` event carrying small display context, mirroring
/// Go's `publishEvent(name, sdk.EventStateChanged, state, fields)`.
fn state_event_with_fields(
    name: &str,
    state: ModuleState,
    fields: HashMap<String, String>,
) -> Event {
    Event {
        module: name.to_string(),
        event_type: EventType::StateChanged,
        message: state.as_str().to_string(),
        at: SystemTime::now(),
        fields,
    }
}

/// Builds an `Error` event carrying a free-form message.
fn error_event(name: &str, message: &str) -> Event {
    Event {
        module: name.to_string(),
        event_type: EventType::Error,
        message: message.to_string(),
        at: SystemTime::now(),
        fields: HashMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU32};

    use async_trait::async_trait;
    use penguin_sdk::SecretError;
    use penguin_sdk::{Event as SdkEvent, EventSink, HostServices, LicenseChecker, SecretStore};
    use tempfile::TempDir;

    use crate::broker::EventReceiver;
    use crate::host::SecretStoreProvider;

    /// A configurable [`Module`] test double. Config and counters live in
    /// atomics/mutexes (never closures) so one control block can be shared
    /// behind `Arc`, registered under a fixed module name, and mutated by a
    /// test after the module has already been loaded — a fresh [`FakeModule`]
    /// is constructed by the factory on every `load`/restart, but it always
    /// reads the same shared control block for its name.
    struct FakeControl {
        fail_init: AtomicBool,
        fail_start: AtomicBool,
        health_level: Mutex<HealthLevel>,
        init_count: AtomicU32,
        start_count: AtomicU32,
        stop_count: AtomicU32,
    }

    impl FakeControl {
        fn new() -> Arc<FakeControl> {
            Arc::new(FakeControl {
                fail_init: AtomicBool::new(false),
                fail_start: AtomicBool::new(false),
                health_level: Mutex::new(HealthLevel::Healthy),
                init_count: AtomicU32::new(0),
                start_count: AtomicU32::new(0),
                stop_count: AtomicU32::new(0),
            })
        }
    }

    thread_local! {
        /// Per-OS-thread, name-keyed registry of [`FakeControl`] blocks.
        ///
        /// `Factory` is a bare `fn() -> Box<dyn Module>` — it cannot close
        /// over per-test state — so each test module name is wired to its own
        /// small named factory function below, and every [`FakeModule`]
        /// instance that function constructs looks itself up here to find its
        /// shared control block. Thread-local rather than a global `Mutex`:
        /// `#[tokio::test]` defaults to a single-threaded runtime, so a
        /// test's body and everything it `tokio::spawn`s run on the one OS
        /// thread the test harness gave that test — different tests (on
        /// different threads) never observe each other's "alpha"/"beta"
        /// registrations, even though the names are reused across tests.
        static CONTROLS: RefCell<BTreeMap<String, Arc<FakeControl>>> = const { RefCell::new(BTreeMap::new()) };
    }

    /// Registers (or replaces) the control block for `name` and returns it.
    fn register_control(name: &str) -> Arc<FakeControl> {
        let control = FakeControl::new();
        CONTROLS.with(|cell| cell.borrow_mut().insert(name.to_string(), control.clone()));
        control
    }

    fn control_for(name: &str) -> Arc<FakeControl> {
        CONTROLS.with(|cell| cell.borrow().get(name).unwrap().clone())
    }

    struct FakeModule {
        name: String,
        control: Arc<FakeControl>,
    }

    #[async_trait]
    impl Module for FakeModule {
        fn info(&self) -> ModuleInfo {
            ModuleInfo {
                name: self.name.clone(),
                version: "0.0.0".to_string(),
                description: String::new(),
                license_feature: String::new(),
            }
        }

        async fn init(&self, host: Arc<dyn HostServices>) -> Result<(), ModuleError> {
            self.control.init_count.fetch_add(1, Ordering::SeqCst);
            // Publishes on every successful init so the broker fan-out
            // regression test has something module-originated to look for.
            host.events().publish(SdkEvent {
                module: self.name.clone(),
                event_type: EventType::Info,
                message: "fake-module-init-event".to_string(),
                at: SystemTime::now(),
                fields: HashMap::new(),
            });
            if self.control.fail_init.load(Ordering::SeqCst) {
                return Err(ModuleError::new("init failed"));
            }
            Ok(())
        }

        async fn start(&self) -> Result<(), ModuleError> {
            self.control.start_count.fetch_add(1, Ordering::SeqCst);
            if self.control.fail_start.load(Ordering::SeqCst) {
                return Err(ModuleError::new("start failed"));
            }
            Ok(())
        }

        async fn stop(&self) -> Result<(), ModuleError> {
            self.control.stop_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn status(&self) -> Result<Status, ModuleError> {
            Ok(Status::default())
        }

        async fn health(&self) -> HealthReport {
            let level = *self.control.health_level.lock().unwrap();
            HealthReport {
                level,
                message: "polled".to_string(),
                checked_at: SystemTime::now(),
            }
        }

        fn commands(&self) -> Vec<CommandSpec> {
            vec![CommandSpec {
                name: "noop".to_string(),
                ..Default::default()
            }]
        }

        async fn dispatch(
            &self,
            _path: &[String],
            _flags: &HashMap<String, String>,
            _args: &[String],
        ) -> Result<CommandResult, ModuleError> {
            Ok(CommandResult::default())
        }

        fn config_schema(&self) -> Option<Vec<u8>> {
            None
        }
    }

    /// Named `Factory` functions — one per test module name. Each looks up
    /// its own shared control block from the global [`CONTROLS`] registry;
    /// see that item's doc for why a single generic factory can't work here.
    fn factory_alpha() -> Box<dyn Module> {
        Box::new(FakeModule {
            name: "alpha".to_string(),
            control: control_for("alpha"),
        })
    }
    fn factory_beta() -> Box<dyn Module> {
        Box::new(FakeModule {
            name: "beta".to_string(),
            control: control_for("beta"),
        })
    }
    fn factory_gamma() -> Box<dyn Module> {
        Box::new(FakeModule {
            name: "gamma".to_string(),
            control: control_for("gamma"),
        })
    }

    /// Minimal [`SecretStore`] double; supervisor tests never exercise it.
    /// Also implements [`SecretStoreProvider`], handing every module the
    /// same no-op instance — real per-module isolation is `host.rs`'s and
    /// `bins/penguind`'s concern, not this file's.
    struct FakeSecretStore;
    #[async_trait]
    impl SecretStore for FakeSecretStore {
        async fn get(&self, _key: &str) -> Result<Vec<u8>, SecretError> {
            Err(SecretError::NotFound)
        }
        async fn set(&self, _key: &str, _value: &[u8]) -> Result<(), SecretError> {
            Ok(())
        }
        async fn delete(&self, _key: &str) -> Result<(), SecretError> {
            Ok(())
        }
    }
    impl SecretStoreProvider for FakeSecretStore {
        fn store_for(&self, _module: &str) -> Arc<dyn SecretStore> {
            Arc::new(FakeSecretStore)
        }
    }

    /// Minimal [`LicenseChecker`] double; everything is enabled.
    struct FakeLicenseChecker;
    impl LicenseChecker for FakeLicenseChecker {
        fn feature_enabled(&self, _key: &str) -> bool {
            true
        }
        fn tier(&self) -> String {
            "free".to_string()
        }
    }

    /// Builds a supervisor over `registry` sharing one broker, with tunable
    /// restart/health parameters so each test controls its own timing.
    ///
    /// Uses the real [`crate::host::DaemonHostFactory`] rather than a hand
    /// rolled test double: it already depends on `penguin-telemetry` for a
    /// working `Metrics`/`Logger` pair, so reusing it here doubles as light
    /// integration coverage between this file and `host.rs` and avoids
    /// needing a direct `prometheus` dependency just for a test stub.
    fn build_supervisor(
        registry: BTreeMap<String, Factory>,
        broker: Arc<EventBroker>,
        max_restarts: u32,
        health_interval: Duration,
        stability_window: Duration,
    ) -> (Supervisor, TempDir, TempDir) {
        build_supervisor_with_external(
            registry,
            broker,
            max_restarts,
            health_interval,
            stability_window,
            None,
        )
    }

    /// Same as [`build_supervisor`], but also wires in an
    /// [`ExternalLoader`] — kept as a second function rather than an added
    /// parameter on [`build_supervisor`] so its many existing callers stay
    /// untouched.
    fn build_supervisor_with_external(
        registry: BTreeMap<String, Factory>,
        broker: Arc<EventBroker>,
        max_restarts: u32,
        health_interval: Duration,
        stability_window: Duration,
        external: Option<Arc<dyn ExternalLoader>>,
    ) -> (Supervisor, TempDir, TempDir) {
        let state_dir = TempDir::new().unwrap();
        let config_dir = TempDir::new().unwrap();
        let telemetry = Arc::new(penguin_telemetry::Telemetry::new("error").unwrap());
        let config_store = Arc::new(crate::config::ConfigStore::new(config_dir.path()));
        let events: Arc<dyn EventSink> = broker.clone();
        let host_factory: Arc<dyn HostFactory> = Arc::new(crate::host::DaemonHostFactory::new(
            telemetry,
            config_store,
            Arc::new(FakeSecretStore),
            Arc::new(FakeLicenseChecker),
            events,
            state_dir.path().to_path_buf(),
        ));
        let supervisor = Supervisor::new(SupervisorConfig {
            registry,
            host_factory,
            broker,
            state_dir: state_dir.path().to_path_buf(),
            max_restarts,
            health_interval,
            stability_window,
            external,
        });
        (supervisor, state_dir, config_dir)
    }

    /// A registry with one entry, mapping `name` to `factory`.
    fn single_registry(name: &str, factory: Factory) -> BTreeMap<String, Factory> {
        let mut registry = BTreeMap::new();
        registry.insert(name.to_string(), factory);
        registry
    }

    async fn state_of(supervisor: &Supervisor, name: &str) -> ModuleState {
        let snapshots = supervisor.list().await;
        for (info, state, _external) in snapshots {
            if info.name == name {
                return state;
            }
        }
        panic!("module {name} not in registry snapshot");
    }

    #[tokio::test]
    async fn load_moves_a_module_to_running_and_list_shows_others_disabled() {
        register_control("alpha");
        register_control("beta");
        let mut registry = single_registry("alpha", factory_alpha);
        registry.insert("beta".to_string(), factory_beta);

        let broker = Arc::new(EventBroker::new(16));
        let (supervisor, _dir, _config_dir) = build_supervisor(
            registry,
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        );

        let state = supervisor.load("alpha").await.unwrap();
        assert_eq!(state, ModuleState::Running);
        assert_eq!(state_of(&supervisor, "alpha").await, ModuleState::Running);
        assert_eq!(state_of(&supervisor, "beta").await, ModuleState::Disabled);
    }

    #[tokio::test]
    async fn load_of_an_unknown_name_is_an_unknown_module_error() {
        let broker = Arc::new(EventBroker::new(16));
        let (supervisor, _dir, _config_dir) = build_supervisor(
            BTreeMap::new(),
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        );

        let err = supervisor.load("ghost").await.unwrap_err();
        assert!(matches!(err, SupervisorError::UnknownModule(name) if name == "ghost"));
    }

    #[tokio::test]
    async fn init_failure_emits_symmetric_events_and_stays_retryable() {
        let control = register_control("alpha");
        control.fail_init.store(true, Ordering::SeqCst);

        let registry = single_registry("alpha", factory_alpha);
        let broker = Arc::new(EventBroker::new(16));
        let mut subscriber = broker.subscribe();
        let (supervisor, _dir, _config_dir) = build_supervisor(
            registry,
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        );

        let err = supervisor.load("alpha").await.unwrap_err();
        assert!(matches!(err, SupervisorError::Module(_)));
        assert_eq!(state_of(&supervisor, "alpha").await, ModuleState::Disabled);

        // Symmetric with a start failure: an error event, then disabled.
        let mut saw_error = false;
        let mut saw_disabled = false;
        for _ in 0..8 {
            let Ok(event) = subscriber.try_recv() else {
                break;
            };
            if event.event_type == EventType::Error {
                saw_error = true;
            }
            if event.event_type == EventType::StateChanged && event.message == "disabled" {
                saw_disabled = true;
            }
        }
        assert!(saw_error, "expected an error event on init failure");
        assert!(saw_disabled, "expected a disabled state-changed event");

        // Retryable: flip the flag and load again.
        control.fail_init.store(false, Ordering::SeqCst);
        let state = supervisor.load("alpha").await.unwrap();
        assert_eq!(state, ModuleState::Running);
    }

    #[tokio::test]
    async fn start_failure_emits_symmetric_events_and_stays_retryable() {
        let control = register_control("alpha");
        control.fail_start.store(true, Ordering::SeqCst);

        let registry = single_registry("alpha", factory_alpha);
        let broker = Arc::new(EventBroker::new(16));
        let mut subscriber = broker.subscribe();
        let (supervisor, _dir, _config_dir) = build_supervisor(
            registry,
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        );

        let err = supervisor.load("alpha").await.unwrap_err();
        assert!(matches!(err, SupervisorError::Module(_)));
        assert_eq!(state_of(&supervisor, "alpha").await, ModuleState::Disabled);

        let mut saw_error = false;
        let mut saw_disabled = false;
        for _ in 0..8 {
            let Ok(event) = subscriber.try_recv() else {
                break;
            };
            if event.event_type == EventType::Error {
                saw_error = true;
            }
            if event.event_type == EventType::StateChanged && event.message == "disabled" {
                saw_disabled = true;
            }
        }
        assert!(saw_error, "expected an error event on start failure");
        assert!(saw_disabled, "expected a disabled state-changed event");

        control.fail_start.store(false, Ordering::SeqCst);
        let state = supervisor.load("alpha").await.unwrap();
        assert_eq!(state, ModuleState::Running);
    }

    #[tokio::test]
    async fn unload_stops_and_disables_but_shutdown_leaves_enabled_set_intact() {
        let control = register_control("alpha");
        let registry = single_registry("alpha", factory_alpha);
        let broker = Arc::new(EventBroker::new(16));
        let (supervisor, dir, _config_dir) = build_supervisor(
            registry,
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        );

        supervisor.load("alpha").await.unwrap();
        supervisor.unload("alpha").await.unwrap();
        assert_eq!(control.stop_count.load(Ordering::SeqCst), 1);
        assert_eq!(state_of(&supervisor, "alpha").await, ModuleState::Disabled);

        let persisted = PersistedState::load(dir.path()).unwrap();
        assert!(!persisted.contains("alpha"));

        // Reload, then shut down: the enabled-set must still contain it.
        supervisor.load("alpha").await.unwrap();
        supervisor.shutdown().await;
        let persisted = PersistedState::load(dir.path()).unwrap();
        assert!(persisted.contains("alpha"));
    }

    #[tokio::test]
    async fn shutdown_stops_modules_in_true_reverse_load_order() {
        register_control("alpha");
        register_control("beta");
        register_control("gamma");
        let mut registry = single_registry("alpha", factory_alpha);
        registry.insert("beta".to_string(), factory_beta);
        registry.insert("gamma".to_string(), factory_gamma);

        let broker = Arc::new(EventBroker::new(64));
        let mut subscriber = broker.subscribe();
        let (supervisor, _dir, _config_dir) = build_supervisor(
            registry,
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        );

        // Load order: alpha, gamma, beta. Alphabetical-descending (Go's
        // approximation of LIFO) would stop gamma, beta, alpha — proving this
        // test actually distinguishes the two orderings.
        supervisor.load("alpha").await.unwrap();
        supervisor.load("gamma").await.unwrap();
        supervisor.load("beta").await.unwrap();

        supervisor.shutdown().await;

        let mut stop_order = Vec::new();
        while let Ok(event) = subscriber.try_recv() {
            if event.event_type == EventType::StateChanged && event.message == "stopping" {
                stop_order.push(event.module);
            }
        }
        assert_eq!(stop_order, vec!["beta", "gamma", "alpha"]);
    }

    #[tokio::test]
    async fn a_module_published_event_reaches_a_subscriber_of_the_same_broker() {
        let control = register_control("alpha");
        let registry = single_registry("alpha", factory_alpha);
        let broker = Arc::new(EventBroker::new(16));
        let mut subscriber = broker.subscribe();
        let (supervisor, _dir, _config_dir) = build_supervisor(
            registry,
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        );

        supervisor.load("alpha").await.unwrap();
        assert_eq!(control.init_count.load(Ordering::SeqCst), 1);

        let mut saw_module_event = false;
        for _ in 0..8 {
            let Ok(event) = subscriber.try_recv() else {
                break;
            };
            if event.message == "fake-module-init-event" {
                saw_module_event = true;
            }
        }
        assert!(
            saw_module_event,
            "module-published event never reached the broker subscriber"
        );
    }

    #[tokio::test]
    async fn restart_budget_parks_the_module_as_failed_with_no_further_restart() {
        let control = register_control("alpha");
        let registry = single_registry("alpha", factory_alpha);
        let broker = Arc::new(EventBroker::new(16));
        // max_restarts = 1 and a huge stability window: the very first
        // report_failure both exceeds the budget and schedules nothing, so
        // there is no timing race with a pending restart task.
        let (supervisor, _dir, _config_dir) = build_supervisor(
            registry,
            broker,
            1,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        );

        supervisor.load("alpha").await.unwrap();
        supervisor.report_failure("alpha", "boom").await;

        assert_eq!(state_of(&supervisor, "alpha").await, ModuleState::Failed);
        // No restart was scheduled, so counts stay at the original load's 1/1.
        assert_eq!(control.init_count.load(Ordering::SeqCst), 1);
        assert_eq!(control.start_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stability_window_gives_a_fresh_restart_budget() {
        register_control("alpha");
        let registry = single_registry("alpha", factory_alpha);
        let broker = Arc::new(EventBroker::new(16));
        // max_restarts = 2 with a 10ms stability window: without the reset,
        // three rapid failures would park the module (attempts 1, 2, 3 all
        // exceed or hit the budget on the second call).
        let (supervisor, _dir, _config_dir) = build_supervisor(
            registry,
            broker,
            2,
            Duration::from_secs(3600),
            Duration::from_millis(10),
        );

        supervisor.load("alpha").await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        for _ in 0..3 {
            supervisor.report_failure("alpha", "flap").await;
            // Every call sees elapsed-since-started_at >= the 10ms window
            // (started_at never moves without a successful restart), so the
            // budget resets to 1 every time instead of accumulating.
            assert_eq!(state_of(&supervisor, "alpha").await, ModuleState::Degraded);
        }
    }

    #[tokio::test]
    async fn unhealthy_health_poll_drives_the_restart_path_to_completion() {
        let control = register_control("alpha");
        let registry = single_registry("alpha", factory_alpha);
        let broker = Arc::new(EventBroker::new(16));
        let (supervisor, _dir, _config_dir) = build_supervisor(
            registry,
            broker,
            5,
            Duration::from_millis(10),
            Duration::from_secs(3600),
        );

        supervisor.load("alpha").await.unwrap();
        assert_eq!(control.init_count.load(Ordering::SeqCst), 1);

        *control.health_level.lock().unwrap() = HealthLevel::Unhealthy;

        // A poll tick (10ms) reports Unhealthy -> report_failure -> Degraded,
        // which also schedules a restart ~100ms out (attempt 1).
        let mut became_degraded = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if state_of(&supervisor, "alpha").await == ModuleState::Degraded {
                became_degraded = true;
                break;
            }
        }
        assert!(
            became_degraded,
            "Unhealthy reading never drove a report_failure"
        );

        // The restart is already scheduled at a fixed delay; flip back to
        // Healthy now so the *replacement* instance's own health-poll loop
        // doesn't immediately trigger a second restart cycle once it takes
        // over, which would make this test's timing non-deterministic.
        *control.health_level.lock().unwrap() = HealthLevel::Healthy;

        let mut became_running = false;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if state_of(&supervisor, "alpha").await == ModuleState::Running {
                became_running = true;
                break;
            }
        }
        assert!(became_running, "module never restarted back to running");
        assert!(control.init_count.load(Ordering::SeqCst) >= 2);
        assert!(control.stop_count.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn degraded_health_poll_marks_state_without_restarting_then_healthy_restores_running() {
        let control = register_control("alpha");
        let registry = single_registry("alpha", factory_alpha);
        let broker = Arc::new(EventBroker::new(16));
        let (supervisor, _dir, _config_dir) = build_supervisor(
            registry,
            broker,
            5,
            Duration::from_millis(10),
            Duration::from_secs(3600),
        );

        supervisor.load("alpha").await.unwrap();

        *control.health_level.lock().unwrap() = HealthLevel::Degraded;
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(state_of(&supervisor, "alpha").await, ModuleState::Degraded);
        // No restart was triggered by a mere health-degraded reading.
        assert_eq!(control.init_count.load(Ordering::SeqCst), 1);
        assert_eq!(control.start_count.load(Ordering::SeqCst), 1);

        *control.health_level.lock().unwrap() = HealthLevel::Healthy;
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(state_of(&supervisor, "alpha").await, ModuleState::Running);
    }

    /// A configurable [`ExternalLoader`] test double. `available` names
    /// resolve to a [`FakeModule`] — exactly the same test double builtin
    /// factories construct, since a loaded external module must be
    /// indistinguishable from a builtin one — `load_errors` names fail with
    /// [`ExternalLoadError::Load`] (found, but verification/launch failed),
    /// and anything else fails with [`ExternalLoadError::NotFound`]. Every
    /// call is counted, so a test can prove the builtin registry
    /// short-circuits before this is ever consulted.
    struct FakeExternalLoader {
        available: Vec<&'static str>,
        load_errors: Vec<(&'static str, &'static str)>,
        call_count: AtomicU32,
    }

    impl FakeExternalLoader {
        fn new(
            available: Vec<&'static str>,
            load_errors: Vec<(&'static str, &'static str)>,
        ) -> Arc<FakeExternalLoader> {
            Arc::new(FakeExternalLoader {
                available,
                load_errors,
                call_count: AtomicU32::new(0),
            })
        }
    }

    #[async_trait]
    impl ExternalLoader for FakeExternalLoader {
        async fn load(&self, name: &str) -> Result<Box<dyn Module>, ExternalLoadError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            for (error_name, message) in &self.load_errors {
                if *error_name == name {
                    return Err(ExternalLoadError::Load(message.to_string()));
                }
            }
            if !self.available.contains(&name) {
                return Err(ExternalLoadError::NotFound(name.to_string()));
            }
            Ok(Box::new(FakeModule {
                name: name.to_string(),
                control: control_for(name),
            }))
        }
    }

    #[tokio::test]
    async fn builtin_registry_wins_and_external_loader_is_never_consulted() {
        register_control("alpha");
        let registry = single_registry("alpha", factory_alpha);
        let broker = Arc::new(EventBroker::new(16));
        let external = FakeExternalLoader::new(vec!["alpha"], Vec::new());
        let (supervisor, _dir, _config_dir) = build_supervisor_with_external(
            registry,
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Some(external.clone()),
        );

        let state = supervisor.load("alpha").await.unwrap();
        assert_eq!(state, ModuleState::Running);
        assert_eq!(
            external.call_count.load(Ordering::SeqCst),
            0,
            "a name already in the builtin registry must never reach the external loader"
        );
    }

    #[tokio::test]
    async fn unregistered_name_falls_through_to_the_external_loader() {
        register_control("ext-plugin");
        let broker = Arc::new(EventBroker::new(16));
        let external = FakeExternalLoader::new(vec!["ext-plugin"], Vec::new());
        let (supervisor, _dir, _config_dir) = build_supervisor_with_external(
            BTreeMap::new(),
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Some(external.clone()),
        );

        let state = supervisor.load("ext-plugin").await.unwrap();
        assert_eq!(state, ModuleState::Running);
        assert_eq!(external.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unknown_to_both_builtin_and_external_is_unknown_module() {
        let broker = Arc::new(EventBroker::new(16));
        let external = FakeExternalLoader::new(Vec::new(), Vec::new());
        let (supervisor, _dir, _config_dir) = build_supervisor_with_external(
            BTreeMap::new(),
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Some(external),
        );

        let err = supervisor.load("ghost").await.unwrap_err();
        assert!(matches!(err, SupervisorError::UnknownModule(name) if name == "ghost"));
    }

    #[tokio::test]
    async fn external_loader_error_is_distinct_from_unknown_module() {
        let broker = Arc::new(EventBroker::new(16));
        let external = FakeExternalLoader::new(Vec::new(), vec![("bad-sig", "sha256 mismatch")]);
        let (supervisor, _dir, _config_dir) = build_supervisor_with_external(
            BTreeMap::new(),
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Some(external),
        );

        let err = supervisor.load("bad-sig").await.unwrap_err();
        match err {
            SupervisorError::ExternalLoad(message) => assert_eq!(message, "sha256 mismatch"),
            other => panic!("expected SupervisorError::ExternalLoad, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn external_module_goes_through_the_same_state_machine_as_a_builtin() {
        let control = register_control("ext-plugin");
        let broker = Arc::new(EventBroker::new(16));
        let external = FakeExternalLoader::new(vec!["ext-plugin"], Vec::new());
        let (supervisor, _dir, _config_dir) = build_supervisor_with_external(
            BTreeMap::new(),
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Some(external),
        );

        let state = supervisor.load("ext-plugin").await.unwrap();
        assert_eq!(state, ModuleState::Running);

        // `FakeModule::status` always self-reports `Status::default()`
        // (state `Disabled`) regardless of the supervisor's own tracked
        // state — the two are deliberately distinct concepts. What matters
        // here is that the call reaches the module at all, which only
        // succeeds once the module is resolvable via `loaded_module_or_err`.
        supervisor
            .status("ext-plugin")
            .await
            .expect("status must be reachable on a loaded external module");

        let health = supervisor.health("ext-plugin").await.unwrap();
        assert_eq!(health.level, HealthLevel::Healthy);

        let result = supervisor
            .dispatch("ext-plugin", &[], &HashMap::new(), &[])
            .await
            .unwrap();
        assert_eq!(result, CommandResult::default());

        supervisor.unload("ext-plugin").await.unwrap();
        assert_eq!(control.stop_count.load(Ordering::SeqCst), 1);

        // Unlike a builtin (which stays `NotLoaded` after unload, since it
        // remains registered forever), an unloaded external module reverts
        // to fully unknown — there is no persistent registry entry for it.
        let err = supervisor.status("ext-plugin").await.unwrap_err();
        assert!(matches!(err, SupervisorError::UnknownModule(name) if name == "ext-plugin"));
    }

    #[tokio::test]
    async fn list_includes_a_loaded_external_module_marked_external() {
        register_control("ext-plugin");
        let broker = Arc::new(EventBroker::new(16));
        let external = FakeExternalLoader::new(vec!["ext-plugin"], Vec::new());
        let (supervisor, _dir, _config_dir) = build_supervisor_with_external(
            BTreeMap::new(),
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Some(external),
        );

        // Not loaded yet: `list()` has no registry entry to synthesize a
        // `disabled` row from, unlike a builtin — so it must be absent
        // entirely rather than showing up as disabled.
        let present_before_load = supervisor
            .list()
            .await
            .into_iter()
            .any(|(info, _, _)| info.name == "ext-plugin");
        assert!(
            !present_before_load,
            "unloaded external module must not appear in list()"
        );

        supervisor.load("ext-plugin").await.unwrap();

        let snapshots = supervisor.list().await;
        let entry = snapshots
            .into_iter()
            .find(|(info, _state, _external)| info.name == "ext-plugin")
            .expect("loaded external module must appear in list()");
        assert_eq!(entry.1, ModuleState::Running);
        assert!(
            entry.2,
            "external module must be flagged external in list()"
        );

        supervisor.unload("ext-plugin").await.unwrap();
        let still_present = supervisor
            .list()
            .await
            .into_iter()
            .any(|(info, _, _)| info.name == "ext-plugin");
        assert!(
            !still_present,
            "an unloaded external module must not linger in list()"
        );
    }

    #[tokio::test]
    async fn unload_of_an_external_module_invokes_its_teardown_exactly_once() {
        let control = register_control("ext-plugin");
        let broker = Arc::new(EventBroker::new(16));
        let external = FakeExternalLoader::new(vec!["ext-plugin"], Vec::new());
        let (supervisor, _dir, _config_dir) = build_supervisor_with_external(
            BTreeMap::new(),
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Some(external),
        );

        supervisor.load("ext-plugin").await.unwrap();
        supervisor.unload("ext-plugin").await.unwrap();

        assert_eq!(control.stop_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn shutdown_of_an_external_module_invokes_its_teardown_exactly_once() {
        let control = register_control("ext-plugin");
        let broker = Arc::new(EventBroker::new(16));
        let external = FakeExternalLoader::new(vec!["ext-plugin"], Vec::new());
        let (supervisor, _dir, _config_dir) = build_supervisor_with_external(
            BTreeMap::new(),
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Some(external),
        );

        supervisor.load("ext-plugin").await.unwrap();
        supervisor.shutdown().await;

        assert_eq!(control.stop_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn init_failure_still_stops_the_instance_to_avoid_leaking_it() {
        let control = register_control("alpha");
        control.fail_init.store(true, Ordering::SeqCst);
        let registry = single_registry("alpha", factory_alpha);
        let broker = Arc::new(EventBroker::new(16));
        let (supervisor, _dir, _config_dir) = build_supervisor(
            registry,
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        );

        let err = supervisor.load("alpha").await.unwrap_err();
        assert!(matches!(err, SupervisorError::Module(_)));
        assert_eq!(
            control.stop_count.load(Ordering::SeqCst),
            1,
            "a failed init must still stop the instance so an external plugin's \
             process cannot leak"
        );
    }

    #[tokio::test]
    async fn start_failure_still_stops_the_instance_to_avoid_leaking_it() {
        let control = register_control("alpha");
        control.fail_start.store(true, Ordering::SeqCst);
        let registry = single_registry("alpha", factory_alpha);
        let broker = Arc::new(EventBroker::new(16));
        let (supervisor, _dir, _config_dir) = build_supervisor(
            registry,
            broker,
            5,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        );

        let err = supervisor.load("alpha").await.unwrap_err();
        assert!(matches!(err, SupervisorError::Module(_)));
        assert_eq!(control.stop_count.load(Ordering::SeqCst), 1);
    }

    /// Polls `subscriber` for a `StateChanged` event carrying `message`,
    /// bounded so a transition that never arrives fails the test instead of
    /// hanging it. Used in place of `state_of` (which walks `list()`, and so
    /// only ever sees *registered* — i.e. builtin — modules) for a module
    /// loaded via the external loader, which `list()` never enumerates.
    async fn wait_for_state_message(subscriber: &mut EventReceiver, message: &str) -> bool {
        for _ in 0..200 {
            let Ok(Ok(event)) =
                tokio::time::timeout(Duration::from_millis(20), subscriber.recv()).await
            else {
                continue;
            };
            if event.event_type == EventType::StateChanged && event.message == message {
                return true;
            }
        }
        false
    }

    #[tokio::test]
    async fn unhealthy_external_module_is_restarted_through_the_external_loader_again() {
        let control = register_control("ext-plugin");
        let broker = Arc::new(EventBroker::new(64));
        let mut subscriber = broker.subscribe();
        let external = FakeExternalLoader::new(vec!["ext-plugin"], Vec::new());
        let (supervisor, _dir, _config_dir) = build_supervisor_with_external(
            BTreeMap::new(),
            broker,
            5,
            Duration::from_millis(10),
            Duration::from_secs(3600),
            Some(external.clone()),
        );

        supervisor.load("ext-plugin").await.unwrap();
        assert_eq!(external.call_count.load(Ordering::SeqCst), 1);

        *control.health_level.lock().unwrap() = HealthLevel::Unhealthy;
        assert!(
            wait_for_state_message(&mut subscriber, "degraded").await,
            "unhealthy reading never drove a restart"
        );

        *control.health_level.lock().unwrap() = HealthLevel::Healthy;
        assert!(
            wait_for_state_message(&mut subscriber, "running").await,
            "external module never restarted back to running"
        );
        assert!(
            external.call_count.load(Ordering::SeqCst) >= 2,
            "restart must re-invoke the external loader, not just the fixed builtin registry"
        );
    }
}
