//! [`HostServices`] for built-in modules, ported from
//! `go-client/internal/daemon/host.go`.
//!
//! # Divergence: `host_for` takes the module's schema
//!
//! Go's `NewHost` receives already-resolved config bytes; the schema lookup
//! happens once in `cmd/penguind/service.go`, in a `hostFactory` closure that
//! closes over a precomputed `name -> schema` map built at startup. This crate
//! has no equivalent wiring file (that lives in the `penguind` binary, a later
//! milestone), so [`HostFactory::host_for`] takes the schema explicitly —
//! [`crate::supervisor::Supervisor`] has the live module instance at `load`
//! time and passes `module.config_schema()` straight through. This keeps
//! schema-validated config working without inventing an out-of-scope wiring
//! module just to precompute a map this crate can build on demand instead.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use penguin_sdk::tools::{ToolError, ToolFuture};
use penguin_sdk::{EventSink, HostServices, LicenseChecker, Logger, Metrics, SecretStore};
use penguin_telemetry::Telemetry;
use penguin_wasm_host::executors::ModuleGauges;
use penguin_wasm_host::tools::ToolMetrics;
use penguin_wasm_host::{
    ModuleToolContext, ToolRegistry, WASM_MODULES_FLAG, build_module_registry,
};

use crate::config::ConfigStore;

/// Builds the [`HostServices`] handed to a module's `Init`.
///
/// One instance is shared by the whole daemon; [`HostFactory::host_for`] is
/// called once per module load and returns a handle scoped to that module.
pub trait HostFactory: Send + Sync {
    /// Builds the host services for `module`, validating its on-disk config
    /// against `schema` (the module's own `Module::config_schema()`).
    fn host_for(&self, module: &str, schema: Option<&[u8]>) -> Arc<dyn HostServices>;
}

/// The [`HostServices`] implementation for one loaded built-in module.
///
/// Every accessor is a cheap clone of a handle resolved once at construction
/// (see [`DaemonHostFactory::host_for`]) — mirrors the Go `HostImpl`, which is
/// likewise a bag of pre-resolved fields rather than doing work per call.
pub struct DaemonHost {
    logger: Arc<dyn Logger>,
    secrets: Arc<dyn SecretStore>,
    license: Arc<dyn LicenseChecker>,
    metrics: Arc<dyn Metrics>,
    data_dir: PathBuf,
    events: Arc<dyn EventSink>,
    config: Vec<u8>,
    tools: ToolWiring,
}

/// Everything needed to build this module's [`ToolRegistry`] on first use.
///
/// The registry is built lazily (and only when the `penguind.wasm-modules`
/// flag is on) because compiling every tool schema is wasted work for the
/// many modules that never call a tool.
struct ToolWiring {
    module: String,
    gauges: ModuleGauges,
    metrics: Option<ToolMetrics>,
    registry: OnceLock<Result<Arc<ToolRegistry>, String>>,
}

impl ToolWiring {
    /// Returns the module's registry, building it from `logger` and `config`
    /// on first call. A build failure is remembered and returned every time.
    fn get(&self, logger: &Arc<dyn Logger>, config: &[u8]) -> Result<Arc<ToolRegistry>, String> {
        self.registry
            .get_or_init(|| {
                build_tool_registry(
                    &self.module,
                    &self.gauges,
                    logger.clone(),
                    config,
                    self.metrics.clone(),
                )
            })
            .clone()
    }
}

/// Builds the standard tool registry for `module` over the daemon's shared
/// prometheus registry; used by both `call_tool` and the wasm module runner.
pub(crate) fn build_tool_registry(
    module: &str,
    gauges: &ModuleGauges,
    logger: Arc<dyn Logger>,
    config: &[u8],
    metrics: Option<ToolMetrics>,
) -> Result<Arc<ToolRegistry>, String> {
    build_module_registry(ModuleToolContext {
        module,
        logger,
        config_yaml: config,
        gauges,
        doh_endpoint: None,
        metrics,
    })
    .map(Arc::new)
    .map_err(|e| e.to_string())
}

impl HostServices for DaemonHost {
    fn logger(&self) -> Arc<dyn Logger> {
        self.logger.clone()
    }

    fn secrets(&self) -> Arc<dyn SecretStore> {
        self.secrets.clone()
    }

    fn license(&self) -> Arc<dyn LicenseChecker> {
        self.license.clone()
    }

    fn metrics(&self) -> Arc<dyn Metrics> {
        self.metrics.clone()
    }

    fn config(&self) -> Vec<u8> {
        self.config.clone()
    }

    fn data_dir(&self) -> PathBuf {
        self.data_dir.clone()
    }

    fn events(&self) -> Arc<dyn EventSink> {
        self.events.clone()
    }

    /// Dispatches a tool call to the module's real executors. Fails loudly
    /// with [`ToolError::Unavailable`] when `penguind.wasm-modules` is off, and
    /// with [`ToolError::Failed`] if the registry cannot be built.
    fn call_tool<'a>(&'a self, name: &'a str, args: serde_json::Value) -> ToolFuture<'a> {
        Box::pin(async move {
            if !self.license.feature_enabled(WASM_MODULES_FLAG) {
                tracing::warn!(
                    module = %self.tools.module,
                    flag = WASM_MODULES_FLAG,
                    "tool call refused: feature flag is off"
                );
                return Err(ToolError::Unavailable);
            }
            let registry = self
                .tools
                .get(&self.logger, &self.config)
                .map_err(|reason| ToolError::Failed {
                    tool: name.to_string(),
                    reason,
                })?;
            registry.call(name, args).await
        })
    }
}

/// Supplies the secret store a single module sees.
///
/// Implementations MUST return a view scoped to `module`; two different
/// module names must never be able to read or overwrite each other's
/// secrets. This is what the Go reference gets from downcasting to
/// `*secrets.Store` and calling `Namespaced(moduleName)`
/// (`go-client/internal/daemon/host.go`) — making isolation a trait
/// [`DaemonHostFactory`] must call through, rather than an `Arc<dyn
/// SecretStore>` it could simply share, closes that parity gap at the type
/// level instead of relying on every caller to remember to wrap one.
///
/// `penguin-daemon` deliberately depends on no concrete secrets backend
/// (see [`DaemonHostFactory`]'s doc), so this trait is expressed purely in
/// terms of [`SecretStore`] from `penguin-sdk`. The production
/// implementation, backed by `penguin_secrets::Store::namespaced`, lives in
/// `bins/penguind/src/host_wiring.rs`.
pub trait SecretStoreProvider: Send + Sync {
    /// Returns the secret store `module` is allowed to see.
    fn store_for(&self, module: &str) -> Arc<dyn SecretStore>;
}

/// Builds a [`DaemonHost`] for every module from one shared set of daemon
/// subsystems.
///
/// `secrets` is a [`SecretStoreProvider`] rather than a bare `Arc<dyn
/// SecretStore>`: [`host_for`](DaemonHostFactory::host_for) calls
/// [`SecretStoreProvider::store_for`] once per module, so per-module secret
/// isolation is part of this type's contract instead of something a caller
/// could forget to layer on afterward. `license`, by contrast, has no
/// per-module wrapping — one shared licensing client is correct here,
/// matching the Go reference. Neither is constructed in this crate: they
/// come from `penguin-secrets`/`penguin-licensing`, and the `penguind`
/// binary supplies whatever backs them (including test doubles). `events`
/// must be the same [`crate::broker::EventBroker`] instance the daemon's
/// gRPC `WatchEvents` subscribes to — that sharing is what fixes the Go
/// double-broker bug (see the `lib.rs` module doc).
pub struct DaemonHostFactory {
    telemetry: Arc<Telemetry>,
    config_store: Arc<ConfigStore>,
    secrets: Arc<dyn SecretStoreProvider>,
    license: Arc<dyn LicenseChecker>,
    events: Arc<dyn EventSink>,
    state_dir: PathBuf,
    tool_metrics: Option<ToolMetrics>,
    /// Module gauge ledger shared by every run, so `metrics_publish` caps
    /// hold per module rather than per run.
    gauges: ModuleGauges,
}

impl DaemonHostFactory {
    /// Builds a factory sharing `telemetry`, `config`, `secrets`, `license`,
    /// and `events` across every module it constructs a host for. `secrets`
    /// still yields each module its own isolated view — see
    /// [`SecretStoreProvider`].
    pub fn new(
        telemetry: Arc<Telemetry>,
        config: Arc<ConfigStore>,
        secrets: Arc<dyn SecretStoreProvider>,
        license: Arc<dyn LicenseChecker>,
        events: Arc<dyn EventSink>,
        state_dir: PathBuf,
    ) -> DaemonHostFactory {
        // Tool-call counters/histograms are registered once and shared by every
        // module's registry; a failure degrades to no tool telemetry, never a
        // failed daemon start.
        let tool_metrics = match ToolMetrics::register(telemetry.registry()) {
            Ok(metrics) => Some(metrics),
            Err(err) => {
                tracing::warn!(error = %err, "tool-call metrics not registered");
                None
            }
        };
        DaemonHostFactory {
            tool_metrics,
            gauges: ModuleGauges::new(telemetry.registry().clone()),
            telemetry,
            config_store: config,
            secrets,
            license,
            events,
            state_dir,
        }
    }
}

impl DaemonHostFactory {
    /// Builds the tool registry for a standalone wasm module (no `HostServices`
    /// instance), resolving its on-disk config like `host_for` does.
    pub(crate) fn registry_for_wasm(&self, module: &str) -> Result<Arc<ToolRegistry>, String> {
        let logger = self.telemetry.module_logger(module);
        let config = resolve_config(&self.config_store, module, None, logger.as_ref());
        build_tool_registry(
            module,
            &self.gauges,
            logger,
            &config,
            self.tool_metrics.clone(),
        )
    }

    /// The shared license checker, for the flag gate in the wasm runner.
    pub(crate) fn license_checker(&self) -> Arc<dyn LicenseChecker> {
        self.license.clone()
    }
}

impl HostFactory for DaemonHostFactory {
    fn host_for(&self, module: &str, schema: Option<&[u8]>) -> Arc<dyn HostServices> {
        let logger = self.telemetry.module_logger(module);
        let config = resolve_config(&self.config_store, module, schema, logger.as_ref());
        let data_dir = ensure_data_dir(&self.state_dir, module, logger.as_ref());

        Arc::new(DaemonHost {
            logger: logger.clone(),
            secrets: self.secrets.store_for(module),
            license: self.license.clone(),
            metrics: self.telemetry.module_registerer(module),
            data_dir,
            events: self.events.clone(),
            tools: ToolWiring {
                module: module.to_string(),
                gauges: self.gauges.clone(),
                metrics: self.tool_metrics.clone(),
                registry: OnceLock::new(),
            },
            config,
        })
    }
}

/// Resolves and schema-validates `module`'s on-disk config.
///
/// A read, parse, or validation failure is logged and treated as "no config"
/// — matching Go's `hostFactory` closure in `service.go`, which never fails
/// module construction over a bad config file; the module falls back to its
/// own defaults instead.
fn resolve_config(
    store: &ConfigStore,
    module: &str,
    schema: Option<&[u8]>,
    logger: &dyn Logger,
) -> Vec<u8> {
    match store.module_raw(module, schema) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => Vec::new(),
        Err(err) => {
            logger.warn(
                "invalid module config; module will start with defaults",
                &[("module", module), ("error", &err.to_string())],
            );
            Vec::new()
        }
    }
}

/// Creates the module's private data directory (`<state_dir>/<module>`, mode
/// 0700 on Unix).
///
/// A creation failure is logged and non-fatal, matching Go's `NewHost`: a
/// module that never touches `DataDir` is unaffected, and one that does gets a
/// clear error at first use rather than a failed load over an unrelated path.
fn ensure_data_dir(state_dir: &Path, module: &str, logger: &dyn Logger) -> PathBuf {
    let dir = state_dir.join(module);

    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    set_dir_builder_mode(&mut builder);

    if let Err(err) = builder.create(&dir) {
        logger.warn(
            "could not create module data dir",
            &[
                ("module", module),
                ("dir", &dir.display().to_string()),
                ("error", &err.to_string()),
            ],
        );
    }
    dir
}

/// Applies the 0700 owner-only mode to directories a [`std::fs::DirBuilder`]
/// creates. A no-op on non-Unix targets, where this bit pattern has no
/// equivalent (mirrors the same helper in `state.rs`).
#[cfg(unix)]
fn set_dir_builder_mode(builder: &mut std::fs::DirBuilder) {
    use std::os::unix::fs::DirBuilderExt;
    builder.mode(0o700);
}

/// Non-Unix stub for [`set_dir_builder_mode`]; see its doc.
#[cfg(not(unix))]
fn set_dir_builder_mode(_builder: &mut std::fs::DirBuilder) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use penguin_sdk::SecretError;
    use tempfile::TempDir;

    use crate::broker::EventBroker;

    /// A trivial in-memory [`SecretStore`]; used only through
    /// [`FakeSecretStoreProvider`] below, never constructed directly.
    #[derive(Default)]
    struct InMemorySecretStore {
        values: Mutex<HashMap<String, Vec<u8>>>,
    }

    #[async_trait]
    impl SecretStore for InMemorySecretStore {
        async fn get(&self, key: &str) -> Result<Vec<u8>, SecretError> {
            let values = self.values.lock().unwrap();
            values.get(key).cloned().ok_or(SecretError::NotFound)
        }
        async fn set(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
            let mut values = self.values.lock().unwrap();
            values.insert(key.to_string(), value.to_vec());
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), SecretError> {
            let mut values = self.values.lock().unwrap();
            let Some(_removed) = values.remove(key) else {
                return Err(SecretError::NotFound);
            };
            Ok(())
        }
    }

    /// A [`SecretStoreProvider`] test double that hands each module name its
    /// own [`InMemorySecretStore`] — modeling the same per-module isolation
    /// contract the production implementation provides over
    /// `penguin_secrets::Store::namespaced` (see `bins/penguind`'s
    /// `host_wiring.rs`), without pulling that concrete backend into this
    /// library crate's own tests.
    #[derive(Default)]
    struct FakeSecretStoreProvider {
        modules: Mutex<HashMap<String, Arc<InMemorySecretStore>>>,
    }

    impl SecretStoreProvider for FakeSecretStoreProvider {
        fn store_for(&self, module: &str) -> Arc<dyn SecretStore> {
            let mut modules = self.modules.lock().unwrap();
            let store = modules
                .entry(module.to_string())
                .or_insert_with(|| Arc::new(InMemorySecretStore::default()));
            store.clone()
        }
    }

    /// A [`LicenseChecker`] double that reports everything enabled at the
    /// free tier; host tests only care that the same instance is shared.
    struct FakeLicenseChecker;

    impl LicenseChecker for FakeLicenseChecker {
        fn feature_enabled(&self, _key: &str) -> bool {
            true
        }
        fn tier(&self) -> String {
            "free".to_string()
        }
    }

    /// Builds a factory over a fresh temp config dir and temp state dir.
    fn test_factory() -> (TempDir, TempDir, DaemonHostFactory) {
        let config_dir = TempDir::new().unwrap();
        let state_dir = TempDir::new().unwrap();
        let telemetry = Arc::new(Telemetry::new("error").unwrap());
        let config_store = Arc::new(ConfigStore::new(config_dir.path()));
        let broker: Arc<dyn EventSink> = Arc::new(EventBroker::new(4));

        let factory = DaemonHostFactory::new(
            telemetry,
            config_store,
            Arc::new(FakeSecretStoreProvider::default()),
            Arc::new(FakeLicenseChecker),
            broker,
            state_dir.path().to_path_buf(),
        );
        (config_dir, state_dir, factory)
    }

    #[test]
    fn host_for_creates_the_module_data_dir_with_owner_only_mode() {
        let (_config_dir, state_dir, factory) = test_factory();
        let host = factory.host_for("squawk", None);

        let expected = state_dir.path().join("squawk");
        assert_eq!(host.data_dir(), expected);
        assert!(expected.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&expected).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn host_for_returns_empty_config_when_no_module_file_exists() {
        let (_config_dir, _state_dir, factory) = test_factory();
        let host = factory.host_for("squawk", None);
        assert!(host.config().is_empty());
    }

    #[test]
    fn host_for_returns_raw_bytes_for_a_present_unvalidated_config() {
        let (config_dir, _state_dir, factory) = test_factory();
        let modules_dir = config_dir.path().join("modules.d");
        std::fs::create_dir_all(&modules_dir).unwrap();
        std::fs::write(modules_dir.join("squawk.yaml"), "endpoint: us-east\n").unwrap();

        let host = factory.host_for("squawk", None);
        assert_eq!(host.config(), b"endpoint: us-east\n");
    }

    #[test]
    fn host_for_returns_empty_config_when_schema_validation_fails() {
        let (config_dir, _state_dir, factory) = test_factory();
        let modules_dir = config_dir.path().join("modules.d");
        std::fs::create_dir_all(&modules_dir).unwrap();
        std::fs::write(modules_dir.join("squawk.yaml"), "port: 53\n").unwrap();

        let schema = br#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"endpoint":{"type":"string"}},"required":["endpoint"]}"#;
        let host = factory.host_for("squawk", Some(schema));

        // Validation failed (missing required "endpoint"); the module falls
        // back to its own defaults rather than the load failing outright.
        assert!(host.config().is_empty());
    }

    #[test]
    fn host_for_accepts_config_matching_its_schema() {
        let (config_dir, _state_dir, factory) = test_factory();
        let modules_dir = config_dir.path().join("modules.d");
        std::fs::create_dir_all(&modules_dir).unwrap();
        std::fs::write(modules_dir.join("squawk.yaml"), "endpoint: us-east\n").unwrap();

        let schema = br#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"endpoint":{"type":"string"}},"required":["endpoint"]}"#;
        let host = factory.host_for("squawk", Some(schema));
        assert_eq!(host.config(), b"endpoint: us-east\n");
    }

    #[test]
    fn host_for_is_non_fatal_when_the_data_dir_cannot_be_created() {
        // Point state_dir at a plain file, not a directory: MkdirAll-equivalent
        // creation must fail, but host_for must still return a usable host
        // rather than panicking or erroring the whole call.
        let root = TempDir::new().unwrap();
        let blocking_file = root.path().join("not-a-dir");
        std::fs::write(&blocking_file, b"x").unwrap();

        let config_dir = TempDir::new().unwrap();
        let telemetry = Arc::new(Telemetry::new("error").unwrap());
        let config_store = Arc::new(ConfigStore::new(config_dir.path()));
        let broker: Arc<dyn EventSink> = Arc::new(EventBroker::new(4));
        let factory = DaemonHostFactory::new(
            telemetry,
            config_store,
            Arc::new(FakeSecretStoreProvider::default()),
            Arc::new(FakeLicenseChecker),
            broker,
            blocking_file.clone(),
        );

        let host = factory.host_for("squawk", None);
        assert_eq!(host.data_dir(), blocking_file.join("squawk"));
    }

    #[test]
    fn host_for_shares_the_same_injected_license_across_modules() {
        // One shared licensing client is correct here — unlike secrets, this
        // matches the Go reference, which never namespaces license checks
        // per module.
        let (_config_dir, _state_dir, factory) = test_factory();
        let host_a = factory.host_for("module-a", None);
        let host_b = factory.host_for("module-b", None);

        assert_eq!(host_a.license().tier(), host_b.license().tier());
        assert!(Arc::ptr_eq(&host_a.license(), &host_b.license()));
    }

    #[tokio::test]
    async fn host_for_gives_two_modules_isolated_secret_values_for_the_same_key() {
        let (_config_dir, _state_dir, factory) = test_factory();
        let host_a = factory.host_for("module-a", None);
        let host_b = factory.host_for("module-b", None);

        host_a
            .secrets()
            .set("api_key", b"secret-a")
            .await
            .expect("a set");
        host_b
            .secrets()
            .set("api_key", b"secret-b")
            .await
            .expect("b set");

        assert_eq!(
            host_a.secrets().get("api_key").await.expect("a get"),
            b"secret-a"
        );
        assert_eq!(
            host_b.secrets().get("api_key").await.expect("b get"),
            b"secret-b"
        );
    }

    #[tokio::test]
    async fn host_for_deleting_one_modules_secret_leaves_anothers_intact() {
        let (_config_dir, _state_dir, factory) = test_factory();
        let host_a = factory.host_for("module-a", None);
        let host_b = factory.host_for("module-b", None);

        host_a
            .secrets()
            .set("api_key", b"secret-a")
            .await
            .expect("a set");
        host_b
            .secrets()
            .set("api_key", b"secret-b")
            .await
            .expect("b set");

        host_a.secrets().delete("api_key").await.expect("a delete");

        let after_delete = host_a.secrets().get("api_key").await.unwrap_err();
        assert!(matches!(after_delete, SecretError::NotFound));
        assert_eq!(
            host_b
                .secrets()
                .get("api_key")
                .await
                .expect("b still present"),
            b"secret-b"
        );
    }

    #[tokio::test]
    async fn host_for_a_module_cannot_read_a_key_written_under_another_modules_namespace() {
        let (_config_dir, _state_dir, factory) = test_factory();
        let host_a = factory.host_for("module-a", None);
        let host_b = factory.host_for("module-b", None);

        host_b
            .secrets()
            .set("only_in_b", b"secret-b")
            .await
            .expect("b set");

        let err = host_a.secrets().get("only_in_b").await.unwrap_err();
        assert!(matches!(err, SecretError::NotFound));
    }

    #[tokio::test]
    async fn host_for_wires_events_into_the_same_shared_broker() {
        let config_dir = TempDir::new().unwrap();
        let state_dir = TempDir::new().unwrap();
        let telemetry = Arc::new(Telemetry::new("error").unwrap());
        let config_store = Arc::new(ConfigStore::new(config_dir.path()));
        let broker = Arc::new(EventBroker::new(4));
        let events: Arc<dyn EventSink> = broker.clone();

        let factory = DaemonHostFactory::new(
            telemetry,
            config_store,
            Arc::new(FakeSecretStoreProvider::default()),
            Arc::new(FakeLicenseChecker),
            events,
            state_dir.path().to_path_buf(),
        );

        let mut subscriber = broker.subscribe();
        let host = factory.host_for("squawk", None);
        host.events().publish(penguin_sdk::Event {
            module: "squawk".to_string(),
            event_type: penguin_sdk::EventType::Info,
            message: "via host".to_string(),
            at: std::time::SystemTime::now(),
            fields: HashMap::new(),
        });

        let received = subscriber.recv().await.unwrap();
        assert_eq!(received.message, "via host");
    }

    use penguin_sdk::plugin::HostCapability;
    use penguin_sdk::tools::ToolError as TE;
    use serde_json::json;

    /// A license double with a toggleable `penguind.wasm-modules` flag.
    struct FlagLicense(bool);
    impl LicenseChecker for FlagLicense {
        fn feature_enabled(&self, key: &str) -> bool {
            self.0 && key == WASM_MODULES_FLAG
        }
        fn tier(&self) -> String {
            "free".to_string()
        }
    }

    /// Builds a factory with the wasm flag on or off and `config` as the
    /// module's on-disk YAML (when given).
    fn tool_factory(
        flag: bool,
        config: Option<&str>,
    ) -> (TempDir, TempDir, Arc<Telemetry>, Arc<dyn HostServices>) {
        let config_dir = TempDir::new().unwrap();
        let state_dir = TempDir::new().unwrap();
        if let Some(yaml) = config {
            let modules = config_dir.path().join("modules.d");
            std::fs::create_dir_all(&modules).unwrap();
            std::fs::write(modules.join("tooly.yaml"), yaml).unwrap();
        }
        let telemetry = Arc::new(Telemetry::new("error").unwrap());
        let factory = DaemonHostFactory::new(
            telemetry.clone(),
            Arc::new(ConfigStore::new(config_dir.path())),
            Arc::new(FakeSecretStoreProvider::default()),
            Arc::new(FlagLicense(flag)),
            Arc::new(EventBroker::new(4)),
            state_dir.path().to_path_buf(),
        );
        let host = factory.host_for("tooly", None);
        (config_dir, state_dir, telemetry, host)
    }

    #[tokio::test]
    async fn call_tool_fails_loudly_when_the_flag_is_off() {
        let (_c, _s, _t, host) = tool_factory(false, None);
        let err = host
            .call_tool("logger", json!({"level":"INFO","message":"x"}))
            .await
            .unwrap_err();
        assert_eq!(err, TE::Unavailable);
        // The typed wrapper surfaces the same failure.
        let cap = HostCapability::new(host);
        assert_eq!(cap.log("INFO", "x").await.unwrap_err(), TE::Unavailable);
    }

    #[tokio::test]
    async fn call_tool_reaches_real_executors_when_the_flag_is_on() {
        let (_c, _s, telemetry, host) = tool_factory(true, Some("server:\n  port: 8443\n"));
        let cap = HostCapability::new(host);
        cap.log("INFO", "hello\nforged").await.expect("log");
        let cfg = cap.get_config("server.port").await.expect("config");
        assert_eq!(cfg["value"], 8443);
        cap.push_metric("requests", 3.0, json!({"route":"/x"}))
            .await
            .expect("metric");
        let fams = telemetry.registry().gather();
        assert!(
            fams.iter()
                .any(|f| f.name() == "penguind_module_tooly__requests")
        );
        let calls = fams
            .iter()
            .find(|f| f.name() == "penguind_wasm_tool_calls_total")
            .expect("tool call counter");
        assert!(!calls.get_metric().is_empty());
    }

    #[tokio::test]
    async fn call_tool_error_paths_are_typed() {
        let (_c, _s, _t, host) = tool_factory(true, None);
        assert!(matches!(
            host.call_tool("no_such_tool", json!({})).await,
            Err(TE::UnknownTool(_))
        ));
        assert!(matches!(
            host.call_tool("config_read", json!({"path": 7})).await,
            Err(TE::InvalidArgs { .. })
        ));
        assert!(matches!(
            host.call_tool("logger", json!({"level":"INFO"})).await,
            Err(TE::InvalidArgs { .. })
        ));
        assert!(matches!(
            host.call_tool("http_request", json!({"method":"GET","url":"u"}))
                .await,
            Err(TE::NotImplemented(_))
        ));
        assert!(matches!(
            host.call_tool("config_read", json!({"path":"absent"}))
                .await,
            Err(TE::Failed { .. })
        ));
    }

    #[tokio::test]
    async fn call_tool_reports_a_registry_build_failure_every_time() {
        // Unparsable YAML is tolerated by resolve_config only when it reads as
        // empty; valid-but-non-mapping YAML passes through and config_read
        // simply cannot find paths, so force the failure with raw bad YAML in
        // the config bytes via a host built directly.
        let (_c, _s, telemetry, _host) = tool_factory(true, None);
        let wiring = ToolWiring {
            module: "broken".into(),
            gauges: ModuleGauges::new(telemetry.registry().clone()),
            metrics: None,
            registry: OnceLock::new(),
        };
        let logger: Arc<dyn Logger> = Arc::new(penguin_telemetry::TracingLogger::new("broken"));
        let first = wiring.get(&logger, b": : [").err().expect("bad yaml fails");
        let second = wiring.get(&logger, b"valid: yaml").err().expect("memoized");
        assert_eq!(first, second, "failure is memoized, not retried");
    }

    #[test]
    fn a_second_factory_over_the_same_telemetry_degrades_without_failing() {
        let telemetry = Arc::new(Telemetry::new("error").unwrap());
        let mk = || {
            DaemonHostFactory::new(
                telemetry.clone(),
                Arc::new(ConfigStore::new(std::env::temp_dir())),
                Arc::new(FakeSecretStoreProvider::default()),
                Arc::new(FlagLicense(true)),
                Arc::new(EventBroker::new(4)),
                std::env::temp_dir(),
            )
        };
        let first = mk();
        let second = mk();
        assert!(first.tool_metrics.is_some());
        assert!(second.tool_metrics.is_none());
    }
}
