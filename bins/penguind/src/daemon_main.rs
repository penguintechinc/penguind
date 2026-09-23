//! Unix daemon startup: config, telemetry, the single-instance lock, the
//! supervisor, and the gRPC server over the control socket. Ported from the
//! combined `go-client/cmd/penguind/main.go` + `service.go` startup path.
//!
//! Windows service-manager integration (`kardianos/service` in Go) is out of
//! scope here — see [`super::main`]'s `service` short-circuit — so this
//! module only ever runs the daemon in the Go reference's "interactive mode"
//! shape: serve directly, wait for a signal, shut down.

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Server;

use penguin_daemon::broker::EventBroker;
use penguin_daemon::config::{ConfigStore, DaemonConfig};
use penguin_daemon::external::{ExternalLoader, PluginDirLoader};
use penguin_daemon::host::{DaemonHostFactory, HostFactory, SecretStoreProvider};
use penguin_daemon::lock::{self, LockError};
use penguin_daemon::logring::LogRing;
use penguin_daemon::service::{DaemonService, UpdateClient};
use penguin_daemon::supervisor::{Supervisor, SupervisorConfig};
use penguin_ipc::groups_unix::SystemGroups;
use penguin_ipc::listen_unix::{self, ListenerConfig, PeerAuthInterceptor};
use penguin_ipc::{GroupResolver, IpcError};
use penguin_licensing::{LicenseClient, LicenseClientOptions};
use penguin_proto::daemon::v1::daemon_server::DaemonServer;
use penguin_proto::desktop::v1::bridge_action_proxy_server::BridgeActionProxyServer;
use penguin_proto::desktop::v1::session_proxy_server::SessionProxyServer;
use penguin_sdk::{EventSink, LicenseChecker, SecretError};
use penguin_secrets::{Backend as SecretsBackend, Config as SecretsConfig, Store as SecretsStore};
use penguin_telemetry::{Telemetry, TelemetryError};

use crate::host_wiring::SecretsStoreProvider;
use crate::{VERSION, logging};
use penguin_daemon::service::{BridgeActionProxyService, SessionProxyService};

/// Log lines retained per source (a module name, or `""` for the daemon
/// itself) before the oldest are evicted. Generous but arbitrary — nothing
/// in the Go reference specifies a size, since Go never implemented
/// `TailLogs` at all.
const LOG_RING_CAPACITY: usize = 2000;

/// Events buffered per `WatchEvents` subscriber before the slowest one
/// starts lagging.
const EVENT_BROKER_CAPACITY: usize = 256;

/// How often a loaded module's health is polled. A Rust-only addition (see
/// `penguin_daemon`'s crate-level divergence list) with no Go equivalent to
/// match, so this is a reasonable starting default pending real tuning.
const HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// How long a module must run before a subsequent failure resets its
/// restart budget. Same "no Go equivalent" caveat as
/// [`HEALTH_POLL_INTERVAL`].
const STABILITY_WINDOW: Duration = Duration::from_secs(5 * 60);

/// How often the license client re-validates against `license.penguintech.io`
/// in the background. Matches the Go client's default
/// `Options.RefreshInterval` (`go-client/internal/licensing/client.go`).
const LICENSE_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// The PostHog feature flag gating OTLP emission (see `critical-rules.md`
/// Observability + Feature Flags & License Tiers). Resolved through the same
/// [`LicenseChecker`] every other flag/entitlement check in this daemon uses
/// — default OFF (an unset/never-fetched flag reads `false`), with the same
/// last-known-cache graceful degradation the license client already
/// implements for every other flag.
const OTEL_TELEMETRY_FLAG: &str = "penguind.otel-telemetry";

/// The GitHub repository self-updates are fetched from — matches
/// `go-client/.goreleaser.yaml`'s `release.github.{owner,name}`.
const RELEASE_REPO: &str = "penguintechinc/penguin";

/// The minisign public key trusted to verify release archives.
///
/// `None` today: baking the real PenguinTech release-signing key into this
/// binary is a deliberate, reviewed follow-up (see `docs/PARITY.md` and the
/// M7.2 task), not something to fabricate here — a placeholder or made-up
/// key would be strictly worse than no key at all, since it would look
/// configured while verifying nothing real. With no key, `check_update`
/// still works and can report a release is available (read-only, harmless),
/// but `apply_update` fails closed with "no release verification key
/// configured" — see [`penguin_update::UpdateError::NoVerificationKey`].
const RELEASE_PUBLIC_KEY: Option<&str> = None;

/// Adapts [`penguin_update::Updater`] to [`UpdateClient`], the trait
/// [`DaemonService`]'s `CheckUpdate`/`ApplyUpdate` RPC handlers consult (see
/// that trait's doc — this file's construction below used to always pass
/// `None`). The only work this adapter does is flatten
/// `penguin_update::UpdateError` to the trait's plain `String` error type.
struct SelfUpdateClient {
    updater: penguin_update::Updater,
}

#[async_trait::async_trait]
impl UpdateClient for SelfUpdateClient {
    async fn check_update(&self) -> Result<(bool, String), String> {
        self.updater.check().await.map_err(|err| err.to_string())
    }

    async fn apply_update(&self) -> Result<(), String> {
        self.updater.apply().await.map_err(|err| err.to_string())
    }
}

/// Command-line flags for normal daemon startup. The `version`/`--version`
/// and `service` short-circuits in [`super::main`] never reach this parser.
#[derive(Parser, Debug)]
#[command(name = "penguind", disable_version_flag = true)]
struct Args {
    /// Configuration directory (`config.yaml` + `modules.d/`).
    #[arg(long, default_value = "/etc/penguin")]
    config_dir: PathBuf,
    /// State directory: single-instance lock, persisted enabled-set, and
    /// each module's private data directory.
    #[arg(long, default_value = "/var/lib/penguind")]
    state_dir: PathBuf,
    /// Overrides `config.yaml`'s `socketPath` when non-empty.
    #[arg(long, default_value = "")]
    socket: String,
}

/// A fatal daemon-startup failure. [`run`] prints this and exits non-zero;
/// every variant corresponds to one of the "failure is fatal" steps in the
/// startup sequence.
#[derive(Debug, thiserror::Error)]
enum DaemonBinError {
    /// Creating `--state-dir` failed.
    #[error("create state dir: {0}")]
    StateDir(#[source] std::io::Error),
    /// Another `penguind` instance already holds the single-instance lock,
    /// or the lock file itself could not be opened.
    #[error(transparent)]
    Lock(#[from] LockError),
    /// The daemon's log level (from `config.yaml`, or its default) failed
    /// to validate.
    #[error(transparent)]
    Telemetry(#[from] TelemetryError),
    /// Opening the encrypted-file secret store failed — fatal, matching
    /// Go's `secrets.Open` failure path in `cmd/penguind/service.go` (it
    /// releases the single-instance lock and returns an error rather than
    /// starting with no secret storage at all).
    #[error("init secrets store: {0}")]
    Secrets(#[from] SecretError),
    /// Binding the control socket failed.
    #[error(transparent)]
    Listen(#[from] IpcError),
    /// The gRPC server itself failed (not a graceful shutdown).
    #[error("serve: {0}")]
    Serve(#[from] tonic::transport::Error),
}

/// Builds a tokio runtime and drives [`run_daemon`] to completion, mapping
/// any fatal error to a printed message and a non-zero exit code.
pub fn run() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("penguind: build async runtime: {err}");
            return ExitCode::FAILURE;
        }
    };

    let Err(err) = runtime.block_on(run_daemon()) else {
        return ExitCode::SUCCESS;
    };
    eprintln!("penguind: {err}");
    ExitCode::FAILURE
}

/// The full startup sequence: load config, init telemetry, acquire the
/// single-instance lock, build the supervisor and gRPC service, serve until
/// a shutdown signal, then shut the supervisor down cleanly.
async fn run_daemon() -> Result<(), DaemonBinError> {
    let args = Args::parse();

    let config_store = ConfigStore::new(args.config_dir.clone());
    let mut daemon_cfg = match config_store.daemon() {
        Ok(cfg) => cfg,
        Err(err) => {
            // No logger exists yet at this point in the sequence — config
            // load happens before telemetry installs one.
            eprintln!("penguind: invalid daemon config, using defaults: {err}");
            DaemonConfig::defaults()
        }
    };
    if !args.socket.is_empty() {
        daemon_cfg.socket_path = args.socket.clone();
    }

    ensure_state_dir(&args.state_dir).map_err(DaemonBinError::StateDir)?;
    // Single-instance guard. Held for the rest of this function's lifetime;
    // dropping it (on any return path) releases the lock.
    let _lock_guard = lock::acquire(&args.state_dir)?;

    // Real M4 license client: license.penguintech.io with an offline cache
    // under `<state_dir>/license`. `LICENSE_KEY` matches the env var Go
    // reads in `cmd/penguind/service.go`. A missing/empty key or an
    // unreachable server both degrade gracefully — see `LicenseClient`'s own
    // doc — rather than stopping the daemon from starting.
    //
    // Constructed ahead of telemetry (moved earlier than the brief's literal
    // step order) so its `feature_enabled` cache — empty on a fresh daemon,
    // which reads as "off" per `LicenseChecker`'s own contract — can gate the
    // OTel pipeline below before the tracing subscriber is installed. A
    // fresh install therefore starts with OTLP export off, exactly matching
    // "default OFF until validated".
    let license_client = Arc::new(LicenseClient::new(LicenseClientOptions {
        license_key: env::var("LICENSE_KEY").unwrap_or_default(),
        product: String::new(),
        base_url: String::new(),
        cache_dir: Some(args.state_dir.join("license")),
    }));
    let license_refresh = license_client.spawn_background_refresh(LICENSE_REFRESH_INTERVAL);
    let otel_enabled = license_client.feature_enabled(OTEL_TELEMETRY_FLAG);
    let license: Arc<dyn LicenseChecker> = license_client;

    // `otel::init` never panics and never blocks: disabled or a malformed
    // `OTEL_EXPORTER_OTLP_ENDPOINT` both simply yield `None`, logged at warn
    // once the subscriber below exists — an unreachable-but-valid endpoint
    // builds fine and only fails silently at flush time (dead-exporter
    // safety). Timed so the daemon's own startup-latency histogram below
    // reflects the real cost of standing up telemetry, OTel included.
    let telemetry_init_started = std::time::Instant::now();
    let otel_pipeline = penguin_telemetry::otel::init(otel_enabled);

    // The LogRing must exist before installing tracing (its layer needs a
    // handle to append into), so this precedes `Telemetry::new` — the one
    // step reordered from the brief's literal list, since EventBroker has
    // no such dependency and can stay wherever.
    let logs = Arc::new(LogRing::new(LOG_RING_CAPACITY));
    logging::install(logs.clone(), &daemon_cfg.log_level, otel_pipeline.as_ref());
    let telemetry = Arc::new(Telemetry::new(&daemon_cfg.log_level)?);
    let telemetry_init_duration = telemetry.duration_histogram(
        "penguind_telemetry_init_duration_seconds",
        "Time to initialize the daemon's logging, metrics, and (if enabled) OTel pipeline.",
        otel_pipeline.as_ref(),
    )?;
    telemetry_init_duration.record(telemetry_init_started.elapsed().as_secs_f64());

    let broker = Arc::new(EventBroker::new(EVENT_BROKER_CAPACITY));
    let events: Arc<dyn EventSink> = broker.clone();

    // Real M4 secret store: XChaCha20-Poly1305-encrypted files under
    // `<state_dir>/secrets`, with the master key alongside them (see
    // `penguin_secrets::file_backend`). `FileOnly` is deliberate, not a
    // placeholder — the daemon is headless, and `Backend::Auto` would probe
    // a platform keyring/Secret Service, which must never happen here (see
    // that crate's module doc, "Never let a test touch a real OS keyring" —
    // the same reasoning applies in production for a service with no
    // desktop session).
    let secrets_root = Arc::new(SecretsStore::open(SecretsConfig {
        service_name: String::new(),
        backend: SecretsBackend::FileOnly {
            file_dir: args.state_dir.join("secrets"),
        },
    })?);

    // Per-module secret isolation is part of DaemonHostFactory's own
    // contract (see `penguin_daemon::host::SecretStoreProvider`):
    // `SecretsStoreProvider` gives every module its own
    // `secrets_root.namespaced(module)` view, so `host_for` never hands two
    // modules the same store.
    let secrets_provider: Arc<dyn SecretStoreProvider> =
        Arc::new(SecretsStoreProvider::new(secrets_root));
    let host_factory: Arc<dyn HostFactory> = Arc::new(DaemonHostFactory::new(
        telemetry,
        Arc::new(config_store),
        secrets_provider,
        license,
        events,
        args.state_dir.clone(),
    ));

    // `daemon_cfg.plugins_dir` is scanned lazily, one `<name>/` at a time,
    // only when something actually tries to `load` that name — constructing
    // the loader here never touches the filesystem itself, so a plugins_dir
    // that doesn't exist yet (or never will) cannot stop the daemon from
    // starting: every `load` for a name the builtin registry doesn't know
    // just resolves to `PluginDirLoader`'s `NotFound`, exactly like an
    // unregistered builtin name always has.
    let plugin_socket_dir = args.state_dir.join("plugin-sockets");
    if let Err(err) = ensure_state_dir(&plugin_socket_dir) {
        tracing::warn!(
            error = %err,
            dir = %plugin_socket_dir.display(),
            "failed to create plugin socket dir; external plugin loading may be degraded"
        );
    }
    let external: Arc<dyn ExternalLoader> = Arc::new(PluginDirLoader::new(
        PathBuf::from(&daemon_cfg.plugins_dir),
        plugin_socket_dir,
        self_uid(),
    ));

    let supervisor = Supervisor::new(SupervisorConfig {
        // M5: squawk is the first real built-in module (penguin-tobogganing
        // lands in its own later milestone).
        registry: penguin_registry::builtin_modules(),
        host_factory,
        broker: broker.clone(),
        state_dir: args.state_dir.clone(),
        max_restarts: 0, // 0 = use the crate default (backoff::MAX_RESTARTS)
        health_interval: HEALTH_POLL_INTERVAL,
        stability_window: STABILITY_WINDOW,
        external: Some(external),
    });

    for (name, err) in supervisor.start_enabled().await {
        tracing::warn!(module = %name, error = %err, "failed to restore persisted module");
    }

    let update_client: Arc<dyn UpdateClient> = Arc::new(SelfUpdateClient {
        updater: penguin_update::Updater::new(penguin_update::UpdateConfig {
            repo: RELEASE_REPO.to_string(),
            current_version: VERSION.to_string(),
            binary_name: "penguind".to_string(),
            public_key: RELEASE_PUBLIC_KEY.map(str::to_string),
        }),
    });
    let daemon_service = DaemonService::new(
        supervisor.clone(),
        broker,
        logs,
        VERSION,
        Some(update_client),
    );

    let listener_cfg = ListenerConfig {
        path: PathBuf::from(&daemon_cfg.socket_path),
        allowed_group: daemon_cfg.group.clone(),
    };
    let listener = listen_unix::listen(&listener_cfg)?;
    tracing::info!(socket = %daemon_cfg.socket_path, "listening on control socket");
    let incoming = listen_unix::incoming(listener);

    let resolver: Arc<dyn GroupResolver> = Arc::new(SystemGroups);
    let peer_auth = PeerAuthInterceptor::new(self_uid(), daemon_cfg.group.clone(), resolver);

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<DaemonServer<DaemonService>>()
        .await;

    let daemon_svc = InterceptedService::new(DaemonServer::new(daemon_service), peer_auth.clone());
    let health_svc = InterceptedService::new(health_service, peer_auth.clone());

    // Register the session proxy service (Phase 4a/4b poll loop support).
    let session_proxy_svc = InterceptedService::new(
        SessionProxyServer::new(SessionProxyService::new(supervisor.clone())),
        peer_auth.clone(),
    );

    // Register the bridge action proxy service (Phase 4c OBS/webhook dispatch).
    let bridge_action_svc = InterceptedService::new(
        BridgeActionProxyServer::new(BridgeActionProxyService::new(supervisor.clone())),
        peer_auth,
    );

    let serve_result = Server::builder()
        .add_service(daemon_svc)
        .add_service(health_svc)
        .add_service(session_proxy_svc)
        .add_service(bridge_action_svc)
        .serve_with_incoming_shutdown(incoming, wait_for_shutdown_signal())
        .await;

    tracing::info!("shutting down");
    supervisor.shutdown().await;
    license_refresh.stop().await;
    // Flush any buffered spans/logs/metrics before the process exits. Runs
    // off this async worker and is bounded to `OTEL_SHUTDOWN_BUDGET` total
    // (not the SDK's own up-to-30s worst case across all three providers) —
    // see `OtelPipeline::shutdown_with_timeout`'s own doc. A no-op when OTel
    // was never enabled/initialized.
    if let Some(pipeline) = otel_pipeline {
        pipeline
            .shutdown_with_timeout(penguin_telemetry::otel::OTEL_SHUTDOWN_BUDGET)
            .await;
    }
    let _ = std::fs::remove_file(&daemon_cfg.socket_path);

    serve_result.map_err(DaemonBinError::Serve)
}

/// Creates `path` (and any missing parents) with mode `0700` if it does not
/// already exist, matching Go's `os.MkdirAll(stateDir, 0o700)`.
fn ensure_state_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    builder.mode(0o700);
    builder.create(path)
}

/// The current process's uid, for [`PeerAuthInterceptor`]'s "the daemon's
/// own uid is always authorized" rule.
fn self_uid() -> u32 {
    nix::unistd::Uid::current().as_raw()
}

/// Resolves once SIGINT or SIGTERM arrives, driving
/// `Server::serve_with_incoming_shutdown`'s graceful drain.
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    // Registering a signal handler only fails if the underlying syscall
    // setup fails, which would indicate a broken process environment this
    // daemon cannot run in regardless — panicking here is no worse than the
    // process being unable to shut down cleanly at all.
    let mut sigint = signal(SignalKind::interrupt()).expect("register SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("register SIGTERM handler");

    tokio::select! {
        _ = sigint.recv() => tracing::info!(signal = "SIGINT", "received shutdown signal"),
        _ = sigterm.recv() => tracing::info!(signal = "SIGTERM", "received shutdown signal"),
    }
}
