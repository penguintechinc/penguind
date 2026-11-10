//! Daemon wiring for the hub client (`penguin-hub-client`).
//!
//! Everything that decides *where* the daemon talks and *what* a hub may
//! grant comes from the local `hub.yaml` (hub URL, pinned minisign keys,
//! network allowlist, limits ceiling) — never from the hub itself. The loop is
//! spawned only when the PostHog flag `penguind.hub-client` is on (default
//! OFF), and fetched modules reach the wasm host only through
//! [`DaemonHostFactory::run_fetched_wasm`] with the clamped limits.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use penguin_hub_client::{
    ClampedLicense, CredentialStore, DesiredModule, HubCache, HubClient, HubClientConfig,
    HubMetrics, K8sSecretTokenStore, LocalCeiling, ModuleLoadError, ModuleSink, RunMode,
    TOKEN_FILE_ENV, TokenStore, TokenStoreCandidates, run_loop, select_token_store,
};
use penguin_sdk::{LicenseChecker, SecretStore};
use penguin_wasm_host::WasmHostError;
use penguin_wasm_host::distribution::{HubFetcher, NetworkPolicy};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use crate::host::DaemonHostFactory;
use crate::wasm::WasmRunError;

/// PostHog flag gating the whole hub client; absent/unseen means OFF.
pub const HUB_CLIENT_FLAG: &str = "penguind.hub-client";
/// Env var carrying the one-time enrollment token (never a CLI arg).
pub const BOOTSTRAP_ENV: &str = "PENGUIND_HUB_BOOTSTRAP_TOKEN";
/// Local config file name inside the daemon config dir.
pub const HUB_CONFIG_FILE: &str = "hub.yaml";

/// Error code reported to the hub when local policy (the flag) denies a module.
const CODE_POLICY: i64 = 5;
/// Error code reported to the hub when the host fails to load a module.
const CODE_LOAD: i64 = 4;

/// Why the hub client could not be set up; the daemon logs it and runs on without a hub.
#[derive(Debug, thiserror::Error)]
pub enum HubSetupError {
    /// `hub.yaml` could not be read or parsed.
    #[error("hub config: {0}")]
    Config(String),
    /// The client could not be built from the config.
    #[error("hub client setup: {0}")]
    Setup(String),
}

/// Network allowlist for the hub (and any presigned blob host).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkFile {
    /// Allowed FQDNs.
    #[serde(default)]
    pub fqdns: Vec<String>,
    /// Allowed CIDRs.
    #[serde(default)]
    pub cidrs: Vec<String>,
}

/// The local ceiling for hub-delivered modules.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CeilingFile {
    /// Tools a hub-delivered module may ever call (default: none).
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// DNS names a hub-delivered module may ever resolve (default: none).
    #[serde(default)]
    pub allowed_dns: Vec<String>,
    /// Optional fuel ceiling.
    #[serde(default)]
    pub fuel: Option<u64>,
    /// Optional memory ceiling in MiB.
    #[serde(default)]
    pub max_memory_mb: Option<u64>,
    /// Optional per-run tool-call ceiling.
    #[serde(default)]
    pub max_tool_calls: Option<u32>,
}

/// `<config_dir>/hub.yaml`: the only source of hub URL, trust roots and ceiling.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HubFileConfig {
    /// Hub base URL (https).
    pub hub_url: String,
    /// Pinned minisign public keys (current + next, for rotation).
    pub trusted_keys: Vec<String>,
    /// Network policy the hub transport runs under.
    #[serde(default)]
    pub network: NetworkFile,
    /// Optional PEM (client cert chain + key) for mTLS.
    #[serde(default)]
    pub client_identity_path: Option<PathBuf>,
    /// Optional PEM root CA for a private-CA hub.
    #[serde(default)]
    pub extra_root_path: Option<PathBuf>,
    /// Limits ceiling.
    #[serde(default)]
    pub ceiling: CeilingFile,
    /// Offline-cache directory (default `<state_dir>/hub`).
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,
}

/// Reads `<config_dir>/hub.yaml`; `None` when the file does not exist.
pub fn load_hub_config(config_dir: &Path) -> Result<Option<HubFileConfig>, HubSetupError> {
    let path = config_dir.join(HUB_CONFIG_FILE);
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(HubSetupError::Config(format!("{}: {e}", path.display()))),
    };
    let cfg: HubFileConfig = serde_norway::from_str(&raw)
        .map_err(|e| HubSetupError::Config(format!("{}: {e}", path.display())))?;
    if cfg.trusted_keys.is_empty() {
        return Err(HubSetupError::Config(
            "trustedKeys must not be empty".into(),
        ));
    }
    Ok(Some(cfg))
}

/// Module ids the daemon will pass to the wasm host as a module name.
fn module_name_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Runs hub-delivered modules through the wasm host and tracks what is loaded.
pub struct DaemonModuleSink {
    factory: Arc<DaemonHostFactory>,
    loaded: Mutex<HashSet<String>>,
}

impl DaemonModuleSink {
    /// Sink backed by `factory`.
    pub fn new(factory: Arc<DaemonHostFactory>) -> Self {
        Self {
            factory,
            loaded: Mutex::new(HashSet::new()),
        }
    }

    /// Ids currently considered loaded.
    pub fn loaded_ids(&self) -> Vec<String> {
        self.loaded
            .lock()
            .map(|g| g.iter().cloned().collect())
            .unwrap_or_default()
    }
}

#[async_trait]
impl ModuleSink for DaemonModuleSink {
    /// Runs the verified module once under the clamped limits; a host or flag
    /// refusal is reported to the hub as a typed error code.
    async fn load(&self, module: DesiredModule) -> Result<(), ModuleLoadError> {
        if !module_name_ok(&module.id) {
            return Err(ModuleLoadError {
                code: CODE_LOAD,
                reason: "module id is not a safe module name".into(),
            });
        }
        match self
            .factory
            .run_fetched_wasm(&module.id, &module.module, module.limits)
            .await
        {
            Ok(outcome) => {
                tracing::info!(
                    module = %module.id,
                    version = %module.version,
                    exit_code = outcome.exit_code,
                    "hub-delivered module ran"
                );
                if let Ok(mut g) = self.loaded.lock() {
                    g.insert(module.id);
                }
                Ok(())
            }
            Err(WasmRunError::Host(WasmHostError::FlagDisabled(flag))) => Err(ModuleLoadError {
                code: CODE_POLICY,
                reason: format!("flag {flag} is off"),
            }),
            Err(e) => Err(ModuleLoadError {
                code: CODE_LOAD,
                reason: e.to_string(),
            }),
        }
    }

    /// Forgets the module; runs are one-shot, so there is nothing resident to stop.
    async fn unload(&self, id: &str) {
        if let Ok(mut g) = self.loaded.lock() {
            g.remove(id);
        }
        tracing::info!(module = %id, "hub-delivered module unloaded");
    }
}

/// Builds the fetcher, ceiling and client from `cfg` — all local inputs.
pub fn build_client(
    cfg: &HubFileConfig,
    state_dir: &Path,
    sink: Arc<dyn ModuleSink>,
    tokens: Arc<dyn TokenStore>,
    license: Arc<ClampedLicense>,
    registry: &prometheus::Registry,
) -> Result<HubClient, HubSetupError> {
    let setup = |e: &dyn std::fmt::Display| HubSetupError::Setup(e.to_string());
    let policy = NetworkPolicy::new(cfg.network.fqdns.clone(), cfg.network.cidrs.clone())
        .map_err(|e| setup(&e))?;
    let mut fetcher = HubFetcher::new(policy, cfg.trusted_keys.clone());
    if let Some(p) = &cfg.client_identity_path {
        let pem = std::fs::read(p).map_err(|e| setup(&format!("{}: {e}", p.display())))?;
        fetcher = fetcher.with_client_identity_pem(pem);
    }
    if let Some(p) = &cfg.extra_root_path {
        let pem = std::fs::read(p).map_err(|e| setup(&format!("{}: {e}", p.display())))?;
        fetcher = fetcher.with_extra_root_pem(pem);
    }
    let mut ceiling = LocalCeiling::with_grants(
        cfg.ceiling.allowed_tools.clone(),
        cfg.ceiling.allowed_dns.clone(),
    );
    if let Some(f) = cfg.ceiling.fuel {
        ceiling.fuel = f;
    }
    if let Some(mb) = cfg.ceiling.max_memory_mb {
        let bytes = mb.saturating_mul(1024 * 1024);
        ceiling.max_memory_bytes = usize::try_from(bytes).unwrap_or(usize::MAX);
    }
    if let Some(n) = cfg.ceiling.max_tool_calls {
        ceiling.max_tool_calls = n;
    }
    let platform = if cfg!(target_os = "macos") {
        2
    } else if cfg!(windows) {
        3
    } else {
        1
    };
    let mut client_cfg =
        HubClientConfig::new(&cfg.hub_url, platform, env!("CARGO_PKG_VERSION"), ceiling)
            .map_err(|e| setup(&e))?;
    client_cfg.bootstrap_token = std::env::var(BOOTSTRAP_ENV).ok().filter(|t| !t.is_empty());
    let cache_dir = cfg
        .cache_dir
        .clone()
        .unwrap_or_else(|| state_dir.join("hub"));
    let metrics = HubMetrics::register(registry).map_err(|e| setup(&e))?;
    Ok(HubClient::new(
        client_cfg,
        fetcher,
        CredentialStore::from_token_store(tokens),
        HubCache::new(cache_dir),
        sink,
        license,
        metrics,
    ))
}

/// Env var selecting the run mode (`desktop` / `daemonset` / `server`).
pub const RUN_MODE_ENV: &str = "PENGUIND_RUN_MODE";

/// Parses [`RUN_MODE_ENV`]; unset defaults to `server`, an unknown value is
/// logged and also treated as `server`.
pub fn run_mode_from(value: Option<&str>) -> RunMode {
    match value.filter(|v| !v.trim().is_empty()) {
        None => RunMode::Server,
        Some(v) => RunMode::parse(v).unwrap_or_else(|| {
            tracing::warn!(value = %v, env = RUN_MODE_ENV, "unknown run mode; using server");
            RunMode::Server
        }),
    }
}

/// Picks the hub token store for `mode`. `keychain` is `Some` only when the OS
/// keychain is reachable; `token_file` is [`TOKEN_FILE_ENV`] (daemonset).
/// No K8s API writer is wired yet, so a daemonset agent re-bootstraps after a
/// restart once its refresh token rotates.
pub fn hub_token_store(
    mode: RunMode,
    keychain: Option<Arc<dyn SecretStore>>,
    token_file: Option<&Path>,
    encrypted_file: Arc<dyn SecretStore>,
) -> Arc<dyn TokenStore> {
    let k8s_secret = match mode {
        RunMode::Daemonset => token_file.and_then(|p| K8sSecretTokenStore::open(p, None)),
        RunMode::Desktop | RunMode::Server => None,
    };
    select_token_store(
        mode,
        TokenStoreCandidates {
            keychain,
            k8s_secret,
            encrypted_file,
        },
    )
    .store
}

/// Reads [`TOKEN_FILE_ENV`].
pub fn token_file_from_env() -> Option<PathBuf> {
    std::env::var_os(TOKEN_FILE_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Handle on the running hub loop.
pub struct HubTask {
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl HubTask {
    /// Cancels the loop and waits for it to finish.
    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.handle.await;
    }
}

/// Everything [`spawn_hub_client`] needs from the daemon.
pub struct HubSpawn {
    /// Daemon config dir holding `hub.yaml`.
    pub config_dir: PathBuf,
    /// Daemon state dir (default cache location).
    pub state_dir: PathBuf,
    /// Factory that runs fetched modules.
    pub factory: Arc<DaemonHostFactory>,
    /// Token store picked by [`hub_token_store`].
    pub tokens: Arc<dyn TokenStore>,
    /// The flag combiner shared with the factory (licence && hub).
    pub license: Arc<ClampedLicense>,
    /// Registry the hub metrics register into.
    pub registry: prometheus::Registry,
}

/// Starts the hub loop if `penguind.hub-client` is on and `hub.yaml` exists.
/// Any setup problem is logged and the daemon carries on without a hub.
pub async fn spawn_hub_client(spawn: HubSpawn) -> Option<HubTask> {
    if !spawn.license.feature_enabled(HUB_CLIENT_FLAG) {
        tracing::debug!(flag = HUB_CLIENT_FLAG, "hub client disabled by flag");
        return None;
    }
    let cfg = match load_hub_config(&spawn.config_dir) {
        Ok(Some(c)) => c,
        Ok(None) => {
            tracing::info!("hub client flag on but no hub.yaml; not starting");
            return None;
        }
        Err(e) => {
            tracing::error!(error = %e, "hub client not started");
            return None;
        }
    };
    let sink = Arc::new(DaemonModuleSink::new(spawn.factory.clone()));
    let client = match build_client(
        &cfg,
        &spawn.state_dir,
        sink,
        spawn.tokens,
        spawn.license,
        &spawn.registry,
    ) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!(error = %e, "hub client not started");
            return None;
        }
    };
    let status = client.start().await;
    tracing::info!(?status, "hub client started");
    let cancel = CancellationToken::new();
    let handle = tokio::spawn(run_loop(client, cancel.clone()));
    Some(HubTask { cancel, handle })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::io::Cursor;

    use penguin_sdk::{EventSink, SecretError};
    use penguin_telemetry::Telemetry;
    use penguin_wasm_host::WASM_MODULES_FLAG;
    use penguin_wasm_host::distribution::{ManifestClaims, VerifiedModule, signed_payload};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::*;
    use crate::broker::EventBroker;
    use crate::config::ConfigStore;
    use crate::host::SecretStoreProvider;

    use penguin_hub_client::{SecretTokenStore, TokenStoreKind};

    struct NoSecrets;
    #[async_trait]
    impl SecretStore for NoSecrets {
        async fn get(&self, _k: &str) -> Result<Vec<u8>, SecretError> {
            Err(SecretError::NotFound)
        }
        async fn set(&self, _k: &str, _v: &[u8]) -> Result<(), SecretError> {
            Ok(())
        }
        async fn delete(&self, _k: &str) -> Result<(), SecretError> {
            Err(SecretError::NotFound)
        }
    }
    struct Provider;
    impl SecretStoreProvider for Provider {
        fn store_for(&self, _m: &str) -> Arc<dyn SecretStore> {
            Arc::new(NoSecrets)
        }
    }

    /// Licence that enables a fixed flag set.
    struct Flags(BTreeSet<String>);
    impl LicenseChecker for Flags {
        fn feature_enabled(&self, k: &str) -> bool {
            self.0.contains(k)
        }
        fn tier(&self) -> String {
            "free".into()
        }
    }

    fn clamped(flags: &[&str]) -> Arc<ClampedLicense> {
        let set: BTreeSet<String> = flags.iter().map(|s| s.to_string()).collect();
        Arc::new(ClampedLicense::new(Arc::new(Flags(set))))
    }

    struct Fixture {
        _cfg: TempDir,
        state: TempDir,
        factory: Arc<DaemonHostFactory>,
        license: Arc<ClampedLicense>,
        telemetry: Arc<Telemetry>,
    }

    fn fixture(flags: &[&str]) -> Fixture {
        let cfg = TempDir::new().expect("tmp");
        let state = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new("error").expect("telemetry"));
        let license = clamped(flags);
        let events: Arc<dyn EventSink> = Arc::new(EventBroker::new(4));
        let factory = Arc::new(DaemonHostFactory::new(
            telemetry.clone(),
            Arc::new(ConfigStore::new(cfg.path())),
            Arc::new(Provider),
            license.clone(),
            events,
            state.path().to_path_buf(),
        ));
        Fixture {
            _cfg: cfg,
            state,
            factory,
            license,
            telemetry,
        }
    }

    /// Signs `wasm` as `id@1.0.0` with a fresh key and returns the verified module.
    fn verified(id: &str, wasm: &[u8]) -> Arc<VerifiedModule> {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().expect("kp");
        let digest = Sha256::digest(wasm);
        let sha: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let payload = signed_payload(id, "1.0.0", &sha).expect("payload");
        let sig = minisign::sign(Some(&kp.pk), &kp.sk, Cursor::new(payload), None, None)
            .expect("sign")
            .to_string();
        let pk = kp.pk.to_box().expect("box").to_string();
        Arc::new(
            VerifiedModule::verify(
                id,
                "1.0.0",
                &ManifestClaims {
                    id,
                    version: "1.0.0",
                    sha256: &sha,
                    signature: &sig,
                },
                wasm.to_vec(),
                &pk,
            )
            .expect("verified"),
        )
    }

    fn runnable() -> Vec<u8> {
        wat::parse_str(
            r#"(module (memory (export "memory") 1) (func (export "run") (result i32) (i32.const 0)))"#,
        )
        .expect("wat")
    }

    fn desired(id: &str, wasm: &[u8]) -> DesiredModule {
        DesiredModule {
            id: id.into(),
            version: "1.0.0".into(),
            module: verified(id, wasm),
            limits: penguin_wasm_host::ModuleLimits::default(),
        }
    }

    #[test]
    fn module_names_are_restricted() {
        assert!(module_name_ok("demo-1_a.b"));
        for bad in ["", "../x", "a/b", "a b", &"x".repeat(65)] {
            assert!(!module_name_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn hub_yaml_loads_validates_and_rejects_unknowns() {
        let d = TempDir::new().expect("tmp");
        assert!(load_hub_config(d.path()).expect("ok").is_none());
        let path = d.path().join(HUB_CONFIG_FILE);
        std::fs::write(
            &path,
            "hubUrl: https://hub.example/\ntrustedKeys: [k1]\nnetwork:\n  fqdns: [hub.example]\nceiling:\n  allowedTools: [logger]\n",
        )
        .expect("write");
        let c = load_hub_config(d.path()).expect("ok").expect("some");
        assert_eq!(c.hub_url, "https://hub.example/");
        assert_eq!(c.ceiling.allowed_tools, vec!["logger".to_string()]);
        std::fs::write(&path, "hubUrl: https://h/\ntrustedKeys: []\n").expect("write");
        assert!(load_hub_config(d.path()).is_err(), "empty keys");
        std::fs::write(&path, "hubUrl: https://h/\ntrustedKeys: [k]\nbogus: 1\n").expect("write");
        assert!(load_hub_config(d.path()).is_err(), "unknown field");
        std::fs::write(&path, ": : [").expect("write");
        assert!(load_hub_config(d.path()).is_err(), "bad yaml");
    }

    #[test]
    fn io_error_reading_config_is_reported() {
        let d = TempDir::new().expect("tmp");
        std::fs::create_dir(d.path().join(HUB_CONFIG_FILE)).expect("dir");
        assert!(matches!(
            load_hub_config(d.path()),
            Err(HubSetupError::Config(_))
        ));
    }

    #[tokio::test]
    async fn sink_runs_verified_modules_and_maps_refusals_to_codes() {
        let f = fixture(&[WASM_MODULES_FLAG]);
        let sink = DaemonModuleSink::new(f.factory.clone());
        sink.load(desired("good", &runnable())).await.expect("runs");
        assert_eq!(sink.loaded_ids(), vec!["good".to_string()]);
        sink.unload("good").await;
        assert!(sink.loaded_ids().is_empty());
        // empty module has no `run` export -> load failure code.
        let err = sink
            .load(desired("empty", b"\0asm\x01\0\0\0"))
            .await
            .expect_err("no export");
        assert_eq!(err.code, CODE_LOAD);
        // unsafe name refused before the host sees it.
        let err = sink
            .load(desired("../evil", &runnable()))
            .await
            .expect_err("bad name");
        assert_eq!(err.code, CODE_LOAD);
        assert!(sink.loaded_ids().is_empty());
    }

    #[tokio::test]
    async fn sink_reports_policy_code_when_wasm_flag_is_off() {
        let f = fixture(&[]);
        let sink = DaemonModuleSink::new(f.factory.clone());
        let err = sink
            .load(desired("good", &runnable()))
            .await
            .expect_err("flag off");
        assert_eq!(err.code, CODE_POLICY);
    }

    fn file_cfg(extra: &str) -> HubFileConfig {
        serde_norway::from_str(&format!(
            "hubUrl: https://hub.example/\ntrustedKeys: [k]\n{extra}"
        ))
        .expect("cfg")
    }

    fn build(cfg: &HubFileConfig, f: &Fixture) -> Result<HubClient, HubSetupError> {
        build_client(
            cfg,
            f.state.path(),
            Arc::new(DaemonModuleSink::new(f.factory.clone())),
            Arc::new(SecretTokenStore::new(
                Arc::new(NoSecrets),
                TokenStoreKind::EncryptedFile,
            )),
            f.license.clone(),
            f.telemetry.registry(),
        )
    }

    #[tokio::test]
    async fn build_client_applies_local_ceiling_and_rejects_bad_inputs() {
        let f = fixture(&[]);
        let ok = file_cfg("ceiling:\n  fuel: 5\n  maxMemoryMb: 2\n  maxToolCalls: 3\n");
        assert!(build(&ok, &f).is_ok());
        // a second build re-registers the metrics -> duplicate error, surfaced not panicked.
        assert!(matches!(build(&ok, &f), Err(HubSetupError::Setup(_))));
        let f = fixture(&[]);
        assert!(build(&file_cfg("network:\n  cidrs: [not-a-cidr]\n"), &f).is_err());
        let f = fixture(&[]);
        assert!(build(&file_cfg("clientIdentityPath: /nonexistent/id.pem\n"), &f).is_err());
        assert!(build(&file_cfg("extraRootPath: /nonexistent/ca.pem\n"), &f).is_err());
        let mut http = file_cfg("");
        http.hub_url = "http://hub.example/".into();
        assert!(build(&http, &f).is_err(), "http hub url refused");
        // identity + root paths that exist are read.
        let pem = f.state.path().join("x.pem");
        std::fs::write(&pem, b"pem").expect("write");
        let with_files = file_cfg(&format!(
            "clientIdentityPath: {0}\nextraRootPath: {0}\ncacheDir: {1}\n",
            pem.display(),
            f.state.path().join("c").display()
        ));
        let f2 = fixture(&[]);
        assert!(build(&with_files, &f2).is_ok());
    }

    #[tokio::test]
    async fn spawn_is_off_by_default_and_needs_config() {
        let f = fixture(&[]);
        let spawn = |f: &Fixture, license: Arc<ClampedLicense>, dir: PathBuf| HubSpawn {
            config_dir: dir,
            state_dir: f.state.path().to_path_buf(),
            factory: f.factory.clone(),
            tokens: Arc::new(SecretTokenStore::new(
                Arc::new(NoSecrets),
                TokenStoreKind::EncryptedFile,
            )),
            license,
            registry: f.telemetry.registry().clone(),
        };
        // flag OFF (default): nothing starts even with a valid config present.
        let cfgdir = TempDir::new().expect("tmp");
        std::fs::write(
            cfgdir.path().join(HUB_CONFIG_FILE),
            "hubUrl: https://127.0.0.1:1/\ntrustedKeys: [k]\n",
        )
        .expect("write");
        assert!(
            spawn_hub_client(spawn(&f, clamped(&[]), cfgdir.path().to_path_buf()))
                .await
                .is_none()
        );
        // flag ON, no hub.yaml.
        let empty = TempDir::new().expect("tmp");
        assert!(
            spawn_hub_client(spawn(
                &f,
                clamped(&[HUB_CLIENT_FLAG]),
                empty.path().to_path_buf()
            ))
            .await
            .is_none()
        );
        // flag ON, broken hub.yaml.
        let bad = TempDir::new().expect("tmp");
        std::fs::write(bad.path().join(HUB_CONFIG_FILE), "nope: 1\n").expect("write");
        assert!(
            spawn_hub_client(spawn(
                &f,
                clamped(&[HUB_CLIENT_FLAG]),
                bad.path().to_path_buf()
            ))
            .await
            .is_none()
        );
        // flag ON, valid config but metrics already registered -> setup error, no task.
        let f2 = fixture(&[]);
        let _ = build(&file_cfg(""), &f2).expect("first");
        assert!(
            spawn_hub_client(spawn(
                &f2,
                clamped(&[HUB_CLIENT_FLAG]),
                cfgdir.path().to_path_buf()
            ))
            .await
            .is_none()
        );
    }

    #[tokio::test]
    async fn spawn_runs_and_stops_cleanly_when_flag_on() {
        let f = fixture(&[]);
        let cfgdir = TempDir::new().expect("tmp");
        // hub URL outside the (empty) allowlist: every poll is policy-denied, never sent.
        std::fs::write(
            cfgdir.path().join(HUB_CONFIG_FILE),
            "hubUrl: https://127.0.0.1:1/\ntrustedKeys: [k]\n",
        )
        .expect("write");
        let task = spawn_hub_client(HubSpawn {
            config_dir: cfgdir.path().to_path_buf(),
            state_dir: f.state.path().to_path_buf(),
            factory: f.factory.clone(),
            tokens: Arc::new(SecretTokenStore::new(
                Arc::new(NoSecrets),
                TokenStoreKind::EncryptedFile,
            )),
            license: clamped(&[HUB_CLIENT_FLAG]),
            registry: f.telemetry.registry().clone(),
        })
        .await
        .expect("started");
        tokio::time::timeout(std::time::Duration::from_secs(10), task.stop())
            .await
            .expect("stops");
    }

    #[test]
    fn run_mode_defaults_to_server() {
        assert_eq!(run_mode_from(None), RunMode::Server);
        assert_eq!(run_mode_from(Some(" ")), RunMode::Server);
        assert_eq!(run_mode_from(Some("bogus")), RunMode::Server);
        assert_eq!(run_mode_from(Some("desktop")), RunMode::Desktop);
        assert_eq!(run_mode_from(Some("daemonset")), RunMode::Daemonset);
    }

    #[test]
    fn hub_token_store_selects_per_mode_with_fallback() {
        let dir = tempfile::tempdir().expect("tmp");
        let file = dir.path().join("token");
        std::fs::write(&file, b"").expect("w");
        let enc = || Arc::new(NoSecrets) as Arc<dyn SecretStore>;
        let kc = || Some(Arc::new(NoSecrets) as Arc<dyn SecretStore>);
        let k = |m, kc, f: Option<&Path>| hub_token_store(m, kc, f, enc()).kind();
        assert_eq!(k(RunMode::Desktop, kc(), None), TokenStoreKind::Keychain);
        assert_eq!(k(RunMode::Server, kc(), None), TokenStoreKind::Keychain);
        assert_eq!(
            k(RunMode::Daemonset, kc(), Some(&file)),
            TokenStoreKind::KubernetesSecret
        );
        assert_eq!(
            k(RunMode::Daemonset, kc(), None),
            TokenStoreKind::EncryptedFile
        );
        assert_eq!(
            k(RunMode::Desktop, None, Some(&file)),
            TokenStoreKind::EncryptedFile
        );
        assert_eq!(
            k(RunMode::Server, None, None),
            TokenStoreKind::EncryptedFile
        );
    }
}
