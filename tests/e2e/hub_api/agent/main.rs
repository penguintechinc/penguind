//! E2E agent driver for `tests/e2e/hub_api`: the real `penguin-hub-client` sync
//! loop wired to the real daemon wasm path (`DaemonHostFactory::run_fetched_wasm`).
//!
//! Built as a `penguin-daemon` example so it links the daemon exactly as the
//! product does. The pytest harness drives it over stdin/stdout with one JSON
//! command per line and one JSON reply per line; every failure is a reply with
//! `"ok": false`, never a silent default. Nothing here is a test double: the
//! hub, TLS, S3 presigned downloads, minisign verification and the wasm runtime
//! are all the real components.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use penguin_daemon::broker::EventBroker;
use penguin_daemon::config::ConfigStore;
use penguin_daemon::host::{DaemonHostFactory, SecretStoreProvider};
use penguin_hub_client::client::StartStatus;
use penguin_hub_client::{
    ClampedLicense, CredentialStore, DesiredModule, HubCache, HubClient, HubClientConfig,
    HubMetrics, LocalCeiling, ModuleLoadError, ModuleSink, SyncOutcome,
};
use penguin_sdk::{EventSink, LicenseChecker, SecretError, SecretStore};
use penguin_telemetry::Telemetry;
use penguin_wasm_host::WASM_MODULES_FLAG;
use penguin_wasm_host::distribution::{HubFetcher, NetworkPolicy, signed_payload};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Local fuel ceiling; the hub asks for more and must be clamped down to this.
const CEILING_FUEL: u64 = 50_000_000;
/// Local memory ceiling in MiB; the hub asks for less and wins.
const CEILING_MEMORY_MB: u64 = 64;
/// Local per-run tool-call ceiling.
const CEILING_TOOL_CALLS: u32 = 16;

/// Secrets nobody reads: the demo module only calls `logger`.
struct NoSecrets;

#[async_trait]
impl SecretStore for NoSecrets {
    async fn get(&self, _k: &str) -> Result<Vec<u8>, SecretError> {
        Err(SecretError::NotFound)
    }
    async fn set(&self, _k: &str, _v: &[u8]) -> Result<(), SecretError> {
        Err(SecretError::Other("read-only".into()))
    }
    async fn delete(&self, _k: &str) -> Result<(), SecretError> {
        Err(SecretError::NotFound)
    }
}

/// Hands every module the empty store.
struct NoSecretsProvider;

impl SecretStoreProvider for NoSecretsProvider {
    fn store_for(&self, _module: &str) -> Arc<dyn SecretStore> {
        Arc::new(NoSecrets)
    }
}

/// Local license view: only the wasm-modules flag is on (the daemon gate the
/// fetched path must pass).
struct LocalFlags;

impl LicenseChecker for LocalFlags {
    fn feature_enabled(&self, key: &str) -> bool {
        key == WASM_MODULES_FLAG
    }
    fn tier(&self) -> String {
        "free".into()
    }
}

/// In-memory secret store standing in for the OS keychain for one agent; it
/// survives an agent "restart" because the driver keeps it across rebuilds.
#[derive(Default)]
struct MemSecrets(Mutex<HashMap<String, Vec<u8>>>);

#[async_trait]
impl SecretStore for MemSecrets {
    async fn get(&self, k: &str) -> Result<Vec<u8>, SecretError> {
        self.0
            .lock()
            .map_err(|_| SecretError::Other("poisoned".into()))?
            .get(k)
            .cloned()
            .ok_or(SecretError::NotFound)
    }
    async fn set(&self, k: &str, v: &[u8]) -> Result<(), SecretError> {
        self.0
            .lock()
            .map_err(|_| SecretError::Other("poisoned".into()))?
            .insert(k.into(), v.to_vec());
        Ok(())
    }
    async fn delete(&self, k: &str) -> Result<(), SecretError> {
        self.0
            .lock()
            .map_err(|_| SecretError::Other("poisoned".into()))?
            .remove(k)
            .map(|_| ())
            .ok_or(SecretError::NotFound)
    }
}

/// Sink that runs each delivered module through the daemon's
/// `run_fetched_wasm` with the clamped limits and records what happened.
struct RecordingSink {
    factory: Arc<DaemonHostFactory>,
    events: Mutex<Vec<Value>>,
    loaded: Mutex<HashSet<String>>,
}

impl RecordingSink {
    /// Drains the recorded load/unload events.
    fn take(&self) -> Vec<Value> {
        self.events
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default()
    }

    /// Currently loaded module ids, sorted.
    fn loaded(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .loaded
            .lock()
            .map(|g| g.iter().cloned().collect())
            .unwrap_or_default();
        v.sort();
        v
    }

    fn push(&self, v: Value) {
        if let Ok(mut g) = self.events.lock() {
            g.push(v);
        }
    }
}

#[async_trait]
impl ModuleSink for RecordingSink {
    /// Runs the verified module once; a host failure is a load error.
    async fn load(&self, m: DesiredModule) -> Result<(), ModuleLoadError> {
        let mut tools: Vec<String> = m.limits.allowed_tools.iter().cloned().collect();
        tools.sort();
        let limits = json!({
            "fuel": m.limits.fuel,
            "max_memory_bytes": m.limits.max_memory_bytes,
            "max_tool_calls": m.limits.max_tool_calls,
            "allowed_tools": tools,
        });
        let verified_sha = m.module.sha256().to_string();
        match self
            .factory
            .run_fetched_wasm(&m.id, &m.module, m.limits.clone())
            .await
        {
            Ok(out) => {
                let calls: Vec<Value> = out
                    .calls
                    .iter()
                    .map(|c| json!({"tool": c.tool, "code": c.code}))
                    .collect();
                self.push(json!({
                    "event": "load", "id": m.id, "version": m.version,
                    "verified_sha256": verified_sha, "limits": limits,
                    "exit_code": out.exit_code, "calls": calls,
                    "rejected_calls": out.rejected_calls,
                }));
                if let Ok(mut g) = self.loaded.lock() {
                    g.insert(m.id);
                }
                Ok(())
            }
            Err(e) => {
                self.push(json!({"event": "load_error", "id": m.id, "error": e.to_string()}));
                Err(ModuleLoadError {
                    code: 4,
                    reason: e.to_string(),
                })
            }
        }
    }

    async fn unload(&self, id: &str) {
        if let Ok(mut g) = self.loaded.lock() {
            g.remove(id);
        }
        self.push(json!({"event": "unload", "id": id}));
    }
}

/// One simulated agent: its client plus the state that survives a restart.
struct Agent {
    client: Option<HubClient>,
    sink: Arc<RecordingSink>,
    secrets: Arc<MemSecrets>,
    spec: Value,
}

/// The offline signer role: a fresh minisign key per run.
struct Signer {
    kp: minisign::KeyPair,
}

/// Driver state across commands.
struct Driver {
    factory: Arc<DaemonHostFactory>,
    signer: Option<Signer>,
    agents: HashMap<String, Agent>,
    _dirs: Vec<tempfile::TempDir>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Demo guest: `run` calls the `logger` tool once and returns its status code.
fn demo_wasm() -> Result<Vec<u8>, String> {
    let tool = "logger";
    let args = r#"{"level":"INFO","message":"hub e2e demo module ran"}"#;
    let esc = |t: &str| t.bytes().map(|b| format!("\\{b:02x}")).collect::<String>();
    let wat = format!(
        r#"(module
  (import "penguin" "call_tool" (func $ct (param i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{}")
  (data (i32.const 256) "{}")
  (func (export "run") (result i32)
    (call $ct (i32.const 0) (i32.const {}) (i32.const 256) (i32.const {})
              (i32.const 1024) (i32.const 4096))))"#,
        esc(tool),
        esc(args),
        tool.len(),
        args.len()
    );
    wat::parse_str(wat).map_err(|e| e.to_string())
}

fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field `{k}`"))
}

fn strs(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn outcome_json(o: SyncOutcome) -> Value {
    match o {
        SyncOutcome::NotModified => json!({"kind": "not_modified"}),
        SyncOutcome::Applied(r) => json!({"kind": "applied", "result": r}),
        SyncOutcome::Revoked => json!({"kind": "revoked"}),
        SyncOutcome::RetryAfter(d) => json!({"kind": "retry_after", "secs": d.as_secs()}),
        SyncOutcome::Backoff => json!({"kind": "backoff"}),
        SyncOutcome::NoCredentials => json!({"kind": "no_credentials"}),
    }
}

fn start_json(s: StartStatus) -> Value {
    match s {
        StartStatus::Fresh => json!({"kind": "fresh"}),
        StartStatus::Restored(n) => json!({"kind": "restored", "modules": n}),
        StartStatus::Stale => json!({"kind": "stale"}),
        StartStatus::DenyAll => json!({"kind": "deny_all"}),
    }
}

impl Driver {
    fn new() -> Result<Self, String> {
        let cfg = tempfile::TempDir::new().map_err(|e| e.to_string())?;
        let state = tempfile::TempDir::new().map_err(|e| e.to_string())?;
        let telemetry = Arc::new(Telemetry::new("warn").map_err(|e| e.to_string())?);
        let events: Arc<dyn EventSink> = Arc::new(EventBroker::new(16));
        let factory = Arc::new(DaemonHostFactory::new(
            telemetry,
            Arc::new(ConfigStore::new(cfg.path())),
            Arc::new(NoSecretsProvider),
            Arc::new(LocalFlags),
            events,
            state.path().to_path_buf(),
        ));
        Ok(Self {
            factory,
            signer: None,
            agents: HashMap::new(),
            _dirs: vec![cfg, state],
        })
    }

    /// `sign`: writes demo.wasm, manifest.json (signed) and pubkey.txt to `out`.
    fn sign(&mut self, req: &Value) -> Result<Value, String> {
        let out = PathBuf::from(s(req, "out")?);
        let id = s(req, "id")?;
        let version = s(req, "version")?;
        if self.signer.is_none() {
            let kp =
                minisign::KeyPair::generate_unencrypted_keypair().map_err(|e| e.to_string())?;
            self.signer = Some(Signer { kp });
        }
        let signer = self.signer.as_ref().ok_or("signer missing")?;
        let wasm = demo_wasm()?;
        let sha = hex(&Sha256::digest(&wasm));
        let payload = signed_payload(id, version, &sha).map_err(|e| e.to_string())?;
        let sig = minisign::sign(
            Some(&signer.kp.pk),
            &signer.kp.sk,
            Cursor::new(payload),
            Some("penguind hub e2e"),
            None,
        )
        .map_err(|e| e.to_string())?
        .to_string();
        let pubkey = signer
            .kp
            .pk
            .to_box()
            .map_err(|e| e.to_string())?
            .to_string();
        std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
        let wasm_path = out.join("demo.wasm");
        let manifest_path = out.join("manifest.json");
        let pubkey_path = out.join("pubkey.txt");
        std::fs::write(&wasm_path, &wasm).map_err(|e| e.to_string())?;
        let manifest = json!({"id": id, "version": version, "sha256": sha, "signature": sig});
        std::fs::write(&manifest_path, manifest.to_string()).map_err(|e| e.to_string())?;
        std::fs::write(&pubkey_path, &pubkey).map_err(|e| e.to_string())?;
        Ok(json!({
            "wasm": wasm_path, "manifest": manifest_path, "pubkey": pubkey_path, "sha256": sha,
        }))
    }

    /// Builds (or rebuilds after a restart) the hub client for agent `name`.
    fn build(
        &self,
        spec: &Value,
        sink: Arc<RecordingSink>,
        secrets: Arc<MemSecrets>,
    ) -> Result<HubClient, String> {
        let signer = self.signer.as_ref().ok_or("sign first")?;
        let pubkey = signer
            .kp
            .pk
            .to_box()
            .map_err(|e| e.to_string())?
            .to_string();
        let policy = NetworkPolicy::new(strs(spec, "allow_hosts"), strs(spec, "allow_cidrs"))?
            .with_loopback(true);
        let ca = std::fs::read(s(spec, "ca")?).map_err(|e| format!("ca: {e}"))?;
        let fetcher = HubFetcher::new(policy, vec![pubkey]).with_extra_root_pem(ca);
        let mut ceiling = LocalCeiling::with_grants(["logger".to_string()], Vec::<String>::new());
        ceiling.fuel = CEILING_FUEL;
        ceiling.max_memory_bytes =
            usize::try_from(CEILING_MEMORY_MB * 1024 * 1024).map_err(|e| e.to_string())?;
        ceiling.max_tool_calls = CEILING_TOOL_CALLS;
        let mut cfg = HubClientConfig::new(s(spec, "hub_url")?, 1, "0.1.0-e2e", ceiling)
            .map_err(|e| e.to_string())?;
        cfg.bootstrap_token = spec
            .get("bootstrap")
            .and_then(Value::as_str)
            .map(str::to_string);
        let license = Arc::new(ClampedLicense::new(Arc::new(LocalFlags)));
        let metrics =
            HubMetrics::register(&prometheus::Registry::new()).map_err(|e| e.to_string())?;
        let secrets_dyn: Arc<dyn SecretStore> = secrets;
        Ok(HubClient::new(
            cfg,
            fetcher,
            CredentialStore::new(secrets_dyn),
            HubCache::new(s(spec, "cache")?),
            sink,
            license,
            metrics,
        ))
    }

    fn agent(&mut self, req: &Value) -> Result<Value, String> {
        let name = s(req, "name")?.to_string();
        let sink = Arc::new(RecordingSink {
            factory: self.factory.clone(),
            events: Mutex::new(Vec::new()),
            loaded: Mutex::new(HashSet::new()),
        });
        let secrets = Arc::new(MemSecrets::default());
        let client = self.build(req, sink.clone(), secrets.clone())?;
        self.agents.insert(
            name,
            Agent {
                client: Some(client),
                sink,
                secrets,
                spec: req.clone(),
            },
        );
        Ok(json!({}))
    }

    /// `restart`: drops the client (process restart) and rebuilds it over the
    /// same cache dir and credential store, with no bootstrap token.
    fn restart(&mut self, req: &Value) -> Result<Value, String> {
        let name = s(req, "name")?;
        let (mut spec, secrets) = {
            let a = self.agents.get_mut(name).ok_or("unknown agent")?;
            a.client = None;
            (a.spec.clone(), a.secrets.clone())
        };
        if let Some(o) = spec.as_object_mut() {
            o.remove("bootstrap");
        }
        let sink = Arc::new(RecordingSink {
            factory: self.factory.clone(),
            events: Mutex::new(Vec::new()),
            loaded: Mutex::new(HashSet::new()),
        });
        let client = self.build(&spec, sink.clone(), secrets)?;
        let a = self.agents.get_mut(name).ok_or("unknown agent")?;
        a.client = Some(client);
        a.sink = sink;
        Ok(json!({}))
    }

    async fn report(&self, name: &str, extra: Value) -> Result<Value, String> {
        let a = self.agents.get(name).ok_or("unknown agent")?;
        let client = a.client.as_ref().ok_or("agent not running")?;
        let snap = client.snapshot().await;
        Ok(json!({
            "result": extra,
            "applied": snap.applied,
            "etag": snap.etag,
            "revoked": snap.revoked,
            "stale": snap.stale,
            "loaded": a.sink.loaded(),
            "events": a.sink.take(),
        }))
    }

    async fn handle(&mut self, req: &Value) -> Result<Value, String> {
        match s(req, "cmd")? {
            "sign" => self.sign(req),
            "agent" => self.agent(req),
            "restart" => self.restart(req),
            "start" => {
                let name = s(req, "name")?;
                let a = self.agents.get(name).ok_or("unknown agent")?;
                let st = a.client.as_ref().ok_or("agent not running")?.start().await;
                self.report(name, start_json(st)).await
            }
            "sync" => {
                let name = s(req, "name")?;
                let a = self.agents.get(name).ok_or("unknown agent")?;
                let o = a
                    .client
                    .as_ref()
                    .ok_or("agent not running")?
                    .sync_once()
                    .await;
                self.report(name, outcome_json(o)).await
            }
            "tamper_cache" => {
                let name = s(req, "name")?;
                let a = self.agents.get(name).ok_or("unknown agent")?;
                let dir = Path::new(s(&a.spec, "cache")?).join("hub-blobs");
                let mut n = 0u64;
                for e in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
                    let p = e.map_err(|e| e.to_string())?.path();
                    let mut b = std::fs::read(&p).map_err(|e| e.to_string())?;
                    if let Some(last) = b.last_mut() {
                        *last ^= 0xff;
                    }
                    std::fs::write(&p, b).map_err(|e| e.to_string())?;
                    n += 1;
                }
                Ok(json!({"tampered": n}))
            }
            other => Err(format!("unknown cmd `{other}`")),
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    let mut driver = match Driver::new() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("hub_e2e_agent: setup failed: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(req) => match driver.handle(&req).await {
                Ok(v) => json!({"ok": true, "data": v}),
                Err(e) => json!({"ok": false, "error": e}),
            },
            Err(e) => json!({"ok": false, "error": format!("bad json: {e}")}),
        };
        if writeln!(out, "{reply}").and_then(|()| out.flush()).is_err() {
            return std::process::ExitCode::FAILURE;
        }
    }
    std::process::ExitCode::SUCCESS
}
