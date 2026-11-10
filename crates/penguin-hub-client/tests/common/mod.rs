//! Test harness: a TLS mock hub built from the `/api/v1/agent/*` shapes in
//! `services/hub-api/openapi/v1.yaml`, plus signing, secret-store and sink doubles.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Cursor;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use penguin_hub_client::model::ManifestWire;
use penguin_hub_client::{
    ClampedLicense, CredentialStore, DesiredModule, HubCache, HubClient, HubClientConfig,
    HubMetrics, LocalCeiling, ModuleLoadError, ModuleSink,
};
use penguin_sdk::{LicenseChecker, SecretError, SecretStore};
use penguin_wasm_host::distribution::{HubFetcher, NetworkPolicy, signed_payload};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// One recorded request.
#[derive(Debug, Clone)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Mutable behaviour of the mock hub.
pub struct Knobs {
    pub bootstrap: String,
    pub bootstrap_used: bool,
    pub access: String,
    pub refresh: String,
    pub old_refreshes: Vec<String>,
    pub epoch: u32,
    pub bundle: Value,
    pub etag: String,
    pub sync_override: Option<(u16, Vec<(String, String)>)>,
    pub revoked: bool,
    pub status_code: u16,
    pub binaries: HashMap<String, Vec<u8>>,
    pub redirect_binaries: bool,
    pub garbage_sync: bool,
    pub reqs: Vec<Req>,
}

pub struct MockHub {
    pub knobs: Arc<Mutex<Knobs>>,
    pub base_url: String,
    pub root_pem: Vec<u8>,
    pub port: u16,
}

fn envelope(status: &str, data: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "status": status,
        "data": data,
        "meta": {"version": 1, "timestamp": "2026-11-10T00:00:00Z", "trace_id": "t"}
    }))
    .expect("json")
}

fn problem(code: i64, title: &str) -> Vec<u8> {
    envelope(
        "error",
        json!({"type":"about:blank","title":title,"status":0,"code":code}),
    )
}

impl MockHub {
    pub async fn start() -> MockHub {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).expect("cert");
        let root_pem = cert.cert.pem().into_bytes();
        let key = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der())
            .expect("key");
        let chain = vec![cert.cert.der().clone()];
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("server cfg");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let knobs = Arc::new(Mutex::new(Knobs {
            bootstrap: "boot-secret".into(),
            bootstrap_used: false,
            access: String::new(),
            refresh: String::new(),
            old_refreshes: vec![],
            epoch: 0,
            bundle: json!({}),
            etag: "\"etag-1\"".into(),
            sync_override: None,
            revoked: false,
            status_code: 204,
            binaries: HashMap::new(),
            redirect_binaries: false,
            garbage_sync: false,
            reqs: vec![],
        }));
        let k2 = knobs.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let k = k2.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Some(req) = read_request(&mut tls).await else {
                        return;
                    };
                    let (status, headers, body) = route(&k, req);
                    let mut head = format!("HTTP/1.1 {status} X\r\n");
                    for (n, v) in headers {
                        head.push_str(&format!("{n}: {v}\r\n"));
                    }
                    head.push_str(&format!(
                        "Content-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    ));
                    let _ = tls.write_all(head.as_bytes()).await;
                    let _ = tls.write_all(&body).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        MockHub {
            knobs,
            base_url: format!("https://127.0.0.1:{port}/"),
            root_pem,
            port,
        }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut Knobs) -> R) -> R {
        f(&mut self.knobs.lock().expect("lock"))
    }

    pub fn requests(&self, method: &str, path_prefix: &str) -> Vec<Req> {
        self.with(|k| {
            k.reqs
                .iter()
                .filter(|r| r.method == method && r.path.starts_with(path_prefix))
                .cloned()
                .collect()
        })
    }

    /// Registers a module binary and returns its manifest pointing at this hub.
    pub fn publish(&self, signer: &Signer, id: &str, version: &str, wasm: &[u8]) -> ManifestWire {
        let m = signer.manifest(id, version, wasm, &self.base_url);
        self.with(|k| {
            k.binaries.insert(id.to_string(), wasm.to_vec());
        });
        m
    }

    pub fn set_bundle(&self, modules: &[ManifestWire], policy: Value, flags: Value, etag: &str) {
        self.with(|k| {
            k.bundle = json!({
                "agent_id": "11111111-1111-1111-1111-111111111111",
                "generated_at": "2026-11-10T00:00:00Z",
                "policy": policy,
                "flags": flags,
                "modules": modules,
                "poll_interval_s": 300,
                "max_stale_s": 3600,
            });
            k.etag = etag.to_string();
        });
    }
}

async fn read_request<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Option<Req> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_string();
    let path = first.next()?.to_string();
    let mut headers = HashMap::new();
    for l in lines {
        if let Some((n, v)) = l.split_once(':') {
            headers.insert(n.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let want: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < want {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some(Req {
        method,
        path,
        headers,
        body,
    })
}

type Resp = (u16, Vec<(String, String)>, Vec<u8>);

fn json_hdr() -> Vec<(String, String)> {
    vec![("Content-Type".into(), "application/json".into())]
}

fn bearer(req: &Req) -> String {
    req.headers
        .get("authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string()
}

fn issue(k: &mut Knobs) -> Value {
    k.epoch += 1;
    k.access = format!("access-{}", k.epoch);
    k.refresh = format!("refresh-{}", k.epoch);
    json!({
        "agent_id": "11111111-1111-1111-1111-111111111111",
        "access_token": k.access,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": k.refresh,
    })
}

fn route(knobs: &Arc<Mutex<Knobs>>, req: Req) -> Resp {
    let mut k = knobs.lock().expect("lock");
    k.reqs.push(req.clone());
    let unauthorized = || (401, json_hdr(), problem(1001, "unauthorized"));
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/api/v1/agent/enroll") => {
            if bearer(&req) != k.bootstrap || k.bootstrap_used {
                return unauthorized();
            }
            k.bootstrap_used = true;
            let t = issue(&mut k);
            (201, json_hdr(), envelope("success", t))
        }
        ("POST", "/api/v1/agent/token") => {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let presented = body["refresh_token"].as_str().unwrap_or("").to_string();
            if k.old_refreshes.contains(&presented) {
                k.access.clear(); // reuse => whole chain revoked
                k.refresh.clear();
                return unauthorized();
            }
            if presented != k.refresh || presented.is_empty() {
                return unauthorized();
            }
            let old = k.refresh.clone();
            k.old_refreshes.push(old);
            let t = issue(&mut k);
            (200, json_hdr(), envelope("success", t))
        }
        ("GET", "/api/v1/agent/sync") => {
            if bearer(&req) != k.access || k.access.is_empty() {
                return unauthorized();
            }
            if k.revoked {
                return (410, json_hdr(), problem(1010, "agent revoked"));
            }
            if let Some((status, hdrs)) = k.sync_override.clone() {
                return (status, hdrs, problem(1020, "override"));
            }
            if k.garbage_sync {
                return (200, json_hdr(), b"not json".to_vec());
            }
            if req.headers.get("if-none-match") == Some(&k.etag) {
                return (304, vec![("ETag".into(), k.etag.clone())], vec![]);
            }
            let mut h = json_hdr();
            h.push(("ETag".into(), k.etag.clone()));
            (200, h, envelope("success", k.bundle.clone()))
        }
        ("POST", "/api/v1/agent/status") => {
            if bearer(&req) != k.access {
                return unauthorized();
            }
            let code = k.status_code;
            (code, vec![], vec![])
        }
        ("GET", p) if p.starts_with("/api/v1/agent/modules/") => {
            if bearer(&req) != k.access {
                return unauthorized();
            }
            let id = p
                .trim_start_matches("/api/v1/agent/modules/")
                .trim_end_matches("/binary")
                .to_string();
            if k.redirect_binaries {
                return (
                    302,
                    vec![("Location".into(), format!("/blob/{id}"))],
                    vec![],
                );
            }
            match k.binaries.get(&id) {
                Some(b) => (
                    200,
                    vec![("Content-Type".into(), "application/wasm".into())],
                    b.clone(),
                ),
                None => (404, json_hdr(), problem(1404, "not found")),
            }
        }
        ("GET", p) if p.starts_with("/blob/") => {
            let id = p.trim_start_matches("/blob/");
            match k.binaries.get(id) {
                Some(b) => (200, vec![], b.clone()),
                None => (404, vec![], vec![]),
            }
        }
        _ => (404, json_hdr(), problem(1404, "not found")),
    }
}

/// Minisign signer for the "offline signer" role.
pub struct Signer {
    kp: minisign::KeyPair,
}

impl Signer {
    pub fn new() -> Self {
        Self {
            kp: minisign::KeyPair::generate_unencrypted_keypair().expect("keypair"),
        }
    }

    pub fn public_key(&self) -> String {
        self.kp.pk.to_box().expect("box").to_string()
    }

    pub fn manifest(&self, id: &str, version: &str, wasm: &[u8], base: &str) -> ManifestWire {
        let sha = hex(&Sha256::digest(wasm));
        let payload = signed_payload(id, version, &sha).expect("payload");
        let sig = minisign::sign(
            Some(&self.kp.pk),
            &self.kp.sk,
            Cursor::new(payload),
            None,
            None,
        )
        .expect("sign")
        .to_string();
        ManifestWire {
            id: id.into(),
            version: version.into(),
            sha256: sha,
            signature: sig,
            binary_url: format!("{base}api/v1/agent/modules/{id}/binary"),
        }
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// In-memory `SecretStore`.
#[derive(Default)]
pub struct MemSecrets {
    pub map: Mutex<HashMap<String, Vec<u8>>>,
    pub fail: Mutex<bool>,
}

#[async_trait]
impl SecretStore for MemSecrets {
    async fn get(&self, k: &str) -> Result<Vec<u8>, SecretError> {
        if *self.fail.lock().expect("lock") {
            return Err(SecretError::Other("down".into()));
        }
        self.map
            .lock()
            .expect("lock")
            .get(k)
            .cloned()
            .ok_or(SecretError::NotFound)
    }
    async fn set(&self, k: &str, v: &[u8]) -> Result<(), SecretError> {
        self.map.lock().expect("lock").insert(k.into(), v.to_vec());
        Ok(())
    }
    async fn delete(&self, k: &str) -> Result<(), SecretError> {
        self.map
            .lock()
            .expect("lock")
            .remove(k)
            .map(|_| ())
            .ok_or(SecretError::NotFound)
    }
}

/// Recording `ModuleSink`.
#[derive(Default)]
pub struct RecSink {
    pub loaded: Mutex<Vec<(String, String, penguin_wasm_host::ModuleLimits)>>,
    pub unloaded: Mutex<Vec<String>>,
    pub fail: Mutex<BTreeSet<String>>,
}

#[async_trait]
impl ModuleSink for RecSink {
    async fn load(&self, m: DesiredModule) -> Result<(), ModuleLoadError> {
        if self.fail.lock().expect("lock").contains(&m.id) {
            return Err(ModuleLoadError {
                code: 4,
                reason: "refused".into(),
            });
        }
        self.loaded
            .lock()
            .expect("lock")
            .push((m.id, m.version, m.limits));
        Ok(())
    }
    async fn unload(&self, id: &str) {
        self.unloaded.lock().expect("lock").push(id.to_string());
    }
}

/// Licence that enables a fixed set of flags.
pub struct Lic(pub BTreeSet<String>);
impl LicenseChecker for Lic {
    fn feature_enabled(&self, k: &str) -> bool {
        self.0.contains(k)
    }
    fn tier(&self) -> String {
        "pro".into()
    }
}

/// Everything a test needs around one client.
pub struct Env {
    pub hub: MockHub,
    pub signer: Signer,
    pub dir: tempfile::TempDir,
    pub secrets: Arc<MemSecrets>,
    pub sink: Arc<RecSink>,
    pub license: Arc<ClampedLicense>,
    pub registry: prometheus::Registry,
    pub clock: Arc<AtomicI64>,
    pub client: Arc<HubClient>,
}

pub fn ceiling() -> LocalCeiling {
    LocalCeiling::with_grants(
        ["logger".to_string(), "doh_query".to_string()],
        [
            "api.example.com".to_string(),
            "*.svc.example.org".to_string(),
        ],
    )
}

pub const WASM: &[u8] = b"\0asm\x01\0\0\0";

impl Env {
    pub async fn new() -> Env {
        Self::build(None, true, None).await
    }

    /// Builds a client; `reuse` supplies an existing hub/dir/secrets (restart simulation).
    pub async fn build(
        reuse: Option<(MockHub, tempfile::TempDir, Arc<MemSecrets>, Signer)>,
        loopback: bool,
        bootstrap: Option<&str>,
    ) -> Env {
        let (hub, dir, secrets, signer) = match reuse {
            Some(r) => r,
            None => (
                MockHub::start().await,
                tempfile::tempdir().expect("tmp"),
                Arc::new(MemSecrets::default()),
                Signer::new(),
            ),
        };
        let boot = bootstrap.unwrap_or("boot-secret");
        let mut cfg = HubClientConfig::new(&hub.base_url, 1, "0.2.0", ceiling()).expect("cfg");
        cfg.bootstrap_token = Some(boot.to_string());
        let policy = NetworkPolicy::default().with_loopback(loopback);
        let fetcher = HubFetcher::new(policy, vec![signer.public_key()])
            .with_extra_root_pem(hub.root_pem.clone());
        let sink = Arc::new(RecSink::default());
        let license = Arc::new(ClampedLicense::new(Arc::new(Lic(["f.a", "f.b"]
            .iter()
            .map(|s| s.to_string())
            .collect()))));
        let registry = prometheus::Registry::new();
        let metrics = HubMetrics::register(&registry).expect("metrics");
        let clock = Arc::new(AtomicI64::new(1_800_000_000));
        let c2 = clock.clone();
        let client = Arc::new(
            HubClient::new(
                cfg,
                fetcher,
                CredentialStore::new(secrets.clone()),
                HubCache::new(dir.path().join("cache")),
                sink.clone(),
                license.clone(),
                metrics,
            )
            .with_clock(Arc::new(move || c2.load(Ordering::SeqCst))),
        );
        Env {
            hub,
            signer,
            dir,
            secrets,
            sink,
            license,
            registry,
            clock,
            client,
        }
    }

    /// Rebuilds a fresh client over the same hub, cache dir and secrets (a restart).
    pub async fn restart(self, loopback: bool) -> Env {
        let Env {
            hub,
            dir,
            secrets,
            signer,
            ..
        } = self;
        Env::build(Some((hub, dir, secrets, signer)), loopback, None).await
    }

    pub fn advance(&self, secs: i64) {
        self.clock.fetch_add(secs, Ordering::SeqCst);
    }

    pub fn cache_dir(&self) -> std::path::PathBuf {
        self.dir.path().join("cache")
    }

    pub fn counter(&self, name: &str, label: &str) -> f64 {
        for f in self.registry.gather() {
            if f.name() == name {
                for m in f.get_metric() {
                    if m.get_label().iter().any(|l| l.value() == label) {
                        return m.get_counter().value();
                    }
                }
            }
        }
        0.0
    }
}

pub fn flags(v: &[(&str, bool)]) -> Value {
    let m: BTreeMap<_, _> = v.iter().map(|(k, b)| (k.to_string(), *b)).collect();
    json!(m)
}
