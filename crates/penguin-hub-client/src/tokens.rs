//! Where the hub agent's tokens live, chosen by run mode.
//!
//! desktop/server → OS keychain; daemonset → a mounted Kubernetes Secret
//! (written back through the K8s API only when the pod's service account may).
//! The encrypted-file store is the fallback for any mode, used only when the
//! preferred store is unavailable — announced with a WARN and the
//! `penguind_hub_token_store_active{store}` gauge. Never a plaintext file.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use penguin_sdk::{SecretError, SecretStore};

use crate::creds::Credentials;
use crate::error::HubError;

/// Env var naming the mounted Secret file (daemonset mode).
pub const TOKEN_FILE_ENV: &str = "PENGUIND_HUB_TOKEN_FILE";

/// Secret-store key holding the serialised [`Credentials`].
const KEY: &str = "hub-credentials";

/// How penguind is deployed; selects the preferred token store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    /// Interactive desktop session.
    Desktop,
    /// Kubernetes DaemonSet pod.
    Daemonset,
    /// Headless server install.
    Server,
}

impl RunMode {
    /// Parses `desktop` / `daemonset` / `server` (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "desktop" => Some(Self::Desktop),
            "daemonset" => Some(Self::Daemonset),
            "server" => Some(Self::Server),
            _ => None,
        }
    }
}

/// Which backend actually holds the tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenStoreKind {
    /// OS keychain / Credential Manager / Secret Service.
    Keychain,
    /// A mounted Kubernetes Secret.
    KubernetesSecret,
    /// The encrypted-file secret store (fallback).
    EncryptedFile,
}

impl TokenStoreKind {
    /// Metric/log label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Keychain => "keychain",
            Self::KubernetesSecret => "k8s-secret",
            Self::EncryptedFile => "encrypted-file",
        }
    }

    /// Every kind, for zeroing the gauge.
    pub const ALL: [TokenStoreKind; 3] =
        [Self::Keychain, Self::KubernetesSecret, Self::EncryptedFile];
}

/// Loads, saves and clears the agent [`Credentials`].
#[async_trait]
pub trait TokenStore: Send + Sync {
    /// Which backend this is.
    fn kind(&self) -> TokenStoreKind;
    /// The stored credentials; `None` when never enrolled or cleared.
    async fn load(&self) -> Result<Option<Credentials>, HubError>;
    /// Persists rotated credentials.
    async fn save(&self, creds: &Credentials) -> Result<(), HubError>;
    /// Removes the credentials; clearing an absent record is fine.
    async fn clear(&self) -> Result<(), HubError>;
}

fn secret_err(e: impl fmt::Display) -> HubError {
    HubError::Secrets(e.to_string())
}

/// [`TokenStore`] over a [`SecretStore`] (keychain or encrypted file).
pub struct SecretTokenStore {
    store: Arc<dyn SecretStore>,
    kind: TokenStoreKind,
}

impl SecretTokenStore {
    /// Wraps `store`, labelled as `kind`.
    pub fn new(store: Arc<dyn SecretStore>, kind: TokenStoreKind) -> Self {
        Self { store, kind }
    }
}

#[async_trait]
impl TokenStore for SecretTokenStore {
    fn kind(&self) -> TokenStoreKind {
        self.kind
    }

    /// An unparsable record is treated as absent so the agent re-enrolls.
    async fn load(&self) -> Result<Option<Credentials>, HubError> {
        match self.store.get(KEY).await {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
            Err(SecretError::NotFound) => Ok(None),
            Err(e) => Err(secret_err(e)),
        }
    }

    async fn save(&self, creds: &Credentials) -> Result<(), HubError> {
        let bytes = serde_json::to_vec(creds).map_err(secret_err)?;
        self.store.set(KEY, &bytes).await.map_err(secret_err)
    }

    async fn clear(&self) -> Result<(), HubError> {
        match self.store.delete(KEY).await {
            Ok(()) | Err(SecretError::NotFound) => Ok(()),
            Err(e) => Err(secret_err(e)),
        }
    }
}

/// Writes the token Secret through the Kubernetes API. Supplied only when the
/// pod's service account is allowed to update its own Secret.
#[async_trait]
pub trait K8sSecretWriter: Send + Sync {
    /// Replaces the Secret's token payload.
    async fn write(&self, bytes: &[u8]) -> Result<(), HubError>;
    /// Empties the Secret's token payload.
    async fn delete(&self) -> Result<(), HubError>;
}

/// [`TokenStore`] reading a projected Secret file (mode 0400). Writes go only
/// through `writer`; without one, a rotated token is kept in memory and the
/// agent re-bootstraps after a restart. Never writes the mount itself.
pub struct K8sSecretTokenStore {
    path: PathBuf,
    writer: Option<Arc<dyn K8sSecretWriter>>,
}

impl K8sSecretTokenStore {
    /// Opens the mounted file at `path`; `None` when it is absent (store
    /// unavailable, so the caller falls back).
    pub fn open(path: &Path, writer: Option<Arc<dyn K8sSecretWriter>>) -> Option<Self> {
        std::fs::metadata(path)
            .ok()
            .filter(std::fs::Metadata::is_file)
            .map(|_| Self {
                path: path.to_path_buf(),
                writer,
            })
    }
}

#[cfg(unix)]
fn check_mode(meta: &std::fs::Metadata) -> Result<(), HubError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(HubError::Secrets(format!(
            "token secret file mode {mode:o} is group/world accessible; expected 0400"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_mode(_meta: &std::fs::Metadata) -> Result<(), HubError> {
    Ok(())
}

#[async_trait]
impl TokenStore for K8sSecretTokenStore {
    fn kind(&self) -> TokenStoreKind {
        TokenStoreKind::KubernetesSecret
    }

    /// Reads the mounted Secret; a group/world-readable file is refused.
    async fn load(&self) -> Result<Option<Credentials>, HubError> {
        let meta = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(secret_err(e)),
        };
        check_mode(&meta)?;
        let raw = std::fs::read(&self.path).map_err(secret_err)?;
        if raw.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        Ok(serde_json::from_slice(&raw).ok())
    }

    async fn save(&self, creds: &Credentials) -> Result<(), HubError> {
        let Some(w) = &self.writer else {
            return Err(HubError::Secrets(
                "k8s token secret is read-only for this service account; re-bootstrap after restart"
                    .into(),
            ));
        };
        let bytes = serde_json::to_vec(creds).map_err(secret_err)?;
        w.write(&bytes).await
    }

    async fn clear(&self) -> Result<(), HubError> {
        match &self.writer {
            Some(w) => w.delete().await,
            None => {
                tracing::warn!("k8s token secret is read-only; cannot clear it from the pod");
                Ok(())
            }
        }
    }
}

/// The stores available on this host; `None` means unavailable.
pub struct TokenStoreCandidates {
    /// OS keychain, if reachable.
    pub keychain: Option<Arc<dyn SecretStore>>,
    /// Mounted Kubernetes Secret, if present.
    pub k8s_secret: Option<K8sSecretTokenStore>,
    /// Encrypted-file store (always available).
    pub encrypted_file: Arc<dyn SecretStore>,
}

/// The chosen store and whether it is the fallback.
pub struct SelectedTokenStore {
    /// The store to use.
    pub store: Arc<dyn TokenStore>,
    /// True when the preferred store for the mode was unavailable.
    pub fell_back: bool,
}

/// The active store plus every other candidate. Loads migrate legacy
/// encrypted-file credentials into a preferred store (then delete the file
/// copy); clears wipe every candidate, not just the active one.
pub struct CompositeTokenStore {
    active: Arc<dyn TokenStore>,
    /// The encrypted-file store when it is NOT the active one (migration source).
    legacy: Option<Arc<dyn TokenStore>>,
    /// Every non-active candidate, wiped on clear.
    others: Vec<Arc<dyn TokenStore>>,
}

impl CompositeTokenStore {
    /// Moves encrypted-file credentials into the active store, then deletes
    /// the file copy. If the active store cannot accept them (e.g. read-only
    /// Secret), the file copy is kept as the only copy and returned.
    async fn migrate(&self, legacy: &Arc<dyn TokenStore>) -> Result<Option<Credentials>, HubError> {
        let Some(old) = legacy.load().await? else {
            return Ok(None);
        };
        if let Err(e) = self.active.save(&old).await {
            tracing::warn!(
                error = %e,
                store = self.active.kind().label(),
                "could not migrate encrypted-file hub credentials; keeping file copy"
            );
            return Ok(Some(old));
        }
        legacy.clear().await?;
        tracing::info!(
            store = self.active.kind().label(),
            "migrated hub credentials out of the encrypted file"
        );
        Ok(Some(old))
    }
}

#[async_trait]
impl TokenStore for CompositeTokenStore {
    fn kind(&self) -> TokenStoreKind {
        self.active.kind()
    }

    /// Active store first; a stale encrypted-file copy is deleted when the
    /// active store already holds credentials, migrated otherwise.
    async fn load(&self) -> Result<Option<Credentials>, HubError> {
        let current = self.active.load().await?;
        let Some(legacy) = &self.legacy else {
            return Ok(current);
        };
        match current {
            Some(c) => {
                legacy.clear().await?;
                Ok(Some(c))
            }
            None => self.migrate(legacy).await,
        }
    }

    async fn save(&self, creds: &Credentials) -> Result<(), HubError> {
        self.active.save(creds).await
    }

    /// Wipes the active store and every other candidate; every store is
    /// attempted, the first error is returned.
    async fn clear(&self) -> Result<(), HubError> {
        let mut first: Option<HubError> = None;
        for s in std::iter::once(&self.active).chain(self.others.iter()) {
            if let Err(e) = s.clear().await {
                tracing::warn!(error = %e, store = s.kind().label(), "could not wipe hub credentials");
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(()), Err)
    }
}

/// Picks the token store for `mode`: desktop → keychain, daemonset → K8s
/// Secret, server → encrypted file. WARNs when a preferred store is missing.
pub fn select_token_store(mode: RunMode, c: TokenStoreCandidates) -> SelectedTokenStore {
    let keychain: Option<Arc<dyn TokenStore>> = c
        .keychain
        .map(|k| Arc::new(SecretTokenStore::new(k, TokenStoreKind::Keychain)) as _);
    let k8s: Option<Arc<dyn TokenStore>> = c.k8s_secret.map(|k| Arc::new(k) as _);
    let file: Arc<dyn TokenStore> = Arc::new(SecretTokenStore::new(
        c.encrypted_file,
        TokenStoreKind::EncryptedFile,
    ));
    let preferred = match mode {
        RunMode::Desktop => keychain.clone(),
        RunMode::Daemonset => k8s.clone(),
        RunMode::Server => None,
    };
    let fell_back = preferred.is_none() && mode != RunMode::Server;
    let active = preferred.unwrap_or_else(|| file.clone());
    if fell_back {
        tracing::warn!(
            ?mode,
            store = TokenStoreKind::EncryptedFile.label(),
            "preferred hub token store unavailable; using encrypted-file fallback"
        );
    } else {
        tracing::info!(
            store = active.kind().label(),
            ?mode,
            "hub token store selected"
        );
    }
    let is_file = active.kind() == TokenStoreKind::EncryptedFile;
    let others: Vec<Arc<dyn TokenStore>> = [keychain, k8s, Some(file.clone())]
        .into_iter()
        .flatten()
        .filter(|s| s.kind() != active.kind())
        .collect();
    SelectedTokenStore {
        store: Arc::new(CompositeTokenStore {
            active,
            legacy: (!is_file).then_some(file),
            others,
        }),
        fell_back,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct Mem(Mutex<HashMap<String, Vec<u8>>>);

    #[async_trait]
    impl SecretStore for Mem {
        async fn get(&self, k: &str) -> Result<Vec<u8>, SecretError> {
            let g = self
                .0
                .lock()
                .map_err(|e| SecretError::Other(e.to_string()))?;
            g.get(k).cloned().ok_or(SecretError::NotFound)
        }
        async fn set(&self, k: &str, v: &[u8]) -> Result<(), SecretError> {
            let mut g = self
                .0
                .lock()
                .map_err(|e| SecretError::Other(e.to_string()))?;
            g.insert(k.into(), v.to_vec());
            Ok(())
        }
        async fn delete(&self, k: &str) -> Result<(), SecretError> {
            let mut g = self
                .0
                .lock()
                .map_err(|e| SecretError::Other(e.to_string()))?;
            g.remove(k).map(|_| ()).ok_or(SecretError::NotFound)
        }
    }

    struct Broken;

    #[async_trait]
    impl SecretStore for Broken {
        async fn get(&self, _: &str) -> Result<Vec<u8>, SecretError> {
            Err(SecretError::Other("locked".into()))
        }
        async fn set(&self, _: &str, _: &[u8]) -> Result<(), SecretError> {
            Err(SecretError::Other("locked".into()))
        }
        async fn delete(&self, _: &str) -> Result<(), SecretError> {
            Err(SecretError::Other("locked".into()))
        }
    }

    #[derive(Default)]
    struct Writer(Mutex<Option<Vec<u8>>>);

    #[async_trait]
    impl K8sSecretWriter for Writer {
        async fn write(&self, bytes: &[u8]) -> Result<(), HubError> {
            *self.0.lock().map_err(secret_err)? = Some(bytes.to_vec());
            Ok(())
        }
        async fn delete(&self) -> Result<(), HubError> {
            *self.0.lock().map_err(secret_err)? = None;
            Ok(())
        }
    }

    fn creds() -> Credentials {
        Credentials {
            agent_id: "a".into(),
            access_token: "acc".into(),
            access_expires_at: 5,
            refresh_token: "ref".into(),
        }
    }

    fn secret_file(dir: &Path, body: &[u8], mode: u32) -> PathBuf {
        let p = dir.join("token");
        std::fs::write(&p, body).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).expect("chmod");
        }
        #[cfg(not(unix))]
        let _ = mode;
        p
    }

    fn cands(keychain: bool, k8s: Option<K8sSecretTokenStore>) -> TokenStoreCandidates {
        TokenStoreCandidates {
            keychain: keychain.then(|| Arc::new(Mem::default()) as Arc<dyn SecretStore>),
            k8s_secret: k8s,
            encrypted_file: Arc::new(Mem::default()),
        }
    }

    fn k8s_store(dir: &Path) -> K8sSecretTokenStore {
        let p = secret_file(dir, b"", 0o400);
        K8sSecretTokenStore::open(&p, None).expect("open")
    }

    #[test]
    fn run_mode_parses() {
        assert_eq!(RunMode::parse("Desktop"), Some(RunMode::Desktop));
        assert_eq!(RunMode::parse(" daemonset "), Some(RunMode::Daemonset));
        assert_eq!(RunMode::parse("server"), Some(RunMode::Server));
        assert_eq!(RunMode::parse("other"), None);
    }

    #[test]
    fn labels_are_distinct() {
        let l: Vec<_> = TokenStoreKind::ALL.iter().map(|k| k.label()).collect();
        assert_eq!(l, ["keychain", "k8s-secret", "encrypted-file"]);
    }

    #[test]
    fn desktop_prefers_keychain_server_uses_file() {
        let s = select_token_store(RunMode::Desktop, cands(true, None));
        assert_eq!(s.store.kind(), TokenStoreKind::Keychain);
        assert!(!s.fell_back);
        let s = select_token_store(RunMode::Server, cands(true, None));
        assert_eq!(s.store.kind(), TokenStoreKind::EncryptedFile);
        assert!(!s.fell_back, "server is file by design, not a fallback");
    }

    #[test]
    fn daemonset_prefers_k8s_secret_over_keychain() {
        let dir = tempfile::tempdir().expect("tmp");
        let s = select_token_store(RunMode::Daemonset, cands(true, Some(k8s_store(dir.path()))));
        assert_eq!(s.store.kind(), TokenStoreKind::KubernetesSecret);
        assert!(!s.fell_back);
    }

    #[test]
    fn every_mode_falls_back_to_encrypted_file() {
        for mode in [RunMode::Desktop, RunMode::Daemonset] {
            let s = select_token_store(mode, cands(false, None));
            assert_eq!(s.store.kind(), TokenStoreKind::EncryptedFile);
            assert!(s.fell_back);
        }
    }

    #[tokio::test]
    async fn secret_store_round_trip_and_errors() {
        let s = SecretTokenStore::new(Arc::new(Mem::default()), TokenStoreKind::EncryptedFile);
        assert_eq!(s.load().await.expect("load"), None);
        s.save(&creds()).await.expect("save");
        assert_eq!(s.load().await.expect("load"), Some(creds()));
        s.clear().await.expect("clear");
        s.clear().await.expect("idempotent");
        let b = SecretTokenStore::new(Arc::new(Broken), TokenStoreKind::Keychain);
        assert!(b.load().await.is_err());
        assert!(b.save(&creds()).await.is_err());
        assert!(b.clear().await.is_err());
    }

    #[tokio::test]
    async fn k8s_secret_reads_mount_and_is_read_only_without_writer() {
        let dir = tempfile::tempdir().expect("tmp");
        let body = serde_json::to_vec(&creds()).expect("json");
        let p = secret_file(dir.path(), &body, 0o400);
        let s = K8sSecretTokenStore::open(&p, None).expect("open");
        assert_eq!(s.kind(), TokenStoreKind::KubernetesSecret);
        assert_eq!(s.load().await.expect("load"), Some(creds()));
        assert!(s.save(&creds()).await.is_err(), "no writer → re-bootstrap");
        s.clear().await.expect("clear is a logged no-op");
        // The mount itself is never written.
        assert_eq!(std::fs::read(&p).expect("read"), body);
        std::fs::remove_file(&p).expect("rm");
        assert_eq!(s.load().await.expect("gone"), None);
    }

    #[tokio::test]
    async fn k8s_secret_writes_through_api_writer() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = secret_file(dir.path(), b"\n", 0o400);
        let w = Arc::new(Writer::default());
        let s = K8sSecretTokenStore::open(&p, Some(w.clone())).expect("open");
        assert_eq!(s.load().await.expect("empty"), None);
        s.save(&creds()).await.expect("save");
        let written = w.0.lock().expect("lock").clone().expect("written");
        assert_eq!(
            serde_json::from_slice::<Credentials>(&written).ok(),
            Some(creds())
        );
        s.clear().await.expect("clear");
        assert!(w.0.lock().expect("lock").is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn k8s_secret_refuses_world_readable_mount() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = secret_file(dir.path(), b"{}", 0o644);
        let s = K8sSecretTokenStore::open(&p, None).expect("open");
        assert!(s.load().await.is_err());
    }

    #[test]
    fn k8s_secret_absent_is_unavailable() {
        let dir = tempfile::tempdir().expect("tmp");
        assert!(K8sSecretTokenStore::open(&dir.path().join("nope"), None).is_none());
        assert!(K8sSecretTokenStore::open(dir.path(), None).is_none());
    }

    fn shared() -> (Arc<Mem>, Arc<Mem>) {
        (Arc::new(Mem::default()), Arc::new(Mem::default()))
    }

    async fn put(m: &Arc<Mem>, c: &Credentials) {
        SecretTokenStore::new(m.clone(), TokenStoreKind::EncryptedFile)
            .save(c)
            .await
            .expect("seed");
    }

    fn empty(m: &Arc<Mem>) -> bool {
        m.0.lock().expect("lock").is_empty()
    }

    #[tokio::test]
    async fn file_credentials_migrate_into_keychain_and_file_copy_is_deleted() {
        let (kc, file) = shared();
        put(&file, &creds()).await;
        let s = select_token_store(
            RunMode::Desktop,
            TokenStoreCandidates {
                keychain: Some(kc.clone()),
                k8s_secret: None,
                encrypted_file: file.clone(),
            },
        );
        assert_eq!(s.store.load().await.expect("load"), Some(creds()));
        assert!(empty(&file), "file copy deleted after migration");
        assert!(!empty(&kc), "moved into keychain");
        assert_eq!(s.store.load().await.expect("again"), Some(creds()));
    }

    #[tokio::test]
    async fn stale_file_copy_is_deleted_when_keychain_already_has_creds() {
        let (kc, file) = shared();
        put(&kc, &creds()).await;
        let mut stale = creds();
        stale.refresh_token = "old".into();
        put(&file, &stale).await;
        let s = select_token_store(
            RunMode::Desktop,
            TokenStoreCandidates {
                keychain: Some(kc.clone()),
                k8s_secret: None,
                encrypted_file: file.clone(),
            },
        );
        assert_eq!(s.store.load().await.expect("load"), Some(creds()));
        assert!(empty(&file));
    }

    #[tokio::test]
    async fn migration_into_read_only_secret_keeps_file_copy() {
        let dir = tempfile::tempdir().expect("tmp");
        let file = Arc::new(Mem::default());
        put(&file, &creds()).await;
        let s = select_token_store(
            RunMode::Daemonset,
            TokenStoreCandidates {
                keychain: None,
                k8s_secret: Some(k8s_store(dir.path())),
                encrypted_file: file.clone(),
            },
        );
        assert_eq!(s.store.load().await.expect("load"), Some(creds()));
        assert!(!empty(&file), "only copy kept when the Secret is read-only");
    }

    #[tokio::test]
    async fn migration_into_writable_secret_deletes_file_copy() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = secret_file(dir.path(), b"", 0o400);
        let w = Arc::new(Writer::default());
        let file = Arc::new(Mem::default());
        put(&file, &creds()).await;
        let s = select_token_store(
            RunMode::Daemonset,
            TokenStoreCandidates {
                keychain: None,
                k8s_secret: K8sSecretTokenStore::open(&p, Some(w.clone())),
                encrypted_file: file.clone(),
            },
        );
        assert_eq!(s.store.load().await.expect("load"), Some(creds()));
        assert!(empty(&file));
        assert!(w.0.lock().expect("lock").is_some());
    }

    #[tokio::test]
    async fn clear_wipes_every_candidate_store() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = secret_file(dir.path(), b"", 0o400);
        let w = Arc::new(Writer::default());
        *w.0.lock().expect("lock") = Some(b"x".to_vec());
        for mode in [RunMode::Desktop, RunMode::Daemonset, RunMode::Server] {
            let (kc, file) = shared();
            put(&kc, &creds()).await;
            put(&file, &creds()).await;
            *w.0.lock().expect("lock") = Some(b"x".to_vec());
            let s = select_token_store(
                mode,
                TokenStoreCandidates {
                    keychain: Some(kc.clone()),
                    k8s_secret: K8sSecretTokenStore::open(&p, Some(w.clone())),
                    encrypted_file: file.clone(),
                },
            );
            s.store.clear().await.expect("clear");
            assert!(empty(&kc), "{mode:?} keychain wiped");
            assert!(empty(&file), "{mode:?} file wiped");
            assert!(w.0.lock().expect("lock").is_none(), "{mode:?} secret wiped");
        }
    }

    #[tokio::test]
    async fn clear_attempts_all_and_reports_first_error() {
        let file = Arc::new(Mem::default());
        put(&file, &creds()).await;
        let s = select_token_store(
            RunMode::Desktop,
            TokenStoreCandidates {
                keychain: Some(Arc::new(Broken)),
                k8s_secret: None,
                encrypted_file: file.clone(),
            },
        );
        assert!(s.store.clear().await.is_err());
        assert!(empty(&file), "file still wiped despite keychain error");
        assert!(
            s.store.load().await.is_err(),
            "broken active store surfaces"
        );
    }
}
