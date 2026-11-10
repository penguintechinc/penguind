//! [`Store`]: the [`penguin_sdk::SecretStore`] implementation gluing
//! namespace prefixing, backend selection, and error mapping together.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;

use penguin_sdk::{SecretError, SecretStore};

use crate::file_backend::FileBackend;
use crate::platform_backend::PlatformBackend;

/// The keyring service identifier used when [`Config::service_name`] is
/// left empty, matching the Go default.
const DEFAULT_SERVICE_NAME: &str = "penguind";

/// Which backend a [`Store`] should use.
///
/// Mirrors the Go `Store`'s backend-selection order (WinCred → Keychain →
/// SecretService → File): [`Backend::Auto`] tries the OS-provided keyring
/// first and falls back to the encrypted file backend only if the platform
/// keyring is unreachable (e.g. a headless daemon with no D-Bus session).
/// [`Backend::FileOnly`] skips the platform probe entirely.
///
/// **Every test must use [`Backend::FileOnly`].** It is the only selection
/// that can never trigger a real OS credential store lookup or desktop
/// prompt.
pub enum Backend {
    /// Production default: probe the platform keyring, fall back to the
    /// encrypted file backend at `file_dir` if it is unreachable.
    Auto {
        /// Directory the file-backend fallback is rooted at.
        file_dir: PathBuf,
    },
    /// Force the encrypted-file backend only, never touching a platform
    /// keyring.
    FileOnly {
        /// Directory the encrypted-file backend is rooted at.
        file_dir: PathBuf,
    },
    /// Use the OS keyring only; [`Store::open`] fails when it is unreachable
    /// so the caller can choose (and announce) its own fallback.
    PlatformOnly,
}

/// A [`Store`]'s configuration, mirroring the Go `Config` struct.
pub struct Config {
    /// The keyring service identifier used for platform-backend entries.
    /// Empty defaults to `"penguind"`.
    pub service_name: String,
    /// Which backend to use.
    pub backend: Backend,
}

/// The backend a [`Store`] actually talks to, chosen once at [`Store::open`]
/// time.
enum ActiveBackend {
    File(FileBackend),
    Platform(PlatformBackend),
}

/// Namespaced secure secret storage — [`penguin_sdk::SecretStore`] backed by
/// the OS keychain or, as a fallback, an encrypted file store.
///
/// Cloning is cheap: the backend is shared behind an `Arc` and only the
/// namespace prefix is copied, mirroring the Go `Store.Namespaced` struct
/// copy.
#[derive(Clone)]
pub struct Store {
    backend: Arc<ActiveBackend>,
    namespace: String,
}

impl Store {
    /// Opens a store with the backend selection given in `cfg`.
    pub fn open(cfg: Config) -> Result<Store, SecretError> {
        let service_name = if cfg.service_name.is_empty() {
            DEFAULT_SERVICE_NAME.to_string()
        } else {
            cfg.service_name
        };

        let backend = match cfg.backend {
            Backend::FileOnly { file_dir } => ActiveBackend::File(FileBackend::open(file_dir)?),
            Backend::Auto { file_dir } => select_auto_backend(&service_name, file_dir)?,
            Backend::PlatformOnly => {
                if !PlatformBackend::probe(&service_name) {
                    return Err(SecretError::Other("platform keyring unreachable".into()));
                }
                ActiveBackend::Platform(PlatformBackend::new(&service_name))
            }
        };

        Ok(Store {
            backend: Arc::new(backend),
            namespace: String::new(),
        })
    }

    /// Returns a view that prefixes every key with `"<module>/"`. The view
    /// shares this store's backend; only the (cheap) namespace prefix is
    /// copied.
    pub fn namespaced(&self, module: &str) -> Store {
        Store {
            backend: Arc::clone(&self.backend),
            namespace: module.to_string(),
        }
    }

    /// Builds the full backend key: `"<namespace>/<key>"`, or bare `key`
    /// when this store has no namespace.
    fn make_key(&self, key: &str) -> String {
        if self.namespace.is_empty() {
            key.to_string()
        } else {
            format!("{}/{key}", self.namespace)
        }
    }
}

#[async_trait]
impl SecretStore for Store {
    async fn get(&self, key: &str) -> Result<Vec<u8>, SecretError> {
        let full_key = self.make_key(key);
        match &*self.backend {
            ActiveBackend::File(file) => file.get(&full_key),
            ActiveBackend::Platform(platform) => platform.get(&full_key).await,
        }
    }

    async fn set(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
        let full_key = self.make_key(key);
        match &*self.backend {
            ActiveBackend::File(file) => file.set(&full_key, value),
            ActiveBackend::Platform(platform) => platform.set(&full_key, value).await,
        }
    }

    async fn delete(&self, key: &str) -> Result<(), SecretError> {
        let full_key = self.make_key(key);
        match &*self.backend {
            ActiveBackend::File(file) => file.delete(&full_key),
            ActiveBackend::Platform(platform) => platform.delete(&full_key).await,
        }
    }
}

/// Implements [`Backend::Auto`]: probes the platform keyring and falls back
/// to the file backend when it is unreachable.
fn select_auto_backend(
    service_name: &str,
    file_dir: PathBuf,
) -> Result<ActiveBackend, SecretError> {
    if PlatformBackend::probe(service_name) {
        return Ok(ActiveBackend::Platform(PlatformBackend::new(service_name)));
    }
    Ok(ActiveBackend::File(FileBackend::open(file_dir)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every test store is built with [`Backend::FileOnly`] — the only
    /// selection guaranteed to never touch a real platform keyring.
    fn open_test_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(Config {
            service_name: String::new(),
            backend: Backend::FileOnly {
                file_dir: dir.path().to_path_buf(),
            },
        })
        .expect("open store");
        (dir, store)
    }

    #[tokio::test]
    async fn open_succeeds_with_file_backend_and_empty_service_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(Config {
            service_name: String::new(),
            backend: Backend::FileOnly {
                file_dir: dir.path().to_path_buf(),
            },
        });
        assert!(store.is_ok());
    }

    #[tokio::test]
    async fn set_get_round_trip_for_various_values() {
        let (_dir, store) = open_test_store();

        let cases: [(&str, &[u8]); 4] = [
            ("simple", b"test_value"),
            ("empty", b""),
            ("large", &[7u8; 10_000]),
            ("binary", &[0x00, 0x01, 0x02, 0xFF]),
        ];

        for (key, value) in cases {
            store.set(key, value).await.expect("set");
            let got = store.get(key).await.expect("get");
            assert_eq!(got, value, "round trip mismatch for key {key:?}");
        }
    }

    #[tokio::test]
    async fn get_of_missing_key_is_not_found() {
        let (_dir, store) = open_test_store();
        let err = store
            .get("nonexistent")
            .await
            .expect_err("missing key should error");
        assert!(matches!(err, SecretError::NotFound));
    }

    #[tokio::test]
    async fn delete_of_missing_key_is_not_found() {
        // Matches the Go store: Store.Delete wraps keyring.ErrKeyNotFound as
        // sdk.ErrSecretNotFound when the underlying backend has no such key.
        let (_dir, store) = open_test_store();
        let err = store
            .delete("nonexistent")
            .await
            .expect_err("deleting a missing key should error");
        assert!(matches!(err, SecretError::NotFound));
    }

    #[tokio::test]
    async fn delete_existing_key_then_get_fails_not_found() {
        let (_dir, store) = open_test_store();

        store.set("to_delete", b"value").await.expect("set");
        store.delete("to_delete").await.expect("delete");

        let err = store
            .get("to_delete")
            .await
            .expect_err("get after delete should fail");
        assert!(matches!(err, SecretError::NotFound));
    }

    #[tokio::test]
    async fn namespacing_isolates_the_same_key_across_modules() {
        let (_dir, store) = open_test_store();
        let ns1 = store.namespaced("module1");
        let ns2 = store.namespaced("module2");

        ns1.set("secret", b"value1").await.expect("ns1 set");
        ns2.set("secret", b"value2").await.expect("ns2 set");

        assert_eq!(ns1.get("secret").await.expect("ns1 get"), b"value1");
        assert_eq!(ns2.get("secret").await.expect("ns2 get"), b"value2");
    }

    #[tokio::test]
    async fn namespaced_view_cannot_read_the_unnamespaced_key() {
        let (_dir, store) = open_test_store();
        let ns = store.namespaced("module1");

        ns.set("secret", b"namespaced-value").await.expect("ns set");

        let err = store
            .get("secret")
            .await
            .expect_err("the un-namespaced store must not see the namespaced key");
        assert!(matches!(err, SecretError::NotFound));
    }

    #[tokio::test]
    async fn namespaced_delete_only_removes_that_namespaces_key() {
        let (_dir, store) = open_test_store();
        let ns = store.namespaced("module1");

        ns.set("secret", b"value").await.expect("ns set");
        store.set("secret", b"root-value").await.expect("root set");

        ns.delete("secret").await.expect("ns delete");

        let err = ns
            .get("secret")
            .await
            .expect_err("ns get after delete should fail");
        assert!(matches!(err, SecretError::NotFound));
        // The un-namespaced key is untouched.
        assert_eq!(store.get("secret").await.expect("root get"), b"root-value");
    }
}
