//! Agent credentials, persisted only through a [`SecretStore`] (OS keychain or
//! the encrypted-file backend) — never a plaintext file.

use std::fmt;
use std::sync::Arc;

use penguin_sdk::{SecretError, SecretStore};
use serde::{Deserialize, Serialize};

use crate::error::HubError;

/// Secret-store key holding the serialised [`Credentials`].
const KEY: &str = "hub-credentials";

/// The machine JWT and rotating refresh token for this agent.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credentials {
    /// Agent public id (UUID).
    pub agent_id: String,
    /// Short-lived machine JWT.
    pub access_token: String,
    /// Unix seconds at which `access_token` expires.
    pub access_expires_at: i64,
    /// Current single-use refresh token.
    pub refresh_token: String,
}

impl fmt::Debug for Credentials {
    /// Redacts both tokens so credentials can never reach a log line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("agent_id", &self.agent_id)
            .field("access_token", &"****")
            .field("refresh_token", &"****")
            .field("access_expires_at", &self.access_expires_at)
            .finish()
    }
}

/// Loads, saves and clears [`Credentials`] in a [`SecretStore`].
pub struct CredentialStore {
    store: Arc<dyn SecretStore>,
}

impl CredentialStore {
    /// Wraps `store` (callers pass a namespaced view).
    pub fn new(store: Arc<dyn SecretStore>) -> Self {
        Self { store }
    }

    /// Reads the credentials; `None` when never enrolled or cleared. An
    /// unparsable record is treated as absent so the agent re-enrolls.
    pub async fn load(&self) -> Result<Option<Credentials>, HubError> {
        match self.store.get(KEY).await {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
            Err(SecretError::NotFound) => Ok(None),
            Err(e) => Err(HubError::Secrets(e.to_string())),
        }
    }

    /// Persists the credentials.
    pub async fn save(&self, creds: &Credentials) -> Result<(), HubError> {
        let bytes = serde_json::to_vec(creds).map_err(|e| HubError::Secrets(e.to_string()))?;
        self.store
            .set(KEY, &bytes)
            .await
            .map_err(|e| HubError::Secrets(e.to_string()))
    }

    /// Removes the credentials; deleting an absent record is fine.
    pub async fn clear(&self) -> Result<(), HubError> {
        match self.store.delete(KEY).await {
            Ok(()) | Err(SecretError::NotFound) => Ok(()),
            Err(e) => Err(HubError::Secrets(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;

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

    fn creds() -> Credentials {
        Credentials {
            agent_id: "a".into(),
            access_token: "super-secret-access".into(),
            access_expires_at: 5,
            refresh_token: "super-secret-refresh".into(),
        }
    }

    #[test]
    fn debug_never_prints_tokens() {
        let s = format!("{:?}", creds());
        assert!(!s.contains("super-secret"), "{s}");
        assert!(s.contains("****"));
    }

    #[tokio::test]
    async fn save_load_clear_round_trip() {
        let store = CredentialStore::new(Arc::new(Mem::default()));
        assert_eq!(store.load().await.expect("load"), None);
        store.save(&creds()).await.expect("save");
        assert_eq!(store.load().await.expect("load"), Some(creds()));
        store.clear().await.expect("clear");
        store.clear().await.expect("clear is idempotent");
        assert_eq!(store.load().await.expect("load"), None);
    }
}
