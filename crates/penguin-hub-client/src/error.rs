//! Error type for the hub client.

use penguin_wasm_host::distribution::FetchError;

/// Everything that can go wrong talking to the hub or persisting its state.
#[derive(Debug, thiserror::Error)]
pub enum HubError {
    /// The guarded transport refused or failed the request.
    #[error("hub transport: {0}")]
    Transport(#[from] FetchError),
    /// The hub answered with something that is not the documented shape.
    #[error("hub protocol: {0}")]
    Protocol(String),
    /// Credentials were rejected or are missing.
    #[error("hub auth: {0}")]
    Auth(String),
    /// The hub declared this agent revoked (HTTP 410).
    #[error("agent revoked by hub")]
    Revoked,
    /// Credential storage failed.
    #[error("credential store: {0}")]
    Secrets(String),
    /// Offline-cache I/O failed.
    #[error("hub cache: {0}")]
    Cache(String),
    /// Local configuration is invalid.
    #[error("hub config: {0}")]
    Config(String),
}
