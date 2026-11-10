//! The seam between the hub client and whatever runs modules (the daemon).

use std::sync::Arc;

use async_trait::async_trait;
use penguin_wasm_host::ModuleLimits;
use penguin_wasm_host::distribution::VerifiedModule;

/// A verified module plus the clamped limits it must run under.
pub struct DesiredModule {
    /// Module id.
    pub id: String,
    /// Module version.
    pub version: String,
    /// The signature- and digest-verified binary.
    pub module: Arc<VerifiedModule>,
    /// Limits after the clamp; never wider than the local ceiling.
    pub limits: ModuleLimits,
}

/// Why the host would not load a module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleLoadError {
    /// Code reported to the hub in `error_code`.
    pub code: i64,
    /// Local-only reason (never sent to the hub).
    pub reason: String,
}

/// Receives verified modules from the sync loop.
#[async_trait]
pub trait ModuleSink: Send + Sync {
    /// Loads (or reloads) `module`.
    async fn load(&self, module: DesiredModule) -> Result<(), ModuleLoadError>;
    /// Unloads the module with this id (revoked, yanked, or dropped).
    async fn unload(&self, id: &str);
}
