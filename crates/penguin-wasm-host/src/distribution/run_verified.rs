//! `WasmRuntime::run_verified`: the only entry point that accepts fetched modules.

use super::verification::VerifiedModule;
use crate::error::WasmHostError;
use crate::runtime::{ModuleLimits, RunOutcome, WasmRuntime};

impl WasmRuntime {
    /// Runs a module whose id/version/sha256 were signed by the pinned key.
    /// Taking a [`VerifiedModule`] (unconstructible without that check) makes
    /// "run unverified downloaded bytes" a type error.
    pub async fn run_verified(
        &self,
        module: &VerifiedModule,
        limits: ModuleLimits,
    ) -> Result<RunOutcome, WasmHostError> {
        self.run(module.as_bytes(), limits).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use penguin_sdk::LicenseChecker;

    use super::super::verification::{ManifestClaims, fixtures::*};
    use super::*;
    use crate::tools::ToolRegistry;

    struct Off;
    impl LicenseChecker for Off {
        fn feature_enabled(&self, _: &str) -> bool {
            false
        }
        fn tier(&self) -> String {
            String::new()
        }
    }

    #[tokio::test]
    async fn run_verified_is_flag_gated() {
        let rt = WasmRuntime::new(
            Arc::new(ToolRegistry::from_embedded().expect("reg")),
            Arc::new(Off),
        )
        .expect("rt");
        let m = VerifiedModule::verify(
            "demo",
            "1.0.0",
            &ManifestClaims {
                id: "demo",
                version: "1.0.0",
                sha256: SHA,
                signature: SIG_A,
            },
            BINARY.to_vec(),
            PUB_A,
        )
        .expect("verified");
        let err = rt
            .run_verified(&m, ModuleLimits::default())
            .await
            .unwrap_err();
        assert!(matches!(err, WasmHostError::FlagDisabled(_)));
    }
}
