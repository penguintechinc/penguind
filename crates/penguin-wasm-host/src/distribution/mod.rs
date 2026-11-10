//! Module distribution: fetch, verify (sha256 + minisign over id/version/sha256),
//! publish, and the outbound network allowlist.

mod fetcher;
mod network_gatekeeper;
mod publisher;
mod run_verified;
mod verification;

pub use fetcher::{FetchError, GitHubFetcher, ModuleManifest, Resolver};
pub use network_gatekeeper::NetworkPolicy;
pub use publisher::{Publisher, validate_name};
pub use verification::{
    ManifestClaims, VerificationError, VerifiedModule, signed_payload, verify_hash,
    verify_signature,
};
