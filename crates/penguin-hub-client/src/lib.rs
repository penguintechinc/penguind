//! penguind's client for the management hub (`services/hub-api`, protocol in
//! `docs/hub-protocol.md`).
//!
//! The agent enrolls with a one-time bootstrap token, keeps a short-lived
//! machine JWT in a secret store (never a plaintext file), polls
//! `/api/v1/agent/sync` with `ETag`/`If-None-Match`, verifies every delivered
//! module locally (sha256 + minisign against *locally pinned* keys), and
//! applies the hub's policy only as a **narrowing** of a local ceiling. A
//! compromised hub can withhold or roll back; it can never inject code or
//! widen a limit.
//!
//! All hub traffic goes through `penguin_wasm_host::distribution::HubFetcher`,
//! so the https-only / network-policy / IP-pinning / size-cap guarantees are
//! the same as for the GitHub fetcher.

pub mod cache;
pub mod clamp;
pub mod client;
pub mod creds;
pub mod error;
pub mod metrics;
pub mod model;
pub mod runner;
pub mod sink;

pub use cache::{CacheLoad, CachedState, HubCache};
pub use clamp::{ClampedLicense, EffectiveLimits, LocalCeiling, clamp_policy};
pub use client::{HubClient, HubClientConfig, SyncOutcome};
pub use creds::{CredentialStore, Credentials};
pub use error::HubError;
pub use metrics::HubMetrics;
pub use runner::{compute_delay, run_loop};
pub use sink::{DesiredModule, ModuleLoadError, ModuleSink};
