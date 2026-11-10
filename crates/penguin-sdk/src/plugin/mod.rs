//! The go-plugin **server** (plugin-process) side: what an external plugin
//! binary links against to become a `penguin-sdk` plugin the daemon can
//! launch, over exactly the wire protocol
//! `penguin-goplugin-host` speaks as the client.
//!
//! Call [`serve`] from `main()` with a constructed [`crate::Module`]; see
//! its doc comment for the full startup sequence. Everything else in this
//! module is private plumbing:
//!
//! - [`mtls`] — our AutoMTLS identity, the host's pinned certificate, and
//!   the byte-equality verifiers both TLS roles need.
//! - [`handshake`] — the magic-cookie check and the handshake line we print.
//! - [`tls_incoming`] — TLS-wraps the unix listener the main connection is
//!   served on.
//! - [`broker`] — the plugin's side of `GRPCBroker`: unlike
//!   `penguin-goplugin-host` (which calls `StartStream`), we *serve* it, and
//!   use it to dial the host's `HostService` on broker id 1 — the leg no
//!   Go-built plugin has ever exercised (`docs/PARITY.md` §1.10).
//! - [`hostservices`] — the [`crate::HostServices`] implementations exposed
//!   to the module: RPC-backed when the broker leg connects, a graceful
//!   no-op fallback when it doesn't.
//! - [`services`] — the `ModuleService`/`GRPCController`/`GRPCStdio` gRPC
//!   servers wrapping the author's [`crate::Module`].
//!
//! ## Why this is not built on `penguin-goplugin-host`
//!
//! That crate is the go-plugin *host* (client) side and already depends on
//! `penguin-sdk` (it adapts a remote `Module` for the daemon supervisor).
//! `penguin-sdk` depending back on it would be a cycle, so the small amount
//! of protocol logic both sides need — the AutoMTLS certificate template,
//! the pinned-DER verifiers, the handshake line format — is mirrored here by
//! hand instead of shared. Where the two diverge in role (this side *serves*
//! `GRPCBroker` and *dials* `HostService`; the host side is the reverse),
//! that is not duplication, it is the other half of the same protocol.

mod broker;
mod error;
mod handshake;
mod host_capability;
mod hostservices;
mod mtls;
mod serve;
mod services;
mod tls_incoming;

pub use host_capability::HostCapability;
pub use serve::serve;
