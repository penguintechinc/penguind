//! Builds the dynamic clap command tree from the daemon's `ListCommands`.
//!
//! The `penguin` CLI never links module code. Every module's command tree
//! travels over the wire as `penguin.daemon.v1.ModuleCommands` (see
//! `proto/penguin/daemon/v1/daemon.proto`), and this crate turns that data
//! into a runtime-built [`clap`] command tree — the reason the CLI needs
//! clap's builder API rather than its derive macros, which require the tree
//! to be known at compile time.
//!
//! Everything here is a pure function over data: no socket, no daemon, no
//! stdin/stdout. `bins/penguin` is the thin shell that owns the actual gRPC
//! connection and I/O and calls into this crate to decide what the tree looks
//! like, what a parsed invocation should send the daemon, and what text a
//! response renders as — which is what makes all of it unit-testable without
//! a running `penguind`.
//!
//! This is a Go→Rust port of `go-client/cmd/penguin/main.go` and
//! `go-client/internal/cli/builder.go`; every module doc below calls out
//! where Rust's behaviour deliberately diverges from the frozen Go
//! reference, cross-referenced with `docs/PARITY.md`.

pub mod dispatch;
pub mod error;
pub mod flags;
pub mod hub;
pub mod json;
pub mod render;
pub mod socket;
pub mod timestamp;
pub mod tree;
pub mod update;
pub mod verbs;

/// The wire contract types (`penguin.daemon.v1`), re-exported under a short
/// alias so every module in this crate (and `bins/penguin`) spells them the
/// same way.
pub use penguin_proto::daemon::v1 as pb;

/// The only `api_version` this CLI sends. Matches
/// `go-client/cmd/penguin/main.go` and `go-client/internal/cli/builder.go`,
/// both of which hardcode `"v1"` on every request.
pub const API_VERSION: &str = "v1";
