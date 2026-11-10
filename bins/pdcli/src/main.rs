//! Command penguin is the unprivileged CLI for the PenguinTech endpoint
//! agent. It talks to the penguind daemon over authenticated local IPC.
//! Ported from `go-client/cmd/penguin/main.go` and
//! `go-client/internal/cli/builder.go`.
//!
//! Almost all of the CLI's logic — tree construction, request shaping,
//! output rendering, error mapping — lives in `penguin-cli-core` as pure,
//! hermetically-tested functions over data. This binary is the thin shell:
//! it owns the socket connection, the parsed-argument-to-handler dispatch,
//! and stdin/stdout, and nothing else.
//!
//! Unix-only in this milestone, matching `penguind`'s own scope (see
//! `bins/penguind/src/main.rs`) — the eager daemon dial goes through
//! `penguin_ipc::dial_unix`, which only exists on Unix targets.

#[cfg(unix)]
mod cli;
#[cfg(unix)]
mod hub;

#[cfg(unix)]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    cli::run(std::env::args().collect()).await
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("penguin: only Unix targets are supported in this milestone");
    std::process::ExitCode::FAILURE
}
