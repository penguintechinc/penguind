//! penguind core: configuration, supervision, events, and the Daemon gRPC service.
//!
//! The supervisor owns every module's lifecycle and is the only thing that can
//! start or stop one. The gRPC service is a thin translation layer over it, and
//! the event broker is the single fan-out point that both module-published
//! events and `WatchEvents` subscribers share.
//!
//! # Deliberate divergences from the frozen Go reference
//!
//! These are fixes, not drift. Each replaces behaviour that is provably broken
//! in `go-client/internal/daemon`; they are collected here so the M8 parity
//! audit can record them in one place.
//!
//! 1. **One shared event broker.** Go builds two: the host factory publishes
//!    module events into one, while `WatchEvents` subscribes to another that
//!    nothing ever publishes to — so module events reach no subscriber at all.
//!    Here a single broker is constructed once and handed to both.
//! 2. **`running` is published only after `Start` succeeds.** Go announces
//!    `running` before calling `Start`, so a failing start emits a spurious
//!    `running` immediately followed by a failure.
//! 3. **Symmetric load-failure events.** Go emits `StateChanged -> failed` when
//!    `Start` fails but not when `Init` fails. Both paths here emit an error
//!    event followed by `StateChanged -> disabled`, which is what actually
//!    happens: a failed load leaves the module unloaded and retryable.
//! 4. **The restart budget resets after a successful restart.** Go never clears
//!    `restartAttempt`, making `MaxRestarts` a lifetime total for the process
//!    rather than a consecutive-failure count.
//! 5. **Crash detection actually exists.** In Go nothing ever calls
//!    `ReportFailure`, so the whole backoff/restart machine is unreachable. The
//!    supervisor here runs a health-poll loop: `Unhealthy` drives the restart
//!    path, `Degraded` only marks state.
//! 6. **Shutdown stops modules in true reverse load order.** Go sorts names
//!    descending alphabetically while its comment claims LIFO.
//! 7. **The single-instance lock is released on drop** rather than leaked until
//!    process exit.

pub mod backoff;
pub mod broker;
pub mod config;
pub mod external;
pub mod host;
pub mod lock;
pub mod logring;
pub mod service;
pub mod state;
pub mod supervisor;
pub mod wasm;
