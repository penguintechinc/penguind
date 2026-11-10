//! The public contract between the penguin daemon and product modules.
//!
//! Compiled-in modules and external (go-plugin) modules implement the exact
//! same [`Module`] trait; the daemon supervisor cannot tell them apart. This
//! crate is the Rust port of the Go `pkg/sdk` package and the single home for
//! the hand-written conversions between these ergonomic types and the generated
//! `penguin-proto` wire types.
//!
//! Adding a new PenguinTech product client means implementing [`Module`] and
//! registering its [`Factory`] (one line in the built-in registry) or shipping
//! a signed external plugin binary.

pub mod command;
pub mod convert;
pub mod error;
pub mod host;
pub mod module;
pub mod plugin;
pub mod status;
pub mod tools;

pub use command::{CommandResult, CommandSpec, FlagSpec, FlagType};
pub use error::{MetricsError, ModuleError, SecretError};
pub use host::{
    Event, EventSink, EventType, HostServices, LicenseChecker, LogLevel, Logger, Metrics,
    SecretStore,
};
pub use module::{Factory, Module, ModuleInfo};
pub use status::{HealthLevel, HealthReport, ModuleState, Status};
