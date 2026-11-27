//! The Waddles Gateway built-in module: local OBS / streamer / API-testing
//! bridge and CAT-authenticated admin CLI over the Waddles hub, implementing
//! `penguin_sdk::Module`.
//!
//! Owns the local dial-in bridge ([`bridge`]), OBS WebSocket v5 adapter,
//! webhook dispatch (`bridge_action`), and CAT-authenticated (`wdl_c_`)
//! community admin CLI (`commands`).
//!
//! User OAuth / desktop `SessionProxy` lives in
//! `penguin-module-waddles-social`, not here.

mod bridge;
pub mod bridge_action;
mod commands;
mod config;
mod mask;
pub mod metrics;
mod module;
#[cfg(test)]
mod testutil;

pub use module::{WaddlesGatewayModule, factory, get_bridge_action_registry};
