//! The `waddles-social` built-in module: the Discord-like desktop social
//! client module for the Waddles hub, implementing `penguin_sdk::Module`.
//!
//! [`module::WaddlesSocialModule`] is the lifecycle/CLI glue; it wraps
//! `waddles_client::WaddlesClient` for social/community endpoints and hosts
//! [`session_proxy::SessionProxy`] for desktop `penguin.desktop.v1.SessionProxy`
//! Bearer passthrough and `POST /api/v1/auth/refresh` rotation.
//!
//! Local TCP/WS bridge listeners, OBS adapters, and CAT admin commands live
//! in `penguin-module-waddles-gateway`, not here.

mod commands;
pub mod config;
mod mask;
pub mod metrics;
mod module;
pub mod session_proxy;
#[cfg(test)]
mod testutil;

pub use config::{CONFIG_SCHEMA, HubSection, ModuleConfig};
pub use mask::mask_secret;
pub use metrics::WaddlesSocialMetrics;
pub use module::{WaddlesSocialModule, factory, get_session_proxy_registry};
pub use session_proxy::{HttpRequest, HttpResponse, SessionProxy, SessionProxyError};
