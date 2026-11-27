//! An async REST client for the Waddles hub API's `/api/v1` surface —
//! shared by `penguin-module-waddles-social` (User JWT) and
//! `penguin-module-waddles-gateway` (Community Access Token `wdl_c_`).
//! This crate owns request/response typing and error handling only.

pub mod client;
pub mod config;
pub mod error;
pub mod models;
mod tls;

pub use client::WaddlesClient;
pub use config::WaddlesConfig;
pub use error::{ErrorBody, WaddlesError};
