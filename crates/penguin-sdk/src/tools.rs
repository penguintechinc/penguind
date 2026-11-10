//! The universal tool-call surface a module uses to ask the daemon to do work.
//!
//! Every host capability reachable from a WASM module (or a Rust module via
//! [`crate::HostServices::call_tool`]) is a named "tool" whose argument shape is
//! declared in `schemas/tool_definitions.json`. Failures are typed so callers
//! can tell an unknown tool from bad arguments from a tool that is declared but
//! not yet implemented — nothing is silently swallowed.

use std::future::Future;
use std::pin::Pin;

use serde_json::Value;

/// The raw `tool_definitions.json` document — the single source of truth for
/// tool ids and argument schemas, shared by every host implementation.
pub const TOOL_DEFINITIONS_JSON: &str = include_str!("schemas/tool_definitions.json");

/// The boxed future returned by [`crate::HostServices::call_tool`] (kept dyn-safe
/// so `HostServices` stays object-safe without `async_trait` churn).
pub type ToolFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, ToolError>> + Send + 'a>>;

/// Why a tool call failed. Each variant is a distinct, loud failure class.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ToolError {
    /// The tool id is not in the tool definitions.
    #[error("unknown tool: {0}")]
    UnknownTool(String),
    /// The tool is declared but this host has no executor for it.
    #[error("tool not implemented on this host: {0}")]
    NotImplemented(String),
    /// The caller's module is not permitted to use this tool.
    #[error("tool not permitted for this module: {0}")]
    Forbidden(String),
    /// The arguments failed validation against the tool's schema.
    #[error("invalid arguments for tool {tool}: {reason}")]
    InvalidArgs {
        /// The tool that rejected the arguments.
        tool: String,
        /// The first schema violation.
        reason: String,
    },
    /// The executor ran and failed.
    #[error("tool {tool} failed: {reason}")]
    Failed {
        /// The tool that failed.
        tool: String,
        /// The failure detail.
        reason: String,
    },
    /// The executor's result did not match the tool's declared return type.
    #[error("tool {tool} returned an invalid result: {reason}")]
    BadResult {
        /// The tool whose result was rejected.
        tool: String,
        /// What was wrong.
        reason: String,
    },
    /// The executor exceeded its time budget.
    #[error("tool {0} timed out")]
    Timeout(String),
    /// This host provides no tool-call capability at all.
    #[error("tool calls are unavailable on this host")]
    Unavailable,
}
