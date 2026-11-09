//! wasmtime host for PenguinTech WASM modules that call the daemon through
//! "tool calls".
//!
//! A module imports one function, `penguin.call_tool`, and the host dispatches
//! it to a [`tools::ToolRegistry`] whose tool ids and argument schemas come from
//! the SDK's `tool_definitions.json`. Execution is gated by the PostHog flag
//! `penguind.wasm-modules` and bounded by fuel, memory and wall-clock limits.
//!
//! ABI choice: a core-module ptr/len ABI, not the WIT component model — no
//! component toolchain (wit-bindgen/cargo-component) is wired into this repo
//! yet, so guests and test fixtures are plain core modules; the ABI is a single
//! import, small enough to port to WIT later without changing the registry.

pub mod distribution;
pub mod error;
pub mod executors;
pub mod runtime;
pub mod tls;
pub mod tools;

pub use error::WasmHostError;
pub use runtime::{ModuleLimits, RunOutcome, WASM_MODULES_FLAG, WasmRuntime};
pub use tools::{ModuleToolContext, ToolRegistry, build_module_registry};
