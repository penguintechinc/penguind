//! Typed failures for loading and running a WASM module.

use penguin_sdk::tools::ToolError;

/// Why a module could not be loaded or did not run to completion.
#[derive(Debug, thiserror::Error)]
pub enum WasmHostError {
    /// The `penguind.wasm-modules` flag is off (or unseen); nothing was loaded.
    #[error("feature flag {0} is disabled")]
    FlagDisabled(&'static str),
    /// The module bytes exceed the configured size cap.
    #[error("module is {size} bytes, over the {max} byte cap")]
    ModuleTooLarge {
        /// The submitted size.
        size: usize,
        /// The configured cap.
        max: usize,
    },
    /// The engine could not be configured.
    #[error("wasm engine setup failed: {0}")]
    Engine(String),
    /// The bytes are not a valid module.
    #[error("module failed to compile: {0}")]
    Compile(String),
    /// Linking/instantiation failed (e.g. an unknown import).
    #[error("module failed to instantiate: {0}")]
    Instantiate(String),
    /// The module lacks a required export.
    #[error("module is missing required export `{0}`")]
    MissingExport(&'static str),
    /// The fuel budget was exhausted.
    #[error("module exhausted its fuel budget")]
    FuelExhausted,
    /// The memory cap was hit.
    #[error("module exceeded its memory limit")]
    MemoryLimit,
    /// The wall-clock budget elapsed.
    #[error("module exceeded its wall-clock budget")]
    Timeout,
    /// The guest trapped for another reason.
    #[error("module trapped: {0}")]
    Trap(String),
    /// A host-side tool failure surfaced to the embedder.
    #[error(transparent)]
    Tool(#[from] ToolError),
}
