//! The trait every host tool implements.

use async_trait::async_trait;
use serde_json::Value;

/// A host capability exposed to WASM modules as a named tool.
///
/// Arguments have already been validated against the tool's schema by the
/// registry; the returned value is checked against the declared return type.
#[async_trait]
pub trait ToolExecutor: Send + Sync {
    /// The tool id this executor serves (must exist in `tool_definitions.json`).
    fn id(&self) -> &str;
    /// Runs the tool; the `Err` string is surfaced as `ToolError::Failed`.
    async fn execute(&self, args: Value) -> Result<Value, String>;
}
