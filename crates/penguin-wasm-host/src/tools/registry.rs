//! The tool registry: declared tools (from `tool_definitions.json`), the
//! executors registered against them, and the validated dispatch path.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonschema::Validator;
use penguin_sdk::tools::{TOOL_DEFINITIONS_JSON, ToolError};
use serde_json::Value;
use tracing::Instrument;

use crate::executors::ToolExecutor;
use crate::tools::ToolMetrics;

/// Largest accepted serialized argument payload (matches the waddles tool-invoke cap).
/// Enforced at the ABI boundary, where the raw bytes are already in hand, so the
/// registry never re-serializes parsed arguments just to measure them.
pub const MAX_ARGS_BYTES: usize = 64 * 1024;

/// The declared JSON type of a tool's result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnType {
    /// A JSON object.
    Object,
    /// A JSON boolean.
    Boolean,
    /// A JSON string.
    String,
    /// No result; executors must return `null`.
    Void,
}

impl ReturnType {
    fn parse(value: &str) -> Option<ReturnType> {
        match value {
            "object" => Some(ReturnType::Object),
            "boolean" => Some(ReturnType::Boolean),
            "string" => Some(ReturnType::String),
            "void" => Some(ReturnType::Void),
            _ => None,
        }
    }

    fn accepts(&self, value: &Value) -> bool {
        match self {
            ReturnType::Object => value.is_object(),
            ReturnType::Boolean => value.is_boolean(),
            ReturnType::String => value.is_string(),
            ReturnType::Void => value.is_null(),
        }
    }
}

/// One declared tool: its compiled argument schema and return type.
pub struct ToolDefinition {
    /// The tool id guests call by name.
    pub id: String,
    /// Human description from the definitions file.
    pub description: String,
    /// The declared result type.
    pub return_type: ReturnType,
    validator: Validator,
}

/// Failures building or populating a registry (startup-time, always fatal).
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// The definitions document is malformed.
    #[error("invalid tool definitions: {0}")]
    BadDefinitions(String),
    /// An executor was registered for a tool that is not declared.
    #[error("executor registered for undeclared tool: {0}")]
    Undeclared(String),
    /// An executor could not be constructed (bad config or endpoint).
    #[error("executor setup failed: {0}")]
    Executor(String),
    /// Two executors claim the same tool.
    #[error("duplicate executor for tool: {0}")]
    Duplicate(String),
}

/// Declared tools plus their executors.
pub struct ToolRegistry {
    defs: HashMap<String, ToolDefinition>,
    executors: HashMap<String, Arc<dyn ToolExecutor>>,
    timeout: Duration,
    metrics: Option<ToolMetrics>,
}

impl ToolRegistry {
    /// Builds a registry from the SDK's embedded `tool_definitions.json`.
    pub fn from_embedded() -> Result<Self, RegistryError> {
        Self::from_json(TOOL_DEFINITIONS_JSON)
    }

    /// Builds a registry from a definitions document; every schema is compiled
    /// up front so a bad definition fails at startup, not at first call.
    pub fn from_json(json: &str) -> Result<Self, RegistryError> {
        let doc: Value =
            serde_json::from_str(json).map_err(|e| RegistryError::BadDefinitions(e.to_string()))?;
        let tools = doc["tools"]
            .as_array()
            .ok_or_else(|| RegistryError::BadDefinitions("missing `tools` array".into()))?;
        let mut defs = HashMap::new();
        for tool in tools {
            let id = tool["id"]
                .as_str()
                .ok_or_else(|| RegistryError::BadDefinitions("tool without id".into()))?;
            let validator = jsonschema::validator_for(&tool["parameters"])
                .map_err(|e| RegistryError::BadDefinitions(format!("{id}: {e}")))?;
            let rt = tool["return_type"].as_str().unwrap_or("");
            let return_type = ReturnType::parse(rt).ok_or_else(|| {
                RegistryError::BadDefinitions(format!("{id}: return_type {rt:?}"))
            })?;
            let def = ToolDefinition {
                id: id.to_string(),
                description: tool["description"].as_str().unwrap_or("").to_string(),
                return_type,
                validator,
            };
            if defs.insert(id.to_string(), def).is_some() {
                return Err(RegistryError::BadDefinitions(format!(
                    "duplicate tool {id}"
                )));
            }
        }
        Ok(Self {
            defs,
            executors: HashMap::new(),
            timeout: Duration::from_secs(8),
            metrics: None,
        })
    }

    /// Sets the per-call executor deadline (default 8s).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Attaches call telemetry.
    pub fn with_metrics(mut self, metrics: ToolMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Registers an executor; its id must be declared and not yet taken.
    pub fn register(&mut self, executor: Arc<dyn ToolExecutor>) -> Result<(), RegistryError> {
        let id = executor.id().to_string();
        if !self.defs.contains_key(&id) {
            return Err(RegistryError::Undeclared(id));
        }
        if self.executors.contains_key(&id) {
            return Err(RegistryError::Duplicate(id));
        }
        self.executors.insert(id, executor);
        Ok(())
    }

    /// All declared tool ids.
    pub fn tool_ids(&self) -> Vec<String> {
        self.defs.keys().cloned().collect()
    }

    /// Looks up a declared tool.
    pub fn definition(&self, id: &str) -> Option<&ToolDefinition> {
        self.defs.get(id)
    }

    /// Calls a tool with no per-module allowlist.
    pub async fn call(&self, name: &str, args: Value) -> Result<Value, ToolError> {
        self.call_scoped(name, args, None).await
    }

    /// Calls a tool on behalf of a module whose manifest allows only `allowed`
    /// (`None` = unrestricted). Emits a `tool.call` span plus a counter and
    /// latency sample; args are never logged.
    pub async fn call_scoped(
        &self,
        name: &str,
        args: Value,
        allowed: Option<&HashSet<String>>,
    ) -> Result<Value, ToolError> {
        let label = if self.defs.contains_key(name) {
            name
        } else {
            "unresolved"
        };
        let span = tracing::info_span!("tool.call", tool = label);
        let started = Instant::now();
        let result = self
            .dispatch(name, args, allowed)
            .instrument(span.clone())
            .await;
        let outcome = outcome_label(&result);
        if let Some(metrics) = &self.metrics {
            metrics.observe(label, outcome, started.elapsed());
        }
        span.in_scope(|| {
            if result.is_err() {
                tracing::warn!(outcome, "tool call failed");
            }
        });
        result
    }

    async fn dispatch(
        &self,
        name: &str,
        args: Value,
        allowed: Option<&HashSet<String>>,
    ) -> Result<Value, ToolError> {
        let def = self
            .defs
            .get(name)
            .ok_or_else(|| ToolError::UnknownTool(name.to_string()))?;
        if let Some(set) = allowed
            && !set.contains(name)
        {
            return Err(ToolError::Forbidden(name.to_string()));
        }
        if let Err(err) = def.validator.validate(&args) {
            return Err(ToolError::InvalidArgs {
                tool: name.to_string(),
                reason: err.to_string(),
            });
        }
        let executor = self
            .executors
            .get(name)
            .ok_or_else(|| ToolError::NotImplemented(name.to_string()))?;
        let run = executor.execute(args);
        let value = match tokio::time::timeout(self.timeout, run).await {
            Err(_) => return Err(ToolError::Timeout(name.to_string())),
            Ok(Err(reason)) => {
                return Err(ToolError::Failed {
                    tool: name.to_string(),
                    reason,
                });
            }
            Ok(Ok(value)) => value,
        };
        if !def.return_type.accepts(&value) {
            return Err(ToolError::BadResult {
                tool: name.to_string(),
                reason: format!("expected {:?}", def.return_type),
            });
        }
        Ok(value)
    }
}

/// Maps a call result to a bounded metric/log outcome label.
pub fn outcome_label(result: &Result<Value, ToolError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(ToolError::UnknownTool(_)) => "unknown_tool",
        Err(ToolError::NotImplemented(_)) => "not_implemented",
        Err(ToolError::Forbidden(_)) => "forbidden",
        Err(ToolError::InvalidArgs { .. }) => "invalid_args",
        Err(ToolError::Failed { .. }) => "failed",
        Err(ToolError::BadResult { .. }) => "bad_result",
        Err(ToolError::Timeout(_)) => "timeout",
        Err(ToolError::Unavailable) => "unavailable",
    }
}
