//! `logger`: routes a guest log record to the module's host logger.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_sdk::{LogLevel, Logger};
use serde_json::Value;

use super::ToolExecutor;

/// Backs the `logger` tool with the SDK [`Logger`].
pub struct LoggerExecutor {
    logger: Arc<dyn Logger>,
}

impl LoggerExecutor {
    /// Wraps the module's logger.
    pub fn new(logger: Arc<dyn Logger>) -> Self {
        Self { logger }
    }
}

/// Longest guest log message kept, in bytes (longer input is cut, with a marker).
pub const MAX_LOG_MESSAGE_BYTES: usize = 4096;

/// Makes a guest-supplied message safe to log: control characters (newlines,
/// ANSI escapes, NUL) become visible escapes so a guest cannot forge log lines,
/// and the length is capped.
pub fn sanitize_message(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(MAX_LOG_MESSAGE_BYTES));
    for ch in raw.chars() {
        let piece: String = if ch.is_control() {
            ch.escape_default().collect()
        } else {
            ch.to_string()
        };
        if out.len() + piece.len() > MAX_LOG_MESSAGE_BYTES {
            out.push_str("...[truncated]");
            break;
        }
        out.push_str(&piece);
    }
    out
}

#[async_trait]
impl ToolExecutor for LoggerExecutor {
    fn id(&self) -> &str {
        "logger"
    }

    async fn execute(&self, args: Value) -> Result<Value, String> {
        let level_text = args["level"].as_str().unwrap_or("").to_lowercase();
        let level = LogLevel::parse(&level_text).ok_or("unknown log level")?;
        let message = sanitize_message(args["message"].as_str().unwrap_or(""));
        self.logger.log(level, &message, &[]);
        Ok(Value::Null)
    }
}
