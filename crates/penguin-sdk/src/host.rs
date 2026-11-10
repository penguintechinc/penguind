//! Daemon-provided capabilities injected into a module at [`crate::Module::init`].
//!
//! For built-in modules these are backed directly by daemon subsystems. For
//! external plugins the equivalent Go proxies broker each call back to the
//! daemon over gRPC; either way a module sees the same [`HostServices`] surface.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;

use crate::error::{MetricsError, SecretError};
pub use crate::tools::{ToolError, ToolFuture};

/// The bundle of host capabilities a module receives at init time.
///
/// The cheap accessors return shared handles (`Arc<dyn ...>`) rather than doing
/// work, so a module can stash them and use them for the rest of its life.
pub trait HostServices: Send + Sync {
    /// A PII-sanitising logger scoped to this module.
    fn logger(&self) -> Arc<dyn Logger>;
    /// The module's namespaced secure key/value store.
    fn secrets(&self) -> Arc<dyn SecretStore>;
    /// Feature-flag and license-tier checks with offline caching.
    fn license(&self) -> Arc<dyn LicenseChecker>;
    /// A metrics handle namespaced to this module.
    fn metrics(&self) -> Arc<dyn Metrics>;
    /// The module's configuration as raw YAML bytes, already validated by the
    /// daemon against the module's schema. Empty means the operator supplied
    /// none — the module applies its own defaults. Modules must never read
    /// config files themselves; routing config through the host is what
    /// guarantees it was schema-checked.
    fn config(&self) -> Vec<u8>;
    /// The module's private state directory (e.g. `/var/lib/penguind/<module>`).
    fn data_dir(&self) -> PathBuf;
    /// The sink module status-change events are published to.
    fn events(&self) -> Arc<dyn EventSink>;
    /// Invokes a daemon tool by name with JSON arguments (see
    /// `schemas/tool_definitions.json`). The default fails loudly with
    /// [`ToolError::Unavailable`] so a host that has not wired a tool registry
    /// can never appear to succeed.
    fn call_tool<'a>(&'a self, _name: &'a str, _args: serde_json::Value) -> ToolFuture<'a> {
        Box::pin(async { Err(ToolError::Unavailable) })
    }
}

/// Namespaced secure storage backed by the OS keychain/keystore (with an
/// encrypted-file fallback for headless daemons).
///
/// Async because the keychain backends can block on IPC; the daemon must not
/// stall its executor on a secret lookup.
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Fetches a secret, or returns [`SecretError::NotFound`] if absent.
    async fn get(&self, key: &str) -> Result<Vec<u8>, SecretError>;
    /// Stores (or replaces) a secret.
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), SecretError>;
    /// Deletes a secret. Deleting a key that does not exist returns
    /// [`SecretError::NotFound`] rather than succeeding silently — this matches
    /// the Go store, and Go-built plugins rely on it across the plugin boundary
    /// (their host proxy maps the string `"not found"` back to the same
    /// sentinel). An idempotent delete would read more nicely, but it would
    /// change behaviour existing modules already depend on.
    async fn delete(&self, key: &str) -> Result<(), SecretError>;
}

/// Feature-flag and entitlement checks.
///
/// Implementations must degrade gracefully: an unreachable server yields the
/// last cached answer, unknown flags are off, and no call ever panics. That
/// contract is why these are synchronous — they read a cache, never the wire.
pub trait LicenseChecker: Send + Sync {
    /// Reports whether a flag key (e.g. `"penguin.squawk"`) is enabled.
    fn feature_enabled(&self, key: &str) -> bool;
    /// Returns the current license tier (`"free"`, `"professional"`,
    /// `"enterprise"`, or empty when unknown). Tiers are cumulative.
    fn tier(&self) -> String;
}

/// A metrics registerer scoped to a module.
///
/// Mirrors the Go `prometheus.Registerer` a module receives: it registers
/// collectors into the daemon's shared registry under the module's namespace.
pub trait Metrics: Send + Sync {
    /// Registers a collector; a duplicate registration is a [`MetricsError`].
    fn register(&self, collector: Box<dyn prometheus::core::Collector>)
    -> Result<(), MetricsError>;
}

/// The severity of a log record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    /// Verbose developer detail.
    Debug,
    /// Normal operational information.
    #[default]
    Info,
    /// A recoverable problem worth attention.
    Warn,
    /// A failure.
    Error,
}

impl LogLevel {
    /// Returns the lowercase wire string for this level.
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }

    /// Parses a wire string into a level; unknown values return `None`.
    pub fn parse(value: &str) -> Option<LogLevel> {
        match value {
            "debug" => Some(LogLevel::Debug),
            "info" => Some(LogLevel::Info),
            "warn" => Some(LogLevel::Warn),
            "error" => Some(LogLevel::Error),
            _ => None,
        }
    }
}

/// A structured logger scoped to a module.
///
/// The single required method is [`Logger::log`]; the level-named helpers are
/// provided defaults so implementations only write the routing once. Fields are
/// borrowed key/value pairs to keep logging allocation-free at the call site.
pub trait Logger: Send + Sync {
    /// Emits one record at the given level.
    fn log(&self, level: LogLevel, message: &str, fields: &[(&str, &str)]);

    /// Emits a debug record.
    fn debug(&self, message: &str, fields: &[(&str, &str)]) {
        self.log(LogLevel::Debug, message, fields);
    }
    /// Emits an info record.
    fn info(&self, message: &str, fields: &[(&str, &str)]) {
        self.log(LogLevel::Info, message, fields);
    }
    /// Emits a warn record.
    fn warn(&self, message: &str, fields: &[(&str, &str)]) {
        self.log(LogLevel::Warn, message, fields);
    }
    /// Emits an error record.
    fn error(&self, message: &str, fields: &[(&str, &str)]) {
        self.log(LogLevel::Error, message, fields);
    }
}

/// The sink module status-change events are published to (tray, CLI watchers).
pub trait EventSink: Send + Sync {
    /// Publishes one event to all current subscribers.
    fn publish(&self, event: Event);
}

/// The classification of a module event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EventType {
    /// The module's lifecycle state changed.
    #[default]
    StateChanged,
    /// A health transition.
    Health,
    /// Informational.
    Info,
    /// An error condition.
    Error,
}

impl EventType {
    /// Returns the wire string for this event type.
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::StateChanged => "state-changed",
            EventType::Health => "health",
            EventType::Info => "info",
            EventType::Error => "error",
        }
    }

    /// Parses a wire string into an event type; unknown values return `None`.
    pub fn parse(value: &str) -> Option<EventType> {
        match value {
            "state-changed" => Some(EventType::StateChanged),
            "health" => Some(EventType::Health),
            "info" => Some(EventType::Info),
            "error" => Some(EventType::Error),
            _ => None,
        }
    }
}

/// A module status-change notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The publishing module's name.
    pub module: String,
    /// What kind of event this is.
    pub event_type: EventType,
    /// A short human-readable message.
    pub message: String,
    /// When the event occurred.
    pub at: SystemTime,
    /// Small, non-sensitive key/value context for display.
    pub fields: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A test double that records every call routed through the default helpers,
    /// proving they all funnel into `log` with the right level.
    struct RecordingLogger {
        calls: Mutex<Vec<(LogLevel, String)>>,
    }

    impl Logger for RecordingLogger {
        fn log(&self, level: LogLevel, message: &str, _fields: &[(&str, &str)]) {
            let mut calls = self.calls.lock().unwrap();
            calls.push((level, message.to_string()));
        }
    }

    #[test]
    fn log_level_round_trips_and_rejects_unknown() {
        let all = [
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warn,
            LogLevel::Error,
        ];
        for want in all {
            assert_eq!(LogLevel::parse(want.as_str()), Some(want));
        }
        assert_eq!(LogLevel::parse("trace"), None);
    }

    #[test]
    fn event_type_round_trips_and_rejects_unknown() {
        let all = [
            EventType::StateChanged,
            EventType::Health,
            EventType::Info,
            EventType::Error,
        ];
        for want in all {
            assert_eq!(EventType::parse(want.as_str()), Some(want));
        }
        assert_eq!(EventType::parse("panic"), None);
    }

    #[test]
    fn logger_default_helpers_route_to_the_matching_level() {
        let logger = RecordingLogger {
            calls: Mutex::new(Vec::new()),
        };
        logger.debug("d", &[]);
        logger.info("i", &[]);
        logger.warn("w", &[]);
        logger.error("e", &[]);

        let calls = logger.calls.lock().unwrap();
        let expected = [
            (LogLevel::Debug, "d"),
            (LogLevel::Info, "i"),
            (LogLevel::Warn, "w"),
            (LogLevel::Error, "e"),
        ];
        assert_eq!(calls.len(), expected.len());
        for (index, want) in expected.iter().enumerate() {
            assert_eq!(calls[index].0, want.0);
            assert_eq!(calls[index].1, want.1);
        }
    }
}
