//! Shared fixtures: WAT guests, a recording logger and a flag-set license double.
#![allow(dead_code)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use penguin_sdk::{LicenseChecker, LogLevel, Logger};
use penguin_wasm_host::executors::{ConfigReadExecutor, LoggerExecutor};
use penguin_wasm_host::{ModuleLimits, ToolRegistry, WASM_MODULES_FLAG};

/// A license double with an explicit set of enabled flags (unseen = off).
pub struct Flags(pub HashSet<String>);

impl Flags {
    pub fn on() -> Arc<Self> {
        Arc::new(Flags([WASM_MODULES_FLAG.to_string()].into()))
    }
    pub fn off() -> Arc<Self> {
        Arc::new(Flags(HashSet::new()))
    }
}

impl LicenseChecker for Flags {
    fn feature_enabled(&self, key: &str) -> bool {
        self.0.contains(key)
    }
    fn tier(&self) -> String {
        "free".into()
    }
}

/// Captures every log record the `logger` tool routes to the host.
#[derive(Default)]
pub struct RecordingLogger(pub Mutex<Vec<(LogLevel, String)>>);

impl Logger for RecordingLogger {
    fn log(&self, level: LogLevel, message: &str, _fields: &[(&str, &str)]) {
        self.0
            .lock()
            .expect("lock")
            .push((level, message.to_string()));
    }
}

/// A registry with the real `logger` and `config_read` executors.
pub fn registry(logger: Arc<RecordingLogger>) -> ToolRegistry {
    let mut reg = ToolRegistry::from_embedded().expect("embedded definitions");
    reg.register(Arc::new(LoggerExecutor::new(logger)))
        .expect("logger");
    let cfg = ConfigReadExecutor::new(b"a:\n  b: 42\n").expect("config");
    reg.register(Arc::new(cfg)).expect("config_read");
    reg
}

fn escape(text: &str) -> String {
    text.bytes().map(|b| format!("\\{b:02x}")).collect()
}

/// A guest whose `run` makes one `call_tool` and returns the call's result code.
pub fn caller_wasm(tool: &str, args: &str, out_cap: u32) -> Vec<u8> {
    let wat = format!(
        r#"(module
  (import "penguin" "call_tool" (func $ct (param i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{name}")
  (data (i32.const 256) "{args}")
  (func (export "run") (result i32)
    (call $ct (i32.const 0) (i32.const {nl}) (i32.const 256) (i32.const {al})
              (i32.const 1024) (i32.const {cap}))))"#,
        name = escape(tool),
        args = escape(args),
        nl = tool.len(),
        al = args.len(),
        cap = out_cap,
    );
    wat::parse_str(wat).expect("valid wat")
}

/// Compiles raw WAT.
pub fn wasm(wat_text: &str) -> Vec<u8> {
    wat::parse_str(wat_text).expect("valid wat")
}

/// Limits that explicitly allow the four implemented tools (the default denies all).
pub fn open_limits() -> ModuleLimits {
    ModuleLimits::default().allowing(["logger", "config_read", "metrics_publish", "doh_query"])
}
