//! Architecture check: a WASM module calls a daemon tool through wasmtime's
//! `penguin.call_tool` import, the schema-validating registry and a real
//! executor — plus the unknown-tool and limit-exceeded failure paths, and the
//! `penguind.wasm-modules` flag gate.

use std::collections::HashSet;
use std::sync::Arc;

use penguin_sdk::LicenseChecker;
use penguin_wasm_host::executors::ConfigReadExecutor;
use penguin_wasm_host::runtime::abi;
use penguin_wasm_host::{
    ModuleLimits, ToolRegistry, WASM_MODULES_FLAG, WasmHostError, WasmRuntime,
};

/// Limits that explicitly grant `config_read`; the default allowlist is deny-all.
fn open() -> ModuleLimits {
    ModuleLimits::default().allowing(["config_read"])
}

/// Flag double: only the listed flags are on (unseen = off).
struct Flags(HashSet<String>);

impl LicenseChecker for Flags {
    fn feature_enabled(&self, key: &str) -> bool {
        self.0.contains(key)
    }
    fn tier(&self) -> String {
        "free".into()
    }
}

fn flags(on: bool) -> Arc<Flags> {
    let mut set = HashSet::new();
    if on {
        set.insert(WASM_MODULES_FLAG.to_string());
    }
    Arc::new(Flags(set))
}

fn runtime(on: bool) -> WasmRuntime {
    let mut registry = ToolRegistry::from_embedded().expect("embedded tool definitions");
    let config = ConfigReadExecutor::new(b"server:\n  port: 8443\n").expect("config yaml");
    registry
        .register(Arc::new(config))
        .expect("register config_read");
    WasmRuntime::new(Arc::new(registry), flags(on)).expect("runtime")
}

/// A guest that calls `config_read({"path":"server.port"})` and returns the
/// first byte of the result's `"value"` digits plus the result length.
fn guest(tool: &str, args: &str) -> Vec<u8> {
    let esc = |t: &str| t.bytes().map(|b| format!("\\{b:02x}")).collect::<String>();
    let wat = format!(
        r#"(module
  (import "penguin" "call_tool" (func $ct (param i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{}")
  (data (i32.const 256) "{}")
  (func (export "run") (result i32)
    (call $ct (i32.const 0) (i32.const {}) (i32.const 256) (i32.const {})
              (i32.const 1024) (i32.const 4096))))"#,
        esc(tool),
        esc(args),
        tool.len(),
        args.len(),
    );
    wat::parse_str(wat).expect("valid wat")
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_module_tool_call_round_trips_through_the_registry() {
    let wasm = guest("config_read", r#"{"path":"server.port"}"#);
    let out = runtime(true).run(&wasm, open()).await.expect("run");
    // {"path":"server.port","value":8443} == 35 bytes of JSON written to guest memory.
    assert_eq!(out.exit_code, 35);
    assert_eq!(out.calls.len(), 1);
    assert_eq!(out.calls[0].tool, "config_read");
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_tool_is_rejected_with_a_distinct_code() {
    let wasm = guest("does_not_exist", "{}");
    let out = runtime(true).run(&wasm, open()).await.expect("run");
    assert_eq!(out.exit_code, abi::E_UNKNOWN_TOOL);
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_required_argument_is_rejected() {
    let wasm = guest("config_read", "{}");
    let out = runtime(true).run(&wasm, open()).await.expect("run");
    assert_eq!(out.exit_code, abi::E_INVALID_ARGS);
}

#[tokio::test(flavor = "multi_thread")]
async fn fuel_limit_stops_a_runaway_module() {
    let wasm = wat::parse_str(
        r#"(module (memory (export "memory") 1)
  (func (export "run") (result i32) (loop $l (br $l)) (i32.const 0)))"#,
    )
    .expect("wat");
    let limits = ModuleLimits {
        fuel: 50_000,
        ..open()
    };
    let err = runtime(true).run(&wasm, limits).await.expect_err("fuel");
    assert!(matches!(err, WasmHostError::FuelExhausted), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn memory_limit_stops_a_greedy_module() {
    let wasm = wat::parse_str(
        r#"(module (memory (export "memory") 1)
  (func (export "run") (result i32) (memory.grow (i32.const 4096))))"#,
    )
    .expect("wat");
    let limits = ModuleLimits {
        max_memory_bytes: 2 * 1024 * 1024,
        ..open()
    };
    let err = runtime(true).run(&wasm, limits).await.expect_err("memory");
    assert!(matches!(err, WasmHostError::MemoryLimit), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn flag_off_means_nothing_runs() {
    let wasm = guest("config_read", r#"{"path":"server.port"}"#);
    let err = runtime(false).run(&wasm, open()).await.expect_err("flag");
    assert!(matches!(err, WasmHostError::FlagDisabled(_)), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn default_limits_deny_every_tool() {
    let wasm = guest("config_read", r#"{"path":"server.port"}"#);
    let out = runtime(true)
        .run(&wasm, ModuleLimits::default())
        .await
        .expect("run");
    assert_eq!(out.exit_code, abi::E_FORBIDDEN);
}
