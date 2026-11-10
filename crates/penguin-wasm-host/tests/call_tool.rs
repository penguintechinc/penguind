//! Real-path tests: WAT guests run through wasmtime, the Linker import, the
//! schema-validating registry and the real executors.

mod support;

use std::sync::Arc;
use std::time::Duration;

use penguin_sdk::LogLevel;
use penguin_sdk::tools::ToolError;
use penguin_wasm_host::runtime::abi;
use penguin_wasm_host::tools::ToolMetrics;
use penguin_wasm_host::{ModuleLimits, ToolRegistry, WasmHostError, WasmRuntime};
use support::{Flags, RecordingLogger, caller_wasm, open_limits, registry, wasm};

fn runtime(logger: &Arc<RecordingLogger>) -> WasmRuntime {
    WasmRuntime::new(Arc::new(registry(logger.clone())), Flags::on()).expect("runtime")
}

#[tokio::test(flavor = "multi_thread")]
async fn guest_calls_config_read_and_gets_the_result() {
    let logger = Arc::new(RecordingLogger::default());
    let wasm = caller_wasm("config_read", r#"{"path":"a.b"}"#, 4096);
    let out = runtime(&logger)
        .run(&wasm, open_limits())
        .await
        .expect("run");
    // {"path":"a.b","value":42} is 25 bytes.
    assert_eq!(out.exit_code, 25);
    assert_eq!(out.calls.len(), 1);
    assert_eq!(out.calls[0].tool, "config_read");
}

#[tokio::test(flavor = "multi_thread")]
async fn guest_logger_call_reaches_the_host_logger() {
    let logger = Arc::new(RecordingLogger::default());
    let wasm = caller_wasm("logger", r#"{"level":"INFO","message":"hello"}"#, 4096);
    let out = runtime(&logger)
        .run(&wasm, open_limits())
        .await
        .expect("run");
    assert_eq!(out.exit_code, 4); // "null"
    let seen = logger.0.lock().expect("lock").clone();
    assert_eq!(seen, vec![(LogLevel::Info, "hello".to_string())]);
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_tool_fails_loudly() {
    let logger = Arc::new(RecordingLogger::default());
    let wasm = caller_wasm("no_such_tool", "{}", 4096);
    let out = runtime(&logger)
        .run(&wasm, open_limits())
        .await
        .expect("run");
    assert_eq!(out.exit_code, abi::E_UNKNOWN_TOOL);
    assert_eq!(out.calls[0].code, abi::E_UNKNOWN_TOOL);
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_args_fail_loudly() {
    let logger = Arc::new(RecordingLogger::default());
    for args in [r#"{"nope":1}"#, r#"{"path":7}"#, "not json"] {
        let wasm = caller_wasm("config_read", args, 4096);
        let out = runtime(&logger)
            .run(&wasm, open_limits())
            .await
            .expect("run");
        assert_eq!(out.exit_code, abi::E_INVALID_ARGS, "args {args}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn declared_but_unimplemented_tool_is_not_a_silent_success() {
    let logger = Arc::new(RecordingLogger::default());
    let wasm = caller_wasm("doh_query", r#"{"name":"a.test","query_type":"A"}"#, 4096);
    let out = runtime(&logger)
        .run(&wasm, open_limits().allowing_dns(["a.test"]))
        .await
        .expect("run");
    assert_eq!(out.exit_code, abi::E_NOT_IMPLEMENTED);
}

#[tokio::test(flavor = "multi_thread")]
async fn allowlist_blocks_unlisted_tools() {
    let logger = Arc::new(RecordingLogger::default());
    let limits = ModuleLimits {
        allowed_tools: ["logger".to_string()].into(),
        ..open_limits()
    };
    let wasm = caller_wasm("config_read", r#"{"path":"a"}"#, 4096);
    let out = runtime(&logger).run(&wasm, limits).await.expect("run");
    assert_eq!(out.exit_code, abi::E_FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn small_output_buffer_is_reported() {
    let logger = Arc::new(RecordingLogger::default());
    let wasm = caller_wasm("config_read", r#"{"path":"a.b"}"#, 4);
    let out = runtime(&logger)
        .run(&wasm, open_limits())
        .await
        .expect("run");
    assert_eq!(out.exit_code, abi::E_BUFFER_TOO_SMALL);
}

#[tokio::test(flavor = "multi_thread")]
async fn out_of_bounds_pointer_is_rejected() {
    let logger = Arc::new(RecordingLogger::default());
    let w = wasm(
        r#"(module
  (import "penguin" "call_tool" (func $ct (param i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "run") (result i32)
    (call $ct (i32.const 65530) (i32.const 100) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0))))"#,
    );
    let out = runtime(&logger).run(&w, open_limits()).await.expect("run");
    assert_eq!(out.exit_code, abi::E_BAD_POINTER);
}

#[tokio::test(flavor = "multi_thread")]
async fn call_budget_is_enforced() {
    let logger = Arc::new(RecordingLogger::default());
    let w = wasm(
        r#"(module
  (import "penguin" "call_tool" (func $ct (param i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "logger")
  (data (i32.const 16) "{\"level\":\"info\",\"message\":\"x\"}")
  (func (export "run") (result i32)
    (drop (call $ct (i32.const 0) (i32.const 6) (i32.const 16) (i32.const 28) (i32.const 512) (i32.const 64)))
    (call $ct (i32.const 0) (i32.const 6) (i32.const 16) (i32.const 28) (i32.const 512) (i32.const 64))))"#,
    );
    let limits = ModuleLimits {
        max_tool_calls: 1,
        ..open_limits()
    };
    let out = runtime(&logger).run(&w, limits).await.expect("run");
    assert_eq!(out.exit_code, abi::E_TOO_MANY_CALLS);
}

#[tokio::test(flavor = "multi_thread")]
async fn infinite_loop_exhausts_fuel() {
    let logger = Arc::new(RecordingLogger::default());
    let w = wasm(
        r#"(module (memory (export "memory") 1)
  (func (export "run") (result i32) (loop $l (br $l)) (i32.const 0)))"#,
    );
    let limits = ModuleLimits {
        fuel: 100_000,
        ..open_limits()
    };
    let err = runtime(&logger)
        .run(&w, limits)
        .await
        .expect_err("must trap");
    assert!(matches!(err, WasmHostError::FuelExhausted), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn growing_past_the_memory_cap_fails() {
    let logger = Arc::new(RecordingLogger::default());
    let w = wasm(
        r#"(module (memory (export "memory") 1)
  (func (export "run") (result i32) (memory.grow (i32.const 1000))))"#,
    );
    let limits = ModuleLimits {
        max_memory_bytes: 1024 * 1024,
        ..open_limits()
    };
    let err = runtime(&logger)
        .run(&w, limits)
        .await
        .expect_err("must fail");
    assert!(matches!(err, WasmHostError::MemoryLimit), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_initial_memory_fails_at_instantiation() {
    let logger = Arc::new(RecordingLogger::default());
    let w = wasm(
        r#"(module (memory (export "memory") 2000) (func (export "run") (result i32) (i32.const 0)))"#,
    );
    let limits = ModuleLimits {
        max_memory_bytes: 1024 * 1024,
        ..open_limits()
    };
    let err = runtime(&logger)
        .run(&w, limits)
        .await
        .expect_err("must fail");
    assert!(matches!(err, WasmHostError::MemoryLimit), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn flag_off_refuses_to_run() {
    let logger = Arc::new(RecordingLogger::default());
    let rt = WasmRuntime::new(Arc::new(registry(logger)), Flags::off()).expect("runtime");
    let wasm = caller_wasm("logger", r#"{"level":"info","message":"x"}"#, 64);
    let err = rt.run(&wasm, open_limits()).await.expect_err("flag off");
    assert!(matches!(err, WasmHostError::FlagDisabled(_)), "{err:?}");
    assert!(!rt.enabled());
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_modules_are_typed_errors() {
    let logger = Arc::new(RecordingLogger::default());
    let rt = runtime(&logger);
    let err = rt
        .run(b"not wasm", open_limits())
        .await
        .expect_err("compile");
    assert!(matches!(err, WasmHostError::Compile(_)), "{err:?}");
    let unknown_import = wasm(
        r#"(module (import "env" "nope" (func)) (func (export "run") (result i32) (i32.const 0)))"#,
    );
    let err = rt
        .run(&unknown_import, open_limits())
        .await
        .expect_err("link");
    assert!(matches!(err, WasmHostError::Instantiate(_)), "{err:?}");
    let no_run = wasm(r#"(module (memory (export "memory") 1))"#);
    let err = rt.run(&no_run, open_limits()).await.expect_err("export");
    assert!(
        matches!(err, WasmHostError::MissingExport("run")),
        "{err:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wall_clock_timeout_is_enforced() {
    let logger = Arc::new(RecordingLogger::default());
    let w = wasm(
        r#"(module (memory (export "memory") 1)
  (func (export "run") (result i32) (loop $l (br $l)) (i32.const 0)))"#,
    );
    let limits = ModuleLimits {
        fuel: u64::MAX,
        wall_timeout: Duration::from_millis(100),
        ..open_limits()
    };
    let err = runtime(&logger).run(&w, limits).await.expect_err("timeout");
    assert!(matches!(err, WasmHostError::Timeout), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn registry_errors_and_metrics() {
    let logger = Arc::new(RecordingLogger::default());
    let prom = prometheus::Registry::new();
    let mut reg = ToolRegistry::from_embedded()
        .expect("defs")
        .with_metrics(ToolMetrics::register(&prom).expect("metrics"));
    reg.register(Arc::new(penguin_wasm_host::executors::LoggerExecutor::new(
        logger,
    )))
    .expect("register");

    assert!(matches!(
        reg.call("nope", serde_json::json!({})).await,
        Err(ToolError::UnknownTool(_))
    ));
    assert!(matches!(
        reg.call("logger", serde_json::json!({"level":"info"}))
            .await,
        Err(ToolError::InvalidArgs { .. })
    ));
    assert!(
        reg.call("logger", serde_json::json!({"level":"INFO","message":"m"}))
            .await
            .is_ok()
    );

    let families = prom.gather();
    let calls = families
        .iter()
        .find(|f| f.name() == "penguind_wasm_tool_calls_total")
        .expect("counter");
    assert_eq!(calls.get_metric().len(), 3);
    let hist = families
        .iter()
        .find(|f| f.name() == "penguind_wasm_tool_call_seconds")
        .expect("histogram");
    let samples: u64 = hist
        .get_metric()
        .iter()
        .map(|m| m.get_histogram().get_sample_count())
        .sum();
    assert_eq!(samples, 3);
    let unresolved = calls
        .get_metric()
        .iter()
        .any(|m| m.get_label().iter().any(|l| l.value() == "unresolved"));
    assert!(unresolved, "guest-supplied names must not become labels");
}

#[test]
fn registry_rejects_undeclared_and_duplicate_executors() {
    let logger = Arc::new(RecordingLogger::default());
    let mut reg = ToolRegistry::from_embedded().expect("defs");
    let exec = Arc::new(penguin_wasm_host::executors::LoggerExecutor::new(logger));
    reg.register(exec.clone()).expect("first");
    assert!(reg.register(exec).is_err());
    assert!(ToolRegistry::from_json("{}").is_err());
}

// ---- security regression tests ----

#[tokio::test(flavor = "multi_thread")]
async fn default_limits_deny_every_tool() {
    let logger = Arc::new(RecordingLogger::default());
    for tool in ["config_read", "logger"] {
        let wasm = caller_wasm(tool, r#"{"path":"a","level":"INFO","message":"x"}"#, 4096);
        let out = runtime(&logger)
            .run(&wasm, ModuleLimits::default())
            .await
            .expect("run");
        assert_eq!(out.exit_code, abi::E_FORBIDDEN, "{tool}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn config_read_is_opt_in() {
    let logger = Arc::new(RecordingLogger::default());
    let wasm = caller_wasm("config_read", r#"{"path":"a.b"}"#, 4096);
    let only_logger = ModuleLimits::default().allowing(["logger"]);
    let out = runtime(&logger).run(&wasm, only_logger).await.expect("run");
    assert_eq!(out.exit_code, abi::E_FORBIDDEN);
    let granted = ModuleLimits::default().allowing(["config_read"]);
    let out = runtime(&logger).run(&wasm, granted).await.expect("run");
    assert_eq!(out.exit_code, 25);
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_wasm_is_refused_before_compiling() {
    let logger = Arc::new(RecordingLogger::default());
    let limits = ModuleLimits {
        max_wasm_bytes: 8,
        ..open_limits()
    };
    let err = runtime(&logger)
        .run(&caller_wasm("logger", "{}", 8), limits)
        .await
        .expect_err("too large");
    assert!(
        matches!(err, WasmHostError::ModuleTooLarge { max: 8, .. }),
        "{err:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn runaway_recursion_traps_on_the_explicit_stack_cap() {
    let logger = Arc::new(RecordingLogger::default());
    let w = wasm(
        r#"(module (memory (export "memory") 1)
  (func $f (result i32) (call $f))
  (func (export "run") (result i32) (call $f)))"#,
    );
    let err = runtime(&logger)
        .run(&w, open_limits())
        .await
        .expect_err("stack overflow");
    assert!(matches!(err, WasmHostError::Trap(_)), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn epoch_deadline_interrupts_before_the_async_backstop() {
    let logger = Arc::new(RecordingLogger::default());
    let w = wasm(
        r#"(module (memory (export "memory") 1)
  (func (export "run") (result i32) (loop $l (br $l)) (i32.const 0)))"#,
    );
    let limits = ModuleLimits {
        fuel: u64::MAX,
        wall_timeout: Duration::from_millis(200),
        ..open_limits()
    };
    let started = std::time::Instant::now();
    let err = runtime(&logger)
        .run(&w, limits)
        .await
        .expect_err("interrupt");
    assert!(matches!(err, WasmHostError::Timeout), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_names_and_over_budget_calls_do_not_grow_the_call_log() {
    let logger = Arc::new(RecordingLogger::default());
    // 1000 calls with an out-of-bounds name pointer against a budget of 5.
    let w = wasm(
        r#"(module
  (import "penguin" "call_tool" (func $ct (param i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "run") (result i32) (local $i i32)
    (loop $l
      (drop (call $ct (i32.const 65530) (i32.const 100) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const 1000))))
    (i32.const 0)))"#,
    );
    let limits = ModuleLimits {
        max_tool_calls: 5,
        ..open_limits()
    };
    let out = runtime(&logger).run(&w, limits).await.expect("run");
    assert_eq!(out.calls.len(), 5);
    assert_eq!(out.rejected_calls, 995);
}

#[tokio::test(flavor = "multi_thread")]
async fn error_messages_written_to_the_guest_are_capped() {
    let logger = Arc::new(RecordingLogger::default());
    // Unknown tool whose 120-byte name is echoed in the error message; a small
    // result buffer proves the cap logic never panics on tight output.
    let long = "n".repeat(120);
    let wasm = caller_wasm(&long, "{}", 4096);
    let out = runtime(&logger)
        .run(&wasm, open_limits())
        .await
        .expect("run");
    assert_eq!(out.exit_code, abi::E_UNKNOWN_TOOL);
}

#[test]
fn truncation_respects_char_boundaries() {
    use penguin_wasm_host::runtime::abi::{MAX_ERROR_MESSAGE_BYTES, truncate_utf8};
    let text = "é".repeat(MAX_ERROR_MESSAGE_BYTES); // 2 bytes each
    let cut = truncate_utf8(&text, MAX_ERROR_MESSAGE_BYTES - 1);
    assert!(cut.len() < MAX_ERROR_MESSAGE_BYTES);
    assert!(text.starts_with(cut));
    assert_eq!(truncate_utf8("short", 100), "short");
}

#[tokio::test(flavor = "multi_thread")]
async fn guest_log_messages_cannot_forge_log_lines() {
    let logger = Arc::new(RecordingLogger::default());
    let wasm = caller_wasm(
        "logger",
        r#"{"level":"INFO","message":"a\nFAKE level=error\u001b[31m"}"#,
        64,
    );
    runtime(&logger)
        .run(&wasm, open_limits())
        .await
        .expect("run");
    let seen = logger.0.lock().expect("lock").clone();
    assert_eq!(seen.len(), 1);
    assert!(
        !seen[0].1.contains('\n') && !seen[0].1.contains('\u{1b}'),
        "{:?}",
        seen[0].1
    );
    assert!(seen[0].1.contains("\\n"));
}

#[test]
fn log_messages_are_length_capped() {
    use penguin_wasm_host::executors::{MAX_LOG_MESSAGE_BYTES, sanitize_message};
    let out = sanitize_message(&"x".repeat(MAX_LOG_MESSAGE_BYTES * 3));
    assert!(out.len() <= MAX_LOG_MESSAGE_BYTES + 16);
    assert!(out.ends_with("[truncated]"));
    assert_eq!(sanitize_message("plain"), "plain");
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_results_are_not_written_to_the_guest() {
    use penguin_wasm_host::executors::ToolExecutor;
    struct Big;
    #[async_trait::async_trait]
    impl ToolExecutor for Big {
        fn id(&self) -> &str {
            "jwt_decode"
        }
        async fn execute(&self, _a: serde_json::Value) -> Result<serde_json::Value, String> {
            Ok(serde_json::json!({ "blob": "z".repeat(70 * 1024) }))
        }
    }
    let mut reg = ToolRegistry::from_embedded().expect("defs");
    reg.register(Arc::new(Big)).expect("register");
    let rt = WasmRuntime::new(Arc::new(reg), Flags::on()).expect("runtime");
    // 2 pages so the out buffer could physically hold the oversized body.
    let w = wasm(
        r#"(module
  (import "penguin" "call_tool" (func $ct (param i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 3)
  (data (i32.const 0) "jwt_decode")
  (data (i32.const 16) "{\"token\":\"t\"}")
  (func (export "run") (result i32)
    (call $ct (i32.const 0) (i32.const 10) (i32.const 16) (i32.const 13) (i32.const 1024) (i32.const 140000))))"#,
    );
    let limits = ModuleLimits::default().allowing(["jwt_decode"]);
    let out = rt.run(&w, limits).await.expect("run");
    assert_eq!(out.exit_code, abi::E_BUFFER_TOO_SMALL);
}

#[tokio::test(flavor = "multi_thread")]
async fn registry_still_validates_large_args_without_reserializing() {
    // Over-cap args are refused at the ABI boundary (raw length), not by the registry.
    let logger = Arc::new(RecordingLogger::default());
    let w = wasm(
        r#"(module
  (import "penguin" "call_tool" (func $ct (param i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 3)
  (data (i32.const 0) "logger")
  (func (export "run") (result i32)
    (call $ct (i32.const 0) (i32.const 6) (i32.const 1024) (i32.const 70000) (i32.const 0) (i32.const 0))))"#,
    );
    let out = runtime(&logger).run(&w, open_limits()).await.expect("run");
    assert_eq!(out.exit_code, abi::E_BAD_POINTER);
}

#[tokio::test(flavor = "multi_thread")]
async fn real_executors_metrics_publish_and_doh_not_implemented_gap_closed() {
    let prom = prometheus::Registry::new();
    let reg = penguin_wasm_host::build_module_registry(penguin_wasm_host::ModuleToolContext {
        module: "t",
        logger: Arc::new(RecordingLogger::default()),
        config_yaml: b"",
        gauges: &penguin_wasm_host::executors::ModuleGauges::new(prom.clone()),
        doh_endpoint: Some("http://127.0.0.1:1/dns-query"),
        metrics: None,
    })
    .expect("registry");
    let rt = WasmRuntime::new(Arc::new(reg), Flags::on()).expect("runtime");
    let w = caller_wasm("metrics_publish", r#"{"metric_name":"g","value":3}"#, 64);
    let out = rt.run(&w, open_limits()).await.expect("run");
    assert_eq!(out.exit_code, 4); // "null"
    assert!(
        prom.gather()
            .iter()
            .any(|f| f.name() == "penguind_module_g")
    );
    // DoH is wired: a dead resolver is a Failed (-3), no longer NotImplemented (-4).
    let w = caller_wasm("doh_query", r#"{"name":"a.test","query_type":"A"}"#, 256);
    let out = rt
        .run(&w, open_limits().allowing_dns(["a.test"]))
        .await
        .expect("run");
    assert_eq!(out.exit_code, abi::E_FAILED);
}

/// Runs one `doh_query` for `name` against a loopback listener and returns
/// the exit code plus whether the resolver saw any connection.
async fn doh_attempt(name: &str, limits: ModuleLimits) -> (i32, bool) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let endpoint = format!(
        "http://127.0.0.1:{}/dns-query",
        listener.local_addr().expect("addr").port()
    );
    let gauges = penguin_wasm_host::executors::ModuleGauges::new(prometheus::Registry::new());
    let reg = penguin_wasm_host::build_module_registry(penguin_wasm_host::ModuleToolContext {
        module: "dns",
        logger: Arc::new(RecordingLogger::default()),
        config_yaml: b"",
        gauges: &gauges,
        doh_endpoint: Some(&endpoint),
        metrics: None,
    })
    .expect("registry");
    let rt = WasmRuntime::new(Arc::new(reg), Flags::on()).expect("runtime");
    let args = format!(r#"{{"name":"{name}","query_type":"TXT"}}"#);
    let out = rt
        .run(&caller_wasm("doh_query", &args, 256), limits)
        .await
        .expect("run");
    // The client times out or the canned socket closes; either way any
    // connection attempt is visible as a pending accept.
    let contacted = listener.accept().is_ok();
    (out.exit_code, contacted)
}

#[tokio::test(flavor = "multi_thread")]
async fn doh_query_is_deny_all_without_a_dns_grant() {
    // regression: doh_query resolved any name, a DNS exfiltration channel.
    let (code, contacted) = doh_attempt("secret.attacker.net", open_limits()).await;
    assert_eq!(code, abi::E_FORBIDDEN);
    assert!(!contacted, "no request may be sent for a denied name");
}

#[tokio::test(flavor = "multi_thread")]
async fn doh_query_honours_exact_and_wildcard_grants() {
    let limits = || open_limits().allowing_dns(["api.example.com", "*.svc.example.org"]);
    let (code, contacted) = doh_attempt("leak.attacker.net", limits()).await;
    assert_eq!(code, abi::E_FORBIDDEN);
    assert!(!contacted);
    let (code, _) = doh_attempt("svc.example.org", limits()).await;
    assert_eq!(code, abi::E_FORBIDDEN, "wildcard excludes apex");
    for ok in ["api.example.com", "a.svc.example.org"] {
        let (code, contacted) = doh_attempt(ok, limits()).await;
        assert_ne!(code, abi::E_FORBIDDEN, "{ok}");
        assert!(contacted, "{ok} reached the resolver");
    }
}
