//! The wasmtime runtime: engine, per-module bounded `Store`, and the
//! `penguin.call_tool` host import.
//!
//! Guest ABI (core module):
//! - export `memory` and `run() -> i32`
//! - import `penguin.call_tool(name_ptr, name_len, args_ptr, args_len, out_ptr,
//!   out_cap) -> i32`: result is the JSON byte length written to `out` (>= 0),
//!   or a negative [`abi`] code; on error a `{"error":{..}}` body is written to
//!   `out` when it fits. Every failure is also recorded in [`RunOutcome::calls`]
//!   and logged/counted, so a guest ignoring a negative code is still visible.

pub mod abi;
mod limits;

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use penguin_sdk::LicenseChecker;
use wasmtime::{Caller, Config, Engine, Extern, Linker, Module, Store, Trap};

use crate::error::WasmHostError;
use crate::tools::ToolRegistry;

pub use limits::ModuleLimits;
use limits::StoreLimiter;

/// PostHog flag gating the whole WASM module subsystem (unseen = OFF).
pub const WASM_MODULES_FLAG: &str = "penguind.wasm-modules";

/// One tool call a module made, as seen by the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRecord {
    /// The tool name the guest asked for (guest-supplied; never a metric label).
    pub tool: String,
    /// The ABI result code (`>= 0` = bytes written, `< 0` = an [`abi`] error).
    pub code: i32,
}

/// The result of running a module to completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    /// What the guest's `run` returned.
    pub exit_code: i32,
    /// The tool calls made, in order; never longer than the call budget.
    pub calls: Vec<CallRecord>,
    /// Calls refused after the budget was spent (counted, never recorded one by one).
    pub rejected_calls: u64,
}

pub(crate) struct HostState {
    registry: Arc<ToolRegistry>,
    allowed: Arc<HashSet<String>>,
    limiter: StoreLimiter,
    calls: Vec<CallRecord>,
    attempts: u64,
    rejected: u64,
    max_calls: u32,
}

/// Epoch tick period; the ticker thread bumps the engine epoch at this rate.
const EPOCH_TICK: Duration = Duration::from_millis(10);
/// Extra wall time the async backstop waits after the epoch deadline, so a
/// guest trapped by the epoch is reported before the outer timeout drops it.
const BACKSTOP_GRACE: Duration = Duration::from_secs(1);
/// Explicit cap on guest native stack depth (wasmtime's default is not a contract).
const MAX_WASM_STACK: usize = 512 * 1024;
/// Stack given to each async fiber; must exceed [`MAX_WASM_STACK`].
const ASYNC_STACK: usize = 1024 * 1024;

/// Compiles and runs flag-gated, resource-bounded WASM modules.
pub struct WasmRuntime {
    engine: Engine,
    registry: Arc<ToolRegistry>,
    license: Arc<dyn LicenseChecker>,
    stop_ticker: Arc<AtomicBool>,
}

impl Drop for WasmRuntime {
    /// Stops the epoch ticker thread so it does not outlive the runtime.
    fn drop(&mut self) {
        self.stop_ticker.store(true, Ordering::Relaxed);
    }
}

impl WasmRuntime {
    /// Creates a runtime over a tool registry; `license` supplies the flag check.
    pub fn new(
        registry: Arc<ToolRegistry>,
        license: Arc<dyn LicenseChecker>,
    ) -> Result<Self, WasmHostError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        config.max_wasm_stack(MAX_WASM_STACK);
        config.async_stack_size(ASYNC_STACK);
        let engine = Engine::new(&config).map_err(|e| WasmHostError::Engine(e.to_string()))?;
        let stop_ticker = Arc::new(AtomicBool::new(false));
        spawn_epoch_ticker(engine.clone(), stop_ticker.clone())?;
        Ok(Self {
            engine,
            registry,
            license,
            stop_ticker,
        })
    }

    /// Reports whether `penguind.wasm-modules` is on right now.
    pub fn enabled(&self) -> bool {
        self.license.feature_enabled(WASM_MODULES_FLAG)
    }

    /// Runs the module's `run` export under `limits`. Fails with
    /// [`WasmHostError::FlagDisabled`] before touching the bytes when the flag is off.
    pub async fn run(
        &self,
        wasm: &[u8],
        limits: ModuleLimits,
    ) -> Result<RunOutcome, WasmHostError> {
        if !self.enabled() {
            return Err(WasmHostError::FlagDisabled(WASM_MODULES_FLAG));
        }
        if wasm.len() > limits.max_wasm_bytes {
            return Err(WasmHostError::ModuleTooLarge {
                size: wasm.len(),
                max: limits.max_wasm_bytes,
            });
        }
        let module = self.compile(wasm, limits.wall_timeout).await?;
        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        linker
            .func_wrap_async(
                "penguin",
                "call_tool",
                |caller: Caller<'_, HostState>, params: (i32, i32, i32, i32, i32, i32)| {
                    Box::new(abi::call_tool(caller, params))
                },
            )
            .map_err(|e| WasmHostError::Engine(e.to_string()))?;

        let state = HostState {
            registry: self.registry.clone(),
            allowed: Arc::new(limits.allowed_tools.clone()),
            limiter: StoreLimiter::new(limits.max_memory_bytes),
            calls: Vec::new(),
            attempts: 0,
            rejected: 0,
            max_calls: limits.max_tool_calls,
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limiter);
        store
            .set_fuel(limits.fuel)
            .map_err(|e| WasmHostError::Engine(e.to_string()))?;
        store
            .fuel_async_yield_interval(Some(10_000))
            .map_err(|e| WasmHostError::Engine(e.to_string()))?;
        store.set_epoch_deadline(ticks_for(limits.wall_timeout));

        let wall = limits.wall_timeout;
        let work = async {
            let instance = linker
                .instantiate_async(&mut store, &module)
                .await
                .map_err(|e| classify(e, &store, true))?;
            let run = instance
                .get_typed_func::<(), i32>(&mut store, "run")
                .map_err(|_| WasmHostError::MissingExport("run"))?;
            let exit_code = run
                .call_async(&mut store, ())
                .await
                .map_err(|e| classify(e, &store, false))?;
            Ok::<i32, WasmHostError>(exit_code)
        };
        // The epoch deadline traps the guest at `wall`; this outer timeout is
        // the backstop for a host call that is not interruptible by epochs.
        let exit_code = match tokio::time::timeout(wall + BACKSTOP_GRACE, work).await {
            Ok(result) => result?,
            Err(_) => return Err(WasmHostError::Timeout),
        };
        let data = store.data_mut();
        let calls = std::mem::take(&mut data.calls);
        let rejected_calls = data.rejected;
        Ok(RunOutcome {
            exit_code,
            calls,
            rejected_calls,
        })
    }

    /// Compiles untrusted bytes on the blocking pool under the wall-clock
    /// budget, so a pathological module cannot stall the async runtime.
    /// A timed-out compile is abandoned (wasmtime cannot cancel it mid-flight)
    /// but the caller gets [`WasmHostError::Timeout`] immediately.
    async fn compile(&self, wasm: &[u8], budget: Duration) -> Result<Module, WasmHostError> {
        let engine = self.engine.clone();
        let bytes = wasm.to_vec();
        let job = tokio::task::spawn_blocking(move || Module::new(&engine, &bytes));
        match tokio::time::timeout(budget, job).await {
            Err(_) => Err(WasmHostError::Timeout),
            Ok(Err(join)) => Err(WasmHostError::Compile(format!(
                "compile task failed: {join}"
            ))),
            Ok(Ok(Err(e))) => Err(WasmHostError::Compile(e.to_string())),
            Ok(Ok(Ok(module))) => Ok(module),
        }
    }
}

/// Converts a wall-clock budget into epoch ticks (at least one).
fn ticks_for(wall: Duration) -> u64 {
    let ticks = wall.as_millis() / EPOCH_TICK.as_millis();
    u64::try_from(ticks).unwrap_or(u64::MAX).max(1)
}

/// Starts the thread that advances the engine epoch until `stop` is set.
/// Epoch interruption lets the host stop a guest from outside the store.
fn spawn_epoch_ticker(engine: Engine, stop: Arc<AtomicBool>) -> Result<(), WasmHostError> {
    std::thread::Builder::new()
        .name("wasm-epoch-ticker".into())
        .spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(EPOCH_TICK);
                engine.increment_epoch();
            }
        })
        .map(|_| ())
        .map_err(|e| WasmHostError::Engine(format!("epoch ticker: {e}")))
}

/// Maps a wasmtime failure to a typed error, checking the memory-limit flag
/// first because a refused `memory.grow` surfaces as a generic trap/error.
fn classify(err: wasmtime::Error, store: &Store<HostState>, instantiating: bool) -> WasmHostError {
    if store.data().limiter.tripped() {
        return WasmHostError::MemoryLimit;
    }
    match err.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => return WasmHostError::FuelExhausted,
        Some(Trap::Interrupt) => return WasmHostError::Timeout,
        _ => {}
    }
    if instantiating {
        WasmHostError::Instantiate(err.to_string())
    } else {
        WasmHostError::Trap(err.to_string())
    }
}

/// Wall-clock default used by [`ModuleLimits::default`].
pub(crate) const DEFAULT_WALL: Duration = Duration::from_secs(10);

pub(crate) fn memory_of(caller: &mut Caller<'_, HostState>) -> Option<wasmtime::Memory> {
    caller.get_export("memory").and_then(Extern::into_memory)
}

impl HostState {
    pub(crate) fn registry(&self) -> Arc<ToolRegistry> {
        self.registry.clone()
    }
    pub(crate) fn allowed(&self) -> Arc<HashSet<String>> {
        self.allowed.clone()
    }
    /// Appends a call record; the vector can never outgrow the call budget.
    pub(crate) fn record(&mut self, tool: String, code: i32) {
        if self.calls.len() < self.max_calls as usize {
            self.calls.push(CallRecord { tool, code });
        }
    }
    /// Counts one call attempt and reports whether it fits the budget. Every
    /// attempt (including malformed ones) is charged; over-budget attempts only
    /// bump a counter, so guest-driven memory use stays bounded.
    pub(crate) fn begin_call(&mut self) -> bool {
        if self.attempts >= u64::from(self.max_calls) {
            self.rejected = self.rejected.saturating_add(1);
            return false;
        }
        self.attempts += 1;
        true
    }
}
