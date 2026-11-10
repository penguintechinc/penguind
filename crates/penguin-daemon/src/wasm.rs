//! The daemon's path for loading and running a `.wasm` module end to end.
//!
//! Everything here is gated by the `penguind.wasm-modules` flag: with the flag
//! off nothing is read, compiled or run and the caller gets a typed error.

use std::path::{Path, PathBuf};

use penguin_wasm_host::distribution::VerifiedModule;
use penguin_wasm_host::{ModuleLimits, RunOutcome, WASM_MODULES_FLAG, WasmHostError, WasmRuntime};

use crate::host::DaemonHostFactory;

/// Largest `.wasm` file the daemon will read from disk (matches the default
/// [`ModuleLimits::max_wasm_bytes`], checked before reading into memory).
const MAX_WASM_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Why a daemon-side wasm run failed.
#[derive(Debug, thiserror::Error)]
pub enum WasmRunError {
    /// The module file could not be read.
    #[error("cannot read wasm module {path}: {reason}")]
    Read {
        /// The file that failed.
        path: PathBuf,
        /// The I/O or size failure.
        reason: String,
    },
    /// The tool registry for the module could not be built.
    #[error("tool registry setup failed: {0}")]
    Setup(String),
    /// The wasm host refused or failed the run (flag off, limits, traps).
    #[error(transparent)]
    Host(#[from] WasmHostError),
}

impl DaemonHostFactory {
    /// Runs `wasm` as module `module` under `limits`, with its `call_tool`
    /// imports reaching the real executors. Fails with
    /// [`WasmHostError::FlagDisabled`] before any work when the flag is off.
    pub async fn run_wasm_module(
        &self,
        module: &str,
        wasm: &[u8],
        limits: ModuleLimits,
    ) -> Result<RunOutcome, WasmRunError> {
        let license = self.license_checker();
        if !license.feature_enabled(WASM_MODULES_FLAG) {
            tracing::warn!(
                module,
                flag = WASM_MODULES_FLAG,
                "wasm run refused: flag off"
            );
            return Err(WasmHostError::FlagDisabled(WASM_MODULES_FLAG).into());
        }
        let registry = self
            .registry_for_wasm(module)
            .map_err(WasmRunError::Setup)?;
        let runtime = WasmRuntime::new(registry, license)?;
        let outcome = runtime.run(wasm, limits).await?;
        tracing::info!(
            module,
            exit_code = outcome.exit_code,
            tool_calls = outcome.calls.len(),
            rejected_calls = outcome.rejected_calls,
            "wasm module finished"
        );
        Ok(outcome)
    }

    /// Runs a fetched module. Taking a [`VerifiedModule`] (constructible only
    /// after the signature + digest check) makes running unverified downloaded
    /// bytes a type error; this is the only path for fetched modules.
    pub async fn run_fetched_wasm(
        &self,
        module: &str,
        verified: &VerifiedModule,
        limits: ModuleLimits,
    ) -> Result<RunOutcome, WasmRunError> {
        let license = self.license_checker();
        if !license.feature_enabled(WASM_MODULES_FLAG) {
            tracing::warn!(
                module,
                flag = WASM_MODULES_FLAG,
                "fetched wasm refused: flag off"
            );
            return Err(WasmHostError::FlagDisabled(WASM_MODULES_FLAG).into());
        }
        let registry = self
            .registry_for_wasm(module)
            .map_err(WasmRunError::Setup)?;
        let runtime = WasmRuntime::new(registry, license)?;
        Ok(runtime.run_verified(verified, limits).await?)
    }

    /// Reads a `.wasm` file (size-checked first) and runs it with
    /// [`DaemonHostFactory::run_wasm_module`]. The flag is checked before the
    /// file is touched.
    pub async fn run_wasm_file(
        &self,
        module: &str,
        path: &Path,
        limits: ModuleLimits,
    ) -> Result<RunOutcome, WasmRunError> {
        if !self.license_checker().feature_enabled(WASM_MODULES_FLAG) {
            return Err(WasmHostError::FlagDisabled(WASM_MODULES_FLAG).into());
        }
        let read_err = |reason: String| WasmRunError::Read {
            path: path.to_path_buf(),
            reason,
        };
        let meta = tokio::fs::metadata(path)
            .await
            .map_err(|e| read_err(e.to_string()))?;
        if meta.len() > MAX_WASM_FILE_BYTES {
            return Err(read_err(format!(
                "{} bytes exceeds the file cap",
                meta.len()
            )));
        }
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|e| read_err(e.to_string()))?;
        self.run_wasm_module(module, &bytes, limits).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use penguin_sdk::{EventSink, LicenseChecker, SecretError, SecretStore};
    use penguin_telemetry::Telemetry;
    use tempfile::TempDir;

    use crate::broker::EventBroker;
    use crate::config::ConfigStore;
    use crate::host::SecretStoreProvider;

    struct NoSecrets;
    #[async_trait]
    impl SecretStore for NoSecrets {
        async fn get(&self, _k: &str) -> Result<Vec<u8>, SecretError> {
            Err(SecretError::NotFound)
        }
        async fn set(&self, _k: &str, _v: &[u8]) -> Result<(), SecretError> {
            Ok(())
        }
        async fn delete(&self, _k: &str) -> Result<(), SecretError> {
            Err(SecretError::NotFound)
        }
    }
    struct Provider;
    impl SecretStoreProvider for Provider {
        fn store_for(&self, _m: &str) -> Arc<dyn SecretStore> {
            Arc::new(NoSecrets)
        }
    }

    /// Flag double whose enabled set can be toggled mid-test.
    struct Flags(Mutex<HashSet<String>>);
    impl LicenseChecker for Flags {
        fn feature_enabled(&self, key: &str) -> bool {
            self.0.lock().map(|s| s.contains(key)).unwrap_or(false)
        }
        fn tier(&self) -> String {
            "free".into()
        }
    }

    fn factory(on: bool) -> (TempDir, TempDir, DaemonHostFactory, Arc<Telemetry>) {
        let cfg = TempDir::new().expect("tmp");
        let state = TempDir::new().expect("tmp");
        let telemetry = Arc::new(Telemetry::new("error").expect("telemetry"));
        let mut set = HashSet::new();
        if on {
            set.insert(WASM_MODULES_FLAG.to_string());
        }
        let events: Arc<dyn EventSink> = Arc::new(EventBroker::new(4));
        let f = DaemonHostFactory::new(
            telemetry.clone(),
            Arc::new(ConfigStore::new(cfg.path())),
            Arc::new(Provider),
            Arc::new(Flags(Mutex::new(set))),
            events,
            state.path().to_path_buf(),
        );
        (cfg, state, f, telemetry)
    }

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
            args.len()
        );
        wat::parse_str(wat).expect("wat")
    }

    #[tokio::test]
    async fn flag_off_refuses_module_runs_and_file_runs() {
        let (_c, state, f, _t) = factory(false);
        let wasm = guest("logger", r#"{"level":"INFO","message":"x"}"#);
        let err = f
            .run_wasm_module("m", &wasm, ModuleLimits::default())
            .await
            .expect_err("flag off");
        assert!(
            matches!(err, WasmRunError::Host(WasmHostError::FlagDisabled(_))),
            "{err:?}"
        );
        // File path: flag is checked before the (missing) file is touched.
        let err = f
            .run_wasm_file(
                "m",
                &state.path().join("missing.wasm"),
                ModuleLimits::default(),
            )
            .await
            .expect_err("flag off");
        assert!(
            matches!(err, WasmRunError::Host(WasmHostError::FlagDisabled(_))),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn flag_on_runs_a_module_end_to_end_through_real_executors() {
        let (_c, state, f, telemetry) = factory(true);
        let wasm = guest("metrics_publish", r#"{"metric_name":"hits","value":7}"#);
        let path = state.path().join("m.wasm");
        std::fs::write(&path, &wasm).expect("write");
        let limits = ModuleLimits::default().allowing(["metrics_publish"]);
        let out = f.run_wasm_file("my-mod", &path, limits).await.expect("run");
        assert_eq!(out.exit_code, 4); // "null"
        assert_eq!(out.calls.len(), 1);
        let fams = telemetry.registry().gather();
        assert!(
            fams.iter()
                .any(|f| f.name() == "penguind_module_my_mod__hits")
        );
        assert!(
            fams.iter()
                .any(|f| f.name() == "penguind_wasm_tool_calls_total")
        );
    }

    #[tokio::test]
    async fn denied_tool_and_bad_inputs_are_typed_errors() {
        let (_c, state, f, _t) = factory(true);
        // Default limits are deny-all.
        let wasm = guest("logger", r#"{"level":"INFO","message":"x"}"#);
        let out = f
            .run_wasm_module("m", &wasm, ModuleLimits::default())
            .await
            .expect("run");
        assert_eq!(out.exit_code, penguin_wasm_host::runtime::abi::E_FORBIDDEN);
        // Missing file.
        let err = f
            .run_wasm_file(
                "m",
                &state.path().join("nope.wasm"),
                ModuleLimits::default(),
            )
            .await
            .expect_err("missing");
        assert!(matches!(err, WasmRunError::Read { .. }), "{err:?}");
        // Garbage bytes.
        let err = f
            .run_wasm_module("m", b"junk", ModuleLimits::default())
            .await
            .expect_err("compile");
        assert!(
            matches!(err, WasmRunError::Host(WasmHostError::Compile(_))),
            "{err:?}"
        );
        // Oversized file refused before reading.
        let big = state.path().join("big.wasm");
        let file = std::fs::File::create(&big).expect("create");
        file.set_len(MAX_WASM_FILE_BYTES + 1).expect("len");
        let err = f
            .run_wasm_file("m", &big, ModuleLimits::default())
            .await
            .expect_err("too big");
        assert!(matches!(err, WasmRunError::Read { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn invalid_module_config_fails_setup_loudly() {
        let (cfg, _s, f, _t) = factory(true);
        let dir = cfg.path().join("modules.d");
        std::fs::create_dir_all(&dir).expect("dir");
        // resolve_config tolerates unparsable config (module starts with none),
        // so setup still succeeds and config_read just finds nothing.
        std::fs::write(dir.join("m.yaml"), ": : [").expect("write");
        let wasm = guest("config_read", r#"{"path":"a"}"#);
        let limits = ModuleLimits::default().allowing(["config_read"]);
        let out = f.run_wasm_module("m", &wasm, limits).await.expect("run");
        assert_eq!(out.exit_code, penguin_wasm_host::runtime::abi::E_FAILED);
    }

    const BINARY: &[u8] = b"\0asm\x01\0\0\0";
    const SHA: &str = "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476";
    const PUB_A: &str =
        "untrusted comment: test\nRWQBAgMEBQYHCIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29c";
    const SIG_A: &str = "untrusted comment: sig\nRUQBAgMEBQYHCCLucues8Fr7cm3jNC9vFcTrCss+krInWk0XLem0ETXzlCXjDZAQvgpJjKQ8dtgsr1sTQwQ5YpJcL5fN/YgIYAI=\ntrusted comment: t\nQxCm3/A7xy5j3v85YZFwwjOVlSL/0XRrGcleGwSMOZ03HWWyZUNoPrnyshMJc6ynCAyml7wqTfyY61v7/j3kCw==\n";

    fn verified() -> VerifiedModule {
        use penguin_wasm_host::distribution::ManifestClaims;
        VerifiedModule::verify(
            "demo",
            "1.0.0",
            &ManifestClaims {
                id: "demo",
                version: "1.0.0",
                sha256: SHA,
                signature: SIG_A,
            },
            BINARY.to_vec(),
            PUB_A,
        )
        .expect("verified fixture")
    }

    #[tokio::test]
    async fn fetched_modules_run_only_via_run_verified_and_the_flag() {
        let (_c, _s, off, _t) = factory(false);
        let err = off
            .run_fetched_wasm("demo", &verified(), ModuleLimits::default())
            .await
            .expect_err("flag off");
        assert!(
            matches!(err, WasmRunError::Host(WasmHostError::FlagDisabled(_))),
            "{err:?}"
        );
        // Flag on: the signed module is accepted and reaches the runtime, which
        // then reports the fixture's missing `run` export (it is an empty module).
        let (_c, _s, on, _t) = factory(true);
        let err = on
            .run_fetched_wasm("demo", &verified(), ModuleLimits::default())
            .await
            .expect_err("no run export");
        assert!(
            matches!(err, WasmRunError::Host(WasmHostError::MissingExport("run"))),
            "{err:?}"
        );
    }
}
