# WASM Modules

WASM guests run sandboxed business logic and reach the daemon only through `penguin.call_tool` tool calls. Status as of 2026-11-09.

## Roadmap

Source: `.PLAN` (roadmap) and `~/.claude/plans/where-are-we-on-imperative-lynx.md` (status). "Tree check" is the observed working tree; the plan status predates it. Compile and test results were not re-run.

| Phase | Item | Plan status | Tree check |
|---|---|---|---|
| P1 | Universal tool schema | Partial, untracked | `crates/penguin-sdk/src/schemas/tool_definitions.json`, 11 tools, untracked |
| P1 | Executors + async registry | Written, not compiled | Moved into `crates/penguin-wasm-host` (`ToolRegistry`, `LoggerExecutor`, `ConfigReadExecutor`); untracked |
| P1 | Shared-memory arena | Not started | Not started (no code found) |
| P2 | Fetcher, signature + SHA verifier | Written, not compiled | `crates/penguin-wasm-host/src/distribution/` (minisign/Ed25519 + SHA-256) |
| P2 | Network gatekeeper (FQDN/CIDR) | Written, not compiled | `distribution/network_gatekeeper.rs`, default-deny except loopback |
| P3 | CI module pipeline | Broken | `.github/workflows/module_pipeline.yml` uses `wasm32-wasip1`; untracked, not yet proven green |
| P3 | Build, test, publish to `packages/` | Not started | Not verified |
| P4 | Wasmtime runtime + `call_tool` import | Engine + Linker only | Implemented: `WasmRuntime::run` in `runtime/mod.rs`, fuel + memory + wall-clock caps |
| P4 | Module SDK `call_tool` | Calls missing method | `HostServices::call_tool` default method in `crates/penguin-sdk/src/host.rs`; `plugin/host_capability.rs` wraps it |
| P4 | MPSC control-plane queue | Not in plan status | Not started (no `mpsc` code in the wasm path) |
| P4 | Finalize + release SDK | Not started | Not started; `penguin-wasm-host` is `publish = false` |
| P5 | Migrate `squawk`, `tobogganing` | Not started | `modules/squawk` exists; migration not started |
| P5 | Red-team audit | Not started | Not started |

Next steps, from the plan: wire the host into the daemon behind the flag (only the integration test uses it today), add the MPSC queue, add OTel spans per tool call, then run the red-team audit.

## Architecture

```text
guest.wasm  --penguin.call_tool(name, json_args)-->  penguin-wasm-host
                                                      |- flag check   penguind.wasm-modules
                                                      |- allowlist    per-module tool ids
                                                      |- ToolRegistry schema-validated, from tool_definitions.json
                                                      |- executor     logger, config_read, ...
                                                      `- limits       fuel, memory, wall clock, call count
```

| Component | Location | Role |
|---|---|---|
| Host crate | `crates/penguin-wasm-host` | wasmtime runtime, registry, executors, distribution |
| Host import | `penguin.call_tool` (`runtime/mod.rs`, `runtime/abi.rs`) | Single import; ptr/len marshalling |
| Tool schema | `crates/penguin-sdk/src/schemas/tool_definitions.json` | Tool ids, argument schemas, return types |
| SDK client | `crates/penguin-sdk/src/host.rs`, `plugin/host_capability.rs` | `HostServices::call_tool` and typed wrappers |
| Flag | PostHog `penguind.wasm-modules` | Gates all execution; unseen = OFF |

ABI details (import signature, result and error codes, guest memory layout, `MAX_ARGS_BYTES`): see crate docs in `crates/penguin-wasm-host/src/lib.rs`, `runtime/mod.rs`, and `runtime/abi.rs`. The ABI is a core-module ptr/len import, not the WIT component model.

### Tools (schema ids)

| Tool | Needs network | Offline |
|---|---|---|
| `config_read` | No | Yes |
| `logger` | No | Yes |
| `temp_dir` | No | Yes |
| `jwt_decode` | No | Yes |
| `metrics_publish` | Exporter | Not verified |
| `license_verify` | License server on miss | Cached value only; not verified |
| `doh_query`, `dns_forward`, `http_request` | Yes | No |
| `wireguard_kernel_ctrl` | No (kernel netlink) | Not verified (local netlink) |
| `wireguard_userspace_handshake` | Yes (peer endpoint) | No |

### Limits

| Limit | Default | Source |
|---|---|---|
| Fuel | 50,000,000 | `runtime/limits.rs` |
| Linear memory | 16 MiB | `runtime/limits.rs` |
| Wall clock (instantiate + run) | 10 s | `runtime/mod.rs` `DEFAULT_WALL` |
| Tool calls per run | 256 | `runtime/limits.rs` |
| Tool allowlist | Per module (`None` = all declared) | `ModuleLimits` |

Exceeding fuel, memory, wall clock, or the call budget fails the run with a typed error. Each run uses a fresh store, so no state carries between runs.

### Feature flag

- `penguind.wasm-modules` gates `WasmRuntime::run`. When off, the bytes are not compiled.
- Flag keys follow `{product}.{feature-name}` (`critical-rules.md` Feature Flags).
- Default OFF until validated.

### Reference: Waddles connector host

- Source: `~/code/waddles/docs/connector-host-capability.md` (issue #840, "B0").
- Same pattern: pinned guest digest, fresh bounded store per call, fuel + epoch + memory caps, typed error classes.
- Waddles uses the WIT component model (`waddle:connector@1.0.0`). penguind uses the core-module ABI above. Differences are intentional until the crate moves to WIT.

## Offline behavior

Required by `rules/client.md` Offline Mode. Document in README and UI when the daemon ships. Status: not yet in the README.

| Feature | Offline | Notes |
|---|---|---|
| Module execution, local tools | Works | Requires no network |
| Network tools (`doh_query`, `dns_forward`, `http_request`) | Fails | Surface error to the user; no silent fallback |
| Feature flag `penguind.wasm-modules` | Works from cache | Last-known value; never-seen flags are OFF |
| License checks | Works from cache | Offline cache under `state_dir/license` |
| Signature and SHA verification | Works | Local public key; no network |
| Network gatekeeper | Works | Local allowlist |
| Fetch new module from GitHub | Fails | Requires connectivity |
| Telemetry export | Buffered or dropped | Not verified; must never fail the request |

## See Also

- `.PLAN` (local, gitignored) — roadmap source
- `crates/penguin-wasm-host/src/lib.rs` — crate overview
- `~/code/waddles/docs/connector-host-capability.md` — Waddles reference
