//! The actual run loop: dial the daemon, build the command tree, parse, and
//! dispatch to a handler. Every handler below is a few lines of I/O around a
//! `penguin-cli-core` pure function — see that crate for the logic being
//! exercised.

use std::future::Future;
use std::io::Write as _;
use std::process::ExitCode;
use std::time::Duration;

use clap::ArgMatches;
use penguin_cli_core::pb;
use penguin_cli_core::pb::daemon_client::DaemonClient;
use tonic::Status;
use tonic::transport::Channel;

/// This binary's own version, injected at compile time — the `penguin
/// version %s` line's argument, matching `version.Version` in Go.
const LOCAL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Timeout for dialing the daemon's control socket. Matches the
/// `context.WithTimeout(context.Background(), 3*time.Second)` Go's `run()`
/// wraps `ipc.Dial` in — largely academic for a Unix-domain `connect(2)`,
/// which fails or succeeds immediately rather than hanging, but kept for the
/// same "never let a broken daemon hang the CLI forever" reason Go has it.
const DIAL_TIMEOUT: Duration = Duration::from_secs(3);
/// Timeout for the best-effort `ListCommands` call that builds the dynamic
/// tree. Matches Go's `dynamicCtx` in `run()` exactly — deliberately short,
/// since a slow daemon here should degrade to the static-only tree rather
/// than delay every single CLI invocation.
const DISCOVERY_TIMEOUT: Duration = Duration::from_millis(300);
/// Timeout for `Version`. Matches Go's `cmdVersion`.
const VERSION_TIMEOUT: Duration = Duration::from_secs(1);
/// Timeout shared by `ListModules`, `LoadModule`, `UnloadModule`,
/// `GetStatus`, and `CheckUpdate`. Matches Go's corresponding `RunE`
/// functions, all of which use the same 5-second context.
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(5);
/// Timeout for establishing the `TailLogs`/`Dispatch` streams. Matches Go's
/// `cmdLogs`/`Builder.dispatch` context length — but, unlike Go, only for
/// *establishing* the stream. Go reuses the same context for the entire
/// receive loop, which means a Go `logs --follow` session is silently cut
/// off after 30 seconds by its own context expiring (swallowed by the same
/// `if err != nil { break }` documented in docs/PARITY.md §1.11). That is an
/// accidental limitation, not a feature worth reproducing, so Rust's receive
/// loops run with no deadline once the stream is open.
const STREAM_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout for `ApplyUpdate`. Matches Go's `cmdUpdate` apply-phase context.
const APPLY_UPDATE_TIMEOUT: Duration = Duration::from_secs(60);

/// Runs `future` with a deadline, collapsing a timeout into
/// `Status::deadline_exceeded` so every call site can handle "the daemon
/// didn't answer in time" through the same `Result<_, Status>` path as any
/// other RPC failure.
async fn with_timeout<T>(
    duration: Duration,
    future: impl Future<Output = Result<T, Status>>,
) -> Result<T, Status> {
    match tokio::time::timeout(duration, future).await {
        Ok(result) => result,
        Err(_elapsed) => Err(Status::deadline_exceeded("request timed out")),
    }
}

/// True for exactly `pdcli --version` or `pdcli -V` — checked against the
/// raw args before the daemon is dialed or clap parses anything, mirroring
/// `penguind`'s `is_version_request` (`bins/penguind/src/main.rs`) so all
/// three binaries answer the flag instantly and identically. The `version`
/// *subcommand* is untouched: it additionally reports the daemon's version
/// and requires a live connection, so it stays on the normal dial-then-
/// dispatch path in [`run`].
fn is_version_flag(args: &[String]) -> bool {
    args.len() == 1 && (args[0] == "--version" || args[0] == "-V")
}

/// Runs the CLI end to end: resolve the socket path, dial the daemon (best
/// effort — see [`dial`]), build the command tree (static verbs always,
/// dynamic module subtrees only if the daemon answered), parse `args`
/// against it, and dispatch to whichever verb or module command matched.
pub async fn run(args: Vec<String>) -> ExitCode {
    if is_version_flag(&args[1..]) {
        println!("{LOCAL_VERSION}");
        return ExitCode::SUCCESS;
    }

    let socket_path = penguin_cli_core::socket::extract_socket_override(&args[1..])
        .unwrap_or_else(|| penguin_cli_core::socket::DEFAULT_SOCKET_PATH.to_string());

    let mut client = dial(&socket_path).await;

    let mut root = penguin_cli_core::tree::build_static_root();
    let mut modules: Vec<pb::ModuleCommands> = Vec::new();
    if let Some(daemon_client) = client.as_mut() {
        match with_timeout(DISCOVERY_TIMEOUT, fetch_modules(daemon_client)).await {
            Ok(fetched) => {
                root = penguin_cli_core::tree::graft_modules(root, &fetched);
                modules = fetched;
            }
            // Deliberate divergence from Go, which discards this exact
            // error and silently falls back to the static-only tree (see
            // docs/PARITY.md). Rust still falls back — the daemon is
            // reachable but this one call failed, so static verbs and
            // --help should keep working — but it tells the operator why
            // the module commands are missing instead of staying silent.
            Err(status) => eprintln!(
                "penguin: warning: could not list module commands: {}",
                penguin_cli_core::error::friendly_status_message(&status, &socket_path)
            ),
        }
    }

    let matches = match root.clone().try_get_matches_from(args) {
        Ok(matches) => matches,
        // Handles --help/-h and parse errors: clap prints its own message
        // and terminates the process itself.
        Err(err) => err.exit(),
    };

    let Some((name, sub_matches)) = matches.subcommand() else {
        let _ = root.print_help();
        return ExitCode::SUCCESS;
    };

    match name {
        "version" => cmd_version(client, &socket_path).await,
        "modules" => cmd_modules(client, sub_matches, &socket_path).await,
        "load" => cmd_load(client, sub_matches, &socket_path).await,
        "unload" => cmd_unload(client, sub_matches, &socket_path).await,
        "status" => cmd_status(client, sub_matches, &socket_path).await,
        "logs" => cmd_logs(client, sub_matches, &socket_path).await,
        "update" => cmd_update(client, sub_matches, &socket_path).await,
        module_name => cmd_dispatch(client, module_name, &modules, sub_matches, &socket_path).await,
    }
}

/// Connects to the daemon's control socket, or returns `None` if it is
/// unreachable. `None` is not an error here — every caller degrades
/// gracefully: static verbs print the friendly daemon-down message
/// themselves, and the tree simply gains no dynamic module subcommands.
async fn dial(socket_path: &str) -> Option<DaemonClient<Channel>> {
    match tokio::time::timeout(DIAL_TIMEOUT, penguin_ipc::dial_unix::dial(socket_path)).await {
        Ok(Ok(channel)) => Some(DaemonClient::new(channel)),
        Ok(Err(_)) | Err(_) => None,
    }
}

/// Fetches every loaded module's command tree via `ListCommands`.
async fn fetch_modules(
    client: &mut DaemonClient<Channel>,
) -> Result<Vec<pb::ModuleCommands>, Status> {
    let request = pb::ListCommandsRequest {
        api_version: penguin_cli_core::API_VERSION.to_string(),
    };
    let response = client.list_commands(request).await?;
    Ok(response.into_inner().modules)
}

/// Prints the friendly daemon-down message to stderr, prefixed like every
/// other CLI error (`penguin: ...`).
fn print_daemon_unreachable(socket_path: &str) {
    eprintln!(
        "penguin: {}",
        penguin_cli_core::error::daemon_unreachable_message(socket_path)
    );
}

/// Prints an RPC failure to stderr with the standard `penguin: ` prefix.
fn print_rpc_error(status: &Status, socket_path: &str) {
    eprintln!(
        "penguin: {}",
        penguin_cli_core::error::friendly_status_message(status, socket_path)
    );
}

/// Converts a `DispatchChunk`'s `i32` exit code into a process [`ExitCode`],
/// clamping to the `u8` range a process can actually exit with. The clamp
/// guarantees the following cast is exact.
fn exit_code_from(code: i32) -> ExitCode {
    let clamped = code.clamp(0, i32::from(u8::MAX));
    ExitCode::from(clamped as u8)
}

/// `penguin version`. Deliberate divergence from Go: `cmdVersion`
/// (`go-client/cmd/penguin/main.go`) checks the `Version` RPC's error and
/// discards it, printing only the local version line even when the daemon
/// call fails (see docs/PARITY.md §1.11). Rust surfaces that failure instead
/// of silently succeeding with incomplete output.
async fn cmd_version(client: Option<DaemonClient<Channel>>, socket_path: &str) -> ExitCode {
    print!(
        "{}",
        penguin_cli_core::render::render_local_version(LOCAL_VERSION)
    );
    let Some(mut client) = client else {
        print_daemon_unreachable(socket_path);
        return ExitCode::FAILURE;
    };

    let request = pb::VersionRequest {
        api_version: penguin_cli_core::API_VERSION.to_string(),
    };
    match with_timeout(VERSION_TIMEOUT, client.version(request)).await {
        Ok(response) => {
            print!(
                "{}",
                penguin_cli_core::render::render_daemon_version(
                    &response.into_inner().daemon_version
                )
            );
            ExitCode::SUCCESS
        }
        Err(status) => {
            print_rpc_error(&status, socket_path);
            ExitCode::FAILURE
        }
    }
}

/// `penguin modules`.
async fn cmd_modules(
    client: Option<DaemonClient<Channel>>,
    matches: &ArgMatches,
    socket_path: &str,
) -> ExitCode {
    let Some(mut client) = client else {
        print_daemon_unreachable(socket_path);
        return ExitCode::FAILURE;
    };

    let request = pb::ListModulesRequest {
        api_version: penguin_cli_core::API_VERSION.to_string(),
    };
    match with_timeout(DEFAULT_RPC_TIMEOUT, client.list_modules(request)).await {
        Ok(response) => {
            let response = response.into_inner();
            if penguin_cli_core::verbs::json_requested(matches) {
                print!("{}", penguin_cli_core::json::modules_json(&response));
            } else {
                print!(
                    "{}",
                    penguin_cli_core::render::render_modules_table(&response.modules)
                );
            }
            ExitCode::SUCCESS
        }
        Err(status) => {
            print_rpc_error(&status, socket_path);
            ExitCode::FAILURE
        }
    }
}

/// `penguin load <module>`.
async fn cmd_load(
    client: Option<DaemonClient<Channel>>,
    matches: &ArgMatches,
    socket_path: &str,
) -> ExitCode {
    let module = penguin_cli_core::verbs::module_name(matches).expect("required by the clap tree");
    let Some(mut client) = client else {
        print_daemon_unreachable(socket_path);
        return ExitCode::FAILURE;
    };

    let request = pb::LoadModuleRequest {
        api_version: penguin_cli_core::API_VERSION.to_string(),
        name: module.to_string(),
    };
    match with_timeout(DEFAULT_RPC_TIMEOUT, client.load_module(request)).await {
        Ok(response) => {
            print!(
                "{}",
                penguin_cli_core::render::render_load_success(module, &response.into_inner().state)
            );
            ExitCode::SUCCESS
        }
        Err(status) => {
            eprintln!(
                "penguin: {}",
                penguin_cli_core::error::load_error_message(&status, module, socket_path)
            );
            ExitCode::FAILURE
        }
    }
}

/// `penguin unload <module>`.
async fn cmd_unload(
    client: Option<DaemonClient<Channel>>,
    matches: &ArgMatches,
    socket_path: &str,
) -> ExitCode {
    let module = penguin_cli_core::verbs::module_name(matches).expect("required by the clap tree");
    let Some(mut client) = client else {
        print_daemon_unreachable(socket_path);
        return ExitCode::FAILURE;
    };

    let request = pb::UnloadModuleRequest {
        api_version: penguin_cli_core::API_VERSION.to_string(),
        name: module.to_string(),
    };
    match with_timeout(DEFAULT_RPC_TIMEOUT, client.unload_module(request)).await {
        Ok(_) => {
            print!(
                "{}",
                penguin_cli_core::render::render_unload_success(module)
            );
            ExitCode::SUCCESS
        }
        Err(status) => {
            print_rpc_error(&status, socket_path);
            ExitCode::FAILURE
        }
    }
}

/// `penguin status [module]`.
async fn cmd_status(
    client: Option<DaemonClient<Channel>>,
    matches: &ArgMatches,
    socket_path: &str,
) -> ExitCode {
    let module = penguin_cli_core::verbs::module_name(matches)
        .unwrap_or("")
        .to_string();
    let Some(mut client) = client else {
        print_daemon_unreachable(socket_path);
        return ExitCode::FAILURE;
    };

    let request = pb::GetStatusRequest {
        api_version: penguin_cli_core::API_VERSION.to_string(),
        name: module,
    };
    match with_timeout(DEFAULT_RPC_TIMEOUT, client.get_status(request)).await {
        Ok(response) => {
            let response = response.into_inner();
            if penguin_cli_core::verbs::json_requested(matches) {
                print!("{}", penguin_cli_core::json::status_json(&response));
            } else {
                print!(
                    "{}",
                    penguin_cli_core::render::render_status_header(&response.daemon_version)
                );
                print!(
                    "{}",
                    penguin_cli_core::render::render_status_table(&response.modules)
                );
            }
            ExitCode::SUCCESS
        }
        Err(status) => {
            print_rpc_error(&status, socket_path);
            ExitCode::FAILURE
        }
    }
}

/// `penguin logs [module]`. Deliberate divergence from Go: `cmdLogs`
/// (`go-client/cmd/penguin/main.go`) breaks its receive loop on any
/// `stream.Recv()` error — a mid-stream transport failure looks identical to
/// a clean end-of-stream and is silently discarded (docs/PARITY.md §1.11).
/// `tonic::Streaming::message` already distinguishes `Ok(None)` (clean end)
/// from `Err(status)` (real failure) at the type level, so this loop
/// surfaces the latter instead of swallowing it.
async fn cmd_logs(
    client: Option<DaemonClient<Channel>>,
    matches: &ArgMatches,
    socket_path: &str,
) -> ExitCode {
    let options = penguin_cli_core::verbs::logs_options(matches);
    if let Err(message) = penguin_cli_core::verbs::validate_lines(options.lines) {
        eprintln!("penguin: {message}");
        return ExitCode::FAILURE;
    }
    let Some(mut client) = client else {
        print_daemon_unreachable(socket_path);
        return ExitCode::FAILURE;
    };

    let request = pb::TailLogsRequest {
        api_version: penguin_cli_core::API_VERSION.to_string(),
        module: options.module.unwrap_or_default(),
        lines: options.lines,
        follow: options.follow,
    };
    let mut stream = match with_timeout(STREAM_ESTABLISH_TIMEOUT, client.tail_logs(request)).await {
        Ok(response) => response.into_inner(),
        Err(status) => {
            if status.code() == tonic::Code::Unimplemented {
                print!("{}", penguin_cli_core::render::TAIL_LOGS_NOT_IMPLEMENTED);
                return ExitCode::SUCCESS;
            }
            print_rpc_error(&status, socket_path);
            return ExitCode::FAILURE;
        }
    };

    loop {
        match stream.message().await {
            Ok(Some(line)) => print!("{}", penguin_cli_core::render::render_log_line(&line)),
            Ok(None) => return ExitCode::SUCCESS,
            Err(status) => {
                print_rpc_error(&status, socket_path);
                return ExitCode::FAILURE;
            }
        }
    }
}

/// `penguin update [--yes]`.
async fn cmd_update(
    client: Option<DaemonClient<Channel>>,
    matches: &ArgMatches,
    socket_path: &str,
) -> ExitCode {
    let yes = penguin_cli_core::verbs::update_yes(matches);
    let Some(mut client) = client else {
        print_daemon_unreachable(socket_path);
        return ExitCode::FAILURE;
    };

    let check_request = pb::CheckUpdateRequest {
        api_version: penguin_cli_core::API_VERSION.to_string(),
    };
    let check = match with_timeout(DEFAULT_RPC_TIMEOUT, client.check_update(check_request)).await {
        Ok(response) => response.into_inner(),
        Err(status) => {
            print_rpc_error(&status, socket_path);
            return ExitCode::FAILURE;
        }
    };
    print!(
        "{}",
        penguin_cli_core::render::render_update_check(
            &check.current_version,
            &check.latest_version
        )
    );

    match penguin_cli_core::update::decide_update(check.available, yes) {
        penguin_cli_core::update::UpdateAction::NoUpdateAvailable => {
            print!("{}", penguin_cli_core::render::NO_UPDATES_AVAILABLE);
            return ExitCode::SUCCESS;
        }
        penguin_cli_core::update::UpdateAction::Confirm => {
            if !confirm_from_stdin() {
                return ExitCode::SUCCESS;
            }
        }
        penguin_cli_core::update::UpdateAction::Apply => {}
    }

    let apply_request = pb::ApplyUpdateRequest {
        api_version: penguin_cli_core::API_VERSION.to_string(),
    };
    match with_timeout(APPLY_UPDATE_TIMEOUT, client.apply_update(apply_request)).await {
        Ok(response) => {
            let response = response.into_inner();
            if response.applied {
                print!("{}", penguin_cli_core::render::UPDATE_APPLIED_SUCCESS);
            } else {
                // Matches Go: ApplyUpdate never returns a gRPC error status
                // (docs/PARITY.md §2.2) — a reported failure still exits 0.
                print!(
                    "{}",
                    penguin_cli_core::render::render_update_failed(&response.message)
                );
            }
            ExitCode::SUCCESS
        }
        Err(status) => {
            print_rpc_error(&status, socket_path);
            ExitCode::FAILURE
        }
    }
}

/// Prompts on stdout and reads one line from stdin, returning whether the
/// answer confirmed the update. A read failure is treated as "no", matching
/// `cmdUpdate`'s `if _, err := fmt.Scanln(&answer); err != nil { return nil
/// }`.
fn confirm_from_stdin() -> bool {
    print!("{}", penguin_cli_core::render::UPDATE_CONFIRM_PROMPT);
    if std::io::stdout().flush().is_err() {
        return false;
    }
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    penguin_cli_core::update::confirm_answer(&answer)
}

/// Reads all of stdin to EOF, but only when it is piped or redirected
/// rather than an interactive terminal (`std::io::IsTerminal`, stable since
/// Rust 1.70 — no new dependency) — this must never block a real terminal
/// session waiting on a human who was never going to type anything. Empty
/// input (a `/dev/null` redirect, `cat empty-file |`) is treated the same
/// as "nothing piped". See `penguin_cli_core::dispatch::apply_stdin_fallback`
/// for how the result feeds into a dispatched command's positional
/// arguments.
fn read_piped_stdin() -> Option<String> {
    use std::io::IsTerminal as _;
    use std::io::Read as _;

    if std::io::stdin().is_terminal() {
        return None;
    }
    let mut buffer = String::new();
    match std::io::stdin().read_to_string(&mut buffer) {
        Ok(_) if !buffer.is_empty() => Some(buffer),
        _ => None,
    }
}

/// A dynamic module command: `penguin <module> <command...> [args]`.
async fn cmd_dispatch(
    client: Option<DaemonClient<Channel>>,
    module_name: &str,
    modules: &[pb::ModuleCommands],
    matches: &ArgMatches,
    socket_path: &str,
) -> ExitCode {
    let module_commands = modules
        .iter()
        .find(|module| module.module == module_name)
        .map(|module| module.commands.as_slice())
        .unwrap_or_default();

    let Some(mut request) =
        penguin_cli_core::dispatch::resolve_dispatch(module_name, module_commands, matches)
    else {
        eprintln!("penguin: no command given for module {module_name:?}");
        return ExitCode::FAILURE;
    };

    // A leaf command whose `CommandSpec` takes no literal positional
    // (`max_args: 0` — clap already rejected any stray shell token, see
    // `penguin_cli_core::tree::args_positional`) still gets a chance at a
    // value here, but only from a genuine pipe/redirect, never by blocking
    // on an interactive terminal — see `read_piped_stdin`'s doc. This is
    // how a secret (`key set`) or a sensitive payload (`hook <event>`)
    // reaches a command without ever transiting as a literal CLI argument.
    if request.args.is_empty() {
        request.args =
            penguin_cli_core::dispatch::apply_stdin_fallback(request.args, read_piped_stdin());
    }

    let Some(mut client) = client else {
        print_daemon_unreachable(socket_path);
        return ExitCode::FAILURE;
    };

    let mut stream = match with_timeout(STREAM_ESTABLISH_TIMEOUT, client.dispatch(request)).await {
        Ok(response) => response.into_inner(),
        Err(status) => {
            print_rpc_error(&status, socket_path);
            return ExitCode::FAILURE;
        }
    };

    let mut accumulator = penguin_cli_core::dispatch::ChunkAccumulator::new();
    loop {
        match stream.message().await {
            Ok(Some(chunk)) => print!("{}", accumulator.record(&chunk)),
            Ok(None) => return exit_code_from(accumulator.exit_code()),
            Err(status) => {
                print_rpc_error(&status, socket_path);
                return ExitCode::FAILURE;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_flag_matches_both_spellings_and_nothing_else() {
        let owned = |s: &str| s.to_string();
        assert!(is_version_flag(&[owned("--version")]));
        assert!(is_version_flag(&[owned("-V")]));
        assert!(!is_version_flag(&[]));
        assert!(!is_version_flag(&[owned("version")]));
        assert!(!is_version_flag(&[owned("--version"), owned("extra")]));
        assert!(!is_version_flag(&[owned("--socket"), owned("/tmp/x")]));
    }
}
