//! The `penguin.daemon.v1.Daemon` gRPC service, ported from
//! `go-client/internal/daemon/server.go`.
//!
//! [`DaemonService`] is a thin translation layer over [`Supervisor`],
//! [`EventBroker`], and [`LogRing`] — it holds no lifecycle logic of its own,
//! only the request/response and status-code mapping. See the `lib.rs`
//! module doc for the shared-broker fix this depends on.
//!
//! # Divergences from the frozen Go reference
//!
//! 1. **`TailLogs` is a real implementation.** Go returns `UNIMPLEMENTED`
//!    unconditionally; [`LogRing`] (this crate's own addition) makes a real
//!    backlog-then-follow implementation possible.
//! 2. **`WatchEvents` ends gracefully instead of surfacing a raw error.** Go
//!    returns `ctx.Err()` when the stream's context is done. Here the
//!    forwarding task simply stops — on client disconnect (the outbound
//!    channel closes) or on a broker lag/close (`recv` errors) — which ends
//!    the gRPC stream cleanly with no error status at all.
//! 3. **No int32-clamping helper.** Go's `CommandSpec`/`CommandResult` carry
//!    plain `int` and must saturate into proto `int32`. `penguin_sdk`'s
//!    equivalents already use `i32` for `min_args`/`max_args`/`exit_code`,
//!    so the conversions here are direct field copies.
//! 4. **`LoadModule` needs no follow-up `Status` call.** Go's `Load` returns
//!    only an error, so the handler re-fetches status afterward to report
//!    the resulting state. [`Supervisor::load`] already returns the
//!    resulting [`ModuleState`] directly.
//! 5. **`daemon.v1` gets its own small conversion helpers.** It declares its
//!    own `CommandSpec`/`FlagSpec`/`Event`/`LogLine` message shapes, distinct
//!    from `sdk.v1`'s (which `penguin_sdk::convert` already serves) — reusing
//!    those would be a type mismatch, not a shortcut, so this file has its
//!    own small recursive converters instead.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::codegen::BoxStream;
use tonic::{Request, Response, Status};

use penguin_proto::daemon::v1 as pb;
use penguin_proto::daemon::v1::daemon_server::Daemon;
use penguin_proto::desktop::v1 as pb_desktop;
use penguin_proto::desktop::v1::bridge_action_proxy_server::BridgeActionProxy;
use penguin_proto::desktop::v1::session_proxy_server::SessionProxy;
use penguin_sdk::{CommandSpec, Event, FlagSpec, ModuleState};

use crate::broker::{EventBroker, EventReceiver};
use crate::logring::{LogLine, LogReceiver, LogRing};
use crate::supervisor::{Supervisor, SupervisorError};

/// The only `api_version` this daemon accepts (besides the empty string).
const API_VERSION: &str = "v1";

/// Buffer size for the `mpsc` channel backing `WatchEvents`/`TailLogs`
/// forwarding tasks. Small and arbitrary — these are live-tail streams, not
/// bulk transfers, so a slow consumer should feel backpressure quickly
/// rather than buffer unbounded history.
const FORWARD_CHANNEL_CAPACITY: usize = 32;

/// The update-check/apply hook [`DaemonService::check_update`] and
/// [`DaemonService::apply_update`] consult. No implementation exists yet —
/// M7 wires the real `penguin-update` client. Until then every `penguind`
/// binary passes `None`, which takes the graceful "not configured" branch
/// documented on each method below.
#[async_trait]
pub trait UpdateClient: Send + Sync {
    /// Checks for an available update, returning `(available, latest_version)`.
    async fn check_update(&self) -> Result<(bool, String), String>;
    /// Applies the currently-available update.
    async fn apply_update(&self) -> Result<(), String>;
}

/// The `penguin.daemon.v1.Daemon` gRPC service implementation.
pub struct DaemonService {
    supervisor: Supervisor,
    broker: Arc<EventBroker>,
    logs: Arc<LogRing>,
    version: String,
    update: Option<Arc<dyn UpdateClient>>,
}

impl DaemonService {
    /// Builds the service. `broker` must be the exact instance the
    /// supervisor's host factory publishes module events into — sharing one
    /// broker between the two is what fixes the Go double-broker bug (see
    /// the crate-level module doc).
    pub fn new(
        supervisor: Supervisor,
        broker: Arc<EventBroker>,
        logs: Arc<LogRing>,
        version: impl Into<String>,
        update: Option<Arc<dyn UpdateClient>>,
    ) -> DaemonService {
        DaemonService {
            supervisor,
            broker,
            logs,
            version: version.into(),
            update,
        }
    }

    /// Builds one module's `ModuleStatus`, combining its `status()` and
    /// `health()` under a single error path — either call failing (name
    /// unregistered, or registered but not loaded) is one outcome to
    /// [`DaemonService::get_status`], which does not need Go's separate
    /// "look the module up again for health" step.
    async fn module_status_proto(&self, name: &str) -> Result<pb::ModuleStatus, SupervisorError> {
        let status = self.supervisor.status(name).await?;
        let health = self.supervisor.health(name).await?;
        Ok(pb::ModuleStatus {
            name: name.to_string(),
            state: status.state.as_str().to_string(),
            detail: status.detail,
            health: health.level.as_str().to_string(),
            health_message: health.message,
            checked_at_unix_nano: system_time_to_unix_nano(health.checked_at),
        })
    }
}

#[async_trait]
impl Daemon for DaemonService {
    /// Returns the daemon's own version and the accepted API version.
    async fn version(
        &self,
        request: Request<pb::VersionRequest>,
    ) -> Result<Response<pb::VersionResponse>, Status> {
        let req = request.into_inner();
        check_api_version(&req.api_version)?;
        Ok(Response::new(pb::VersionResponse {
            daemon_version: self.version.clone(),
            api_version: API_VERSION.to_string(),
        }))
    }

    /// Lists every registered (builtin) module, loaded or not — an unloaded
    /// name reports the supervisor's synthesized `disabled` state — plus
    /// every currently loaded external plugin, so operators can discover
    /// both what is available to load and what external plugin is already
    /// running.
    ///
    /// `#[instrument]`: this is real inter-process work (a `pdcli`/desktop
    /// RPC call crossing the control socket), so it gets a real OTel span
    /// when the `penguind.otel-telemetry` pipeline is live — see
    /// `critical-rules.md` Observability, "Traces: span the real work".
    /// `skip_all` because `Request<_>` carries no `Debug` worth rendering
    /// into span fields.
    #[tracing::instrument(skip_all, fields(rpc = "list_modules"))]
    async fn list_modules(
        &self,
        request: Request<pb::ListModulesRequest>,
    ) -> Result<Response<pb::ListModulesResponse>, Status> {
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        let mut modules = Vec::new();
        for (info, state, external) in self.supervisor.list().await {
            modules.push(pb::ModuleSummary {
                name: info.name,
                version: info.version,
                description: info.description,
                state: state.as_str().to_string(),
                external,
                license_feature: info.license_feature,
            });
        }
        Ok(Response::new(pb::ListModulesResponse { modules }))
    }

    /// Loads (enables) a module, returning the resulting state on success.
    async fn load_module(
        &self,
        request: Request<pb::LoadModuleRequest>,
    ) -> Result<Response<pb::LoadModuleResponse>, Status> {
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        if req.name.is_empty() {
            return Err(Status::invalid_argument("module name required"));
        }

        let state = self
            .supervisor
            .load(&req.name)
            .await
            .map_err(|err| load_error_to_status(&req.name, &err))?;
        Ok(Response::new(pb::LoadModuleResponse {
            state: state.as_str().to_string(),
        }))
    }

    /// Unloads (disables) a module. Idempotent: a name that was never
    /// loaded — known or not — is a no-op success, matching
    /// [`Supervisor::unload`].
    async fn unload_module(
        &self,
        request: Request<pb::UnloadModuleRequest>,
    ) -> Result<Response<pb::UnloadModuleResponse>, Status> {
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        if req.name.is_empty() {
            return Err(Status::invalid_argument("module name required"));
        }

        if let Err(err) = self.supervisor.unload(&req.name).await
            && !matches!(err, SupervisorError::UnknownModule(_))
        {
            return Err(Status::internal(format!("failed to unload: {err}")));
        }
        Ok(Response::new(pb::UnloadModuleResponse {
            state: ModuleState::Stopped.as_str().to_string(),
        }))
    }

    /// Returns status (and health) for one module, or every registered
    /// module when `name` is empty — silently skipping any that are not
    /// currently loaded.
    ///
    /// `#[instrument]`: see [`DaemonService::list_modules`]'s doc — same
    /// real-RPC-boundary rationale, same `skip_all` reasoning.
    #[tracing::instrument(skip_all, fields(rpc = "get_status"))]
    async fn get_status(
        &self,
        request: Request<pb::GetStatusRequest>,
    ) -> Result<Response<pb::GetStatusResponse>, Status> {
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        let mut modules = Vec::new();
        if req.name.is_empty() {
            for (info, _state, _external) in self.supervisor.list().await {
                let Ok(module_status) = self.module_status_proto(&info.name).await else {
                    continue;
                };
                modules.push(module_status);
            }
        } else {
            let Ok(module_status) = self.module_status_proto(&req.name).await else {
                return Err(Status::not_found(format!(
                    "module {:?} not found",
                    req.name
                )));
            };
            modules.push(module_status);
        }

        Ok(Response::new(pb::GetStatusResponse {
            daemon_version: self.version.clone(),
            modules,
        }))
    }

    /// Lists every loaded module's command tree, skipping any registered
    /// module that is not currently loaded.
    ///
    /// `#[instrument]`: see [`DaemonService::list_modules`]'s doc — same
    /// real-RPC-boundary rationale, same `skip_all` reasoning. Notably, this
    /// is the one handler every `pdcli` invocation besides `--version` hits
    /// first (dynamic command-tree discovery), so it is the daemon's single
    /// most-exercised span.
    #[tracing::instrument(skip_all, fields(rpc = "list_commands"))]
    async fn list_commands(
        &self,
        request: Request<pb::ListCommandsRequest>,
    ) -> Result<Response<pb::ListCommandsResponse>, Status> {
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        let mut modules = Vec::new();
        for (info, _state, _external) in self.supervisor.list().await {
            let Ok(commands) = self.supervisor.commands(&info.name).await else {
                continue;
            };
            let mut proto_commands = Vec::with_capacity(commands.len());
            for command in &commands {
                proto_commands.push(command_spec_to_daemon_proto(command));
            }
            modules.push(pb::ModuleCommands {
                module: info.name,
                commands: proto_commands,
            });
        }
        Ok(Response::new(pb::ListCommandsResponse { modules }))
    }

    /// Server streaming response type for `Dispatch` — always exactly one
    /// item (see [`DaemonService::dispatch`]).
    type DispatchStream = BoxStream<pb::DispatchChunk>;

    /// Executes a command and streams its result as a single final chunk;
    /// this daemon never emits intermediate chunks, matching the Go
    /// reference.
    async fn dispatch(
        &self,
        request: Request<pb::DispatchRequest>,
    ) -> Result<Response<Self::DispatchStream>, Status> {
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        if req.module.is_empty() {
            return Err(Status::invalid_argument("module name required"));
        }

        let result = self
            .supervisor
            .dispatch(&req.module, &req.path, &req.flags, &req.args)
            .await
            .map_err(|err| dispatch_error_to_status(&req.module, &err))?;

        let chunk = pb::DispatchChunk {
            output: result.output,
            json: result.json,
            exit_code: result.exit_code,
            r#final: true,
        };
        let stream: Self::DispatchStream = Box::pin(tokio_stream::once(Ok(chunk)));
        Ok(Response::new(stream))
    }

    /// Server streaming response type for `WatchEvents`.
    type WatchEventsStream = BoxStream<pb::Event>;

    /// Streams module events from the shared broker, optionally filtered to
    /// one module. Ends gracefully (no error) on client disconnect or a
    /// broker lag/close — see the module-level divergence note.
    async fn watch_events(
        &self,
        request: Request<pb::WatchEventsRequest>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        let events = self.broker.subscribe();
        let (tx, rx) = mpsc::channel(FORWARD_CHANNEL_CAPACITY);
        tokio::spawn(forward_events(events, tx, req.module));

        let stream: Self::WatchEventsStream = Box::pin(ReceiverStream::new(rx));
        Ok(Response::new(stream))
    }

    /// Server streaming response type for `TailLogs`.
    type TailLogsStream = BoxStream<pb::LogLine>;

    /// Replays the most recent `lines` for `module` (empty = the daemon's
    /// own log), then — only if `follow` is set — keeps streaming new
    /// appends until the client disconnects or the ring's broadcast lags or
    /// closes. Go returns `UNIMPLEMENTED` here; see the module-level
    /// divergence note.
    async fn tail_logs(
        &self,
        request: Request<pb::TailLogsRequest>,
    ) -> Result<Response<Self::TailLogsStream>, Status> {
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        // Subscribe before reading the backlog: an append racing this call
        // is then never lost, at worst delivered twice (once in the
        // snapshot, once via the live tail) — `follow` callers tolerate a
        // rare duplicate far better than a silent gap.
        let follow = if req.follow {
            Some(self.logs.subscribe(&req.module))
        } else {
            None
        };
        let lines = if req.lines > 0 { req.lines as usize } else { 0 };
        let backlog = self.logs.backlog(&req.module, lines);

        let (tx, rx) = mpsc::channel(FORWARD_CHANNEL_CAPACITY);
        tokio::spawn(forward_logs(backlog, follow, tx));

        let stream: Self::TailLogsStream = Box::pin(ReceiverStream::new(rx));
        Ok(Response::new(stream))
    }

    /// Reports update availability. With no [`UpdateClient`] configured this
    /// always succeeds with `available: false` — the correct
    /// graceful-degradation default, never a gRPC error.
    async fn check_update(
        &self,
        request: Request<pb::CheckUpdateRequest>,
    ) -> Result<Response<pb::CheckUpdateResponse>, Status> {
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        let Some(update) = self.update.as_ref() else {
            return Ok(Response::new(pb::CheckUpdateResponse {
                available: false,
                current_version: self.version.clone(),
                latest_version: self.version.clone(),
            }));
        };

        let (available, latest) = update
            .check_update()
            .await
            .map_err(|err| Status::internal(format!("check update failed: {err}")))?;
        Ok(Response::new(pb::CheckUpdateResponse {
            available,
            current_version: self.version.clone(),
            latest_version: latest,
        }))
    }

    /// Applies the available update. Never returns a gRPC error: with no
    /// [`UpdateClient`] configured, or on an update failure, the outcome is
    /// carried in the response body (`applied: false` + a message) instead.
    async fn apply_update(
        &self,
        request: Request<pb::ApplyUpdateRequest>,
    ) -> Result<Response<pb::ApplyUpdateResponse>, Status> {
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        let Some(update) = self.update.as_ref() else {
            return Ok(Response::new(pb::ApplyUpdateResponse {
                applied: false,
                message: "update client not configured".to_string(),
            }));
        };

        if let Err(err) = update.apply_update().await {
            return Ok(Response::new(pb::ApplyUpdateResponse {
                applied: false,
                message: err,
            }));
        }
        Ok(Response::new(pb::ApplyUpdateResponse {
            applied: true,
            message: "update applied successfully".to_string(),
        }))
    }
}

/// Desktop client session proxy service — multiplexed on the same gRPC server
/// as the main Daemon service. This is a separate service/package to avoid
/// proto-drift conflicts with the frozen daemon.proto.
#[derive(Clone)]
pub struct SessionProxyService {
    supervisor: Supervisor,
}

impl SessionProxyService {
    /// Builds the session proxy service with the same supervisor as the daemon.
    pub fn new(supervisor: Supervisor) -> SessionProxyService {
        SessionProxyService { supervisor }
    }
}

#[async_trait]
impl SessionProxy for SessionProxyService {
    /// Proxies an HTTP request through the waddlebot module's user-session hub proxy.
    async fn proxy_request(
        &self,
        request: Request<pb_desktop::ProxyHttpRequest>,
    ) -> Result<Response<pb_desktop::ProxyHttpResponse>, Status> {
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        // Convert proto headers to session proxy format.
        let headers: Vec<(String, String)> =
            req.headers.into_iter().map(|h| (h.name, h.value)).collect();

        let proxy_req = penguin_module_waddlebot::session_proxy::HttpRequest {
            method: req.method,
            path: req.path,
            headers,
            body: req.body,
        };

        // Forward through the supervisor to the waddlebot module.
        let resp = self
            .supervisor
            .proxy_request("waddlebot", proxy_req)
            .await
            .map_err(|err| proxy_error_to_status(&err))?;

        // Convert response back to proto format.
        let proto_headers: Vec<pb_desktop::Header> = resp
            .headers
            .into_iter()
            .map(|(name, value)| pb_desktop::Header { name, value })
            .collect();

        Ok(Response::new(pb_desktop::ProxyHttpResponse {
            api_version: "v1".to_string(),
            status: resp.status as u32,
            headers: proto_headers,
            body: resp.body,
        }))
    }

    /// Sets the user session (access + refresh tokens, hub base URL) for the
    /// desktop client's hub proxy.
    async fn set_user_session(
        &self,
        request: Request<pb_desktop::UserSession>,
    ) -> Result<Response<pb_desktop::SetUserSessionResponse>, Status> {
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        self.supervisor
            .set_user_session(
                "waddlebot",
                req.access_token,
                if req.refresh_token.is_empty() {
                    None
                } else {
                    Some(req.refresh_token)
                },
                req.hub_base_url,
            )
            .await
            .map_err(|err| proxy_error_to_status(&err))?;

        Ok(Response::new(pb_desktop::SetUserSessionResponse {
            api_version: "v1".to_string(),
        }))
    }
}

/// Bridge action proxy service — dispatches pre-authorized OBS commands and webhooks
/// from the desktop client through the waddlebot module.
#[derive(Clone)]
pub struct BridgeActionProxyService {
    supervisor: Supervisor,
}

impl BridgeActionProxyService {
    /// Builds the bridge action proxy service with the same supervisor as the daemon.
    pub fn new(supervisor: Supervisor) -> BridgeActionProxyService {
        BridgeActionProxyService { supervisor }
    }
}

#[async_trait]
impl BridgeActionProxy for BridgeActionProxyService {
    /// Executes a bridge action (OBS command or webhook) through the waddlebot module.
    async fn execute_bridge_action(
        &self,
        request: Request<pb_desktop::BridgeActionRequest>,
    ) -> Result<Response<pb_desktop::BridgeActionResponse>, Status> {
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        let module_name = req.module_name.clone();
        let result = self
            .supervisor
            .execute_bridge_action(&module_name, req.into())
            .await
            .map_err(|err| bridge_action_error_to_status(&err))?;

        Ok(Response::new(result.into()))
    }
}

/// Validates a request's `api_version` field: empty or `"v1"` is accepted
/// (empty lets lenient callers omit it); anything else is `UNIMPLEMENTED`,
/// per the PenguinTech gRPC versioning standard — never silently routed to a
/// mismatched handler.
fn check_api_version(version: &str) -> Result<(), Status> {
    if version.is_empty() || version == API_VERSION {
        return Ok(());
    }
    Err(Status::unimplemented(format!(
        "api_version {version:?} not supported"
    )))
}

/// Maps a [`Supervisor::load`] failure to its gRPC status: an unregistered
/// name is `NOT_FOUND`; anything else (a real `init`/`start` failure) is
/// `PERMISSION_DENIED`, matching the Go reference's "remaining failures are
/// license/entitlement denials" framing.
fn load_error_to_status(name: &str, err: &SupervisorError) -> Status {
    if matches!(err, SupervisorError::UnknownModule(_)) {
        return Status::not_found(format!("module {name:?} not found"));
    }
    Status::permission_denied(format!("cannot load module: {err}"))
}

/// Maps a [`Supervisor::dispatch`] failure to its gRPC status: a name that
/// is unregistered or simply not loaded is `NOT_FOUND`; a real dispatch
/// failure from the module itself is `INTERNAL`.
fn dispatch_error_to_status(name: &str, err: &SupervisorError) -> Status {
    if matches!(
        err,
        SupervisorError::UnknownModule(_) | SupervisorError::NotLoaded(_)
    ) {
        return Status::not_found(format!("module {name:?} not found"));
    }
    Status::internal(format!("dispatch failed: {err}"))
}

/// Maps a proxy request failure to its gRPC status: module not loaded is
/// `UNAVAILABLE`; user-session not set is `FAILED_PRECONDITION`; other errors
/// are `INTERNAL`.
fn proxy_error_to_status(err: &SupervisorError) -> Status {
    match err {
        SupervisorError::NotLoaded(_) => Status::unavailable("waddlebot module not loaded"),
        SupervisorError::UnknownModule(_) => Status::not_found("waddlebot module not found"),
        SupervisorError::Module(e) => {
            // Check if this is a user-session-not-set error.
            let msg = e.to_string();
            if msg.contains("no active session") {
                Status::failed_precondition("user session not set")
            } else {
                Status::internal(format!("proxy error: {e}"))
            }
        }
        _ => Status::internal(format!("proxy error: {err}")),
    }
}

/// Maps a bridge action failure to its gRPC status: module not loaded is
/// `UNAVAILABLE`; other module errors are `INTERNAL`.
fn bridge_action_error_to_status(err: &SupervisorError) -> Status {
    match err {
        SupervisorError::NotLoaded(_) => Status::unavailable("waddlebot module not loaded"),
        SupervisorError::UnknownModule(_) => Status::not_found("waddlebot module not found"),
        SupervisorError::Module(e) => Status::internal(format!("bridge action error: {e}")),
        _ => Status::internal(format!("bridge action error: {err}")),
    }
}

/// Drains `events` into `tx`, translating to the wire type and applying
/// `module_filter` (empty = all modules). Ends the loop — and so the RPC's
/// stream — the moment either side goes away: `recv` erroring (the broker
/// closed, or this subscriber lagged and lost events) or `tx.send` failing
/// (the client disconnected and tonic dropped the receiving half). Both
/// endings are graceful; neither is surfaced to the client as an error.
async fn forward_events(
    mut events: EventReceiver,
    tx: mpsc::Sender<Result<pb::Event, Status>>,
    module_filter: String,
) {
    loop {
        let Ok(event) = events.recv().await else {
            return;
        };
        if !module_filter.is_empty() && event.module != module_filter {
            continue;
        }
        if tx.send(Ok(event_to_daemon_proto(&event))).await.is_err() {
            return;
        }
    }
}

/// Replays `backlog` into `tx`, then — only when `follow` is `Some` — keeps
/// forwarding new appends until the client disconnects or the receiver
/// lags/closes, applying the same graceful-end rule as [`forward_events`].
/// `follow: None` (the RPC's `follow: false`) simply drops `tx` after the
/// backlog, ending the stream.
async fn forward_logs(
    backlog: Vec<LogLine>,
    mut follow: Option<LogReceiver>,
    tx: mpsc::Sender<Result<pb::LogLine, Status>>,
) {
    for line in backlog {
        if tx.send(Ok(log_line_to_proto(&line))).await.is_err() {
            return;
        }
    }
    let Some(receiver) = follow.as_mut() else {
        return;
    };
    loop {
        let Ok(line) = receiver.recv().await else {
            return;
        };
        if tx.send(Ok(log_line_to_proto(&line))).await.is_err() {
            return;
        }
    }
}

/// Converts a daemon-internal event to its `daemon.v1` wire form.
fn event_to_daemon_proto(event: &Event) -> pb::Event {
    pb::Event {
        module: event.module.clone(),
        r#type: event.event_type.as_str().to_string(),
        message: event.message.clone(),
        at_unix_nano: system_time_to_unix_nano(event.at),
        fields: event.fields.clone(),
    }
}

/// Converts a ring-buffered log line to its `daemon.v1` wire form.
fn log_line_to_proto(line: &LogLine) -> pb::LogLine {
    pb::LogLine {
        at_unix_nano: system_time_to_unix_nano(line.at),
        level: line.level.clone(),
        message: line.message.clone(),
    }
}

/// Converts a command spec (and its whole subtree) to its `daemon.v1` wire
/// form. A sibling of `penguin_sdk::convert::command_spec_to_proto`, not a
/// reuse of it — `daemon.v1` declares its own distinct `CommandSpec` message.
fn command_spec_to_daemon_proto(command: &CommandSpec) -> pb::CommandSpec {
    let mut flags = Vec::with_capacity(command.flags.len());
    for flag in &command.flags {
        flags.push(flag_spec_to_daemon_proto(flag));
    }
    let mut subcommands = Vec::with_capacity(command.subcommands.len());
    for sub in &command.subcommands {
        subcommands.push(command_spec_to_daemon_proto(sub));
    }
    pb::CommandSpec {
        name: command.name.clone(),
        r#use: command.use_line.clone(),
        short: command.short.clone(),
        flags,
        subcommands,
        tray: command.tray,
        min_args: command.min_args,
        max_args: command.max_args,
    }
}

/// Converts a flag spec to its `daemon.v1` wire form.
fn flag_spec_to_daemon_proto(flag: &FlagSpec) -> pb::FlagSpec {
    pb::FlagSpec {
        name: flag.name.clone(),
        shorthand: flag.shorthand.clone(),
        usage: flag.usage.clone(),
        default: flag.default.clone(),
        r#type: flag.flag_type.as_str().to_string(),
    }
}

/// Converts a wall-clock time to Unix nanoseconds, matching Go's `UnixNano`
/// (negative for times before the epoch). A private sibling of
/// `penguin_sdk::convert`'s identical helper — that one is not `pub`, so it
/// cannot be reused across crates.
fn system_time_to_unix_nano(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_nanos() as i64,
        Err(before_epoch) => -(before_epoch.duration().as_nanos() as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tempfile::TempDir;
    use tokio_stream::StreamExt;

    use penguin_sdk::{
        CommandResult, EventSink, EventType, Factory, FlagType, HealthLevel, HealthReport,
        HostServices, LicenseChecker, Module, ModuleError, ModuleInfo, SecretError, SecretStore,
        Status as SdkStatus,
    };

    use crate::config::ConfigStore;
    use crate::external::{ExternalLoadError, ExternalLoader};
    use crate::host::{DaemonHostFactory, HostFactory, SecretStoreProvider};
    use crate::supervisor::SupervisorConfig;

    /// Per-module mutable state a [`FakeModule`] reads/writes, shared via
    /// [`Arc`] so a test can flip a flag after the module is already loaded.
    struct FakeControl {
        fail_init: AtomicBool,
        health_level: Mutex<HealthLevel>,
        dispatch_result: Mutex<CommandResult>,
        dispatch_err: Mutex<Option<String>>,
    }

    impl FakeControl {
        fn new() -> Arc<FakeControl> {
            Arc::new(FakeControl {
                fail_init: AtomicBool::new(false),
                health_level: Mutex::new(HealthLevel::Healthy),
                dispatch_result: Mutex::new(CommandResult::default()),
                dispatch_err: Mutex::new(None),
            })
        }
    }

    thread_local! {
        /// Per-OS-thread, name-keyed registry of [`FakeControl`] blocks —
        /// `Factory` is a bare function pointer that cannot close over
        /// per-test state, so each named factory below looks itself up
        /// here. See `supervisor.rs`'s identical pattern for the full
        /// rationale (thread-local is safe because `#[tokio::test]` pins a
        /// test's body and everything it spawns to one OS thread).
        static CONTROLS: std::cell::RefCell<BTreeMap<String, Arc<FakeControl>>> =
            const { std::cell::RefCell::new(BTreeMap::new()) };
    }

    fn register_control(name: &str) -> Arc<FakeControl> {
        let control = FakeControl::new();
        CONTROLS.with(|cell| cell.borrow_mut().insert(name.to_string(), control.clone()));
        control
    }

    fn control_for(name: &str) -> Arc<FakeControl> {
        CONTROLS.with(|cell| cell.borrow().get(name).unwrap().clone())
    }

    struct FakeModule {
        name: String,
        control: Arc<FakeControl>,
    }

    #[async_trait]
    impl Module for FakeModule {
        fn info(&self) -> ModuleInfo {
            ModuleInfo {
                name: self.name.clone(),
                version: "1.0.0".to_string(),
                description: "a fake module".to_string(),
                license_feature: String::new(),
            }
        }

        async fn init(&self, host: Arc<dyn HostServices>) -> Result<(), ModuleError> {
            // Publishes on every successful init so the WatchEvents fan-out
            // regression test has something module-originated to look for.
            host.events().publish(Event {
                module: self.name.clone(),
                event_type: EventType::Info,
                message: "fake-module-init-event".to_string(),
                at: SystemTime::now(),
                fields: HashMap::new(),
            });
            if self.control.fail_init.load(Ordering::SeqCst) {
                return Err(ModuleError::new("init failed"));
            }
            Ok(())
        }

        async fn start(&self) -> Result<(), ModuleError> {
            Ok(())
        }

        async fn stop(&self) -> Result<(), ModuleError> {
            Ok(())
        }

        async fn status(&self) -> Result<SdkStatus, ModuleError> {
            let mut detail = HashMap::new();
            detail.insert("endpoint".to_string(), "us-east".to_string());
            Ok(SdkStatus {
                state: ModuleState::Running,
                detail,
            })
        }

        async fn health(&self) -> HealthReport {
            let level = *self.control.health_level.lock().unwrap();
            HealthReport {
                level,
                message: "polled".to_string(),
                checked_at: SystemTime::now(),
            }
        }

        fn commands(&self) -> Vec<CommandSpec> {
            vec![CommandSpec {
                name: "root".to_string(),
                use_line: "root".to_string(),
                short: "root command".to_string(),
                flags: vec![FlagSpec {
                    name: "json".to_string(),
                    shorthand: "j".to_string(),
                    usage: "json output".to_string(),
                    default: "false".to_string(),
                    flag_type: FlagType::Bool,
                }],
                subcommands: vec![CommandSpec {
                    name: "child".to_string(),
                    use_line: "root child".to_string(),
                    short: "child command".to_string(),
                    flags: Vec::new(),
                    subcommands: Vec::new(),
                    tray: false,
                    min_args: 1,
                    max_args: -1,
                }],
                tray: true,
                min_args: 0,
                max_args: 0,
            }]
        }

        async fn dispatch(
            &self,
            _path: &[String],
            _flags: &HashMap<String, String>,
            _args: &[String],
        ) -> Result<CommandResult, ModuleError> {
            if let Some(message) = self.control.dispatch_err.lock().unwrap().clone() {
                return Err(ModuleError::new(message));
            }
            Ok(self.control.dispatch_result.lock().unwrap().clone())
        }

        fn config_schema(&self) -> Option<Vec<u8>> {
            None
        }
    }

    fn factory_alpha() -> Box<dyn Module> {
        Box::new(FakeModule {
            name: "alpha".to_string(),
            control: control_for("alpha"),
        })
    }

    fn factory_beta() -> Box<dyn Module> {
        Box::new(FakeModule {
            name: "beta".to_string(),
            control: control_for("beta"),
        })
    }

    /// A [`SecretStore`] double; service tests never exercise it. Also
    /// implements [`SecretStoreProvider`], handing every module the same
    /// no-op instance — safe here only because no test ever reads or writes
    /// through it (real isolation is `host.rs`'s and `bins/penguind`'s
    /// concern, not this file's).
    struct FakeSecretStore;
    #[async_trait]
    impl SecretStore for FakeSecretStore {
        async fn get(&self, _key: &str) -> Result<Vec<u8>, SecretError> {
            Err(SecretError::NotFound)
        }
        async fn set(&self, _key: &str, _value: &[u8]) -> Result<(), SecretError> {
            Ok(())
        }
        async fn delete(&self, _key: &str) -> Result<(), SecretError> {
            Ok(())
        }
    }
    impl SecretStoreProvider for FakeSecretStore {
        fn store_for(&self, _module: &str) -> Arc<dyn SecretStore> {
            Arc::new(FakeSecretStore)
        }
    }

    /// A [`LicenseChecker`] double; everything is enabled.
    struct FakeLicenseChecker;
    impl LicenseChecker for FakeLicenseChecker {
        fn feature_enabled(&self, _key: &str) -> bool {
            true
        }
        fn tier(&self) -> String {
            "free".to_string()
        }
    }

    /// A configurable [`UpdateClient`] double.
    struct FakeUpdateClient {
        available: bool,
        latest: String,
        check_err: Option<String>,
        apply_err: Option<String>,
    }

    #[async_trait]
    impl UpdateClient for FakeUpdateClient {
        async fn check_update(&self) -> Result<(bool, String), String> {
            if let Some(err) = &self.check_err {
                return Err(err.clone());
            }
            Ok((self.available, self.latest.clone()))
        }

        async fn apply_update(&self) -> Result<(), String> {
            if let Some(err) = &self.apply_err {
                return Err(err.clone());
            }
            Ok(())
        }
    }

    /// Everything one test needs to drive [`DaemonService`] directly: the
    /// service, a handle to its underlying supervisor (for setting up state
    /// via the domain layer) and log ring, and the temp dirs that must
    /// outlive them — named with a leading underscore so they are never
    /// dropped early by a partial destructure.
    struct ServiceFixture {
        service: DaemonService,
        supervisor: Supervisor,
        logs: Arc<LogRing>,
        _state_dir: TempDir,
        _config_dir: TempDir,
    }

    /// Builds a [`DaemonService`] over a fresh [`Supervisor`] and shared
    /// broker/log ring, mirroring `supervisor.rs`'s `build_supervisor` test
    /// helper.
    fn build_service(
        registry: BTreeMap<String, Factory>,
        update: Option<Arc<dyn UpdateClient>>,
    ) -> ServiceFixture {
        build_service_with_external(registry, update, None)
    }

    /// Same as [`build_service`], but also wires in an [`ExternalLoader`] —
    /// kept as a second function rather than an added parameter on
    /// [`build_service`] so its many existing callers stay untouched.
    fn build_service_with_external(
        registry: BTreeMap<String, Factory>,
        update: Option<Arc<dyn UpdateClient>>,
        external: Option<Arc<dyn ExternalLoader>>,
    ) -> ServiceFixture {
        let state_dir = TempDir::new().unwrap();
        let config_dir = TempDir::new().unwrap();
        let telemetry = Arc::new(penguin_telemetry::Telemetry::new("error").unwrap());
        let config_store = Arc::new(ConfigStore::new(config_dir.path()));
        let broker = Arc::new(EventBroker::new(32));
        let events: Arc<dyn EventSink> = broker.clone();
        let host_factory: Arc<dyn HostFactory> = Arc::new(DaemonHostFactory::new(
            telemetry,
            config_store,
            Arc::new(FakeSecretStore),
            Arc::new(FakeLicenseChecker),
            events,
            state_dir.path().to_path_buf(),
        ));
        let supervisor = Supervisor::new(SupervisorConfig {
            registry,
            host_factory,
            broker: broker.clone(),
            state_dir: state_dir.path().to_path_buf(),
            max_restarts: 5,
            health_interval: Duration::from_secs(3600),
            stability_window: Duration::from_secs(3600),
            external,
        });
        let logs = Arc::new(LogRing::new(32));
        let service = DaemonService::new(supervisor.clone(), broker, logs.clone(), "1.2.3", update);
        ServiceFixture {
            service,
            supervisor,
            logs,
            _state_dir: state_dir,
            _config_dir: config_dir,
        }
    }

    fn single_registry(name: &str, factory: Factory) -> BTreeMap<String, Factory> {
        let mut registry = BTreeMap::new();
        registry.insert(name.to_string(), factory);
        registry
    }

    /// Extracts the `Err` from a `dispatch` call's `Result`. Plain
    /// `.unwrap_err()` does not work here: it requires `Response<T>: Debug`,
    /// and the boxed `Stream` inside a successful `Dispatch` response is not
    /// `Debug` — this never touches the `Ok` value, so that bound is never
    /// needed.
    fn expect_err<T>(result: Result<T, Status>) -> Status {
        let Err(status) = result else {
            panic!("expected an error response");
        };
        status
    }

    #[test]
    fn check_api_version_accepts_empty_and_v1() {
        assert!(check_api_version("").is_ok());
        assert!(check_api_version("v1").is_ok());
    }

    #[test]
    fn check_api_version_rejects_unknown_with_quoted_message() {
        let err = check_api_version("v2").unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
        assert_eq!(err.message(), "api_version \"v2\" not supported");
    }

    #[tokio::test]
    async fn version_returns_daemon_version_and_api_v1() {
        register_control("alpha");
        let fixture = build_service(single_registry("alpha", factory_alpha), None);

        let response = fixture
            .service
            .version(Request::new(pb::VersionRequest {
                api_version: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.daemon_version, "1.2.3");
        assert_eq!(response.api_version, "v1");
    }

    #[tokio::test]
    async fn version_rejects_unknown_api_version_as_unimplemented() {
        let fixture = build_service(BTreeMap::new(), None);
        let err = fixture
            .service
            .version(Request::new(pb::VersionRequest {
                api_version: "v2".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn list_modules_includes_both_loaded_and_disabled_registered_modules() {
        register_control("alpha");
        register_control("beta");
        let mut registry = single_registry("alpha", factory_alpha);
        registry.insert("beta".to_string(), factory_beta);
        let fixture = build_service(registry, None);
        fixture.supervisor.load("alpha").await.unwrap();

        let response = fixture
            .service
            .list_modules(Request::new(pb::ListModulesRequest {
                api_version: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();

        let mut by_name: HashMap<String, pb::ModuleSummary> = HashMap::new();
        for module in response.modules {
            by_name.insert(module.name.clone(), module);
        }
        assert_eq!(by_name["alpha"].state, "running");
        assert_eq!(by_name["beta"].state, "disabled");
        assert!(!by_name["alpha"].external);
    }

    #[tokio::test]
    async fn load_module_empty_name_is_invalid_argument() {
        let fixture = build_service(BTreeMap::new(), None);
        let err = fixture
            .service
            .load_module(Request::new(pb::LoadModuleRequest {
                api_version: String::new(),
                name: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn load_module_unknown_name_is_not_found() {
        let fixture = build_service(BTreeMap::new(), None);
        let err = fixture
            .service
            .load_module(Request::new(pb::LoadModuleRequest {
                api_version: String::new(),
                name: "ghost".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    /// A minimal [`ExternalLoader`] test double for the gRPC-layer mapping
    /// tests below: `available` resolves to nothing more than a bare
    /// success/failure signal, since these tests only care about the status
    /// code `LoadModule` returns, not the resulting module's behaviour
    /// (that equivalence is exhaustively covered in `supervisor.rs`'s own
    /// test suite).
    struct FakeExternalLoader {
        available: Vec<&'static str>,
        load_errors: Vec<(&'static str, &'static str)>,
    }

    #[async_trait]
    impl ExternalLoader for FakeExternalLoader {
        async fn load(&self, name: &str) -> Result<Box<dyn Module>, ExternalLoadError> {
            for (error_name, message) in &self.load_errors {
                if *error_name == name {
                    return Err(ExternalLoadError::Load(message.to_string()));
                }
            }
            if !self.available.contains(&name) {
                return Err(ExternalLoadError::NotFound(name.to_string()));
            }
            register_control(name);
            Ok(Box::new(FakeModule {
                name: name.to_string(),
                control: control_for(name),
            }))
        }
    }

    #[tokio::test]
    async fn load_module_unknown_to_both_builtin_and_external_is_still_not_found() {
        let external: Arc<dyn ExternalLoader> = Arc::new(FakeExternalLoader {
            available: Vec::new(),
            load_errors: Vec::new(),
        });
        let fixture = build_service_with_external(BTreeMap::new(), None, Some(external));
        let err = fixture
            .service
            .load_module(Request::new(pb::LoadModuleRequest {
                api_version: String::new(),
                name: "ghost".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn load_module_of_an_external_plugin_succeeds_through_the_grpc_layer() {
        let external: Arc<dyn ExternalLoader> = Arc::new(FakeExternalLoader {
            available: vec!["ext-plugin"],
            load_errors: Vec::new(),
        });
        let fixture = build_service_with_external(BTreeMap::new(), None, Some(external));
        let response = fixture
            .service
            .load_module(Request::new(pb::LoadModuleRequest {
                api_version: String::new(),
                name: "ext-plugin".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.state, "running");
    }

    #[tokio::test]
    async fn load_module_external_verification_failure_is_permission_denied() {
        let external: Arc<dyn ExternalLoader> = Arc::new(FakeExternalLoader {
            available: Vec::new(),
            load_errors: vec![("bad-sig", "sha256 mismatch")],
        });
        let fixture = build_service_with_external(BTreeMap::new(), None, Some(external));
        let err = fixture
            .service
            .load_module(Request::new(pb::LoadModuleRequest {
                api_version: String::new(),
                name: "bad-sig".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn load_module_init_failure_is_permission_denied() {
        let control = register_control("alpha");
        control.fail_init.store(true, Ordering::SeqCst);
        let fixture = build_service(single_registry("alpha", factory_alpha), None);

        let err = fixture
            .service
            .load_module(Request::new(pb::LoadModuleRequest {
                api_version: String::new(),
                name: "alpha".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn load_module_success_returns_running_state() {
        register_control("alpha");
        let fixture = build_service(single_registry("alpha", factory_alpha), None);

        let response = fixture
            .service
            .load_module(Request::new(pb::LoadModuleRequest {
                api_version: "v1".to_string(),
                name: "alpha".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.state, "running");
    }

    #[tokio::test]
    async fn unload_module_empty_name_is_invalid_argument() {
        let fixture = build_service(BTreeMap::new(), None);
        let err = fixture
            .service
            .unload_module(Request::new(pb::UnloadModuleRequest {
                api_version: String::new(),
                name: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn unload_module_of_a_never_loaded_module_is_idempotent_success() {
        let fixture = build_service(BTreeMap::new(), None);
        let response = fixture
            .service
            .unload_module(Request::new(pb::UnloadModuleRequest {
                api_version: String::new(),
                name: "ghost".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.state, "stopped");
    }

    #[tokio::test]
    async fn unload_module_of_a_loaded_module_stops_it() {
        register_control("alpha");
        let fixture = build_service(single_registry("alpha", factory_alpha), None);
        fixture.supervisor.load("alpha").await.unwrap();

        let response = fixture
            .service
            .unload_module(Request::new(pb::UnloadModuleRequest {
                api_version: String::new(),
                name: "alpha".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.state, "stopped");

        let status = fixture
            .service
            .get_status(Request::new(pb::GetStatusRequest {
                api_version: String::new(),
                name: "alpha".to_string(),
            }))
            .await;
        assert!(status.is_err());
    }

    #[tokio::test]
    async fn get_status_named_module_not_found() {
        let fixture = build_service(BTreeMap::new(), None);
        let err = fixture
            .service
            .get_status(Request::new(pb::GetStatusRequest {
                api_version: String::new(),
                name: "ghost".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn get_status_all_modules_skips_unloaded_silently() {
        register_control("alpha");
        register_control("beta");
        let mut registry = single_registry("alpha", factory_alpha);
        registry.insert("beta".to_string(), factory_beta);
        let fixture = build_service(registry, None);
        fixture.supervisor.load("alpha").await.unwrap();

        let response = fixture
            .service
            .get_status(Request::new(pb::GetStatusRequest {
                api_version: String::new(),
                name: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.modules.len(), 1);
        assert_eq!(response.modules[0].name, "alpha");
        assert_eq!(response.modules[0].health, "healthy");
    }

    #[tokio::test]
    async fn list_commands_skips_unloaded_modules_and_converts_recursively() {
        register_control("alpha");
        register_control("beta");
        let mut registry = single_registry("alpha", factory_alpha);
        registry.insert("beta".to_string(), factory_beta);
        let fixture = build_service(registry, None);
        fixture.supervisor.load("alpha").await.unwrap();

        let response = fixture
            .service
            .list_commands(Request::new(pb::ListCommandsRequest {
                api_version: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.modules.len(), 1);
        let module_commands = &response.modules[0];
        assert_eq!(module_commands.module, "alpha");
        let root = &module_commands.commands[0];
        assert_eq!(root.name, "root");
        assert_eq!(root.flags[0].r#type, "bool");
        assert_eq!(root.subcommands[0].name, "child");
        assert_eq!(root.subcommands[0].min_args, 1);
        assert_eq!(root.subcommands[0].max_args, -1);
    }

    #[tokio::test]
    async fn dispatch_empty_module_is_invalid_argument() {
        let fixture = build_service(BTreeMap::new(), None);
        let err = expect_err(
            fixture
                .service
                .dispatch(Request::new(pb::DispatchRequest {
                    api_version: String::new(),
                    module: String::new(),
                    path: Vec::new(),
                    flags: HashMap::new(),
                    args: Vec::new(),
                }))
                .await,
        );
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn dispatch_unloaded_module_is_not_found() {
        register_control("alpha");
        let fixture = build_service(single_registry("alpha", factory_alpha), None);
        let err = expect_err(
            fixture
                .service
                .dispatch(Request::new(pb::DispatchRequest {
                    api_version: String::new(),
                    module: "alpha".to_string(),
                    path: Vec::new(),
                    flags: HashMap::new(),
                    args: Vec::new(),
                }))
                .await,
        );
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn dispatch_module_error_is_internal() {
        let control = register_control("alpha");
        *control.dispatch_err.lock().unwrap() = Some("boom".to_string());
        let fixture = build_service(single_registry("alpha", factory_alpha), None);
        fixture.supervisor.load("alpha").await.unwrap();

        let err = expect_err(
            fixture
                .service
                .dispatch(Request::new(pb::DispatchRequest {
                    api_version: String::new(),
                    module: "alpha".to_string(),
                    path: Vec::new(),
                    flags: HashMap::new(),
                    args: Vec::new(),
                }))
                .await,
        );
        assert_eq!(err.code(), tonic::Code::Internal);
    }

    #[tokio::test]
    async fn dispatch_emits_exactly_one_final_chunk() {
        let control = register_control("alpha");
        *control.dispatch_result.lock().unwrap() = CommandResult {
            output: "ok".to_string(),
            json: b"{}".to_vec(),
            exit_code: 0,
        };
        let fixture = build_service(single_registry("alpha", factory_alpha), None);
        fixture.supervisor.load("alpha").await.unwrap();

        let mut stream = fixture
            .service
            .dispatch(Request::new(pb::DispatchRequest {
                api_version: String::new(),
                module: "alpha".to_string(),
                path: vec!["root".to_string()],
                flags: HashMap::new(),
                args: Vec::new(),
            }))
            .await
            .unwrap()
            .into_inner();

        let chunk = stream.next().await.unwrap().unwrap();
        assert_eq!(chunk.output, "ok");
        assert!(chunk.r#final);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn watch_events_receives_a_module_published_event_through_the_shared_broker() {
        register_control("alpha");
        let fixture = build_service(single_registry("alpha", factory_alpha), None);

        let mut stream = fixture
            .service
            .watch_events(Request::new(pb::WatchEventsRequest {
                api_version: String::new(),
                module: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();

        fixture.supervisor.load("alpha").await.unwrap();

        let mut saw_module_event = false;
        for _ in 0..8 {
            let Ok(Some(Ok(event))) =
                tokio::time::timeout(Duration::from_secs(2), stream.next()).await
            else {
                break;
            };
            if event.message == "fake-module-init-event" {
                saw_module_event = true;
                break;
            }
        }
        assert!(
            saw_module_event,
            "watch_events never saw the module's own published event"
        );
    }

    #[tokio::test]
    async fn watch_events_filters_by_module() {
        register_control("alpha");
        register_control("beta");
        let mut registry = single_registry("alpha", factory_alpha);
        registry.insert("beta".to_string(), factory_beta);
        let fixture = build_service(registry, None);

        let mut stream = fixture
            .service
            .watch_events(Request::new(pb::WatchEventsRequest {
                api_version: String::new(),
                module: "beta".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();

        fixture.supervisor.load("alpha").await.unwrap();
        fixture.supervisor.load("beta").await.unwrap();

        let mut saw_beta_init_event = false;
        for _ in 0..12 {
            let Ok(Some(Ok(event))) =
                tokio::time::timeout(Duration::from_millis(500), stream.next()).await
            else {
                break;
            };
            assert_eq!(
                event.module, "beta",
                "filtered stream leaked an alpha event"
            );
            if event.message == "fake-module-init-event" {
                saw_beta_init_event = true;
            }
        }
        assert!(saw_beta_init_event);
    }

    #[tokio::test]
    async fn tail_logs_replays_backlog_then_ends_when_follow_is_false() {
        let fixture = build_service(BTreeMap::new(), None);
        fixture.logs.append(
            "alpha",
            LogLine {
                at: SystemTime::now(),
                level: "info".to_string(),
                message: "one".to_string(),
            },
        );
        fixture.logs.append(
            "alpha",
            LogLine {
                at: SystemTime::now(),
                level: "info".to_string(),
                message: "two".to_string(),
            },
        );

        let mut stream = fixture
            .service
            .tail_logs(Request::new(pb::TailLogsRequest {
                api_version: String::new(),
                module: "alpha".to_string(),
                lines: 10,
                follow: false,
            }))
            .await
            .unwrap()
            .into_inner();

        let first = stream.next().await.unwrap().unwrap();
        let second = stream.next().await.unwrap().unwrap();
        assert_eq!(first.message, "one");
        assert_eq!(second.message, "two");
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn tail_logs_follows_new_appends_when_follow_is_true() {
        let fixture = build_service(BTreeMap::new(), None);
        fixture.logs.append(
            "alpha",
            LogLine {
                at: SystemTime::now(),
                level: "info".to_string(),
                message: "before".to_string(),
            },
        );

        let mut stream = fixture
            .service
            .tail_logs(Request::new(pb::TailLogsRequest {
                api_version: String::new(),
                module: "alpha".to_string(),
                lines: 10,
                follow: true,
            }))
            .await
            .unwrap()
            .into_inner();

        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.message, "before");

        fixture.logs.append(
            "alpha",
            LogLine {
                at: SystemTime::now(),
                level: "info".to_string(),
                message: "after".to_string(),
            },
        );
        let second = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(second.message, "after");
    }

    #[tokio::test]
    async fn check_update_with_no_client_reports_unavailable_without_error() {
        let fixture = build_service(BTreeMap::new(), None);
        let response = fixture
            .service
            .check_update(Request::new(pb::CheckUpdateRequest {
                api_version: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!response.available);
        assert_eq!(response.current_version, "1.2.3");
        assert_eq!(response.latest_version, "1.2.3");
    }

    #[tokio::test]
    async fn check_update_with_client_returns_its_result() {
        let update: Arc<dyn UpdateClient> = Arc::new(FakeUpdateClient {
            available: true,
            latest: "9.9.9".to_string(),
            check_err: None,
            apply_err: None,
        });
        let fixture = build_service(BTreeMap::new(), Some(update));
        let response = fixture
            .service
            .check_update(Request::new(pb::CheckUpdateRequest {
                api_version: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(response.available);
        assert_eq!(response.latest_version, "9.9.9");
    }

    #[tokio::test]
    async fn apply_update_with_no_client_reports_not_configured() {
        let fixture = build_service(BTreeMap::new(), None);
        let response = fixture
            .service
            .apply_update(Request::new(pb::ApplyUpdateRequest {
                api_version: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!response.applied);
        assert_eq!(response.message, "update client not configured");
    }

    #[tokio::test]
    async fn apply_update_with_client_reports_success() {
        let ok_client: Arc<dyn UpdateClient> = Arc::new(FakeUpdateClient {
            available: false,
            latest: String::new(),
            check_err: None,
            apply_err: None,
        });
        let fixture = build_service(BTreeMap::new(), Some(ok_client));
        let response = fixture
            .service
            .apply_update(Request::new(pb::ApplyUpdateRequest {
                api_version: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(response.applied);
    }

    #[tokio::test]
    async fn apply_update_with_client_failure_returns_its_message_not_a_grpc_error() {
        let failing_client: Arc<dyn UpdateClient> = Arc::new(FakeUpdateClient {
            available: false,
            latest: String::new(),
            check_err: None,
            apply_err: Some("update server unreachable".to_string()),
        });
        let fixture = build_service(BTreeMap::new(), Some(failing_client));
        let response = fixture
            .service
            .apply_update(Request::new(pb::ApplyUpdateRequest {
                api_version: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!response.applied);
        assert_eq!(response.message, "update server unreachable");
    }
}
