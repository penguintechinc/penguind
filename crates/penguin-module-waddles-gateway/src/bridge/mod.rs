//! waddles-gateway's local **dial-in** bridge: a loopback server integration
//! scripts (OBS overlays, chat-platform glue, anything running alongside
//! the daemon on the same host) connect *into*, to get brokered, per-script
//! access to the Waddles hub.
//!
//! # The security model
//!
//! The module holds one upstream Community Access Token (CAT) — a secret
//! read once from `host.secrets()` (see [`crate::module::WaddlesGatewayModule::init`])
//! and never written to disk, logs, or a command's output unmasked (see
//! [`crate::mask`]). A connecting script must **never** see it: the bridge
//! makes every hub call itself, on the script's behalf, using its own copy
//! of the client — a script only ever holds a narrow, local, bridge-minted
//! credential scoped to a handful of operations (see [`scope`]), which the
//! bridge can revoke without touching the CAT at all. [`relay`]'s doc
//! covers exactly how the CAT is kept out of a relayed response even in an
//! adversarial-hub scenario; `relay`'s test module proves it end-to-end.
//!
//! Two transports feed one shared core ([`BridgeState`]) — the transport is
//! just the door, not a second security boundary with its own rules:
//!
//! - **[`http`] (loopback TCP + WebSocket).** A script authenticates with a
//!   per-script bearer token [`state::BridgeState::tokens`] minted for it
//!   (see [`token`]). [`start`] refuses to bind anything but a loopback
//!   address.
//! - **[`unixsock`] (unix domain socket).** No bearer token: the socket's
//!   `0660` permissions plus a per-connection `SO_PEERCRED` check — the
//!   exact same [`penguin_ipc`] decision logic `penguind`'s own control
//!   socket uses — establish trust, so a script only needs to *name* itself.
//!
//! # A later track: dial-**out**
//!
//! This module is the dial-**in** direction only — scripts connecting to
//! the daemon. A dial-**out** adapter (e.g. one that drives an OBS
//! WebSocket connection *from* the daemon) is a separate, later track; see
//! [`BridgeAdapter`] for the seam it plugs into. Nothing implements that
//! trait yet.

mod http;
pub mod obs;
mod relay;
mod scope;
mod state;
mod token;
mod unixsock;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use penguin_ipc::groups_unix::SystemGroups;
use serde_json::json;

use scope::Scope;
use state::{BridgeEvent, BridgeState};

use crate::config::BridgeSection;
use crate::module::WaddlesGatewayModule;

/// The seam a later, separate track (a dial-**out** adapter — see this
/// module's doc) plugs an outbound integration into, without this track
/// needing to know anything about what that integration actually is.
/// Nothing implements this yet; [`BridgeDeps::adapters`] is always empty
/// today — this trait exists so that later track has a registration point
/// to compile against rather than needing to modify [`start`] itself.
pub trait BridgeAdapter: Send + Sync {
    /// A short, stable name for logs/diagnostics.
    fn name(&self) -> &str;

    /// Called once, immediately after the bridge's transports are up, with
    /// a handle to the shared [`BridgeState`]. An adapter uses this to
    /// [`BridgeState::publish_event`] and/or [`BridgeState::subscribe`],
    /// spawning whatever background task it needs off of `state` — e.g. a
    /// future OBS adapter would open its own outbound WebSocket connection
    /// here and translate OBS events into [`BridgeEvent`]s.
    fn attach(&self, state: Arc<BridgeState>) -> Result<(), BridgeError>;
}

/// What [`start`] needs from the rest of the module.
pub struct BridgeDeps {
    /// A handle to the module — [`relay`] calls hub methods through
    /// `module.client()`/`module.call(..)`, so a community switch
    /// (`community use <id>`) is honored by the bridge automatically.
    pub module: WaddlesGatewayModule,
    /// The module's live Community Access Token — kept only so [`relay`]
    /// can scrub it defensively out of a relayed response/error. Never
    /// sent to, or accepted from, a connecting script.
    pub cat: String,
    /// Dial-out adapters to attach once the bridge is up. Always empty in
    /// this track — see [`BridgeAdapter`].
    pub adapters: Vec<Arc<dyn BridgeAdapter>>,
}

/// Everything that can go wrong standing the bridge's transports up.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// `bridge.listen_tcp` parsed but named a non-loopback address — the
    /// bridge's whole security model assumes only local processes can ever
    /// reach it, so this is refused rather than silently honored.
    #[error("bridge.listen_tcp {addr:?} must be a loopback address")]
    NonLoopbackTcp { addr: String },
    /// `bridge.listen_tcp` did not parse as a socket address at all.
    #[error("invalid bridge.listen_tcp address {addr:?}: {source}")]
    InvalidTcpAddr {
        addr: String,
        #[source]
        source: std::net::AddrParseError,
    },
    /// Binding the TCP listener itself failed (e.g. the port is in use).
    #[error("failed to bind bridge TCP listener on {addr}: {source}")]
    TcpBind {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    /// Binding the unix listener failed — see [`penguin_ipc::IpcError`] for
    /// the specific step.
    #[error("failed to bind bridge unix listener: {0}")]
    UnixBind(#[from] penguin_ipc::IpcError),
    /// A [`BridgeAdapter::attach`] call failed.
    #[error("adapter {name} failed to attach: {source}")]
    AdapterAttach {
        name: String,
        #[source]
        source: Box<BridgeError>,
    },
}

/// A running bridge's transports, returned by [`start`] and torn down by
/// [`BridgeHandle::stop`]. Owned by [`crate::module::WaddlesGatewayModule`]
/// across a `start`/`stop` cycle — see that module's `start_bridge`/
/// `stop_bridge` doc.
pub struct BridgeHandle {
    cancel: CancellationToken,
    tcp_task: Option<JoinHandle<()>>,
    unix_task: Option<JoinHandle<()>>,
    tcp_local_addr: Option<SocketAddr>,
    unix_local_path: Option<PathBuf>,
    // Read via `BridgeHandle::state` — a future token-issuing CLI command
    // or `BridgeAdapter` is the intended production caller; this crate's
    // own tests are the only caller today.
    #[allow(dead_code)]
    state: Arc<BridgeState>,
}

impl BridgeHandle {
    /// The TCP transport's real bound address, once [`start`] has bound it
    /// — `None` if `bridge.listen_tcp` was empty (that transport was never
    /// started).
    pub fn tcp_local_addr(&self) -> Option<SocketAddr> {
        self.tcp_local_addr
    }

    /// The unix transport's socket path, once [`start`] has bound it —
    /// `None` if `bridge.listen_unix` was empty.
    pub fn unix_local_path(&self) -> Option<&Path> {
        self.unix_local_path.as_deref()
    }

    /// The shared bridge core — for a caller (tests today; a future
    /// token-issuing CLI command or [`BridgeAdapter`] eventually) that
    /// needs to mint tokens or publish events directly.
    #[allow(dead_code)]
    pub fn state(&self) -> &Arc<BridgeState> {
        &self.state
    }

    /// Signals both transports to stop accepting new connections and waits
    /// for their accept loops to exit, so the TCP port and the unix socket
    /// are both guaranteed released before this returns. In-flight
    /// connections already accepted are not individually awaited — a
    /// stuck client must never block shutdown.
    pub async fn stop(self) {
        self.cancel.cancel();
        if let Some(task) = self.tcp_task {
            let _ = task.await;
        }
        if let Some(task) = self.unix_task {
            let _ = task.await;
        }
    }
}

/// Binds and starts whichever of `cfg`'s two transports have a non-empty
/// address configured (both, one, or — trivially — neither), then attaches
/// `deps.adapters`. Binding happens synchronously, so a bad address (in
/// use, non-loopback, unparsable, or a unix-socket setup failure) is
/// returned immediately rather than surfacing later from a background
/// task; only the accept loops themselves are spawned and left running.
///
/// Callers (today, only [`crate::module::WaddlesGatewayModule::start_bridge`])
/// are expected to check `cfg.enabled` before calling this — `start` itself
/// does not consult it, since [`crate::config::BridgeSection::enabled`] is a
/// module-level policy decision, not a transport-binding one.
pub async fn start(cfg: &BridgeSection, deps: BridgeDeps) -> Result<BridgeHandle, BridgeError> {
    let state = Arc::new(BridgeState::new(deps.module, deps.cat));
    for name in &cfg.allowed_integrations {
        state.tokens.register(name, Scope::all());
        // Mint an initial TCP bearer token so the transport is immediately
        // usable. `mint` never fails here — `name` was just registered on
        // the line above — so the `Option` is intentionally discarded: this
        // track builds the bridge's server-side mechanics, not the (later,
        // separate) operator-facing way a script actually learns its
        // token. `TokenRegistry::mint` remains directly callable — by a
        // test today, a future token-issuing CLI command eventually — to
        // get a fresh one.
        state.tokens.mint(name);
    }

    let cancel = CancellationToken::new();

    let (tcp_task, tcp_local_addr) = start_tcp(cfg, &state, &cancel).await?;
    let (unix_task, unix_local_path) = start_unix(cfg, &state, &cancel)?;

    for adapter in &deps.adapters {
        adapter
            .attach(Arc::clone(&state))
            .map_err(|source| BridgeError::AdapterAttach {
                name: adapter.name().to_string(),
                source: Box::new(source),
            })?;
    }

    // A subscriber connected before this point can never see it (broadcast
    // channels don't replay), but it establishes the event stream as
    // genuinely live from the moment the bridge is up, and gives any
    // already-subscribed test/adapter a real event to observe.
    state.publish_event(BridgeEvent {
        kind: "bridge.started".to_string(),
        data: json!({
            "tcp": tcp_local_addr.map(|addr| addr.to_string()),
            "unix": unix_local_path.as_ref().map(|path| path.display().to_string()),
        }),
    });

    Ok(BridgeHandle {
        cancel,
        tcp_task,
        unix_task,
        tcp_local_addr,
        unix_local_path,
        state,
    })
}

async fn start_tcp(
    cfg: &BridgeSection,
    state: &Arc<BridgeState>,
    cancel: &CancellationToken,
) -> Result<(Option<JoinHandle<()>>, Option<SocketAddr>), BridgeError> {
    if cfg.listen_tcp.is_empty() {
        return Ok((None, None));
    }

    let addr: SocketAddr =
        cfg.listen_tcp
            .parse()
            .map_err(|source| BridgeError::InvalidTcpAddr {
                addr: cfg.listen_tcp.clone(),
                source,
            })?;
    if !addr.ip().is_loopback() {
        return Err(BridgeError::NonLoopbackTcp {
            addr: cfg.listen_tcp.clone(),
        });
    }

    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| BridgeError::TcpBind {
            addr: cfg.listen_tcp.clone(),
            source,
        })?;
    let local_addr = listener.local_addr().ok();

    let router = http::router(Arc::clone(state));
    let shutdown = cancel.clone();
    let task = tokio::spawn(async move {
        let server = axum::serve(listener, router);
        let _ = server
            .with_graceful_shutdown(async move { shutdown.cancelled().await })
            .await;
    });

    Ok((Some(task), local_addr))
}

fn start_unix(
    cfg: &BridgeSection,
    state: &Arc<BridgeState>,
    cancel: &CancellationToken,
) -> Result<(Option<JoinHandle<()>>, Option<PathBuf>), BridgeError> {
    if cfg.listen_unix.is_empty() {
        return Ok((None, None));
    }

    let path = PathBuf::from(&cfg.listen_unix);
    let listener = unixsock::bind(&path, "")?;

    let auth = unixsock::UnixAuth {
        self_uid: nix::unistd::Uid::current().as_raw(),
        allowed_group: String::new(),
        resolver: Arc::new(SystemGroups),
    };
    let state = Arc::clone(state);
    let cancel = cancel.clone();
    let task = tokio::spawn(async move {
        unixsock::serve(listener, state, auth, cancel).await;
    });

    Ok((Some(task), Some(path)))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;
    use crate::testutil::{FakeHost, MockHub, MockResponse, RecordingLogger};
    use penguin_sdk::{Module, SecretStore};

    async fn init_module(hub: &MockHub, cat: &str) -> WaddlesGatewayModule {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        if !cat.is_empty() {
            host.secrets.set("cat", cat.as_bytes()).await.unwrap();
        }
        host.config = serde_json::to_vec(&json!({
            "hub": {"base_url": hub.base_url},
            "community_id": "11111111-1111-4111-8111-111111111111",
        }))
        .unwrap();
        let module = WaddlesGatewayModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");
        module
    }

    fn no_adapters() -> Vec<Arc<dyn BridgeAdapter>> {
        Vec::new()
    }

    #[tokio::test]
    async fn start_binds_both_transports_and_stop_releases_both() {
        let hub = MockHub::start().await;
        let module = init_module(&hub, "").await;
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("bridge.sock");
        let cfg = BridgeSection {
            enabled: true,
            listen_tcp: "127.0.0.1:0".to_string(),
            listen_unix: socket_path.to_string_lossy().into_owned(),
            allowed_integrations: vec!["watcher".to_string()],
            ..Default::default()
        };
        let deps = BridgeDeps {
            module,
            cat: String::new(),
            adapters: no_adapters(),
        };

        let handle = start(&cfg, deps).await.expect("bridge starts");
        let tcp_addr = handle.tcp_local_addr().expect("tcp bound");
        assert!(
            socket_path.exists(),
            "unix socket file must exist while running"
        );

        // Both transports must be reachable while running.
        assert!(TcpStream::connect(tcp_addr).await.is_ok());
        assert!(tokio::net::UnixStream::connect(&socket_path).await.is_ok());

        handle.stop().await;

        // Both must be released afterward — nothing left listening.
        assert!(TcpStream::connect(tcp_addr).await.is_err());
        assert!(tokio::net::UnixStream::connect(&socket_path).await.is_err());

        hub.stop().await;
    }

    #[tokio::test]
    async fn non_loopback_tcp_address_is_refused() {
        let hub = MockHub::start().await;
        let module = init_module(&hub, "").await;
        let cfg = BridgeSection {
            enabled: true,
            listen_tcp: "0.0.0.0:0".to_string(),
            listen_unix: String::new(),
            allowed_integrations: Vec::new(),
            ..Default::default()
        };
        let deps = BridgeDeps {
            module,
            cat: String::new(),
            adapters: no_adapters(),
        };

        let Err(err) = start(&cfg, deps).await else {
            panic!("a non-loopback bridge.listen_tcp must be refused");
        };
        assert!(matches!(err, BridgeError::NonLoopbackTcp { .. }));

        hub.stop().await;
    }

    #[tokio::test]
    async fn empty_addresses_leave_both_transports_unbound() {
        let hub = MockHub::start().await;
        let module = init_module(&hub, "").await;
        let cfg = BridgeSection {
            enabled: true,
            listen_tcp: String::new(),
            listen_unix: String::new(),
            allowed_integrations: Vec::new(),
            ..Default::default()
        };
        let deps = BridgeDeps {
            module,
            cat: String::new(),
            adapters: no_adapters(),
        };

        let handle = start(&cfg, deps)
            .await
            .expect("start succeeds with nothing to bind");
        assert_eq!(handle.tcp_local_addr(), None);
        assert_eq!(handle.unix_local_path(), None);

        handle.stop().await;
        hub.stop().await;
    }

    /// The end-to-end proof this whole module exists for: even when a hub
    /// response leaks the live CAT into raw, non-JSON error text (simulating
    /// a misbehaving proxy/debug page echoing request headers), neither the
    /// bridge's HTTP response nor its log output ever carries the raw
    /// secret — only [`crate::mask::mask_secret`]'s rendering does.
    #[tokio::test]
    async fn the_live_cat_never_reaches_a_response_body_or_a_log_line() {
        let cat = "wdl_c_ABSOLUTELY_SECRET_LIVE_VALUE";
        let hub = MockHub::start().await;
        hub.respond(
            "PUT",
            "/admin/11111111-1111-4111-8111-111111111111/music/settings",
            MockResponse::json(
                500,
                format!("<html>upstream debug page: saw Authorization: Bearer {cat}</html>"),
            ),
        )
        .await;

        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        let recorder = Arc::new(RecordingLogger::default());
        host.logger = recorder.clone();
        host.secrets.set("cat", cat.as_bytes()).await.unwrap();
        host.config = serde_json::to_vec(&json!({
            "hub": {"base_url": hub.base_url},
            "community_id": "11111111-1111-4111-8111-111111111111",
        }))
        .unwrap();
        let module = WaddlesGatewayModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");

        let cfg = BridgeSection {
            enabled: true,
            listen_tcp: "127.0.0.1:0".to_string(),
            listen_unix: String::new(),
            allowed_integrations: vec!["music-panel".to_string()],
            ..Default::default()
        };
        let deps = BridgeDeps {
            module,
            cat: cat.to_string(),
            adapters: no_adapters(),
        };
        let handle = start(&cfg, deps).await.expect("bridge starts");
        let token = handle
            .state()
            .tokens
            .mint("music-panel")
            .expect("registered");
        let addr = handle.tcp_local_addr().expect("tcp bound");

        let client = reqwest::Client::new();
        let response = client
            .post(format!("http://{addr}/rpc"))
            .json(&json!({
                "integration": "music-panel", "token": token,
                "op": "music.update", "params": {"volume_limit": 10},
            }))
            .send()
            .await
            .unwrap();
        let body: Value = response.json().await.unwrap();
        let error_text = body["error"]
            .as_str()
            .expect("relay error surfaced")
            .to_string();

        assert!(
            !error_text.contains(cat),
            "raw CAT leaked into the response body"
        );
        assert!(
            error_text.contains("****"),
            "expected the masked rendering in its place"
        );

        for line in recorder.lines() {
            assert!(
                !line.contains(cat),
                "raw CAT leaked into a log line: {line}"
            );
        }

        handle.stop().await;
        hub.stop().await;
    }

    /// Reads exactly one server-to-client WebSocket text frame off a raw
    /// TCP connection, performing just enough of an RFC 6455 client
    /// handshake to reach `101 Switching Protocols` — no WS client crate is
    /// in the workspace, and this bridge's own server-side handling (via
    /// axum's `ws` feature) is the thing under test, not a client library.
    async fn read_one_ws_text_frame(addr: SocketAddr, path_and_query: String) -> String {
        use base64::Engine as _;

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 16]);
        let request = format!(
            "GET {path_and_query} HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("send handshake");

        let mut headers = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte).await.expect("read headers");
            headers.push(byte[0]);
            if headers.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let headers = String::from_utf8_lossy(&headers);
        assert!(
            headers.starts_with("HTTP/1.1 101"),
            "expected 101 Switching Protocols, got: {headers}"
        );

        let mut frame_head = [0u8; 2];
        stream
            .read_exact(&mut frame_head)
            .await
            .expect("read frame head");
        assert_eq!(frame_head[0] & 0x0f, 0x1, "expected a text frame");
        assert_eq!(frame_head[1] & 0x80, 0, "server frames must not be masked");
        let mut payload_len = (frame_head[1] & 0x7f) as usize;
        if payload_len == 126 {
            let mut extended = [0u8; 2];
            stream
                .read_exact(&mut extended)
                .await
                .expect("read extended length");
            payload_len = u16::from_be_bytes(extended) as usize;
        }
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload).await.expect("read payload");
        String::from_utf8(payload).expect("payload is UTF-8")
    }

    #[tokio::test]
    async fn ws_delivers_a_published_event_to_a_connected_client() {
        let hub = MockHub::start().await;
        let module = init_module(&hub, "").await;
        let cfg = BridgeSection {
            enabled: true,
            listen_tcp: "127.0.0.1:0".to_string(),
            listen_unix: String::new(),
            allowed_integrations: vec!["watcher".to_string()],
            ..Default::default()
        };
        let deps = BridgeDeps {
            module,
            cat: String::new(),
            adapters: no_adapters(),
        };
        let handle = start(&cfg, deps).await.expect("bridge starts");
        let token = handle.state().tokens.mint("watcher").expect("registered");
        let addr = handle.tcp_local_addr().expect("tcp bound");

        let path = format!("/ws?integration=watcher&token={token}");
        let read_task = tokio::spawn(read_one_ws_text_frame(addr, path));

        let state = Arc::clone(handle.state());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while state.subscriber_count() == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "client never subscribed in time"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        state.publish_event(BridgeEvent {
            kind: "test.event".to_string(),
            data: json!({"hello": "world"}),
        });

        let received = tokio::time::timeout(Duration::from_secs(5), read_task)
            .await
            .expect("no timeout")
            .expect("read task did not panic");
        let value: Value = serde_json::from_str(&received).expect("valid JSON payload");
        assert_eq!(value["kind"], "test.event");
        assert_eq!(value["data"]["hello"], "world");

        handle.stop().await;
        hub.stop().await;
    }
}
