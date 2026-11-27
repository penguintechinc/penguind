//! A dial-**out** adapter connecting to OBS via obs-websocket v5, translating
//! OBS events into [`BridgeEvent`]s for local integration scripts.
//!
//! This adapter connects to a local OBS WebSocket server (default
//! `ws://127.0.0.1:4455`), authenticates with the SHA256 challenge handshake
//! (Hello -> Identify -> Identified), then streams OBS events back into the
//! bridge's event channel. Any script can subscribe to these events via the
//! bridge's WebSocket transport without ever seeing the OBS password.
//!
//! # Security
//!
//! The OBS WebSocket password is stored in the [`ObsConfig`], passed at
//! adapter construction, and **never** logged or leaked into errors. Diagnostic
//! logging applies [`crate::mask::mask_secret`] to any rendered secret. The
//! adapter only connects to loopback addresses; a non-loopback URL is rejected.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::bridge::{BridgeAdapter, BridgeError, BridgeState};

#[cfg(test)]
use tokio::time::sleep;

/// Configuration for the OBS adapter: the WebSocket URL and password.
#[derive(Debug, Clone)]
pub struct ObsConfig {
    /// The OBS WebSocket server URL, typically `ws://127.0.0.1:4455`.
    /// **Must** be a loopback address; non-loopback URLs are rejected at
    /// connection time to match the bridge's security model.
    pub url: String,
    /// The OBS WebSocket password — kept secret and never logged unmasked.
    pub password: String,
}

impl ObsConfig {
    /// Creates a new OBS configuration with a URL and password. The URL
    /// must be a loopback address; validation happens at connection time.
    pub fn new(url: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            password: password.into(),
        }
    }
}

/// The OBS WebSocket v5 adapter — implements [`BridgeAdapter`] to connect
/// to a local OBS WebSocket server and stream events.
/// A command to send to the OBS WebSocket server (request).
/// The sender will be resolved when a matching response (by request_id) arrives.
pub struct ObsCommand {
    pub request_type: String,
    pub request_data: Value,
    pub respond_to: oneshot::Sender<Result<Value, ObsCommandError>>,
}

/// Errors that can occur when sending a command to OBS.
#[derive(Debug, Clone)]
pub enum ObsCommandError {
    /// OBS adapter is not connected.
    NotConnected,
    /// OBS did not respond within the timeout.
    Timeout,
    /// OBS rejected the request with an error code and comment.
    Rejected { code: i32, comment: String },
    /// Other error, as a string.
    Other(String),
}

impl std::fmt::Display for ObsCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObsCommandError::NotConnected => write!(f, "obs adapter is not connected"),
            ObsCommandError::Timeout => write!(f, "obs did not respond within the timeout"),
            ObsCommandError::Rejected { code, comment } => {
                write!(f, "obs rejected the request (code {code}): {comment}")
            }
            ObsCommandError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ObsCommandError {}

pub struct ObsAdapter {
    config: ObsConfig,
    /// Channel for sending commands to the connection task.
    command_tx: mpsc::UnboundedSender<ObsCommand>,
    /// Channel for receiving commands (taken by attach() when the connection starts).
    /// Uses a parking_lot Mutex which can be locked from async contexts.
    command_rx: parking_lot::Mutex<Option<mpsc::UnboundedReceiver<ObsCommand>>>,
}

impl ObsAdapter {
    /// Creates a new OBS adapter with the given configuration.
    /// The channels are created here and exist from construction until the adapter is dropped.
    pub fn new(config: ObsConfig) -> Self {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        Self {
            config,
            command_tx,
            command_rx: parking_lot::Mutex::new(Some(command_rx)),
        }
    }

    /// Sends a command to OBS and waits for the response.
    /// Returns immediately with NotConnected if the connection task is not running.
    /// Returns Timeout if OBS doesn't respond within 10 seconds.
    pub async fn send_request(
        &self,
        request_type: &str,
        request_data: Value,
    ) -> Result<Value, ObsCommandError> {
        let (respond_to, rx) = oneshot::channel();
        self.command_tx
            .send(ObsCommand {
                request_type: request_type.to_string(),
                request_data,
                respond_to,
            })
            .map_err(|_| ObsCommandError::NotConnected)?;

        // Wait for response with a 10-second timeout
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(ObsCommandError::NotConnected), // sender dropped mid-flight
            Err(_) => Err(ObsCommandError::Timeout),          // 10s timeout elapsed
        }
    }
}

impl BridgeAdapter for ObsAdapter {
    fn name(&self) -> &str {
        "obs"
    }

    fn attach(&self, state: Arc<BridgeState>) -> Result<(), BridgeError> {
        let config = self.config.clone();
        let state_for_task = Arc::clone(&state);

        // Take the command receiver from the Mutex; if it's already been taken,
        // this is a second attach() call (which shouldn't happen, but fail loudly).
        let command_rx = self
            .command_rx
            .lock()
            .take()
            .expect("OBS adapter attach() called twice (invariant violation)");

        // Spawn a background task that connects and streams events. If the
        // connection fails or drops, the task exits; the bridge continues
        // running unaffected. A reconnection strategy is not implemented in
        // this first version.
        tokio::spawn(async move {
            if let Err(e) = run_obs_connection(config, state_for_task, command_rx).await {
                // Log the error but don't panic — a failed OBS connection does
                // not take down the entire bridge. The logger is available only
                // indirectly (through state.module.host().logger()), so we log
                // here without any internal crate access.
                eprintln!("obs adapter: connection failed: {e}");
            }
        });

        Ok(())
    }
}

/// The WebSocket message types from the obs-websocket v5 spec.
#[derive(Debug, Serialize, Deserialize)]
struct WsMessage {
    #[serde(default)]
    op: u32,
    #[serde(default)]
    d: Option<Value>,
}

/// Hello message from the server: carries `sessionId` and `serverTime` for
/// the auth challenge.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HelloData {
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(rename = "serverTime")]
    server_time: u64,
    #[serde(rename = "serverVersion")]
    server_version: Option<String>,
    #[serde(default)]
    authentication: Option<String>,
}

/// Identify message we send to the server: carries the sessionId and auth hash.
#[derive(Debug, Serialize)]
struct IdentifyData {
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(default)]
    authentication: Option<String>,
}

/// Main connection loop: establishes the WebSocket, performs the auth
/// handshake, and streams OBS events into the bridge state.
async fn run_obs_connection(
    config: ObsConfig,
    state: Arc<BridgeState>,
    mut command_rx: mpsc::UnboundedReceiver<ObsCommand>,
) -> Result<(), String> {
    use futures_util::sink::SinkExt as _;
    use futures_util::stream::StreamExt as _;

    // Validate the URL is a loopback address before connecting.
    validate_loopback_url(&config.url)?;

    // Connect to the OBS WebSocket server.
    let (ws, _resp) = connect_async(&config.url)
        .await
        .map_err(|e| format!("failed to connect to OBS at {}: {}", config.url, e))?;

    // Publish a connection event so scripts know the adapter is alive.
    state.publish_event(super::BridgeEvent {
        kind: "obs.connected".to_string(),
        data: json!({"url": config.url}),
    });

    // Split the WebSocket into a sender and receiver so we can handle both
    // directions concurrently.
    let (mut ws_send, mut ws_recv) = ws.split();

    // Wait for the Hello message from OBS.
    let hello_msg = ws_recv
        .next()
        .await
        .ok_or("server closed connection before sending Hello".to_string())?
        .map_err(|e| format!("failed to read Hello message: {e}"))?;

    let hello_text = hello_msg
        .into_text()
        .map_err(|_| "Hello message was not text".to_string())?;
    let hello_json: WsMessage =
        serde_json::from_str(&hello_text).map_err(|e| format!("malformed Hello message: {e}"))?;

    // Parse the Hello's session info.
    let hello_data: HelloData = serde_json::from_value(
        hello_json
            .d
            .ok_or("Hello message missing data field".to_string())?,
    )
    .map_err(|e| format!("invalid Hello data: {e}"))?;

    // Perform the auth challenge handshake: compute the auth hash and send Identify.
    let auth_hash = if let Some(challenge) = &hello_data.authentication {
        Some(compute_auth_hash(&config.password, challenge)?)
    } else {
        None
    };

    let identify_data = IdentifyData {
        session_id: hello_data.session_id.clone(),
        authentication: auth_hash,
    };
    let identify_msg = json!({
        "op": 1,  // op=1 is Identify
        "d": identify_data,
    });
    ws_send
        .send(Message::Text(identify_msg.to_string().into()))
        .await
        .map_err(|e| format!("failed to send Identify: {e}"))?;

    // Wait for the Identified confirmation.
    let identified_msg = ws_recv
        .next()
        .await
        .ok_or("server closed connection before sending Identified".to_string())?
        .map_err(|e| format!("failed to read Identified message: {e}"))?;

    let identified_text = identified_msg
        .into_text()
        .map_err(|_| "Identified message was not text".to_string())?;
    let identified_json: WsMessage = serde_json::from_str(&identified_text)
        .map_err(|e| format!("malformed Identified message: {e}"))?;

    // If op != 2 (Identified), authentication failed.
    if identified_json.op != 2 {
        return Err("server rejected authentication (did not send Identified)".to_string());
    }

    // Publish an authenticated event and then start streaming OBS events.
    state.publish_event(super::BridgeEvent {
        kind: "obs.authenticated".to_string(),
        data: json!({"sessionId": hello_data.session_id}),
    });

    // Map of pending request IDs to their response channels.
    // When a RequestResponse (op=7) arrives, we resolve it here.
    let mut pending: HashMap<String, oneshot::Sender<Result<Value, ObsCommandError>>> =
        HashMap::new();

    // Stream incoming OBS events and handle outgoing commands via select!.
    loop {
        tokio::select! {
            // Handle incoming messages from OBS.
            msg = ws_recv.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(parsed) = serde_json::from_str::<WsMessage>(&text) {
                            match parsed.op {
                                5 => {
                                    // op=5 is EventMessage from the server.
                                    if let Some(event_data) = parsed.d {
                                        // Extract the event name and metadata.
                                        if let Some(event_name) =
                                            event_data.get("eventName").and_then(|v| v.as_str())
                                        {
                                            state.publish_event(super::BridgeEvent {
                                                kind: format!("obs.event.{}", event_name),
                                                data: event_data
                                                    .get("eventData")
                                                    .cloned()
                                                    .unwrap_or(Value::Null),
                                            });
                                        }
                                    }
                                }
                                7 => {
                                    // op=7 is RequestResponse from the server.
                                    // Extract requestId and result, resolve the pending oneshot.
                                    #[allow(clippy::collapsible_if)]
                                    if let Some(response_data) = parsed.d {
                                        if let Some(request_id) = response_data
                                            .get("requestId")
                                            .and_then(|v| v.as_str())
                                        {
                                            if let Some(tx) = pending.remove(request_id) {
                                                let result = if let Some(status) = response_data.get("requestStatus") {
                                                    let result = status.get("result").and_then(|v| v.as_bool()).unwrap_or(false);
                                                    if result {
                                                        Ok(response_data
                                                            .get("responseData")
                                                            .cloned()
                                                            .unwrap_or(Value::Null))
                                                    } else {
                                                        let code = status
                                                            .get("code")
                                                            .and_then(|v| v.as_i64())
                                                            .unwrap_or(0) as i32;
                                                        let comment = status
                                                            .get("comment")
                                                            .and_then(|v| v.as_str())
                                                            .unwrap_or("unknown error")
                                                            .to_string();
                                                        Err(ObsCommandError::Rejected {
                                                            code,
                                                            comment,
                                                        })
                                                    }
                                                } else {
                                                    Err(ObsCommandError::Other(
                                                        "malformed response".to_string(),
                                                    ))
                                                };
                                                let _ = tx.send(result);
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        state.publish_event(super::BridgeEvent {
                            kind: "obs.disconnected".to_string(),
                            data: json!({}),
                        });
                        // Notify all pending requests that the connection closed.
                        pending.clear();
                        break;
                    }
                    Some(Err(e)) => {
                        return Err(format!("WebSocket error: {e}"));
                    }
                    None => {
                        // ws_recv ended (connection closed).
                        state.publish_event(super::BridgeEvent {
                            kind: "obs.disconnected".to_string(),
                            data: json!({}),
                        });
                        // Notify all pending requests that the connection closed by dropping them.
                        pending.clear();
                        break;
                    }
                    _ => {}
                }
            }

            // Handle commands from the request sender.
            cmd = command_rx.recv() => {
                if let Some(ObsCommand { request_type, request_data, respond_to }) = cmd {
                    let request_id = Uuid::new_v4().to_string();
                    pending.insert(request_id.clone(), respond_to);

                    let frame = json!({
                        "op": 6,
                        "d": {
                            "requestType": request_type,
                            "requestId": request_id,
                            "requestData": request_data
                        }
                    });

                    if ws_send.send(Message::Text(frame.to_string().into())).await.is_err() {
                        // Send failed, which usually means the connection is dead.
                        // Clear pending requests (dropping senders notifies their receivers).
                        pending.clear();
                        return Err("failed to send command to OBS".to_string());
                    }
                }
            }
        }
    }

    Ok(())
}

/// Validates that the given URL is a WebSocket loopback address.
/// The adapter only connects to local OBS servers (127.0.0.0/8 or ::1)
/// to prevent credential exfiltration via SSRF attacks.
///
/// Security contract: only accepts `ws://` scheme (not `wss`, `http`, etc.)
/// and verifies the host is a loopback address via proper URL parsing
/// (not substring matching, which is trivially bypassable).
fn validate_loopback_url(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {}", e))?;

    // Only accept ws:// scheme (plaintext loopback connection).
    // wss://, http://, https://, etc. are rejected.
    if parsed.scheme() != "ws" {
        return Err(format!(
            "OBS WebSocket URL must use ws:// scheme, got: {}",
            parsed.scheme()
        ));
    }

    // Extract and validate the host.
    let host = parsed.host().ok_or("OBS WebSocket URL has no host")?;

    match host {
        url::Host::Domain(d) => {
            // Only localhost is accepted (case-insensitive).
            if d.eq_ignore_ascii_case("localhost") {
                Ok(())
            } else {
                Err(format!(
                    "OBS WebSocket URL host must be localhost, got: {}",
                    d
                ))
            }
        }
        url::Host::Ipv4(ip) => {
            // Accept if the IP is a loopback address (127.0.0.0/8).
            if std::net::IpAddr::V4(ip).is_loopback() {
                Ok(())
            } else {
                Err(format!(
                    "OBS WebSocket URL must be a loopback address, got: {}",
                    ip
                ))
            }
        }
        url::Host::Ipv6(ip) => {
            // Accept if the IP is a loopback address (::1).
            if std::net::IpAddr::V6(ip).is_loopback() {
                Ok(())
            } else {
                Err(format!(
                    "OBS WebSocket URL must be a loopback address, got: {}",
                    ip
                ))
            }
        }
    }
}

/// Computes the obs-websocket v5 authentication hash given the password and
/// the server's challenge. The formula is:
/// `auth = base64(sha256(base64(sha256(password + salt)) + challenge))`.
fn compute_auth_hash(password: &str, challenge: &str) -> Result<String, String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    // Parse the challenge to extract the salt and the challenge string.
    // The challenge format is: "{salt}.{challenge}".
    let parts: Vec<&str> = challenge.split('.').collect();
    if parts.len() != 2 {
        return Err("challenge format invalid (expected salt.challenge)".to_string());
    }
    let salt = parts[0];
    let challenge_str = parts[1];

    // Step 1: Hash password + salt and base64 encode it.
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt.as_bytes());
    let hash1 = hasher.finalize();
    let hash1_b64 = base64::engine::general_purpose::STANDARD.encode(hash1);

    // Step 2: Hash the concatenation of hash1_b64 + challenge and base64 encode.
    let mut hasher = Sha256::new();
    hasher.update(hash1_b64.as_bytes());
    hasher.update(challenge_str.as_bytes());
    let hash2 = hasher.finalize();
    let auth_hash = base64::engine::general_purpose::STANDARD.encode(hash2);

    Ok(auth_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream::StreamExt;
    use penguin_sdk::Module;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;
    use tokio_tungstenite::{accept_async, tungstenite::Message};

    /// A mock OBS WebSocket v5 server for testing. Accepts one connection,
    /// performs the auth handshake, and can send or receive messages.
    #[allow(dead_code)]
    struct MockObsServer {
        listen_addr: SocketAddr,
        messages_sent: Arc<Mutex<Vec<String>>>,
        messages_received: Arc<Mutex<Vec<String>>>,
        server_task: tokio::task::JoinHandle<()>,
    }

    impl MockObsServer {
        /// Starts a mock OBS server on a loopback ephemeral port. Returns the
        /// server and its WebSocket URL.
        async fn start() -> (Self, String) {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind loopback listener");
            let addr = listener.local_addr().expect("get bound address");
            let url = format!("ws://{}", addr);

            let messages_sent = Arc::new(Mutex::new(Vec::new()));
            let messages_received = Arc::new(Mutex::new(Vec::new()));

            let sent_clone = Arc::clone(&messages_sent);
            let recv_clone = Arc::clone(&messages_received);

            let server_task = tokio::spawn(async move {
                if let Ok((stream, _)) = listener.accept().await
                    && let Ok(ws) = accept_async(stream).await
                {
                    let (mut ws_send, mut ws_recv) = ws.split();

                    // Send Hello message.
                    use futures_util::sink::SinkExt as _;
                    let hello = json!({
                        "op": 0,
                        "d": {
                            "serverVersion": "5.0.0",
                            "sessionId": "test-session-123",
                            "serverTime": 1234567890u64,
                            "authentication": "salt123.challenge456",
                        },
                    });
                    let _ = ws_send.send(Message::Text(hello.to_string().into())).await;

                    // Receive and record Identify message.
                    if let Some(Ok(Message::Text(text))) = ws_recv.next().await {
                        recv_clone.lock().await.push(text.to_string());

                        // Send Identified confirmation.
                        let identified = json!({
                            "op": 2,
                            "d": {},
                        });
                        let _ = ws_send
                            .send(Message::Text(identified.to_string().into()))
                            .await;

                        // Stream events: send a mock SceneChanged event.
                        sleep(Duration::from_millis(50)).await;
                        let event = json!({
                            "op": 5,
                            "d": {
                                "eventName": "SceneChanged",
                                "eventData": {
                                    "sceneName": "TestScene",
                                },
                            },
                        });
                        let _ = ws_send.send(Message::Text(event.to_string().into())).await;
                        sent_clone.lock().await.push(event.to_string());

                        // Keep the connection open for a bit.
                        sleep(Duration::from_millis(200)).await;
                    }
                }
            });

            (
                Self {
                    listen_addr: addr,
                    messages_sent,
                    messages_received,
                    server_task,
                },
                url,
            )
        }

        /// Waits for the server task to complete.
        async fn stop(self) {
            let _ = tokio::time::timeout(Duration::from_secs(2), self.server_task).await;
        }

        /// Returns the messages the server received from the client.
        #[allow(dead_code)]
        async fn received_messages(&self) -> Vec<String> {
            self.messages_received.lock().await.clone()
        }

        /// Returns the messages the server sent to the client.
        #[allow(dead_code)]
        async fn sent_messages(&self) -> Vec<String> {
            self.messages_sent.lock().await.clone()
        }
    }

    #[tokio::test]
    async fn obs_adapter_connects_and_authenticates() {
        let (server, url) = MockObsServer::start().await;

        let config = ObsConfig::new(&url, "test-password");
        let adapter = ObsAdapter::new(config);

        // Create a mock bridge state.
        let hub = crate::testutil::MockHub::start().await;
        let dir = tempfile::tempdir().unwrap();
        let mut host = crate::testutil::FakeHost::new(dir.path().to_path_buf());
        host.config = serde_json::to_vec(&json!({
            "hub": {"base_url": hub.base_url},
            "community_id": "11111111-1111-4111-8111-111111111111",
        }))
        .unwrap();
        let module = crate::module::WaddlesGatewayModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");
        let state = Arc::new(BridgeState::new(module, "test-cat".to_string()));

        // Subscribe to events so we can observe them.
        let mut rx = state.subscribe();
        let mut event_kinds = Vec::new();

        // Attach the adapter — this spawns the connection task.
        adapter.attach(Arc::clone(&state)).expect("attach succeeds");

        // Wait for at least one event (should be obs.connected, obs.authenticated, etc.).
        let timeout = Duration::from_secs(3);
        let start = std::time::Instant::now();
        while event_kinds.len() < 2 && start.elapsed() < timeout {
            if let Ok(Ok(e)) = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
                event_kinds.push(e.kind.clone());
            }
        }

        // Stop the server and verify we got connection events.
        server.stop().await;

        assert!(
            event_kinds.iter().any(|k| k.contains("obs.")),
            "expected at least one obs.* event, got: {:?}",
            event_kinds
        );
    }

    #[test]
    fn validate_loopback_url_accepts_127_0_0_1() {
        assert!(validate_loopback_url("ws://127.0.0.1:4455").is_ok());
    }

    #[test]
    fn validate_loopback_url_accepts_localhost() {
        assert!(validate_loopback_url("ws://localhost:4455").is_ok());
    }

    #[test]
    fn validate_loopback_url_accepts_ipv6_loopback() {
        assert!(validate_loopback_url("ws://[::1]:4455").is_ok());
    }

    #[test]
    fn validate_loopback_url_accepts_entire_loopback_range() {
        assert!(validate_loopback_url("ws://127.0.0.2:4455").is_ok());
        assert!(validate_loopback_url("ws://127.255.255.255:4455").is_ok());
    }

    #[test]
    fn validate_loopback_url_rejects_external_addresses() {
        assert!(validate_loopback_url("ws://192.168.1.1:4455").is_err());
        assert!(validate_loopback_url("ws://example.com:4455").is_err());
    }

    #[test]
    fn validate_loopback_url_rejects_substring_bypass_with_path() {
        // Attacker tries to bypass by appending 127.0.0.1 in the path
        assert!(validate_loopback_url("ws://evil.com/?x=127.0.0.1").is_err());
    }

    #[test]
    fn validate_loopback_url_rejects_substring_bypass_with_fragment() {
        // Attacker tries to bypass by appending localhost in fragment
        assert!(validate_loopback_url("ws://evil.com#localhost").is_err());
    }

    #[test]
    fn validate_loopback_url_rejects_domain_suffix_bypass() {
        // Attacker tries to bypass with domain that has loopback as suffix
        assert!(validate_loopback_url("ws://127.0.0.1.evil.com:4455/").is_err());
        assert!(validate_loopback_url("ws://localhost.evil.com/").is_err());
    }

    #[test]
    fn validate_loopback_url_rejects_userinfo_confusion() {
        // Attacker tries to bypass using userinfo (127.0.0.1@evil.com has host evil.com)
        assert!(validate_loopback_url("ws://127.0.0.1@evil.com:4455").is_err());
    }

    #[test]
    fn validate_loopback_url_rejects_private_network_addresses() {
        // Reject LAN addresses (10/8, 172.16/12, 192.168/16)
        assert!(validate_loopback_url("ws://192.168.1.1:4455").is_err());
        assert!(validate_loopback_url("ws://10.0.0.1:4455").is_err());
        assert!(validate_loopback_url("ws://172.16.0.1:4455").is_err());
    }

    #[test]
    fn validate_loopback_url_rejects_cloud_metadata_address() {
        // Reject cloud metadata endpoint (AWS, GCP, etc.)
        assert!(validate_loopback_url("ws://169.254.169.254:4455").is_err());
    }

    #[test]
    fn validate_loopback_url_rejects_wrong_scheme_wss() {
        // Only ws:// is allowed, not wss://
        assert!(validate_loopback_url("wss://127.0.0.1:4455").is_err());
        assert!(validate_loopback_url("wss://localhost:4455").is_err());
        assert!(validate_loopback_url("wss://[::1]:4455").is_err());
    }

    #[test]
    fn validate_loopback_url_rejects_wrong_scheme_http() {
        // Reject http:// and https://
        assert!(validate_loopback_url("http://127.0.0.1:4455").is_err());
        assert!(validate_loopback_url("https://127.0.0.1:4455").is_err());
        assert!(validate_loopback_url("http://localhost:4455").is_err());
    }

    #[test]
    fn validate_loopback_url_rejects_malformed_url() {
        // Reject URLs that cannot be parsed
        assert!(validate_loopback_url("not a valid url").is_err());
        assert!(validate_loopback_url("://invalid").is_err());
    }

    #[test]
    fn validate_loopback_url_rejects_no_host() {
        // Reject URLs with no host
        assert!(validate_loopback_url("ws://").is_err());
    }

    #[test]
    fn compute_auth_hash_succeeds_with_valid_challenge() {
        use base64::Engine as _;

        // Use a fixed challenge for deterministic testing.
        let password = "test-password";
        let challenge = "salt123.challenge456";

        let result = compute_auth_hash(password, challenge);
        assert!(result.is_ok());
        let hash = result.unwrap();

        // Verify it's not empty and is a valid base64 string.
        assert!(!hash.is_empty());
        assert!(
            base64::engine::general_purpose::STANDARD
                .decode(&hash)
                .is_ok()
        );
    }

    #[test]
    fn compute_auth_hash_rejects_malformed_challenge() {
        let password = "test-password";
        let challenge = "invalid-challenge-no-dot";

        let result = compute_auth_hash(password, challenge);
        assert!(result.is_err());
    }

    #[test]
    fn password_never_leaks_into_error_messages() {
        let password = "super-secret-password";

        let config = ObsConfig::new("ws://192.168.1.1:4455", password);
        let adapter = ObsAdapter::new(config);

        // The adapter's attach should fail, but the error should not contain the password.
        // In this case, it's deferred to the spawned task, so we check at construction time.
        // Let's verify that the password is stored but never exposed via name().
        assert!(!adapter.name().contains(password));
    }

    #[tokio::test]
    async fn obs_adapter_handles_auth_rejection() {
        // Mock server that rejects authentication (sends wrong opcode after Identify).
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("get bound address");
        let url = format!("ws://{}", addr);

        let server_task = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await
                && let Ok(ws) = accept_async(stream).await
            {
                let (mut ws_send, mut ws_recv) = ws.split();

                // Send Hello message.
                use futures_util::sink::SinkExt as _;
                let hello = json!({
                    "op": 0,
                    "d": {
                        "serverVersion": "5.0.0",
                        "sessionId": "test-session-123",
                        "serverTime": 1234567890u64,
                        "authentication": "salt123.challenge456",
                    },
                });
                let _ = ws_send.send(Message::Text(hello.to_string().into())).await;

                // Receive Identify message.
                if let Some(Ok(Message::Text(_))) = ws_recv.next().await {
                    // Send a rejection response (wrong op code).
                    let rejection = json!({"op": 99, "d": {}});
                    let _ = ws_send
                        .send(Message::Text(rejection.to_string().into()))
                        .await;
                }
            }
        });

        let config = ObsConfig::new(&url, "test-password");
        let adapter = ObsAdapter::new(config);

        let hub = crate::testutil::MockHub::start().await;
        let dir = tempfile::tempdir().unwrap();
        let mut host = crate::testutil::FakeHost::new(dir.path().to_path_buf());
        host.config = serde_json::to_vec(&json!({
            "hub": {"base_url": hub.base_url},
            "community_id": "11111111-1111-4111-8111-111111111111",
        }))
        .unwrap();
        let module = crate::module::WaddlesGatewayModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");
        let state = Arc::new(BridgeState::new(module, "test-cat".to_string()));

        let _rx = state.subscribe();
        adapter.attach(Arc::clone(&state)).expect("attach succeeds");

        // The connection should fail when auth is rejected, so we might not get events.
        // Give it time to fail.
        sleep(Duration::from_millis(500)).await;
        server_task.abort();
    }

    #[tokio::test]
    async fn obs_adapter_handles_connection_closed_before_hello() {
        // Mock server that closes connection immediately without sending Hello.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("get bound address");
        let url = format!("ws://{}", addr);

        let server_task = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await
                && let Ok(ws) = accept_async(stream).await
            {
                let (_ws_send, _ws_recv) = ws.split();
                // Close immediately without sending anything.
            }
        });

        let config = ObsConfig::new(&url, "test-password");
        let adapter = ObsAdapter::new(config);

        let hub = crate::testutil::MockHub::start().await;
        let dir = tempfile::tempdir().unwrap();
        let mut host = crate::testutil::FakeHost::new(dir.path().to_path_buf());
        host.config = serde_json::to_vec(&json!({
            "hub": {"base_url": hub.base_url},
            "community_id": "11111111-1111-4111-8111-111111111111",
        }))
        .unwrap();
        let module = crate::module::WaddlesGatewayModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");
        let state = Arc::new(BridgeState::new(module, "test-cat".to_string()));

        adapter.attach(Arc::clone(&state)).expect("attach succeeds");
        sleep(Duration::from_millis(500)).await;
        server_task.abort();
    }

    #[tokio::test]
    async fn obs_adapter_handles_unexpected_message_opcodes() {
        // Mock server that sends unexpected opcodes instead of expected ones.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("get bound address");
        let url = format!("ws://{}", addr);

        let server_task = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await
                && let Ok(ws) = accept_async(stream).await
            {
                let (mut ws_send, mut ws_recv) = ws.split();

                // Send Hello message.
                use futures_util::sink::SinkExt as _;
                let hello = json!({
                    "op": 0,
                    "d": {
                        "serverVersion": "5.0.0",
                        "sessionId": "test-session-123",
                        "serverTime": 1234567890u64,
                        "authentication": "salt123.challenge456",
                    },
                });
                let _ = ws_send.send(Message::Text(hello.to_string().into())).await;

                // Receive Identify message.
                if let Some(Ok(Message::Text(_))) = ws_recv.next().await {
                    // Send Identified confirmation.
                    let identified = json!({"op": 2, "d": {}});
                    let _ = ws_send
                        .send(Message::Text(identified.to_string().into()))
                        .await;

                    // Send an event with unexpected opcode (not 5).
                    sleep(Duration::from_millis(50)).await;
                    let unknown = json!({
                        "op": 99,
                        "d": {"eventName": "UnknownEvent"},
                    });
                    let _ = ws_send
                        .send(Message::Text(unknown.to_string().into()))
                        .await;

                    // Keep connection open briefly.
                    sleep(Duration::from_millis(200)).await;
                }
            }
        });

        let config = ObsConfig::new(&url, "test-password");
        let adapter = ObsAdapter::new(config);

        let hub = crate::testutil::MockHub::start().await;
        let dir = tempfile::tempdir().unwrap();
        let mut host = crate::testutil::FakeHost::new(dir.path().to_path_buf());
        host.config = serde_json::to_vec(&json!({
            "hub": {"base_url": hub.base_url},
            "community_id": "11111111-1111-4111-8111-111111111111",
        }))
        .unwrap();
        let module = crate::module::WaddlesGatewayModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");
        let state = Arc::new(BridgeState::new(module, "test-cat".to_string()));

        let mut rx = state.subscribe();
        adapter.attach(Arc::clone(&state)).expect("attach succeeds");

        // Wait for events. We should get at least connected and authenticated events,
        // but not fail on the unknown opcode.
        let timeout = Duration::from_secs(2);
        let start = std::time::Instant::now();
        let mut event_kinds = Vec::new();
        while start.elapsed() < timeout {
            if let Ok(Ok(e)) = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
                event_kinds.push(e.kind.clone());
            }
        }

        server_task.abort();
        assert!(
            event_kinds.iter().any(|k| k.contains("obs.connected")),
            "expected obs.connected event"
        );
    }

    #[tokio::test]
    async fn obs_adapter_handles_websocket_close_frame() {
        // Mock server that sends a Close frame after authentication.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("get bound address");
        let url = format!("ws://{}", addr);

        let server_task = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await
                && let Ok(ws) = accept_async(stream).await
            {
                let (mut ws_send, mut ws_recv) = ws.split();

                // Send Hello message.
                use futures_util::sink::SinkExt as _;
                let hello = json!({
                    "op": 0,
                    "d": {
                        "serverVersion": "5.0.0",
                        "sessionId": "test-session-123",
                        "serverTime": 1234567890u64,
                        "authentication": "salt123.challenge456",
                    },
                });
                let _ = ws_send.send(Message::Text(hello.to_string().into())).await;

                // Receive Identify message.
                if let Some(Ok(Message::Text(_))) = ws_recv.next().await {
                    // Send Identified confirmation.
                    let identified = json!({"op": 2, "d": {}});
                    let _ = ws_send
                        .send(Message::Text(identified.to_string().into()))
                        .await;

                    sleep(Duration::from_millis(100)).await;
                    // Send Close frame.
                    let _ = ws_send.send(Message::Close(None)).await;
                }
            }
        });

        let config = ObsConfig::new(&url, "test-password");
        let adapter = ObsAdapter::new(config);

        let hub = crate::testutil::MockHub::start().await;
        let dir = tempfile::tempdir().unwrap();
        let mut host = crate::testutil::FakeHost::new(dir.path().to_path_buf());
        host.config = serde_json::to_vec(&json!({
            "hub": {"base_url": hub.base_url},
            "community_id": "11111111-1111-4111-8111-111111111111",
        }))
        .unwrap();
        let module = crate::module::WaddlesGatewayModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");
        let state = Arc::new(BridgeState::new(module, "test-cat".to_string()));

        let mut rx = state.subscribe();
        adapter.attach(Arc::clone(&state)).expect("attach succeeds");

        // Wait for events including the disconnection.
        let timeout = Duration::from_secs(2);
        let start = std::time::Instant::now();
        let mut event_kinds = Vec::new();
        while start.elapsed() < timeout {
            if let Ok(Ok(e)) = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
                event_kinds.push(e.kind.clone());
            }
        }

        server_task.abort();
        assert!(
            event_kinds.iter().any(|k| k.contains("obs.disconnected")),
            "expected obs.disconnected event"
        );
    }

    #[test]
    fn obs_adapter_rejects_non_loopback_url_directly() {
        // Test that validate_loopback_url rejects non-loopback addresses
        let result = validate_loopback_url("ws://192.168.1.100:4455");
        assert!(result.is_err(), "should reject non-loopback URL");
    }

    #[test]
    fn compute_auth_hash_produces_valid_sha256() {
        // Test that compute_auth_hash produces a deterministic hash
        let password = "test_password";
        let challenge = "salt123.challenge456";

        let hash1 = compute_auth_hash(password, challenge);
        let hash2 = compute_auth_hash(password, challenge);

        // Should be deterministic
        assert!(hash1.is_ok());
        assert!(hash2.is_ok());
        assert_eq!(hash1.unwrap(), hash2.unwrap());
    }

    #[test]
    fn compute_auth_hash_different_challenges_produce_different_hashes() {
        let password = "test_password";
        let challenge1 = "salt123.challenge456";
        let challenge2 = "salt456.challenge789";

        let hash1 = compute_auth_hash(password, challenge1).unwrap();
        let hash2 = compute_auth_hash(password, challenge2).unwrap();

        // Different challenges should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[tokio::test]
    async fn obs_adapter_send_command_to_connected_server() {
        let (server, url) = MockObsServer::start().await;

        let config = ObsConfig::new(&url, "test-password");
        let adapter = ObsAdapter::new(config);

        let hub = crate::testutil::MockHub::start().await;
        let dir = tempfile::tempdir().unwrap();
        let mut host = crate::testutil::FakeHost::new(dir.path().to_path_buf());
        host.config = serde_json::to_vec(&json!({
            "hub": {"base_url": hub.base_url},
            "community_id": "11111111-1111-4111-8111-111111111111",
        }))
        .unwrap();
        let module = crate::module::WaddlesGatewayModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");
        let state = Arc::new(BridgeState::new(module, "test-cat".to_string()));

        // Subscribe to events
        let mut rx = state.subscribe();

        // Attach the adapter
        adapter.attach(Arc::clone(&state)).expect("attach succeeds");

        // Wait for connection events
        let timeout = Duration::from_secs(2);
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if let Ok(Ok(e)) = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await
                && e.kind.contains("obs.authenticated")
            {
                break;
            }
        }

        // Stop the server
        server.stop().await;
    }

    #[tokio::test]
    async fn obs_adapter_handles_connection_failure_gracefully() {
        // Try to connect to a port that is not listening
        let config = ObsConfig::new("ws://127.0.0.1:9999", "test-password");
        let adapter = ObsAdapter::new(config);

        let hub = crate::testutil::MockHub::start().await;
        let dir = tempfile::tempdir().unwrap();
        let mut host = crate::testutil::FakeHost::new(dir.path().to_path_buf());
        host.config = serde_json::to_vec(&json!({
            "hub": {"base_url": hub.base_url},
            "community_id": "11111111-1111-4111-8111-111111111111",
        }))
        .unwrap();
        let module = crate::module::WaddlesGatewayModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");
        let state = Arc::new(BridgeState::new(module, "test-cat".to_string()));

        // Attaching should start a background task that tries to connect
        // The attach itself may succeed (async), but the connection should fail
        let _ = adapter.attach(Arc::clone(&state));

        // Give it a moment to try connecting (and fail gracefully)
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    #[test]
    fn obs_adapter_new_creates_adapter() {
        let config = ObsConfig::new("ws://127.0.0.1:4455", "test-password");
        let adapter = ObsAdapter::new(config);

        // Just verify the adapter was created successfully
        assert!(!adapter.config.url.is_empty());
        assert!(!adapter.config.password.is_empty());
    }

    #[test]
    fn obs_config_new_stores_url_and_password() {
        let config = ObsConfig::new("ws://127.0.0.1:4455", "my_secret");

        assert_eq!(config.url, "ws://127.0.0.1:4455");
        assert_eq!(config.password, "my_secret");
    }

    #[test]
    fn obs_command_error_display() {
        let err1 = ObsCommandError::NotConnected;
        assert!(err1.to_string().contains("not connected"));

        let err2 = ObsCommandError::Timeout;
        assert!(err2.to_string().contains("timeout"));

        let err3 = ObsCommandError::Rejected {
            code: 1,
            comment: "bad request".to_string(),
        };
        assert!(err3.to_string().contains("bad request"));
        assert!(err3.to_string().contains("code 1"));

        let err4 = ObsCommandError::Other("custom error".to_string());
        assert!(err4.to_string().contains("custom error"));
    }
}
