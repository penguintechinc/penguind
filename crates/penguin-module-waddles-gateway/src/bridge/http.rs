//! The bridge's loopback TCP transport: an [`axum::Router`] exposing one
//! JSON RPC endpoint (`POST /rpc`) and one event-push WebSocket
//! (`GET /ws`), both authenticated by a per-script bearer token — see
//! `bridge::token` for where that token comes from.
//!
//! A script is identified by the token alone; `integration` in the request
//! is a redundant, explicit cross-check (the token must belong to the name
//! the caller claims), not a second credential — defense in depth against a
//! caller that reuses a token under the wrong name by mistake.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::bridge::scope::Operation;
use crate::bridge::state::{BridgeState, ScopedRelayError};

/// `POST /rpc`'s request body.
#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub integration: String,
    #[serde(default)]
    pub token: String,
    pub op: String,
    #[serde(default)]
    pub params: Value,
}

/// `POST /rpc`'s response body — always this shape, `ok` tells a caller
/// which of `result`/`error` is populated without inspecting the HTTP
/// status separately.
#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl RpcResponse {
    /// Also used by [`crate::bridge::unixsock`], which speaks the same
    /// request/response shapes over a line-delimited unix socket instead of
    /// HTTP.
    pub(crate) fn ok(result: Value) -> RpcResponse {
        RpcResponse {
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub(crate) fn err(message: impl Into<String>) -> RpcResponse {
        RpcResponse {
            ok: false,
            result: None,
            error: Some(message.into()),
        }
    }
}

/// Builds the bridge's TCP router, scoped to `state`.
pub fn router(state: Arc<BridgeState>) -> Router {
    Router::new()
        .route("/rpc", post(rpc_handler))
        .route("/ws", get(ws_handler))
        .with_state(state)
}

async fn rpc_handler(
    State(state): State<Arc<BridgeState>>,
    axum::Json(request): axum::Json<RpcRequest>,
) -> (StatusCode, axum::Json<RpcResponse>) {
    let Some(identity) = state.tokens.authorize_token(&request.token) else {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(RpcResponse::err("invalid or missing token")),
        );
    };
    if identity.name != request.integration {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(RpcResponse::err("token does not match integration")),
        );
    }
    let Some(op) = Operation::parse(&request.op) else {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(RpcResponse::err(format!(
                "unknown operation: {}",
                request.op
            ))),
        );
    };

    match state.relay(&identity, op, &request.params).await {
        Ok(result) => (StatusCode::OK, axum::Json(RpcResponse::ok(result))),
        Err(ScopedRelayError::OutOfScope) => (
            StatusCode::FORBIDDEN,
            axum::Json(RpcResponse::err(
                "integration is not permitted to invoke this operation",
            )),
        ),
        Err(ScopedRelayError::Relay(err)) => (
            StatusCode::BAD_GATEWAY,
            axum::Json(RpcResponse::err(err.to_string())),
        ),
    }
}

/// `GET /ws`'s query-string authentication — a WebSocket handshake has no
/// convenient place for a JSON body, so the same bearer token travels as a
/// query parameter instead. Parsed by hand from [`Uri::query`] rather than
/// via axum's `Query` extractor: the workspace's `axum` dependency doesn't
/// enable the `query` feature, and `token`/`integration` are always plain
/// ASCII (bridge-minted hex tokens, simple identifier names), so the
/// percent-decoding a general-purpose query parser would add is not needed
/// here.
fn parse_query_pairs(raw: &str) -> HashMap<String, String> {
    let mut pairs = HashMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default();
        pairs.insert(key.to_string(), value.to_string());
    }
    pairs
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    uri: Uri,
    State(state): State<Arc<BridgeState>>,
) -> Response {
    let query = parse_query_pairs(uri.query().unwrap_or_default());
    let token = query.get("token").cloned().unwrap_or_default();
    let integration = query.get("integration").cloned().unwrap_or_default();

    let Some(identity) = state.tokens.authorize_token(&token) else {
        return (StatusCode::UNAUTHORIZED, "invalid or missing token").into_response();
    };
    if identity.name != integration {
        return (StatusCode::UNAUTHORIZED, "token does not match integration").into_response();
    }
    ws.on_upgrade(move |socket| forward_events(socket, state))
}

/// Forwards every event the bridge publishes to one connected WebSocket
/// client until it disconnects, the connection errors, or this subscriber
/// falls too far behind ([`tokio::sync::broadcast::error::RecvError::Lagged`]).
/// Also drains (and discards) anything the client sends — this channel is
/// push-only; a client message is only read so a closed connection is
/// noticed promptly.
async fn forward_events(mut socket: WebSocket, state: Arc<BridgeState>) {
    let mut events = state.subscribe();
    loop {
        tokio::select! {
            event = events.recv() => {
                let Ok(event) = event else { return; };
                let Ok(text) = serde_json::to_string(&event) else { continue; };
                if socket.send(Message::Text(text.into())).await.is_err() {
                    return;
                }
            }
            incoming = socket.recv() => {
                if !matches!(incoming, Some(Ok(_))) {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use tokio::net::TcpListener;

    use super::*;
    use crate::bridge::scope::Scope;
    use crate::bridge::state::BridgeState;
    use crate::module::WaddlesGatewayModule;
    use crate::testutil::{FakeHost, MockHub};
    use penguin_sdk::Module;

    async fn spawn_router(state: Arc<BridgeState>) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state);
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        (format!("http://{addr}"), task)
    }

    async fn state_against(hub: &MockHub) -> Arc<BridgeState> {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.config = serde_json::to_vec(&serde_json::json!({
            "hub": {"base_url": hub.base_url},
            "community_id": "11111111-1111-4111-8111-111111111111",
        }))
        .unwrap();
        let module = WaddlesGatewayModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");
        Arc::new(BridgeState::new(module, "wdl_c_livesecret".to_string()))
    }

    #[tokio::test]
    async fn rpc_rejects_a_missing_token_with_401() {
        let hub = MockHub::start().await;
        let state = state_against(&hub).await;
        let (base, task) = spawn_router(state).await;

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base}/rpc"))
            .json(&serde_json::json!({"integration": "obs-overlay", "op": "status", "params": {}}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

        task.abort();
        hub.stop().await;
    }

    #[tokio::test]
    async fn rpc_rejects_an_out_of_scope_operation_with_403() {
        let hub = MockHub::start().await;
        let state = state_against(&hub).await;
        state
            .tokens
            .register("obs-overlay", HashSet::from([Scope::BrowserSourceRead]));
        let token = state.tokens.mint("obs-overlay").unwrap();
        let (base, task) = spawn_router(state).await;

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base}/rpc"))
            .json(&serde_json::json!({
                "integration": "obs-overlay", "token": token,
                "op": "music.get", "params": {},
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);

        task.abort();
        hub.stop().await;
    }

    #[tokio::test]
    async fn rpc_rejects_an_unknown_operation_with_403_not_400() {
        let hub = MockHub::start().await;
        let state = state_against(&hub).await;
        state.tokens.register("obs-overlay", Scope::all());
        let token = state.tokens.mint("obs-overlay").unwrap();
        let (base, task) = spawn_router(state).await;

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base}/rpc"))
            .json(&serde_json::json!({
                "integration": "obs-overlay", "token": token,
                "op": "totally.bogus", "params": {},
            }))
            .send()
            .await
            .unwrap();
        // Fail-closed: an operation nothing recognizes is denied the same
        // way an out-of-scope one is, not treated as a client input error.
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);

        task.abort();
        hub.stop().await;
    }

    #[tokio::test]
    async fn rpc_allows_an_in_scope_operation_and_returns_the_relayed_result() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/admin/11111111-1111-4111-8111-111111111111/browser-sources",
            crate::testutil::MockResponse::json(
                200,
                r#"{"success":true,"sources":[{"sourceType":"chat","url":"https://x/y","token":"z","isActive":true}]}"#,
            ),
        )
        .await;
        let state = state_against(&hub).await;
        state
            .tokens
            .register("obs-overlay", HashSet::from([Scope::BrowserSourceRead]));
        let token = state.tokens.mint("obs-overlay").unwrap();
        let (base, task) = spawn_router(state).await;

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base}/rpc"))
            .json(&serde_json::json!({
                "integration": "obs-overlay", "token": token,
                "op": "browser_sources.list", "params": {},
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let body: RpcResponseForTest = response.json().await.unwrap();
        assert!(body.ok);
        assert_eq!(body.result.unwrap()["sources"].as_array().unwrap().len(), 1);

        task.abort();
        hub.stop().await;
    }

    /// A local mirror of [`RpcResponse`] for deserializing test responses —
    /// [`RpcResponse`] itself only derives `Serialize`.
    #[derive(Debug, serde::Deserialize)]
    struct RpcResponseForTest {
        ok: bool,
        result: Option<Value>,
    }
}
