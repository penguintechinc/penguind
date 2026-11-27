//! The bridge's unix-socket transport: the same JSON request/response
//! surface as [`crate::bridge::http`], but over a `0660` unix-domain socket
//! whose connecting peer's `SO_PEERCRED` identity — via
//! [`penguin_ipc::check_peer`], the exact same decision logic
//! `penguind`'s own control socket uses — *is* the credential. No bearer
//! token: a script only names which integration it is; the OS already
//! proved the process asking is trusted, or the connection is refused
//! before a single byte of it is read.
//!
//! One JSON request object per line in, one JSON [`RpcResponse`] object per
//! line out — a minimal framing chosen so this transport needs nothing
//! beyond `tokio::net::UnixStream`, no HTTP or WebSocket stack of its own.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;

use penguin_ipc::listen_unix::{self, ListenerConfig};
use penguin_ipc::{AuthError, GroupResolver, IpcError, PeerCredentials, check_peer};

use crate::bridge::http::{RpcRequest, RpcResponse};
use crate::bridge::scope::Operation;
use crate::bridge::state::{BridgeState, ScopedRelayError};

/// Peer-authorization parameters, mirroring exactly what `penguind`'s own
/// control socket passes to [`penguin_ipc::listen_unix::PeerAuthInterceptor`].
/// [`crate::config::BridgeSection`] has no group field yet, so
/// [`crate::bridge::start`] always passes an empty `allowed_group` — meaning
/// only root or the daemon's own uid may connect today, a deliberately
/// conservative default until an operator-facing way to widen it exists.
pub struct UnixAuth {
    pub self_uid: u32,
    pub allowed_group: String,
    pub resolver: Arc<dyn GroupResolver>,
}

/// Binds the bridge's unix socket at `path` with the same `0660`-inside-
/// `0750` permissions [`penguin_ipc::listen_unix`] gives the daemon's own
/// control socket.
pub fn bind(path: &Path, allowed_group: &str) -> Result<UnixListener, IpcError> {
    let cfg = ListenerConfig {
        path: PathBuf::from(path),
        allowed_group: allowed_group.to_string(),
    };
    listen_unix::listen(&cfg)
}

/// Accepts connections on `listener` until `cancel` fires, handling each on
/// its own spawned task. Returns as soon as `cancel` fires — in-flight
/// connection tasks are not awaited here, matching the TCP transport's own
/// graceful-shutdown contract of "stop accepting new work", not "wait out
/// every existing client".
pub async fn serve(
    listener: UnixListener,
    state: Arc<BridgeState>,
    auth: UnixAuth,
    cancel: CancellationToken,
) {
    let auth = Arc::new(auth);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            accepted = listener.accept() => {
                let Ok((stream, _addr)) = accepted else { continue; };
                let state = Arc::clone(&state);
                let auth = Arc::clone(&auth);
                tokio::spawn(async move {
                    handle_connection(stream, state, auth.as_ref()).await;
                });
            }
        }
    }
}

/// The pure authorization decision a connection is checked against —
/// factored out of [`handle_connection`] so it can be exercised directly
/// with fabricated [`PeerCredentials`] and a fake [`GroupResolver`], the
/// same pattern `penguin_ipc::authorize`'s own tests use, without needing a
/// real socket or a real second OS user.
fn authorize_connection(creds: Option<PeerCredentials>, auth: &UnixAuth) -> Result<(), AuthError> {
    check_peer(
        creds,
        auth.self_uid,
        &auth.allowed_group,
        auth.resolver.as_ref(),
    )
}

/// Reads one peer-cred check, then a JSON request per line until the peer
/// disconnects. An unauthorized peer is dropped immediately — not even an
/// error line is written back, matching the daemon's own control socket:
/// fail-closed, silently.
async fn handle_connection(stream: UnixStream, state: Arc<BridgeState>, auth: &UnixAuth) {
    let creds = stream.peer_cred().ok().map(|cred| PeerCredentials {
        uid: cred.uid(),
        gid: cred.gid(),
    });
    if authorize_connection(creds, auth).is_err() {
        return;
    }

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = match reader.read_line(&mut line).await {
            Ok(bytes_read) => bytes_read,
            Err(_read_error) => return,
        };
        if bytes_read == 0 {
            return; // peer closed the connection
        }

        let response = handle_request(&state, line.trim_end()).await;
        let Ok(mut rendered) = serde_json::to_vec(&response) else {
            return;
        };
        rendered.push(b'\n');
        if writer.write_all(&rendered).await.is_err() {
            return;
        }
    }
}

/// Resolves one request line to a response — the unix-transport twin of
/// `bridge::http::rpc_handler`, using [`crate::bridge::token::TokenRegistry::identity_for_name`]
/// instead of a bearer token: this connection already crossed the
/// peer-cred boundary, so naming a *registered* integration is all a script
/// needs here.
async fn handle_request(state: &BridgeState, raw: &str) -> RpcResponse {
    let request: RpcRequest = match serde_json::from_str(raw) {
        Ok(request) => request,
        Err(err) => return RpcResponse::err(format!("invalid request: {err}")),
    };
    let Some(identity) = state.tokens.identity_for_name(&request.integration) else {
        return RpcResponse::err("unknown integration");
    };
    let Some(op) = Operation::parse(&request.op) else {
        return RpcResponse::err(format!("unknown operation: {}", request.op));
    };

    match state.relay(&identity, op, &request.params).await {
        Ok(result) => RpcResponse::ok(result),
        Err(ScopedRelayError::OutOfScope) => {
            RpcResponse::err("integration is not permitted to invoke this operation")
        }
        Err(ScopedRelayError::Relay(err)) => RpcResponse::err(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    use super::*;
    use crate::bridge::scope::Scope;
    use crate::bridge::state::BridgeState;
    use crate::module::WaddlesGatewayModule;
    use crate::testutil::{FakeHost, MockHub, MockResponse};
    use penguin_sdk::Module;

    /// Deterministic, privilege-free stand-in for
    /// `penguin_ipc::groups_unix::SystemGroups` — mirrors
    /// `penguin_ipc::authorize`'s own test fixture exactly.
    struct FakeResolver {
        groups: Vec<(String, u32)>,
    }

    impl GroupResolver for FakeResolver {
        fn group_gid(&self, name: &str) -> Option<u32> {
            self.groups
                .iter()
                .find(|(group_name, _gid)| group_name == name)
                .map(|(_name, gid)| *gid)
        }

        fn user_groups(&self, _uid: u32) -> Option<Vec<u32>> {
            None
        }
    }

    fn auth(self_uid: u32, allowed_group: &str) -> UnixAuth {
        UnixAuth {
            self_uid,
            allowed_group: allowed_group.to_string(),
            resolver: Arc::new(FakeResolver { groups: Vec::new() }),
        }
    }

    #[test]
    fn authorize_connection_allows_the_daemons_own_uid() {
        let creds = PeerCredentials {
            uid: 1000,
            gid: 1000,
        };
        assert!(authorize_connection(Some(creds), &auth(1000, "")).is_ok());
    }

    #[test]
    fn authorize_connection_allows_root_regardless_of_configuration() {
        let creds = PeerCredentials { uid: 0, gid: 0 };
        assert!(authorize_connection(Some(creds), &auth(1000, "")).is_ok());
    }

    #[test]
    fn authorize_connection_denies_an_unrelated_uid_with_no_group_configured() {
        let creds = PeerCredentials {
            uid: 2000,
            gid: 2000,
        };
        assert!(authorize_connection(Some(creds), &auth(1000, "")).is_err());
    }

    #[test]
    fn authorize_connection_denies_with_no_peer_credentials_at_all() {
        assert!(authorize_connection(None, &auth(1000, "")).is_err());
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

    /// End-to-end: a real connection from this same process (therefore
    /// always either root or the daemon's own uid — see the module doc for
    /// why that makes this test valid without requiring root specifically)
    /// is accepted, authorized, and gets a real relayed result back.
    #[tokio::test]
    async fn a_connection_is_accepted_authorized_and_served() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/admin/11111111-1111-4111-8111-111111111111/browser-sources",
            MockResponse::json(200, r#"{"success":true,"sources":[]}"#),
        )
        .await;
        let state = state_against(&hub).await;
        state
            .tokens
            .register("obs-overlay", HashSet::from([Scope::BrowserSourceRead]));

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("bridge.sock");
        let listener = bind(&socket_path, "").expect("bind succeeds");
        let cancel = CancellationToken::new();
        let serve_task = tokio::spawn(serve(
            listener,
            Arc::clone(&state),
            auth(nix::unistd::Uid::current().as_raw(), ""),
            cancel.clone(),
        ));

        let stream = UnixStream::connect(&socket_path).await.expect("connect");
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let request = serde_json::json!({
            "integration": "obs-overlay", "op": "browser_sources.list", "params": {},
        });
        let mut line = serde_json::to_vec(&request).unwrap();
        line.push(b'\n');
        writer.write_all(&line).await.unwrap();

        let mut response_line = String::new();
        reader.read_line(&mut response_line).await.unwrap();
        let response: serde_json::Value = serde_json::from_str(response_line.trim_end()).unwrap();
        assert_eq!(response["ok"], true);
        assert_eq!(response["result"]["sources"].as_array().unwrap().len(), 0);

        cancel.cancel();
        serve_task.await.ok();
        hub.stop().await;
    }

    /// An integration name never registered gets a fail-closed error line —
    /// peer-cred alone does not grant an identity, only a known name does.
    #[tokio::test]
    async fn an_unregistered_integration_name_is_rejected() {
        let hub = MockHub::start().await;
        let state = state_against(&hub).await;

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("bridge.sock");
        let listener = bind(&socket_path, "").expect("bind succeeds");
        let cancel = CancellationToken::new();
        let serve_task = tokio::spawn(serve(
            listener,
            Arc::clone(&state),
            auth(nix::unistd::Uid::current().as_raw(), ""),
            cancel.clone(),
        ));

        let stream = UnixStream::connect(&socket_path).await.expect("connect");
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let request = serde_json::json!({"integration": "ghost", "op": "status", "params": {}});
        let mut line = serde_json::to_vec(&request).unwrap();
        line.push(b'\n');
        writer.write_all(&line).await.unwrap();

        let mut response_line = String::new();
        reader.read_line(&mut response_line).await.unwrap();
        let response: serde_json::Value = serde_json::from_str(response_line.trim_end()).unwrap();
        assert_eq!(response["ok"], false);

        cancel.cancel();
        serve_task.await.ok();
        hub.stop().await;
    }
}
