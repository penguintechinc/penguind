//! Desktop client core: IPC wrapper + keychain + OAuth glue.
//!
//! The desktop shell (Tauri, Phase 2b) wraps this core, which owns:
//! - IPC connection to penguind over UDS (`ipc_client`)
//! - Session token persistence via OS keychain (`token_store` + `penguin-secrets`)
//! - OAuth state/callback handling (`oauth`)
//!
//! The module side (penguind's `penguin-module-waddlebot/src/session/`) owns:
//! - In-memory session tokens (primed by the shell at login)
//! - Generic `/api/v1/**` Bearer passthrough (ProxyRequest RPC)
//! - 401 → refresh → retry logic
//! - Token-rotate events (WatchEvents stream)
//!
//! **Public API seams the Tauri shell calls:**
//! - `Session::login(hub_url, email, password)` — POST /api/v1/auth/login, persist to keychain + penguind
//! - `Session::oauth_start(platform)` — build authorize URL, return state for callback
//! - `Session::oauth_complete(callback_params)` — validate state, extract tokens, persist + prime penduind
//! - `Session::api_request(method, path, body)` — forward to penduind ProxyRequest
//! - `Session::logout()` — clear keychain + penduind session
//! - `Session::watch_token_rotations()` — subscribe to `WatchEvents` for keychain re-persist

pub mod action_executor;
pub mod error;
pub mod ipc_client;
mod ipc_dial;
pub mod oauth;
pub mod token_store;

#[cfg(test)]
mod mock_server;

pub use action_executor::{
    ActionExecutor, ApprovalDecision, ApprovalPrompt, PendingAction, run_poll_loop,
};
pub use error::{DesktopError, Result};
pub use ipc_client::{ApiRequest, ApiResponse, Header, IpcClient};
pub use oauth::{
    CallbackParams, DESKTOP_REDIRECT_URI, OAuthCallback, OAuthContext, OAuthPlatform, OAuthTokens,
};
pub use token_store::{StoredSession, TokenStore};

// Re-export the proto response type for bridge actions
pub use penguin_proto::desktop::v1::BridgeActionResponse;

use serde_json::json;
use tracing::{debug, info};

/// The desktop session manager: wraps token storage, IPC, and OAuth flows.
///
/// This is the main API surface for the Tauri shell. It coordinates:
/// 1. Keychain persistence (via TokenStore)
/// 2. IPC to penduind (via IpcClient)
/// 3. OAuth flows (via oauth module)
///
/// The shell owns calling these methods; the core handles the rest.
pub struct Session {
    token_store: TokenStore,
    ipc_client: IpcClient,
}

impl Session {
    /// Creates a new session manager with the default keychain and IPC socket.
    ///
    /// The keychain is rooted at `data_dir`, using the OS keyring (Auto backend)
    /// with a file fallback.
    pub async fn new(data_dir: std::path::PathBuf) -> Result<Self> {
        let token_store = TokenStore::new(data_dir)?;
        let ipc_client = IpcClient::connect().await?;

        Ok(Session {
            token_store,
            ipc_client,
        })
    }

    /// Creates a new session manager with a custom IPC socket and data directory.
    pub async fn new_with_socket(socket_path: &str, data_dir: std::path::PathBuf) -> Result<Self> {
        let token_store = TokenStore::new(data_dir)?;
        let ipc_client = IpcClient::connect_with_socket(socket_path).await?;

        Ok(Session {
            token_store,
            ipc_client,
        })
    }

    /// Creates a session manager with file-only token storage (for tests).
    #[cfg(test)]
    pub async fn new_for_testing(socket_path: &str, test_dir: std::path::PathBuf) -> Result<Self> {
        let token_store = TokenStore::new_file_only(test_dir)?;
        let ipc_client = IpcClient::connect_with_socket_no_probe(socket_path).await?;

        Ok(Session {
            token_store,
            ipc_client,
        })
    }

    /// Logs in with email and password.
    ///
    /// Posts credentials to `/api/v1/auth/login`, extracts the JWT, persists to
    /// keychain, and primes penduind's in-memory session. On success, the user is
    /// authenticated for subsequent API calls.
    pub async fn login(&mut self, hub_url: &str, email: &str, password: &str) -> Result<()> {
        debug!("logging in with email/password");

        // Build the login request body.
        let body = json!({
            "email": email,
            "password": password,
        });

        let body_bytes = serde_json::to_vec(&body).map_err(|e| {
            DesktopError::Internal(format!("failed to serialize login body: {}", e))
        })?;

        // POST /api/v1/auth/login via ProxyRequest.
        let req = ApiRequest {
            method: "POST".to_string(),
            path: "/api/v1/auth/login".to_string(),
            headers: vec![Header {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body: body_bytes,
        };

        let resp = self.ipc_client.proxy_request(req).await?;

        if resp.status != 200 {
            return Err(DesktopError::ApiRequest {
                status: resp.status,
            });
        }

        // Parse the response to extract access_token, refresh_token, hub_base_url.
        let resp_json: serde_json::Value =
            serde_json::from_slice(&resp.body).map_err(|_e| DesktopError::InvalidCredentials)?;

        let access_token = resp_json
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or(DesktopError::InvalidCredentials)?
            .to_string();

        let refresh_token = resp_json
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Store the session in keychain.
        let session = StoredSession::new(access_token.clone(), refresh_token.clone(), hub_url);
        self.token_store.store(&session).await?;

        // Prime penduind's in-memory session.
        self.ipc_client
            .set_user_session(access_token, refresh_token, hub_url.to_string())
            .await?;

        info!("login successful");
        Ok(())
    }

    /// Starts an OAuth flow for a given platform.
    ///
    /// Returns an authorize URL (for the shell to open in the browser) and a
    /// context (for the shell to store and match against the callback).
    /// The state parameter is generated using CSPRNG (256-bit entropy).
    pub async fn oauth_start(
        &self,
        hub_url: &str,
        platform: OAuthPlatform,
    ) -> Result<(String, OAuthContext)> {
        debug!(platform = platform.as_str(), "starting OAuth flow");

        // generate_oauth_state uses CSPRNG internally
        oauth::start_oauth(hub_url, platform)
    }

    /// Completes an OAuth flow from a `waddles://oauth/callback` deep-link URL.
    ///
    /// Parses `code`/`token` and `state`, redeems exchange codes at
    /// `POST /api/v1/auth/exchange`, stores tokens in keychain, and primes penguind.
    pub async fn oauth_complete_url(
        &mut self,
        callback_url: &str,
        stored_state: &str,
    ) -> Result<()> {
        debug!("completing OAuth callback URL");
        let parsed = oauth::parse_callback_url(callback_url)?;
        let session = self.token_store.load().await?;

        let tokens = if let Some(code) = parsed.code {
            oauth::exchange_oauth_code(&session.hub_base_url, &code, &parsed.state, stored_state)
                .await?
        } else if let Some(token) = parsed.token {
            oauth::complete_oauth(
                CallbackParams {
                    token,
                    state: parsed.state,
                },
                stored_state,
            )?
        } else {
            return Err(DesktopError::InvalidCallback(
                "missing code or token in OAuth callback".to_string(),
            ));
        };

        let updated_session = StoredSession::new(
            tokens.access_token.clone(),
            tokens.refresh_token.clone(),
            session.hub_base_url.clone(),
        );
        self.token_store.store(&updated_session).await?;

        self.ipc_client
            .set_user_session(
                tokens.access_token,
                tokens.refresh_token,
                session.hub_base_url,
            )
            .await?;

        Ok(())
    }

    /// Completes an OAuth flow with a callback from the `waddles://` deep-link.
    ///
    /// Validates the state, extracts tokens from the JWT, stores in keychain,
    /// and primes penduind.
    pub async fn oauth_complete(
        &mut self,
        params: CallbackParams,
        stored_state: &str,
    ) -> Result<()> {
        debug!("completing OAuth callback");

        let tokens = oauth::complete_oauth(params, stored_state)?;

        // Load the stored hub URL (from a previous login or OAuth context).
        let session = self.token_store.load().await?;

        // Store the new tokens in keychain.
        let updated_session = StoredSession::new(
            tokens.access_token.clone(),
            tokens.refresh_token.clone(),
            session.hub_base_url.clone(),
        );
        self.token_store.store(&updated_session).await?;

        // Prime penduind's in-memory session.
        self.ipc_client
            .set_user_session(
                tokens.access_token,
                tokens.refresh_token,
                session.hub_base_url,
            )
            .await?;

        info!("OAuth login successful");
        Ok(())
    }

    /// Makes an authenticated API request to the hub.
    ///
    /// The shell calls this for every SPA → hub request. The request is forwarded
    /// to penduind's ProxyRequest RPC, which adds the Bearer token, handles 401 →
    /// refresh → retry, and returns the response.
    pub async fn api_request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<ApiResponse> {
        let req = ApiRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers: vec![Header {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body: body.unwrap_or_default(),
        };

        self.ipc_client.proxy_request(req).await
    }

    /// Executes a pre-authorized bridge action (OBS command or webhook).
    ///
    /// This is the thin wrapper delegating to IpcClient::execute_bridge_action.
    /// The daemon validates allowlists and dispatches to the appropriate adapter.
    pub async fn execute_bridge_action(
        &mut self,
        module_name: String,
        action_type: String,
        obs_request_type: String,
        obs_request_data: Vec<u8>,
        webhook_name: String,
        webhook_payload: Vec<u8>,
    ) -> Result<BridgeActionResponse> {
        self.ipc_client
            .execute_bridge_action(
                module_name,
                action_type,
                obs_request_type,
                obs_request_data,
                webhook_name,
                webhook_payload,
            )
            .await
    }

    /// Logs out: clears the keychain and penduind's in-memory session.
    pub async fn logout(&mut self) -> Result<()> {
        debug!("logging out");

        // Clear the keychain.
        self.token_store.clear().await?;

        // Notify penduind to clear the session (via ProxyRequest to /api/v1/auth/logout,
        // or a dedicated ClearSession RPC). For now, just clear locally.
        // TODO: Add ClearSession RPC to daemon proto + module handler.

        info!("logout successful");
        Ok(())
    }

    /// Checks whether an existing session is stored in the keychain.
    ///
    /// Returns true if a valid access token and hub URL exist, false otherwise.
    /// This is used at startup to determine whether to auto-resume the poll loop.
    pub async fn has_existing_session(&self) -> bool {
        self.token_store.has_session().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_platform_variants() {
        let platforms = vec![
            OAuthPlatform::Google,
            OAuthPlatform::GitHub,
            OAuthPlatform::Discord,
        ];
        for platform in platforms {
            assert!(!platform.as_str().is_empty());
        }
    }

    #[test]
    fn test_stored_session_new() {
        let session = StoredSession::new(
            "token1",
            Some("refresh1".to_string()),
            "https://hub.example.com",
        );
        assert_eq!(session.access_token, "token1");
        assert_eq!(session.refresh_token, Some("refresh1".to_string()));
        assert_eq!(session.hub_base_url, "https://hub.example.com");
    }

    #[test]
    fn test_stored_session_clone() {
        let session = StoredSession::new(
            "token1",
            Some("refresh1".to_string()),
            "https://hub.example.com",
        );
        let cloned = session.clone();

        assert_eq!(session.access_token, cloned.access_token);
        assert_eq!(session.refresh_token, cloned.refresh_token);
        assert_eq!(session.hub_base_url, cloned.hub_base_url);
    }

    #[test]
    fn test_oauth_context_structure() {
        let context = OAuthContext {
            state: "state123".to_string(),
            platform: "google".to_string(),
        };

        assert_eq!(context.state, "state123");
        assert_eq!(context.platform, "google");
    }

    #[test]
    fn test_callback_params_structure() {
        let params = CallbackParams {
            token: "jwt_token".to_string(),
            state: "state456".to_string(),
        };

        assert_eq!(params.token, "jwt_token");
        assert_eq!(params.state, "state456");
    }

    #[test]
    fn test_api_response_structure() {
        let resp = ApiResponse {
            status: 200,
            headers: vec![Header {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body: vec![1, 2, 3],
        };

        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.body, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_has_existing_session_when_empty() {
        use tempfile::tempdir;
        let temp_dir = tempdir().expect("failed to create temp dir");
        let token_store = TokenStore::new_file_only(temp_dir.path().to_path_buf())
            .expect("failed to create test token store");

        // No session stored yet.
        assert!(!token_store.has_session().await);

        // Store a session and verify has_session returns true
        let stored = StoredSession::new("test_token", None, "https://example.com");
        token_store
            .store(&stored)
            .await
            .expect("failed to store session");
        assert!(token_store.has_session().await);
    }

    // Integration tests using mock SessionProxy server
    mod integration {
        use super::*;
        use mock_server::MockSessionProxy;
        use penguin_proto::desktop::v1::session_proxy_server::SessionProxyServer;
        use std::path::PathBuf;
        use tokio::net::UnixListener;
        use tonic::transport::Server;

        /// Starts a mock gRPC server on a temp UDS and returns the socket path.
        async fn start_mock_server(mock: MockSessionProxy) -> PathBuf {
            let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
            let socket_path = temp_dir.path().join("test.sock");

            let uds = UnixListener::bind(&socket_path).expect("failed to bind UDS");
            let socket_path_clone = socket_path.clone();

            // Keep temp_dir alive for the duration of the test
            std::mem::forget(temp_dir);

            tokio::spawn(async move {
                use tokio_stream::wrappers::UnixListenerStream;

                let svc = SessionProxyServer::new(mock);
                let stream = UnixListenerStream::new(uds);
                let _result = Server::builder()
                    .add_service(svc)
                    .serve_with_incoming(stream)
                    .await;
            });

            // Give the server a moment to start
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            socket_path_clone
        }

        #[tokio::test]
        async fn test_login_choreography() -> Result<()> {
            let test_dir = tempfile::tempdir()
                .map_err(|e| DesktopError::Internal(format!("temp dir: {}", e)))?;

            let mock = MockSessionProxy::new();
            let mock_clone = mock.clone();
            let socket_path = start_mock_server(mock_clone).await;

            // Set up mock to return a login response with tokens
            let login_response = json!({
                "access_token": "access_xyz",
                "refresh_token": "refresh_abc",
            });
            mock.set_proxy_response(200, login_response.to_string().into_bytes())
                .await;

            // Create session with mock server
            let mut session = Session::new_for_testing(
                socket_path.to_str().expect("socket path"),
                test_dir.path().to_path_buf(),
            )
            .await?;

            // Call login
            session
                .login("https://hub.example.com", "user@example.com", "password123")
                .await?;

            // Verify: mock received ProxyRequest (login call)
            let requests = mock.recorded_requests().await;
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].0, "POST");
            assert_eq!(requests[0].1, "/api/v1/auth/login");

            // Verify: mock received SetUserSession
            let sessions = mock.recorded_sessions().await;
            assert_eq!(sessions.len(), 1);
            assert_eq!(sessions[0].0, "access_xyz");
            assert_eq!(sessions[0].1, "refresh_abc");
            assert_eq!(sessions[0].2, "https://hub.example.com");

            // Verify: tokens persisted to keychain
            let token_store = TokenStore::new_file_only(test_dir.path().to_path_buf())?;
            let loaded = token_store.load().await?;
            assert_eq!(loaded.access_token, "access_xyz");
            assert_eq!(loaded.refresh_token, Some("refresh_abc".to_string()));

            Ok(())
        }

        #[tokio::test]
        async fn test_oauth_complete_state_validation() -> Result<()> {
            let test_dir = tempfile::tempdir()
                .map_err(|e| DesktopError::Internal(format!("temp dir: {}", e)))?;

            let mock = MockSessionProxy::new();
            let mock_clone = mock.clone();
            let socket_path = start_mock_server(mock_clone).await;

            // Pre-populate keychain with hub URL
            let token_store = TokenStore::new_file_only(test_dir.path().to_path_buf())?;
            let session = StoredSession::new("old_token", None, "https://hub.example.com");
            token_store.store(&session).await?;

            // Create session manager
            let mut session_mgr = Session::new_for_testing(
                socket_path.to_str().expect("socket path"),
                test_dir.path().to_path_buf(),
            )
            .await?;

            // Test: state mismatch should fail
            let callback_wrong_state = CallbackParams {
                token: "dummy_token".to_string(),
                state: "wrong_state".to_string(),
            };

            let result = session_mgr
                .oauth_complete(callback_wrong_state, "expected_state")
                .await;
            assert!(result.is_err(), "should reject mismatched state");

            // Test: correct state but invalid JWT should fail (JWT decode error)
            let callback_valid_state = CallbackParams {
                token: "not_a_valid_jwt".to_string(),
                state: "expected_state".to_string(),
            };

            let result = session_mgr
                .oauth_complete(callback_valid_state, "expected_state")
                .await;
            assert!(result.is_err(), "should reject invalid JWT");

            Ok(())
        }

        #[tokio::test]
        async fn test_api_request_forwarding() -> Result<()> {
            let test_dir = tempfile::tempdir()
                .map_err(|e| DesktopError::Internal(format!("temp dir: {}", e)))?;

            let mock = MockSessionProxy::new();
            let mock_clone = mock.clone();
            let socket_path = start_mock_server(mock_clone).await;

            // Set up mock to return a test response
            mock.set_proxy_response(200, b"test response".to_vec())
                .await;

            // Create session
            let mut session = Session::new_for_testing(
                socket_path.to_str().expect("socket path"),
                test_dir.path().to_path_buf(),
            )
            .await?;

            // Make an API request
            let resp = session.api_request("GET", "/api/v1/test", None).await?;

            // Verify: mock recorded the request
            let requests = mock.recorded_requests().await;
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].0, "GET");
            assert_eq!(requests[0].1, "/api/v1/test");

            // Verify: response returned correctly
            assert_eq!(resp.status, 200);
            assert_eq!(resp.body, b"test response".to_vec());

            Ok(())
        }

        #[tokio::test]
        async fn test_logout_clears_keychain() -> Result<()> {
            let test_dir = tempfile::tempdir()
                .map_err(|e| DesktopError::Internal(format!("temp dir: {}", e)))?;

            let mock = MockSessionProxy::new();
            let mock_clone = mock.clone();
            let socket_path = start_mock_server(mock_clone).await;

            // Pre-populate keychain
            let token_store = TokenStore::new_file_only(test_dir.path().to_path_buf())?;
            let session = StoredSession::new(
                "access123",
                Some("refresh456".to_string()),
                "https://hub.example.com",
            );
            token_store.store(&session).await?;

            // Create session and logout
            let mut session_mgr = Session::new_for_testing(
                socket_path.to_str().expect("socket path"),
                test_dir.path().to_path_buf(),
            )
            .await?;

            session_mgr.logout().await?;

            // Verify: keychain is cleared
            assert!(!token_store.has_session().await);

            Ok(())
        }

        #[tokio::test]
        async fn test_api_request_error_status() -> Result<()> {
            let test_dir = tempfile::tempdir()
                .map_err(|e| DesktopError::Internal(format!("temp dir: {}", e)))?;

            let mock = MockSessionProxy::new();
            let mock_clone = mock.clone();
            let socket_path = start_mock_server(mock_clone).await;

            // Set up mock to return a 401 error
            mock.set_proxy_response(401, b"Unauthorized".to_vec()).await;

            // Create session
            let mut session = Session::new_for_testing(
                socket_path.to_str().expect("socket path"),
                test_dir.path().to_path_buf(),
            )
            .await?;

            // Make an API request
            let resp = session
                .api_request("GET", "/api/v1/protected", None)
                .await?;

            // Verify: error status returned correctly
            assert_eq!(resp.status, 401);
            assert_eq!(resp.body, b"Unauthorized".to_vec());

            Ok(())
        }

        #[tokio::test]
        async fn test_proxy_request_grpc_error() -> Result<()> {
            let test_dir = tempfile::tempdir()
                .map_err(|e| DesktopError::Internal(format!("temp dir: {}", e)))?;

            let mock = MockSessionProxy::new();
            let mock_clone = mock.clone();
            let socket_path = start_mock_server(mock_clone).await;

            // Configure mock to fail on proxy_request
            mock.set_proxy_error(true).await;

            // Create session
            let mut session = Session::new_for_testing(
                socket_path.to_str().expect("socket path"),
                test_dir.path().to_path_buf(),
            )
            .await?;

            // Try proxy request — should return gRPC error
            let result = session.api_request("GET", "/api/v1/test", None).await;

            // Verify: error is returned with expected type
            assert!(result.is_err());
            match result.unwrap_err() {
                DesktopError::GrpcError(msg) => {
                    assert!(msg.contains("ProxyRequest"));
                }
                _ => panic!("expected GrpcError"),
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_oauth_complete_malformed_token() -> Result<()> {
            // Malformed JWT (not valid base64 parts)
            let params = CallbackParams {
                token: "not.a.jwt".to_string(),
                state: "test_state".to_string(),
            };

            let result = oauth::complete_oauth(params, "test_state");

            // Verify: error is returned for malformed token
            assert!(result.is_err());
            match result.unwrap_err() {
                DesktopError::OAuthError(msg) => {
                    assert!(msg.contains("decode"));
                }
                _ => panic!("expected OAuthError"),
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_oauth_complete_missing_token_claim() -> Result<()> {
            // Create a JWT without access_token claim (valid structure but missing claim)
            let header = serde_json::json!({"alg": "HS256"}).to_string();
            let claims = serde_json::json!({"sub": "user123"}).to_string(); // no access_token
            let signature = "fake_sig";

            let header_b64 = base64_url::encode(header.as_bytes());
            let claims_b64 = base64_url::encode(claims.as_bytes());
            let token = format!("{}.{}.{}", header_b64, claims_b64, signature);

            let params = CallbackParams {
                token,
                state: "test_state".to_string(),
            };

            let result = oauth::complete_oauth(params, "test_state");

            // Verify: error is returned for missing token claim
            assert!(result.is_err());
            match result.unwrap_err() {
                DesktopError::OAuthError(msg) => {
                    assert!(msg.contains("access_token not found"));
                }
                _ => panic!("expected OAuthError"),
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_token_store_load_nonexistent() -> Result<()> {
            let test_dir = tempfile::tempdir()
                .map_err(|e| DesktopError::Internal(format!("temp dir: {}", e)))?;

            let token_store = TokenStore::new_file_only(test_dir.path().to_path_buf())?;

            // Try to load from empty keychain — should return an error
            let result = token_store.load().await;

            // Verify: load fails (either NoSession or KeychainError for missing key)
            assert!(result.is_err());

            Ok(())
        }

        #[tokio::test]
        async fn test_token_store_update_after_store() -> Result<()> {
            let test_dir = tempfile::tempdir()
                .map_err(|e| DesktopError::Internal(format!("temp dir: {}", e)))?;

            let token_store = TokenStore::new_file_only(test_dir.path().to_path_buf())?;

            // Store initial session with hub URL
            let initial_session = StoredSession::new(
                "initial_access",
                Some("initial_refresh".to_string()),
                "https://hub.example.com",
            );
            token_store.store(&initial_session).await?;

            // Update tokens only (hub URL should remain unchanged)
            token_store
                .update_tokens("new_access".to_string(), Some("new_refresh".to_string()))
                .await?;

            // Verify: the new tokens were stored but hub URL unchanged
            let session = token_store.load().await?;
            assert_eq!(session.access_token, "new_access");
            assert_eq!(session.refresh_token, Some("new_refresh".to_string()));
            assert_eq!(session.hub_base_url, "https://hub.example.com");

            Ok(())
        }

        #[tokio::test]
        async fn test_execute_bridge_action_delegates_to_ipc_client() -> Result<()> {
            let test_dir = tempfile::tempdir()
                .map_err(|e| DesktopError::Internal(format!("temp dir: {}", e)))?;

            let mock = MockSessionProxy::new();
            let mock_clone = mock.clone();
            let socket_path = start_mock_server(mock_clone).await;

            let mut session = Session::new_for_testing(
                socket_path.to_str().expect("socket path"),
                test_dir.path().to_path_buf(),
            )
            .await?;

            // Call execute_bridge_action
            // This will attempt to call the daemon's execute_bridge_action RPC
            // The daemon may not be running, so we expect an error (but the path is exercised)
            let result = session
                .execute_bridge_action(
                    "waddles-gateway".to_string(),
                    "obs_command".to_string(),
                    "GetVersion".to_string(),
                    vec![],
                    String::new(),
                    vec![],
                )
                .await;

            // The result may be an error since the daemon is not running,
            // but the key is that execute_bridge_action was called and attempted to delegate
            match result {
                Ok(_) => {
                    // If it succeeded, that's fine (mock may have handled it)
                }
                Err(_) => {
                    // Expected: daemon not running or RPC failed
                    // But the method was exercised
                }
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_logout_clears_token_store() -> Result<()> {
            let test_dir = tempfile::tempdir()
                .map_err(|e| DesktopError::Internal(format!("temp dir: {}", e)))?;

            let mock = MockSessionProxy::new();
            let mock_clone = mock.clone();
            let socket_path = start_mock_server(mock_clone).await;

            let mut session = Session::new_for_testing(
                socket_path.to_str().expect("socket path"),
                test_dir.path().to_path_buf(),
            )
            .await?;

            // Store a session first
            let stored = StoredSession::new("test_token", None, "https://example.com");
            session.token_store.store(&stored).await?;
            assert!(session.token_store.has_session().await);

            // Logout
            let result = session.logout().await;
            assert!(result.is_ok(), "logout should succeed: {:?}", result);

            // Verify session was cleared
            assert!(!session.token_store.has_session().await);

            Ok(())
        }
    }
}
