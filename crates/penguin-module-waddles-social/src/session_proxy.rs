//! Desktop client user-session hub proxy: generic Bearer passthrough with automatic
//! token refresh.
//!
//! Holds the current user's `{access_token, refresh_token, hub_base_url}` in-memory
//! (set via `SetUserSession` RPC, never persisted daemon-side). Proxies arbitrary
//! `/api/v1/**` requests to the hub with the Bearer token and handles 401 → refresh
//! → retry logic.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use thiserror::Error;
use tokio::time::timeout;
use tracing::{debug, warn};
use url::Url;

/// User session credentials and hub configuration, held in-memory.
/// Never logged or exposed in any response.
#[derive(Clone, Debug)]
struct SessionCredentials {
    access_token: String,
    refresh_token: Option<String>,
    hub_base_url: Url,
}

/// Errors from user-session proxy operations.
#[derive(Error, Debug)]
pub enum SessionProxyError {
    #[error("no active session")]
    NoSession,
    #[error("invalid hub base url")]
    InvalidUrl,
    #[error("hub request failed: {0}")]
    HubRequest(String),
    #[error("token refresh failed: {0}")]
    TokenRefresh(String),
    #[error("invalid credentials")]
    InvalidCredentials,
}

/// Generic HTTP request/response types for the proxy.
#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A user-session hub proxy: forwards `/api/v1/**` requests with Bearer auth,
/// handles 401 → refresh → retry, and emits token-rotate events on refresh.
///
/// Tokens live in-memory only, set via `set_session()` and cleared on logout.
/// The desktop shell owns keychain persistence and OAuth; this proxy owns the
/// machine-to-machine refresh flow.
pub struct SessionProxy {
    credentials: Mutex<Option<SessionCredentials>>,
    has_rotated: AtomicBool,
}

impl SessionProxy {
    /// Creates a new proxy with no active session.
    pub fn new() -> Self {
        SessionProxy {
            credentials: Mutex::new(None),
            has_rotated: AtomicBool::new(false),
        }
    }
}

impl Default for SessionProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionProxy {
    /// Sets the current user session: access + optional refresh token, and hub base URL.
    /// Credentials are held in-memory only.
    /// SECURITY: Validates URL and scheme (HTTPS required except for loopback).
    pub fn set_session(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        hub_base_url: String,
    ) -> Result<(), SessionProxyError> {
        // Parse the URL strictly — must be a valid absolute URL.
        let parsed_url = Url::parse(&hub_base_url).map_err(|_| SessionProxyError::InvalidUrl)?;

        // Security: HTTPS required, or HTTP only for loopback development.
        let is_https = parsed_url.scheme() == "https";
        let is_loopback = matches!(
            parsed_url.host_str(),
            Some("127.0.0.1") | Some("::1") | Some("localhost")
        );

        if !is_https && !is_loopback {
            return Err(SessionProxyError::HubRequest(
                "plaintext Bearer transport forbidden to non-loopback hosts".to_string(),
            ));
        }

        let creds = SessionCredentials {
            access_token,
            refresh_token,
            hub_base_url: parsed_url,
        };

        *self.credentials.lock().expect("credentials mutex poisoned") = Some(creds);
        self.has_rotated.store(false, Ordering::SeqCst);

        debug!("user session set");
        Ok(())
    }

    /// Clears the current session (e.g., on logout).
    pub fn clear_session(&self) {
        *self.credentials.lock().expect("credentials mutex poisoned") = None;
        self.has_rotated.store(false, Ordering::SeqCst);
        debug!("user session cleared");
    }

    /// Returns whether a token refresh occurred (for the shell to re-persist to keychain).
    pub fn token_rotated(&self) -> bool {
        self.has_rotated.load(Ordering::SeqCst)
    }

    /// Reset the rotated flag after the caller has processed the event.
    pub fn clear_rotated_flag(&self) {
        self.has_rotated.store(false, Ordering::SeqCst);
    }

    /// Proxies an HTTP request to the hub:
    /// 1. Attaches the current access token as `Authorization: Bearer <token>`.
    /// 2. Forwards to `{hub_base_url}{path}` over HTTPS.
    /// 3. On 401: if refresh token exists, POST `/api/v1/auth/refresh`, store new
    ///    token, set the rotated flag, and retry the original request once.
    /// 4. Strips hop-by-hop headers from the response.
    /// 5. Never logs token values (use telemetry sanitizer if any appear in errors).
    pub async fn forward_request(
        &self,
        req: HttpRequest,
    ) -> Result<HttpResponse, SessionProxyError> {
        let mut creds = self
            .credentials
            .lock()
            .expect("credentials mutex poisoned")
            .clone()
            .ok_or(SessionProxyError::NoSession)?;

        let mut retry_count = 0;
        loop {
            let response = self.send_request(&creds, &req).await?;
            let status = response.status;

            // On 401 and refresh token exists, and we haven't already retried: try refresh + retry.
            if status == 401 && retry_count == 0 {
                if let Some(refresh_token) = &creds.refresh_token.clone() {
                    match self.refresh_token(&creds, refresh_token).await {
                        Ok(outcome) => {
                            // Update in-memory tokens and set rotated flag.
                            {
                                let mut creds_mut =
                                    self.credentials.lock().expect("credentials mutex poisoned");
                                if let Some(creds_inner) = creds_mut.as_mut() {
                                    creds_inner.access_token = outcome.access_token;
                                    if let Some(new_refresh) = outcome.refresh_token {
                                        creds_inner.refresh_token = Some(new_refresh);
                                    }
                                }
                            }
                            self.has_rotated.store(true, Ordering::SeqCst);
                            debug!("token refreshed, retrying original request");

                            // Re-acquire creds with the new token for the retry.
                            creds = self
                                .credentials
                                .lock()
                                .expect("credentials mutex poisoned")
                                .clone()
                                .ok_or(SessionProxyError::NoSession)?;

                            retry_count += 1;
                            continue; // Retry the request
                        }
                        Err(e) => {
                            warn!("token refresh failed: {}", e);
                            // Fall through: return the 401.
                            return Ok(response);
                        }
                    }
                } else {
                    debug!("401 received, no refresh token available");
                    return Ok(response);
                }
            }

            // If we get here, return the response (either success or non-401 error).
            return Ok(response);
        }
    }

    /// Sends an HTTP request with the given credentials, returning the raw response.
    /// SECURITY: Validates request path to prevent SSRF, uses safe URL joining.
    async fn send_request(
        &self,
        creds: &SessionCredentials,
        req: &HttpRequest,
    ) -> Result<HttpResponse, SessionProxyError> {
        // Validate path: must be an absolute path starting with /api/v1/
        validate_request_path(&req.path)?;

        // Safe URL joining: parse the path and join with the base URL.
        // This prevents SSRF via string concatenation.
        let url = creds
            .hub_base_url
            .join(&req.path)
            .map_err(|_| SessionProxyError::HubRequest("invalid path".to_string()))?;

        // Security: verify the joined URL is still on the same host and scheme as the base.
        if url.host_str() != creds.hub_base_url.host_str()
            || url.scheme() != creds.hub_base_url.scheme()
        {
            return Err(SessionProxyError::HubRequest(
                "path redirect to different host/scheme detected".to_string(),
            ));
        }

        let client = reqwest::Client::new();
        let mut builder = match req.method.to_uppercase().as_str() {
            "GET" => client.get(url),
            "POST" => client.post(url),
            "PUT" => client.put(url),
            "DELETE" => client.delete(url),
            "PATCH" => client.patch(url),
            _ => {
                return Err(SessionProxyError::HubRequest(format!(
                    "unsupported method: {}",
                    req.method
                )));
            }
        };

        // Attach Bearer auth — this is set by the proxy, never from the client.
        builder = builder.header("Authorization", format!("Bearer {}", creds.access_token));

        // Add custom headers (ALLOWLIST only — never forward auth headers).
        for (name, value) in &req.headers {
            if is_forwardable_header(name) {
                builder = builder.header(name, value);
            }
        }

        // Attach body if present.
        if !req.body.is_empty() {
            builder = builder.body(req.body.clone());
        }

        // Forward with timeout.
        let response = timeout(Duration::from_secs(30), builder.send())
            .await
            .map_err(|_| SessionProxyError::HubRequest("timeout".to_string()))?
            .map_err(|e| SessionProxyError::HubRequest(e.to_string()))?;

        let status = response.status().as_u16();

        // Collect response headers, stripping hop-by-hop.
        let mut response_headers = Vec::new();
        for (name, value) in response.headers().iter() {
            if !is_hop_by_hop_header(name.as_str())
                && let Ok(value_str) = value.to_str()
            {
                response_headers.push((name.to_string(), value_str.to_string()));
            }
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| SessionProxyError::HubRequest(e.to_string()))?
            .to_vec();

        Ok(HttpResponse {
            status,
            headers: response_headers,
            body,
        })
    }

    /// POST `/api/v1/auth/refresh` to the hub with the refresh token.
    /// Accepts `token` (Waddles hub-api canonical) or `access_token` alias,
    /// and captures rotated `refresh_token` when returned.
    async fn refresh_token(
        &self,
        creds: &SessionCredentials,
        refresh_token: &str,
    ) -> Result<RefreshOutcome, SessionProxyError> {
        let url = creds
            .hub_base_url
            .join("/api/v1/auth/refresh")
            .map_err(|_| SessionProxyError::TokenRefresh("invalid hub base url".to_string()))?;
        let body = serde_json::json!({ "refresh_token": refresh_token });

        let client = reqwest::Client::new();
        let response = timeout(Duration::from_secs(10), client.post(url).json(&body).send())
            .await
            .map_err(|_| SessionProxyError::TokenRefresh("timeout".to_string()))?
            .map_err(|e| SessionProxyError::TokenRefresh(e.to_string()))?;

        if !response.status().is_success() {
            return Err(SessionProxyError::TokenRefresh(format!(
                "hub returned {}",
                response.status()
            )));
        }

        let refresh_response: serde_json::Value = response
            .json()
            .await
            .map_err(|e| SessionProxyError::TokenRefresh(e.to_string()))?;

        let access_token = refresh_response
            .get("token")
            .or_else(|| refresh_response.get("access_token"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                SessionProxyError::TokenRefresh(
                    "no token or access_token in refresh response".to_string(),
                )
            })?;

        let rotated_refresh_token = refresh_response
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        Ok(RefreshOutcome {
            access_token,
            refresh_token: rotated_refresh_token,
        })
    }
}

struct RefreshOutcome {
    access_token: String,
    refresh_token: Option<String>,
}

/// Validates that a request path is safe to forward to the hub.
/// SECURITY: Must be an absolute path starting with /api/v1/, no SSRF vectors.
fn validate_request_path(path: &str) -> Result<(), SessionProxyError> {
    // Must start with /
    if !path.starts_with('/') {
        return Err(SessionProxyError::HubRequest(
            "path must be absolute".to_string(),
        ));
    }

    // Must start with /api/v1/
    if !path.starts_with("/api/v1/") {
        return Err(SessionProxyError::HubRequest(
            "path must start with /api/v1/".to_string(),
        ));
    }

    // Reject paths with @ (authority separator in URLs)
    if path.contains('@') {
        return Err(SessionProxyError::HubRequest(
            "path contains invalid character".to_string(),
        ));
    }

    // Reject paths starting with // (network-path reference)
    if path.starts_with("//") {
        return Err(SessionProxyError::HubRequest(
            "path cannot start with //".to_string(),
        ));
    }

    // Reject paths with .. (directory traversal)
    if path.contains("..") {
        return Err(SessionProxyError::HubRequest(
            "path traversal detected".to_string(),
        ));
    }

    // Reject if path contains a scheme (://)
    if path.contains("://") {
        return Err(SessionProxyError::HubRequest(
            "path cannot contain scheme".to_string(),
        ));
    }

    Ok(())
}

/// Allowlist of headers that client can provide; we never forward auth/security headers.
/// SECURITY: The proxy sets Authorization; never allow client-supplied auth headers.
fn is_forwardable_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "content-type"
            | "accept"
            | "accept-language"
            | "accept-encoding"
            | "x-request-id"
            | "x-correlation-id"
            | "user-agent"
    )
}

/// HTTP hop-by-hop headers that should never be forwarded.
fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "via"
            | "host"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_session_valid_url() {
        let proxy = SessionProxy::new();

        let result = proxy.set_session(
            "token123".to_string(),
            Some("refresh456".to_string()),
            "https://hub.example.com".to_string(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_set_session_invalid_url() {
        let proxy = SessionProxy::new();

        let result = proxy.set_session(
            "token123".to_string(),
            Some("refresh456".to_string()),
            "hub.example.com".to_string(),
        );

        assert!(matches!(result, Err(SessionProxyError::InvalidUrl)));
    }

    #[test]
    fn test_clear_session() {
        let proxy = SessionProxy::new();

        proxy
            .set_session(
                "token123".to_string(),
                None,
                "https://hub.example.com".to_string(),
            )
            .unwrap();

        proxy.clear_session();

        // Attempting to forward without a session should fail.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            proxy
                .forward_request(HttpRequest {
                    method: "GET".to_string(),
                    path: "/api/v1/test".to_string(),
                    headers: vec![],
                    body: vec![],
                })
                .await
        });

        assert!(matches!(result, Err(SessionProxyError::NoSession)));
    }

    #[test]
    fn test_token_rotated_flag() {
        let proxy = SessionProxy::new();

        assert!(!proxy.token_rotated());

        proxy
            .set_session(
                "token".to_string(),
                None,
                "https://hub.example.com".to_string(),
            )
            .unwrap();

        // Flag should not be set until a refresh occurs (tested via mocked hub).
        assert!(!proxy.token_rotated());

        proxy.clear_rotated_flag();
        assert!(!proxy.token_rotated());
    }

    #[test]
    fn test_hop_by_hop_headers() {
        assert!(is_hop_by_hop_header("Connection"));
        assert!(is_hop_by_hop_header("Keep-Alive"));
        assert!(is_hop_by_hop_header("Transfer-Encoding"));
        assert!(!is_hop_by_hop_header("X-Custom-Header"));
        assert!(!is_hop_by_hop_header("Content-Type"));
    }

    // ========== SECURITY TESTS: SSRF / BEARER EXFILTRATION ==========

    #[test]
    fn test_validate_path_rejects_network_path_reference() {
        // Reject //evil.com
        assert!(validate_request_path("//evil.com").is_err());
    }

    #[test]
    fn test_validate_path_rejects_full_url_in_path() {
        // Reject https://evil.com/x
        assert!(validate_request_path("https://evil.com/api/v1/x").is_err());
    }

    #[test]
    fn test_validate_path_rejects_authority_separator() {
        // Reject /api/v1/x@evil.com and @evil.com
        assert!(validate_request_path("/api/v1/x@evil.com").is_err());
        assert!(validate_request_path("@evil.com").is_err());
    }

    #[test]
    fn test_validate_path_rejects_non_api_path() {
        // Reject /admin/x, /status, etc. — must be /api/v1/
        assert!(validate_request_path("/admin/x").is_err());
        assert!(validate_request_path("/status").is_err());
        assert!(validate_request_path("/api/v2/x").is_err());
    }

    #[test]
    fn test_validate_path_rejects_directory_traversal() {
        // Reject /api/v1/../admin
        assert!(validate_request_path("/api/v1/../admin").is_err());
    }

    #[test]
    fn test_validate_path_accepts_valid_paths() {
        // Accept /api/v1/users, /api/v1/auth/refresh, etc.
        assert!(validate_request_path("/api/v1/users").is_ok());
        assert!(validate_request_path("/api/v1/auth/refresh").is_ok());
        assert!(validate_request_path("/api/v1/resources?query=value").is_ok());
    }

    #[test]
    fn test_set_session_rejects_http_to_non_loopback() {
        let proxy = SessionProxy::new();
        // Reject http:// to a non-loopback host
        let result = proxy.set_session(
            "token".to_string(),
            None,
            "http://hub.example.com".to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_set_session_accepts_https() {
        let proxy = SessionProxy::new();
        // Accept https://
        let result = proxy.set_session(
            "token".to_string(),
            None,
            "https://hub.example.com".to_string(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_set_session_accepts_http_to_loopback() {
        let proxy = SessionProxy::new();
        // Accept http:// to loopback
        let result = proxy.set_session(
            "token".to_string(),
            None,
            "http://127.0.0.1:8080".to_string(),
        );
        assert!(result.is_ok());
        let result = proxy.set_session("token".to_string(), None, "http://localhost".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_forwardable_headers_allowlist() {
        // These are OK to forward
        assert!(is_forwardable_header("Content-Type"));
        assert!(is_forwardable_header("Accept"));
        assert!(is_forwardable_header("X-Request-ID"));
        // These are NOT OK — never forward auth headers
        assert!(!is_forwardable_header("Authorization"));
        assert!(!is_forwardable_header("Cookie"));
        assert!(!is_forwardable_header("Proxy-Authorization"));
        // Hop-by-hop also rejected (overlap OK)
        assert!(!is_forwardable_header("Connection"));
    }

    // ========== INTEGRATION TESTS: WIREMOCK MOCK HUB ==========

    #[tokio::test]
    async fn test_forward_request_happy_path() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Initialize rustls crypto provider for reqwest client
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Start mock hub server
        let mock_server = MockServer::start().await;

        // Mock: GET /api/v1/users returns 200 with JSON
        Mock::given(method("GET"))
            .and(path("/api/v1/users"))
            .and(header("authorization", "Bearer valid_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "user123",
                "name": "Alice"
            })))
            .mount(&mock_server)
            .await;

        let proxy = SessionProxy::new();
        proxy
            .set_session(
                "valid_token".to_string(),
                None,
                format!("http://{}", mock_server.address()),
            )
            .expect("set_session failed");

        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/v1/users".to_string(),
            headers: vec![],
            body: vec![],
        };

        let response = proxy
            .forward_request(request)
            .await
            .expect("forward failed");

        assert_eq!(response.status, 200);
        let body_str = String::from_utf8(response.body).expect("body not utf8");
        let body_json: serde_json::Value =
            serde_json::from_str(&body_str).expect("json parse failed");
        assert_eq!(body_json["name"], "Alice");
    }

    #[tokio::test]
    async fn test_forward_request_with_custom_headers() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Initialize rustls crypto provider for reqwest client
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let mock_server = MockServer::start().await;

        // Mock: verify X-Request-ID is forwarded, but not Authorization
        Mock::given(method("GET"))
            .and(path("/api/v1/resource"))
            .and(header("x-request-id", "req-123"))
            .and(header("authorization", "Bearer token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&mock_server)
            .await;

        let proxy = SessionProxy::new();
        proxy
            .set_session(
                "token".to_string(),
                None,
                format!("http://{}", mock_server.address()),
            )
            .expect("set_session failed");

        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/v1/resource".to_string(),
            headers: vec![
                ("X-Request-ID".to_string(), "req-123".to_string()),
                ("Authorization".to_string(), "Bearer IGNORED".to_string()), // Should NOT forward this
            ],
            body: vec![],
        };

        let response = proxy
            .forward_request(request)
            .await
            .expect("forward failed");
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn test_successful_request_with_refresh_token_available() {
        // Test that a successful request works end-to-end with a refresh token on hand.
        // (Full 401→refresh→retry requires complex state tracking; this tests 200 success path.)
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Initialize rustls crypto provider for reqwest client
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let mock_server = MockServer::start().await;

        // Mock: GET /api/v1/users → 200 success
        Mock::given(method("GET"))
            .and(path("/api/v1/users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "user123"
            })))
            .mount(&mock_server)
            .await;

        let proxy = SessionProxy::new();
        proxy
            .set_session(
                "access_token".to_string(),
                Some("refresh_token".to_string()),
                format!("http://{}", mock_server.address()),
            )
            .expect("set_session failed");

        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/v1/users".to_string(),
            headers: vec![],
            body: vec![],
        };

        let response = proxy
            .forward_request(request)
            .await
            .expect("forward failed");

        // Should get 200
        assert_eq!(response.status, 200);
        // Token should NOT have rotated (no 401, no refresh)
        assert!(!proxy.token_rotated());
    }

    #[tokio::test]
    async fn test_401_no_refresh_token_returns_401() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Initialize rustls crypto provider for reqwest client
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let mock_server = MockServer::start().await;

        // Mock: GET /api/v1/users → 401 (no refresh token, so should NOT retry)
        Mock::given(method("GET"))
            .and(path("/api/v1/users"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let proxy = SessionProxy::new();
        proxy
            .set_session(
                "token".to_string(),
                None, // No refresh token
                format!("http://{}", mock_server.address()),
            )
            .expect("set_session failed");

        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/v1/users".to_string(),
            headers: vec![],
            body: vec![],
        };

        let response = proxy
            .forward_request(request)
            .await
            .expect("forward failed");

        // Should return 401 (no retry)
        assert_eq!(response.status, 401);
        assert!(!proxy.token_rotated());
    }

    #[tokio::test]
    async fn test_401_refresh_failure_returns_401() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Initialize rustls crypto provider for reqwest client
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let mock_server = MockServer::start().await;

        // First call: GET /api/v1/users → 401
        Mock::given(method("GET"))
            .and(path("/api/v1/users"))
            .respond_with(ResponseTemplate::new(401))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        // Refresh call: POST /api/v1/auth/refresh → 500 (failure)
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/refresh"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let proxy = SessionProxy::new();
        proxy
            .set_session(
                "token".to_string(),
                Some("bad_refresh".to_string()),
                format!("http://{}", mock_server.address()),
            )
            .expect("set_session failed");

        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/v1/users".to_string(),
            headers: vec![],
            body: vec![],
        };

        let response = proxy
            .forward_request(request)
            .await
            .expect("forward failed");

        // Should return 401 (refresh failed, no retry)
        assert_eq!(response.status, 401);
        assert!(!proxy.token_rotated());
    }

    #[test]
    fn test_token_rotate_flag_lifecycle() {
        // Test that the token rotated flag can be set and cleared correctly.
        let proxy = SessionProxy::new();

        // Initially false
        assert!(!proxy.token_rotated());

        // Set a session (doesn't set the flag)
        proxy
            .set_session(
                "token".to_string(),
                None,
                "https://hub.example.com".to_string(),
            )
            .expect("set_session failed");
        assert!(!proxy.token_rotated());

        // Manually simulate what forward_request does when refresh succeeds:
        // This would normally be done inside forward_request after a successful refresh
        // For this test, we just verify the flag lifecycle
        proxy
            .has_rotated
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(proxy.token_rotated());

        // Clear the flag
        proxy.clear_rotated_flag();
        assert!(!proxy.token_rotated());

        // Can be set again
        proxy
            .has_rotated
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(proxy.token_rotated());

        // Clearing session also clears the flag
        proxy.clear_session();
        assert!(!proxy.token_rotated());
    }

    #[tokio::test]
    async fn test_set_session_lifecycle() {
        // Initialize rustls crypto provider for reqwest client
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let proxy = SessionProxy::new();

        // Initially no session
        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/v1/test".to_string(),
            headers: vec![],
            body: vec![],
        };

        let result = proxy.forward_request(request.clone()).await;
        assert!(matches!(result, Err(SessionProxyError::NoSession)));

        // Set session
        proxy
            .set_session(
                "token1".to_string(),
                Some("refresh1".to_string()),
                "https://hub.example.com".to_string(),
            )
            .expect("set_session failed");

        // Replace session
        proxy
            .set_session(
                "token2".to_string(),
                Some("refresh2".to_string()),
                "https://hub2.example.com".to_string(),
            )
            .expect("set_session replaced");

        // Clear session
        proxy.clear_session();

        let result = proxy.forward_request(request).await;
        assert!(matches!(result, Err(SessionProxyError::NoSession)));
    }

    #[tokio::test]
    async fn test_hub_5xx_error_handling() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Initialize rustls crypto provider for reqwest client
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let mock_server = MockServer::start().await;

        // Mock: GET /api/v1/resource → 500
        Mock::given(method("GET"))
            .and(path("/api/v1/resource"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let proxy = SessionProxy::new();
        proxy
            .set_session(
                "token".to_string(),
                None,
                format!("http://{}", mock_server.address()),
            )
            .expect("set_session failed");

        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/v1/resource".to_string(),
            headers: vec![],
            body: vec![],
        };

        let response = proxy
            .forward_request(request)
            .await
            .expect("forward failed");

        // Should return the 500 (not an error, a valid response)
        assert_eq!(response.status, 500);
        let body_str = String::from_utf8(response.body).expect("body not utf8");
        assert_eq!(body_str, "Internal Server Error");
    }

    #[tokio::test]
    async fn test_post_with_body() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Initialize rustls crypto provider for reqwest client
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let mock_server = MockServer::start().await;

        // Mock: POST /api/v1/items with body
        Mock::given(method("POST"))
            .and(path("/api/v1/items"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "item123"
            })))
            .mount(&mock_server)
            .await;

        let proxy = SessionProxy::new();
        proxy
            .set_session(
                "token".to_string(),
                None,
                format!("http://{}", mock_server.address()),
            )
            .expect("set_session failed");

        let body = serde_json::to_vec(&serde_json::json!({
            "name": "New Item"
        }))
        .expect("json encode failed");

        let request = HttpRequest {
            method: "POST".to_string(),
            path: "/api/v1/items".to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body,
        };

        let response = proxy
            .forward_request(request)
            .await
            .expect("forward failed");

        assert_eq!(response.status, 201);
        let body_str = String::from_utf8(response.body).expect("body not utf8");
        let body_json: serde_json::Value =
            serde_json::from_str(&body_str).expect("json parse failed");
        assert_eq!(body_json["id"], "item123");
    }

    #[tokio::test]
    async fn test_response_headers_hop_by_hop_stripped() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Initialize rustls crypto provider for reqwest client
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let mock_server = MockServer::start().await;

        // Mock: respond with hop-by-hop headers that should be stripped
        Mock::given(method("GET"))
            .and(path("/api/v1/test"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("Transfer-Encoding", "chunked") // hop-by-hop, should be stripped
                    .append_header("X-Custom-Header", "custom-value") // should be kept
                    .set_body_string("test body"),
            )
            .mount(&mock_server)
            .await;

        let proxy = SessionProxy::new();
        proxy
            .set_session(
                "token".to_string(),
                None,
                format!("http://{}", mock_server.address()),
            )
            .expect("set_session failed");

        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/v1/test".to_string(),
            headers: vec![],
            body: vec![],
        };

        let response = proxy
            .forward_request(request)
            .await
            .expect("forward failed");

        // Transfer-Encoding should be stripped
        let has_transfer_encoding = response
            .headers
            .iter()
            .any(|(k, _)| k.to_lowercase() == "transfer-encoding");
        assert!(
            !has_transfer_encoding,
            "hop-by-hop Transfer-Encoding should be stripped"
        );

        // X-Custom-Header should be present
        let has_custom = response
            .headers
            .iter()
            .any(|(k, _)| k.to_lowercase() == "x-custom-header");
        assert!(has_custom, "X-Custom-Header should be present");
    }

    #[tokio::test]
    async fn test_401_refresh_with_waddles_token_and_rotated_refresh_retries_successfully() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/communities/my"))
            .and(header("authorization", "Bearer expired_jwt"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/refresh"))
            .and(body_json(
                serde_json::json!({"refresh_token": "old_refresh"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "token": "fresh_jwt",
                "refresh_token": "rotated_refresh"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/communities/my"))
            .and(header("authorization", "Bearer fresh_jwt"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"communities": []})),
            )
            .mount(&mock_server)
            .await;

        let proxy = SessionProxy::new();
        proxy
            .set_session(
                "expired_jwt".to_string(),
                Some("old_refresh".to_string()),
                format!("http://{}", mock_server.address()),
            )
            .expect("set_session failed");

        let response = proxy
            .forward_request(HttpRequest {
                method: "GET".to_string(),
                path: "/api/v1/communities/my".to_string(),
                headers: vec![],
                body: vec![],
            })
            .await
            .expect("forward_request failed");

        assert_eq!(response.status, 200);
        assert!(proxy.token_rotated());
        let stored_refresh = proxy
            .credentials
            .lock()
            .expect("mutex")
            .as_ref()
            .and_then(|c| c.refresh_token.clone());
        assert_eq!(stored_refresh.as_deref(), Some("rotated_refresh"));
    }

    #[tokio::test]
    async fn test_401_refresh_accepts_access_token_alias() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/test"))
            .and(header("authorization", "Bearer old_jwt"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "alias_jwt"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/test"))
            .and(header("authorization", "Bearer alias_jwt"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock_server)
            .await;

        let proxy = SessionProxy::new();
        proxy
            .set_session(
                "old_jwt".to_string(),
                Some("refresh_1".to_string()),
                format!("http://{}", mock_server.address()),
            )
            .expect("set_session failed");

        let response = proxy
            .forward_request(HttpRequest {
                method: "GET".to_string(),
                path: "/api/v1/test".to_string(),
                headers: vec![],
                body: vec![],
            })
            .await
            .expect("forward_request failed");

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert!(proxy.token_rotated());
    }
}
