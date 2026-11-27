//! [`WaddleAiClient`]: a thin HTTP client for the three server-side
//! surfaces this module talks to — a liveness/auth probe, the Tier-1
//! denylist snapshot, and normalized hook-event forwarding.
//!
//! This client never decides anything. It carries bytes to WaddleAI's
//! engine and hands back whatever it answers with; see this crate's
//! top-level doc for the architectural boundary this is built to respect.
//! The exact wire contract below is this crate's best-known shape for the
//! agent-hooks API (built in parallel, server-side) — every endpoint path
//! and payload field is called out where it matters, so a later contract
//! change is a small, localized diff rather than a redesign.

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{WaddleAiError, parse_error_body};

/// WaddleAI's production API. Follows the same `{product}.app` convention
/// documented for `waddlebot` (`waddles.app`) in
/// `~/.claude/rules/penguintech.md`'s product domain table. Override
/// `base_url` for local/beta testing.
pub const DEFAULT_BASE_URL: &str = "https://waddleai.app/api/v1";

/// Default per-request timeout. Hooks run synchronously inside an agent's
/// loop (see [`crate::metrics`]'s doc on `hook_evaluation_latency_seconds`),
/// so this is deliberately short: a hung request must not stall the
/// caller's editor/CLI indefinitely.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Configuration for [`WaddleAiClient`].
///
/// `Debug` is implemented by hand rather than derived: nothing currently
/// formats a `Config` with `{:?}`, but a derived impl would print
/// `virtual_key` unmasked, which is exactly the kind of latent landmine a
/// future `debug!("{:?}", config)` walks straight into. See
/// [`crate::mask::mask_secret`], the same helper every other call site in
/// this crate that surfaces the key already routes through.
#[derive(Clone)]
pub struct Config {
    /// The API's base URL, e.g. `https://waddleai.app/api/v1`. A trailing
    /// slash is tolerated — [`WaddleAiClient::new`] normalizes it.
    pub base_url: String,
    /// The `wa-`-prefixed virtual key, sent as `Authorization: Bearer
    /// <virtual_key>` on every request. Read from `host.secrets()` by
    /// [`crate::module::WaddleAiModule::init`] — never from config, see
    /// that method's doc.
    pub virtual_key: String,
    /// Per-request timeout, applied to the whole client's underlying HTTP
    /// client.
    pub timeout: Duration,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("base_url", &self.base_url)
            .field("virtual_key", &crate::mask::mask_secret(&self.virtual_key))
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            base_url: DEFAULT_BASE_URL.to_string(),
            virtual_key: String::new(),
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// The outcome of [`WaddleAiClient::health`].
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HealthResponse {
    /// Server-reported status string (e.g. `"ok"`); not interpreted by this
    /// client — a 2xx response is what [`WaddleAiClient::health`]'s caller
    /// actually treats as "reachable and authorized". Read only by this
    /// module's own tests (asserting the field decodes correctly), never by
    /// production code, hence the explicit allow.
    #[serde(default)]
    #[allow(dead_code)]
    pub status: String,
}

/// One synced Tier-1 denylist snapshot, as returned by
/// [`WaddleAiClient::fetch_denylist`] (`GET /api/v1/hooks/policy`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DenylistResponse {
    /// The denylist patterns themselves, verbatim from the server.
    #[serde(default)]
    pub denylist_patterns: Vec<String>,
    /// Server-reported RFC3339 timestamp for this snapshot, stored in
    /// [`crate::cache::DenylistCache::version`] for display.
    #[serde(default)]
    pub updated_at: String,
}

/// Request body for `POST /api/v1/hooks/evaluate` (§18.1).
#[derive(Debug, Clone, Serialize)]
pub struct EvaluateRequest {
    pub hook_version: &'static str,
    pub ecosystem: String,
    pub event: String,
    pub tool_name: String,
    pub tool_input: Value,
    pub session_id: String,
    pub workspace_path: Option<String>,
    pub occurred_at: String,
}

/// WaddleAI's decision for one forwarded hook event, as returned by
/// [`WaddleAiClient::evaluate_hook_event`] (`POST /api/v1/hooks/evaluate`).
#[derive(Debug, Clone, Deserialize)]
pub struct EvaluateResponse {
    /// `"allow"`, `"deny"`, `"ask"`, or `"redirect"`.
    pub decision: String,
    /// A human-readable reason (nullable in §18.2), surfaced to the caller.
    #[serde(default)]
    pub reason: Option<String>,
    /// Optional matched rule identifier from the server.
    #[serde(default)]
    pub rule_id: Option<Value>,
    /// Server-side evaluation duration in milliseconds.
    #[serde(default)]
    #[allow(dead_code)]
    pub evaluated_in_ms: u64,
    /// Optional target model when `decision == "redirect"`.
    #[serde(default)]
    pub redirect_model: Option<String>,
    /// Optional active skills list when `decision == "redirect"`.
    #[serde(default)]
    pub active_skills: Option<Vec<String>>,
}

/// Request body for `POST /api/v1/hooks/telemetry` (§18.1).
#[derive(Debug, Clone, Serialize)]
pub struct TelemetryRequest {
    pub ecosystem: String,
    pub event: String,
    pub tool_name: String,
    pub session_id: String,
    pub tool_input: Value,
    pub occurred_at: String,
}

/// Response body for `POST /api/v1/hooks/telemetry`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TelemetryResponse {
    #[serde(default)]
    #[allow(dead_code)]
    pub accepted: bool,
}

/// An async client for the WaddleAI agent-hooks API. Holds its own
/// `reqwest::Client` internally (cheap to reuse) — build once, share across
/// calls.
pub struct WaddleAiClient {
    http: reqwest::Client,
    base_url: String,
    virtual_key: String,
}

impl WaddleAiClient {
    /// Builds a client. Fails only if the HTTP/TLS stack can't be
    /// constructed — never touches the network.
    pub fn new(config: Config) -> Result<WaddleAiClient, WaddleAiError> {
        let tls_config = crate::tls::build_tls_config();
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls_config)
            .timeout(config.timeout)
            .build()
            .map_err(|err| WaddleAiError::Setup(err.to_string()))?;

        Ok(WaddleAiClient {
            http,
            base_url: config.base_url.trim_end_matches('/').to_string(),
            virtual_key: config.virtual_key,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// Derives the root `/healthz` URL from `base_url` by stripping a trailing
    /// `/api/v1` prefix if present (`https://waddleai.app/api/v1` ->
    /// `https://waddleai.app/healthz`).
    fn healthz_url(&self) -> String {
        let root = self
            .base_url
            .strip_suffix("/api/v1")
            .unwrap_or(&self.base_url);
        format!("{root}/healthz")
    }

    /// Sends `builder`, adding the `Authorization: Bearer <virtual_key>`
    /// header first, then decodes the body: JSON into `T` on any 2xx
    /// status, otherwise a typed [`WaddleAiError`] carrying the parsed
    /// error body.
    async fn execute<T: DeserializeOwned>(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<T, WaddleAiError> {
        let response = builder
            .bearer_auth(&self.virtual_key)
            .send()
            .await
            .map_err(|err| WaddleAiError::Transport(err.to_string()))?;

        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|err| WaddleAiError::Transport(err.to_string()))?;

        if status.is_success() {
            return serde_json::from_slice(&bytes)
                .map_err(|err| WaddleAiError::Decode(err.to_string()));
        }

        let body = parse_error_body(&bytes);
        let status_code = status.as_u16();
        if status_code == 401 || status_code == 403 {
            return Err(WaddleAiError::Auth {
                status: status_code,
                body,
            });
        }
        Err(WaddleAiError::Status {
            status: status_code,
            body,
        })
    }

    /// A cheap liveness/auth probe: `GET /healthz` at the server root.
    pub async fn health(&self) -> Result<HealthResponse, WaddleAiError> {
        self.execute(self.http.get(self.healthz_url())).await
    }

    /// Fetches the canonical Tier-1 denylist snapshot (`GET /api/v1/hooks/policy`).
    pub async fn fetch_denylist(&self) -> Result<DenylistResponse, WaddleAiError> {
        self.execute(self.http.get(self.url("/hooks/policy"))).await
    }

    /// Forwards one normalized hook event to `POST /api/v1/hooks/evaluate`
    /// and returns WaddleAI's decision.
    pub async fn evaluate_hook_event(
        &self,
        request: &EvaluateRequest,
    ) -> Result<EvaluateResponse, WaddleAiError> {
        self.execute(self.http.post(self.url("/hooks/evaluate")).json(request))
            .await
    }

    /// Sends a fire-and-forget telemetry event to `POST /api/v1/hooks/telemetry`.
    pub async fn send_telemetry(
        &self,
        request: &TelemetryRequest,
    ) -> Result<TelemetryResponse, WaddleAiError> {
        self.execute(self.http.post(self.url("/hooks/telemetry")).json(request))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{MockResponse, MockServer};

    fn config_for(server: &MockServer) -> Config {
        Config {
            base_url: server.base_url.clone(),
            virtual_key: "wa-test-key".to_string(),
            ..Config::default()
        }
    }

    #[test]
    fn default_points_at_the_real_api_with_a_five_second_timeout() {
        let config = Config::default();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert!(config.virtual_key.is_empty());
    }

    #[test]
    fn debug_never_prints_the_virtual_key_unmasked() {
        let config = Config {
            virtual_key: "wa-supersecretvirtualkey".to_string(),
            ..Config::default()
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("supersecretvirtualkey"));
        assert!(rendered.contains("****lkey"));
    }

    #[test]
    fn healthz_url_strips_api_v1_suffix_when_present() {
        let with_v1 = WaddleAiClient::new(Config {
            base_url: "https://waddleai.app/api/v1/".to_string(),
            ..Config::default()
        })
        .expect("build client");
        assert_eq!(with_v1.healthz_url(), "https://waddleai.app/healthz");

        let bare = WaddleAiClient::new(Config {
            base_url: "http://127.0.0.1:8080".to_string(),
            ..Config::default()
        })
        .expect("build client");
        assert_eq!(bare.healthz_url(), "http://127.0.0.1:8080/healthz");
    }

    #[tokio::test]
    async fn health_sends_the_bearer_token_and_decodes_status() {
        let server = MockServer::start().await;
        server
            .respond(
                "GET",
                "/healthz",
                MockResponse::json(200, r#"{"status":"ok"}"#),
            )
            .await;
        let client = WaddleAiClient::new(config_for(&server)).expect("build client");

        let health = client.health().await.expect("health succeeds");
        assert_eq!(health.status, "ok");

        let requests = server.requests().await;
        assert_eq!(
            requests[0].header("authorization"),
            Some("Bearer wa-test-key")
        );

        server.stop().await;
    }

    #[tokio::test]
    async fn health_maps_401_to_auth_error() {
        let server = MockServer::start().await;
        server
            .respond(
                "GET",
                "/healthz",
                MockResponse::json(401, r#"{"error":"invalid virtual key"}"#),
            )
            .await;
        let client = WaddleAiClient::new(config_for(&server)).expect("build client");

        let err = client.health().await.expect_err("401 must be an error");
        assert!(matches!(err, WaddleAiError::Auth { status: 401, .. }));

        server.stop().await;
    }

    #[tokio::test]
    async fn fetch_denylist_decodes_patterns_and_updated_at() {
        let server = MockServer::start().await;
        server
            .respond(
                "GET",
                "/hooks/policy",
                MockResponse::json(
                    200,
                    r#"{"denylist_patterns":[".env*",".git/**"],"updated_at":"2026-11-27T00:00:00Z"}"#,
                ),
            )
            .await;
        let client = WaddleAiClient::new(config_for(&server)).expect("build client");

        let snapshot = client.fetch_denylist().await.expect("fetch succeeds");
        assert_eq!(snapshot.updated_at, "2026-11-27T00:00:00Z");
        assert_eq!(snapshot.denylist_patterns, vec![".env*", ".git/**"]);

        server.stop().await;
    }

    #[tokio::test]
    async fn evaluate_hook_event_sends_v1_contract_and_decodes_null_reason_and_redirect() {
        let server = MockServer::start().await;
        server
            .respond(
                "POST",
                "/hooks/evaluate",
                MockResponse::json(
                    200,
                    r#"{"decision":"redirect","reason":null,"rule_id":"r-1","evaluated_in_ms":4,"redirect_model":"qwen2.5:7b","active_skills":["git-ops"]}"#,
                ),
            )
            .await;
        let client = WaddleAiClient::new(config_for(&server)).expect("build client");

        let req = EvaluateRequest {
            hook_version: "1",
            ecosystem: "claude-code".to_string(),
            event: "pre_tool_use".to_string(),
            tool_name: "Bash".to_string(),
            tool_input: serde_json::json!({"command": "git status"}),
            session_id: "sess-1".to_string(),
            workspace_path: Some("/repo".to_string()),
            occurred_at: "2026-11-27T00:00:00Z".to_string(),
        };
        let decision = client
            .evaluate_hook_event(&req)
            .await
            .expect("evaluate succeeds");
        assert_eq!(decision.decision, "redirect");
        assert_eq!(decision.reason, None);
        assert_eq!(decision.redirect_model.as_deref(), Some("qwen2.5:7b"));
        assert_eq!(
            decision.active_skills.as_deref(),
            Some(&["git-ops".to_string()][..])
        );

        let requests = server.requests().await;
        let body = requests[0].json_body();
        assert_eq!(body["hook_version"], "1");
        assert_eq!(body["ecosystem"], "claude-code");
        assert_eq!(body["event"], "pre_tool_use");
        assert_eq!(body["tool_name"], "Bash");
        assert_eq!(body["tool_input"]["command"], "git status");

        server.stop().await;
    }

    #[tokio::test]
    async fn send_telemetry_posts_to_hooks_telemetry_and_decodes_202() {
        let server = MockServer::start().await;
        server
            .respond(
                "POST",
                "/hooks/telemetry",
                MockResponse::json(202, r#"{"accepted":true}"#),
            )
            .await;
        let client = WaddleAiClient::new(config_for(&server)).expect("build client");

        let req = TelemetryRequest {
            ecosystem: "antigravity".to_string(),
            event: "post_tool_use".to_string(),
            tool_name: "Read".to_string(),
            session_id: "sess-2".to_string(),
            tool_input: serde_json::json!({"file_path": "README.md"}),
            occurred_at: "2026-11-27T00:00:00Z".to_string(),
        };
        let resp = client
            .send_telemetry(&req)
            .await
            .expect("telemetry succeeds");
        assert!(resp.accepted);

        let requests = server.requests().await;
        let body = requests[0].json_body();
        assert_eq!(body["ecosystem"], "antigravity");
        assert_eq!(body["event"], "post_tool_use");
        assert_eq!(body["tool_name"], "Read");

        server.stop().await;
    }

    #[tokio::test]
    async fn transport_error_against_an_unreachable_host_is_reported_as_transport() {
        let unreachable = MockServer::unreachable_base_url().await;
        let client = WaddleAiClient::new(Config {
            base_url: unreachable,
            virtual_key: "wa-test-key".to_string(),
            ..Config::default()
        })
        .expect("build client");

        let err = client.health().await.expect_err("unreachable must fail");
        assert!(matches!(err, WaddleAiError::Transport(_)));
    }
}
