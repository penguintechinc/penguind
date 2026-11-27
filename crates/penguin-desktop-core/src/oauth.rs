//! OAuth flow helpers: building authorize URLs and handling callbacks.
//!
//! This module provides the state/token-exchange logic for OAuth flows. It does
//! NOT handle browser open or `waddles://` deep-link capture — those are GUI
//! concerns for the Tauri shell (Phase 2b).
//!
//! Expected flow:
//! 1. Call `start_oauth(platform)` to get an authorize URL and state.
//! 2. Tauri shell opens the browser to that URL.
//! 3. Hub redirects to `waddles://oauth/callback?token=<jwt>&state=<state>`.
//! 4. Tauri shell's deep-link handler calls `complete_oauth(callback_params)`.
//! 5. Tokens are extracted, validated, and returned for keychain storage.

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::error::{DesktopError, Result};

/// OAuth platforms supported by the hub.
#[derive(Clone, Copy, Debug)]
pub enum OAuthPlatform {
    Google,
    GitHub,
    Discord,
}

impl OAuthPlatform {
    /// The OAuth provider name as used in hub API paths.
    pub fn as_str(&self) -> &'static str {
        match self {
            OAuthPlatform::Google => "google",
            OAuthPlatform::GitHub => "github",
            OAuthPlatform::Discord => "discord",
        }
    }
}

/// The desktop OAuth deep-link redirect URI allowlisted by Waddles `hub-api`.
pub const DESKTOP_REDIRECT_URI: &str = "waddles://oauth/callback";

/// Parsed parameters from a `waddles://oauth/callback` deep-link URL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthCallback {
    /// Single-use exchange code (redeemed via `POST /api/v1/auth/exchange`).
    pub code: Option<String>,
    /// Legacy direct JWT parameter, if present.
    pub token: Option<String>,
    /// The state parameter echoed back by the hub.
    pub state: String,
}
/// Legacy parameters extracted from `waddles://oauth/callback?token=...&state=...`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallbackParams {
    /// The JWT issued by the hub (should contain `access_token`/`refresh_token`).
    pub token: String,
    /// The state parameter (should match what was returned by `start_oauth`).
    pub state: String,
}

/// State + metadata returned by `start_oauth()`, to be stored until the
/// callback is received.
#[derive(Clone, Debug, Serialize)]
pub struct OAuthContext {
    /// The state parameter sent to the hub, which must be echoed back.
    pub state: String,
    /// The platform we're authenticating with (for logging/UI).
    pub platform: String,
}

/// Builds the hub authorize URL for a given OAuth platform.
///
/// The hub's `/api/v1/auth/oauth/{platform}` endpoint returns a redirect to the
/// provider's consent form. The Tauri shell opens the browser to that URL, and
/// after consent, the provider redirects back to a hub callback which then
/// redirects to `waddles://oauth/callback?token=...&state=...`.
/// Generates a cryptographically secure random state parameter for OAuth flow.
/// Uses OS RNG to generate ≥128 bits of entropy, then base64url-encodes.
/// **SECURITY**: Uses OS-provided cryptographic RNG to prevent CSRF attacks.
pub fn generate_oauth_state() -> Result<String> {
    let mut state_bytes = [0u8; 32]; // 256 bits of entropy

    // Use getrandom to fill from OS entropy source
    getrandom::getrandom(&mut state_bytes)
        .map_err(|e| DesktopError::Internal(format!("RNG error: {}", e)))?;

    // Base64url encode without padding
    let state = base64_url::encode(&state_bytes);

    debug!("generated OAuth state (256-bit entropy)");
    Ok(state)
}

/// Compares two state values using constant-time equality to prevent timing attacks.
/// Returns true only if both states are identical.
pub fn verify_oauth_state(callback_state: &str, stored_state: &str) -> bool {
    use subtle::ConstantTimeEq;

    callback_state
        .as_bytes()
        .ct_eq(stored_state.as_bytes())
        .into()
}

pub fn start_oauth(hub_base_url: &str, platform: OAuthPlatform) -> Result<(String, OAuthContext)> {
    // Validate the hub URL.
    let hub_url = url::Url::parse(hub_base_url)
        .map_err(|e| DesktopError::UrlError(format!("invalid hub URL: {}", e)))?;

    // Generate a cryptographically secure state parameter (256-bit entropy, base64url-encoded)
    let state = generate_oauth_state()?;

    // Build the authorize endpoint with redirect_uri=waddles://oauth/callback and state.
    let mut authorize_url = hub_url
        .join(&format!("/api/v1/auth/oauth/{}", platform.as_str()))
        .map_err(|e| DesktopError::UrlError(format!("failed to build authorize URL: {}", e)))?;

    authorize_url
        .query_pairs_mut()
        .append_pair("redirect_uri", DESKTOP_REDIRECT_URI)
        .append_pair("state", &state);

    let authorize_url_with_state = authorize_url.to_string();

    debug!(platform = platform.as_str(), "OAuth authorize URL built");

    let context = OAuthContext {
        state: state.clone(),
        platform: platform.as_str().to_string(),
    };

    Ok((authorize_url_with_state, context))
}

/// Parses a `waddles://oauth/callback?code=...&state=...` deep-link URL.
/// Rejects any URL that does not match scheme `waddles`, host `oauth`, path `/callback`.
pub fn parse_callback_url(callback_url: &str) -> Result<OAuthCallback> {
    let parsed = url::Url::parse(callback_url)
        .map_err(|e| DesktopError::InvalidCallback(format!("invalid callback URL: {e}")))?;

    if parsed.scheme() != "waddles"
        || parsed.host_str() != Some("oauth")
        || parsed.path() != "/callback"
    {
        return Err(DesktopError::InvalidCallback(
            "callback URL must use waddles://oauth/callback".to_string(),
        ));
    }

    let mut code: Option<String> = None;
    let mut token: Option<String> = None;
    let mut state: Option<String> = None;
    let mut error: Option<String> = None;

    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "code" if !v.is_empty() => code = Some(v.into_owned()),
            "token" if !v.is_empty() => token = Some(v.into_owned()),
            "state" if !v.is_empty() => state = Some(v.into_owned()),
            "error" if !v.is_empty() => error = Some(v.into_owned()),
            _ => {}
        }
    }

    if let Some(err) = error {
        return Err(DesktopError::OAuthError(format!(
            "oauth callback error: {err}"
        )));
    }

    let state = state.ok_or_else(|| {
        DesktopError::InvalidCallback("missing state parameter in OAuth callback".to_string())
    })?;

    if code.is_none() && token.is_none() {
        return Err(DesktopError::InvalidCallback(
            "missing code or token parameter in OAuth callback".to_string(),
        ));
    }

    Ok(OAuthCallback { code, token, state })
}

/// Redeems a single-use OAuth exchange `code` at `POST {hub_base_url}/api/v1/auth/exchange`
/// after constant-time `state` verification.
pub async fn exchange_oauth_code(
    hub_base_url: &str,
    code: &str,
    callback_state: &str,
    stored_state: &str,
) -> Result<OAuthTokens> {
    if !verify_oauth_state(callback_state, stored_state) {
        return Err(DesktopError::InvalidCallback(
            "state mismatch (CSRF or forged callback)".to_string(),
        ));
    }
    if code.trim().is_empty() {
        return Err(DesktopError::InvalidCallback(
            "missing OAuth exchange code".to_string(),
        ));
    }

    let hub_url = url::Url::parse(hub_base_url)
        .map_err(|e| DesktopError::UrlError(format!("invalid hub URL: {e}")))?;
    let exchange_url = hub_url
        .join("/api/v1/auth/exchange")
        .map_err(|e| DesktopError::UrlError(format!("failed to build exchange URL: {e}")))?;

    let client = reqwest::Client::new();
    let response = client
        .post(exchange_url)
        .json(&serde_json::json!({ "code": code }))
        .send()
        .await
        .map_err(|e| DesktopError::OAuthError(format!("OAuth exchange request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(DesktopError::OAuthError(format!(
            "OAuth exchange failed with status {}",
            response.status()
        )));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| DesktopError::OAuthError(format!("invalid OAuth exchange JSON: {e}")))?;

    let access_token = body
        .get("token")
        .or_else(|| body.get("access_token"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            DesktopError::OAuthError("no token in OAuth exchange response".to_string())
        })?;

    let refresh_token = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    Ok(OAuthTokens {
        access_token,
        refresh_token,
    })
}

/// Processes an OAuth callback from the `waddles://` deep-link.
///
/// Validates the state parameter and extracts tokens from the JWT. The tokens
/// should then be stored in the keychain and primed in penguind.
pub fn complete_oauth(params: CallbackParams, stored_state: &str) -> Result<OAuthTokens> {
    // Validate state parameter using constant-time comparison to prevent timing attacks.
    if !verify_oauth_state(&params.state, stored_state) {
        return Err(DesktopError::InvalidCallback(
            "state mismatch (CSRF or forged callback)".to_string(),
        ));
    }

    // Parse the JWT to extract tokens. Since the hub issued this JWT and we're
    // just reading it (not authenticating it), we skip signature verification.
    let tokens = extract_tokens_from_jwt(&params.token)?;

    debug!("OAuth callback processed, tokens extracted");

    Ok(tokens)
}

/// Tokens extracted from the OAuth JWT response.
#[derive(Clone, Debug)]
pub struct OAuthTokens {
    /// The access token (Bearer credential for API calls).
    pub access_token: String,
    /// Optional refresh token (if the hub issued one).
    pub refresh_token: Option<String>,
}

/// Extracts access_token and refresh_token from a JWT without verifying the signature.
///
/// **SECURITY NOTE**: This decodes JWT claims WITHOUT signature verification. This is safe
/// only when:
///
/// 1. Called on our own stored tokens (to extract expiry for refresh scheduling), OR
/// 2. Called on OAuth callback tokens where state validation provides CSRF protection.
///
/// KNOWN LIMITATION: The OAuth callback flow accepts an unverified JWT from the hub's
/// redirect URL. This is mitigated by:
///
/// - Constant-time state validation (prevents unsolicited callback injection)
/// - Deep-link redirect to local OS handler (no network MITM)
///
/// TODO(security): Hub must add PKCE code-exchange or JWKS endpoint for proper verification.
/// Until then, state guard is the anti-injection mitigation (tracked separately).
fn extract_tokens_from_jwt(jwt: &str) -> Result<OAuthTokens> {
    // Decode claims WITHOUT signature verification. Use dangerous::insecure_decode to be
    // explicit that we are intentionally reading unverified claims. This is acceptable
    // because: (1) state validation provides CSRF protection, (2) the token is read only
    // after the state check passes, and (3) we cannot verify without hub-provided JWKS.
    let token_data = jsonwebtoken::dangerous::insecure_decode::<serde_json::Value>(jwt)
        .map_err(|e| DesktopError::OAuthError(format!("failed to decode JWT: {}", e)))?;

    let claims = &token_data.claims;

    // Extract access_token (should be in the "sub" or a custom claim).
    let access_token = claims
        .get("access_token")
        .or_else(|| claims.get("token"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| DesktopError::OAuthError("access_token not found in JWT".to_string()))?
        .to_string();

    // Extract refresh_token if present.
    let refresh_token = claims
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(OAuthTokens {
        access_token,
        refresh_token,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_platform_as_str() {
        assert_eq!(OAuthPlatform::Google.as_str(), "google");
        assert_eq!(OAuthPlatform::GitHub.as_str(), "github");
        assert_eq!(OAuthPlatform::Discord.as_str(), "discord");
    }

    #[test]
    fn test_start_oauth_valid_hub_url() {
        let hub_url = "https://hub.example.com";

        let (url, context) = start_oauth(hub_url, OAuthPlatform::Google).unwrap();

        assert!(url.contains("/api/v1/auth/oauth/google"));
        assert!(url.contains("state="));
        assert!(!context.state.is_empty());
        assert_eq!(context.platform, "google");
    }

    #[test]
    fn test_start_oauth_invalid_hub_url() {
        let result = start_oauth("not a url", OAuthPlatform::Google);
        assert!(result.is_err());
    }

    #[test]
    fn test_oauth_state_generated_and_different() {
        // Verify CSPRNG generates different states each time
        let state1 = generate_oauth_state().unwrap();
        let state2 = generate_oauth_state().unwrap();

        assert_ne!(state1, state2);
        assert!(!state1.is_empty());
        assert!(!state2.is_empty());
    }

    #[test]
    fn test_verify_oauth_state_constant_time() {
        let state = "test_state_value";

        // Should match
        assert!(verify_oauth_state(state, state));

        // Should not match
        assert!(!verify_oauth_state("other_state", state));
        assert!(!verify_oauth_state(state, "other_state"));
        assert!(!verify_oauth_state("", state));
    }

    #[test]
    fn test_complete_oauth_state_mismatch() {
        let params = CallbackParams {
            token: "fake_jwt".to_string(),
            state: "wrong_state".to_string(),
        };

        let result = complete_oauth(params, "expected_state");
        assert!(result.is_err());
    }

    #[test]
    fn test_oauth_tokens_structure() {
        let tokens = OAuthTokens {
            access_token: "access_token_123".to_string(),
            refresh_token: Some("refresh_token_456".to_string()),
        };

        assert_eq!(tokens.access_token, "access_token_123");
        assert_eq!(tokens.refresh_token, Some("refresh_token_456".to_string()));
    }

    #[test]
    fn test_oauth_tokens_no_refresh() {
        let tokens = OAuthTokens {
            access_token: "access_token_789".to_string(),
            refresh_token: None,
        };

        assert_eq!(tokens.access_token, "access_token_789");
        assert_eq!(tokens.refresh_token, None);
    }

    #[test]
    fn test_oauth_context_clone() {
        let context = OAuthContext {
            state: "state_xyz".to_string(),
            platform: "github".to_string(),
        };

        let cloned = context.clone();
        assert_eq!(cloned.state, context.state);
        assert_eq!(cloned.platform, context.platform);
    }

    #[test]
    fn test_callback_params_clone() {
        let params = CallbackParams {
            token: "token_abc".to_string(),
            state: "state_def".to_string(),
        };

        let cloned = params.clone();
        assert_eq!(cloned.token, params.token);
        assert_eq!(cloned.state, params.state);
    }

    #[test]
    fn test_start_oauth_url_encoding() {
        let hub_url = "https://hub.example.com";

        let (url, _context) = start_oauth(hub_url, OAuthPlatform::Google).unwrap();

        // State should be present and URL-encoded in the URL
        assert!(url.contains("state="));
        assert!(url.contains("redirect_uri=waddles%3A%2F%2Foauth%2Fcallback"));
        // CSPRNG-generated state should be base64url-encoded, which contains only safe chars
        // but urlencoding::encode may still encode it; verify it's in the URL
        assert!(!_context.state.is_empty());
    }

    #[test]
    fn test_parse_callback_url_code_and_state() {
        let cb = parse_callback_url("waddles://oauth/callback?code=exch_123&state=st_abc").unwrap();
        assert_eq!(cb.code.as_deref(), Some("exch_123"));
        assert_eq!(cb.token, None);
        assert_eq!(cb.state, "st_abc");
    }

    #[test]
    fn test_parse_callback_url_rejects_wrong_scheme_or_missing_fields() {
        assert!(parse_callback_url("https://evil.com/oauth/callback?code=1&state=2").is_err());
        assert!(parse_callback_url("waddles://other/callback?code=1&state=2").is_err());
        assert!(parse_callback_url("waddles://oauth/callback?code=1").is_err());
        assert!(parse_callback_url("waddles://oauth/callback?state=2").is_err());
        assert!(
            parse_callback_url("waddles://oauth/callback?error=access_denied&state=2").is_err()
        );
    }

    #[tokio::test]
    async fn test_exchange_oauth_code_posts_to_auth_exchange() {
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/exchange"))
            .and(body_json(serde_json::json!({ "code": "exch_xyz" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "token": "jwt_session_token"
            })))
            .mount(&server)
            .await;

        let tokens = exchange_oauth_code(&server.uri(), "exch_xyz", "st_1", "st_1")
            .await
            .expect("exchange succeeds");
        assert_eq!(tokens.access_token, "jwt_session_token");
        assert_eq!(tokens.refresh_token, None);

        let err = exchange_oauth_code(&server.uri(), "exch_xyz", "bad_state", "st_1")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("state mismatch"));
    }
}
