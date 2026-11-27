//! Client configuration: which hub, which community, and which credential a
//! [`crate::WaddlebotClient`] uses.

use std::time::Duration;

/// waddlebot's production hub — see `~/.claude/rules/penguintech.md`'s
/// product domain table (`waddlebot` → `waddles.app`). [`Config::default`]
/// points here so a config built with only `community_id`/`cat` overridden
/// talks to the real hub; override `base_url` for local/mock testing.
pub const DEFAULT_BASE_URL: &str = "https://waddles.app/api/v1";

/// Default per-request timeout — matches squawk-client's `doh::DohClient`
/// default.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for [`crate::WaddlesClient`].
#[derive(Debug, Clone)]
pub struct WaddlesConfig {
    /// The hub API's base URL, e.g. `https://waddles.app/api/v1`. A
    /// trailing slash is tolerated — [`crate::WaddlesClient::new`]
    /// normalizes it.
    pub base_url: String,
    /// The community UUID this client acts on. Every admin-scoped endpoint is
    /// namespaced under `/admin/{community_id}/...` (`<cuuid:community_id>`).
    pub community_id: String,
    /// Bearer credential — either a User JWT (for `waddles-social`) or a
    /// Community Access Token (`wdl_c_<hex>`, for `waddles-gateway`), sent as
    /// `Authorization: Bearer <token>` on every request.
    pub token: String,
    /// Per-request timeout, applied to the whole `WaddlesClient`'s
    /// underlying HTTP client.
    pub timeout: Duration,
}

impl Default for WaddlesConfig {
    fn default() -> Self {
        WaddlesConfig {
            base_url: DEFAULT_BASE_URL.to_string(),
            community_id: String::new(),
            token: String::new(),
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// Validates standard 8-4-4-4-12 UUID format (36 ASCII characters).
pub fn is_valid_uuid(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_points_at_the_real_hub_with_a_thirty_second_timeout() {
        let config = WaddlesConfig::default();
        assert_eq!(config.base_url, "https://waddles.app/api/v1");
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert!(config.community_id.is_empty());
        assert!(config.token.is_empty());
    }

    #[test]
    fn uuid_validation_accepts_valid_and_rejects_invalid() {
        assert!(is_valid_uuid("11111111-1111-4111-8111-111111111111"));
        assert!(is_valid_uuid("A1B2C3D4-E5F6-4789-ABCD-0123456789EF"));
        assert!(!is_valid_uuid(""));
        assert!(!is_valid_uuid("42"));
        assert!(!is_valid_uuid("11111111-1111-4111-8111-11111111111g"));
        assert!(!is_valid_uuid("11111111111141118111111111111111"));
    }
}
