//! Typed request/response bodies for the endpoints [`crate::client`]
//! implements.
//!
//! A response struct only ever names the fields this crate actually reads.
//! serde ignores unmatched JSON keys by default (no `deny_unknown_fields`
//! anywhere here), so a struct like [`CommunitiesResponse`] happily
//! deserializes a `{"success": true, "communities": [...]}` body without
//! needing a field for `success` — the envelope structs below lean on that
//! deliberately, to avoid a `#[serde(default)]`/dead-field pair per
//! endpoint for a value nothing ever reads.
//!
//! Field casing follows the hub's actual JSON, not a blanket convention:
//! most controllers hand-map their SQL rows to camelCase before calling
//! `res.json`, but `tokenController.js` (`listCATs`, `listScopes`) returns
//! raw `SELECT` column aliases — already snake_case — verbatim. Each struct
//! below is cased to match its specific endpoint, confirmed against the
//! controller source, not assumed.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Communities ──────────────────────────────────────────────────────

/// One community `GET /communities/my` reports the caller as a member of.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Community {
    pub id: String,
    pub name: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub logo_url: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub member_count: i64,
    pub role: String,
    #[serde(default)]
    pub joined_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CommunitiesResponse {
    #[serde(default)]
    pub(crate) communities: Vec<Community>,
}

// ── Browser sources (OBS overlay URLs) ──────────────────────────────

/// One OBS browser-source URL, from `GET /admin/{community}/browser-sources`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserSource {
    pub source_type: String,
    pub url: String,
    pub token: String,
    pub is_active: bool,
    #[serde(default)]
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct BrowserSourcesResponse {
    #[serde(default)]
    pub(crate) sources: Vec<BrowserSource>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub(crate) struct RegenerateBrowserSourcesRequest<'a> {
    #[serde(rename = "sourceType", skip_serializing_if = "Option::is_none")]
    pub(crate) source_type: Option<&'a str>,
}

// ── Generic message envelope ─────────────────────────────────────────

/// The `{"message": "..."}` shape several write endpoints answer with
/// (CAT revoke, provider disconnect, radio station removal, browser-source
/// regenerate).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MessageResponse {
    #[serde(default)]
    pub(crate) message: String,
}

// ── CAT/token management ─────────────────────────────────────────────

/// A permission scope from the catalog (`GET /admin/{community}/tokens/scopes`).
/// Field names match `tokenController.js`'s raw `SELECT` column aliases —
/// this response is not camelCased like most others.
#[derive(Debug, Clone, Deserialize)]
pub struct PermissionScope {
    pub scope_key: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ScopesResponse {
    #[serde(default)]
    pub(crate) scopes: Vec<PermissionScope>,
}

/// A Community Access Token's metadata (never the plaintext secret — that's
/// only ever returned once, by [`NewToken`]). Field names match
/// `listCATs`'s raw `SELECT` aliases, same caveat as [`PermissionScope`].
#[derive(Debug, Clone, Deserialize)]
pub struct Cat {
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    pub is_revoked: bool,
    #[serde(default)]
    pub created_by_name: Option<String>,
}

/// `GET /admin/{community}/tokens/cats` — unlike most list endpoints this
/// has no `success`/wrapper key at all; `tokens`/`quota`/`used` are the
/// top-level response body.
#[derive(Debug, Clone, Deserialize)]
pub struct CatList {
    pub tokens: Vec<Cat>,
    pub quota: i64,
    pub used: i64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NewCatRequest<'a> {
    pub(crate) name: &'a str,
    pub(crate) scopes: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expires_at: Option<&'a str>,
}

/// The plaintext CAT secret from `POST /admin/{community}/tokens/cats` —
/// shown exactly once; the hub only ever stores its hash afterward.
#[derive(Debug, Clone, Deserialize)]
pub struct NewToken {
    pub token: String,
    #[serde(default)]
    pub message: String,
}

// ── Music ─────────────────────────────────────────────────────────────

/// A community's music module settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MusicSettings {
    pub id: i64,
    pub community_id: String,
    #[serde(default)]
    pub default_provider: Option<String>,
    pub autoplay_enabled: bool,
    pub volume_limit: i64,
    #[serde(default)]
    pub allowed_genres: Vec<String>,
    #[serde(default)]
    pub blocked_artists: Vec<String>,
    pub require_dj_approval: bool,
    pub is_active: bool,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MusicSettingsResponse {
    pub(crate) settings: MusicSettings,
}

/// A partial update to a community's music settings — every field is
/// optional, matching `updateMusicSettings`'s "only touch what's present"
/// behavior.
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MusicSettingsUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autoplay_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_genres: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_artists: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_dj_approval: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
}

/// One connected (or previously connected) music provider.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MusicProvider {
    pub id: i64,
    pub community_id: i64,
    pub provider_name: String,
    pub is_connected: bool,
    pub is_active: bool,
    #[serde(default)]
    pub oauth_expires_at: Option<String>,
    #[serde(default)]
    pub last_sync: Option<String>,
    #[serde(default)]
    pub config: Value,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MusicProvidersResponse {
    #[serde(default)]
    pub(crate) providers: Vec<MusicProvider>,
}

/// A radio station entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RadioStation {
    pub id: i64,
    pub community_id: String,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub genre: Option<String>,
    pub is_active: bool,
    #[serde(default)]
    pub created_by: Option<i64>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Pagination metadata as `getRadioStations` shapes it: `pages`, not
/// `totalPages` — see [`AnnouncementPagination`] for the announcements
/// endpoint's different field name for the same concept.
#[derive(Debug, Clone, Deserialize)]
pub struct RadioStationPagination {
    pub page: i64,
    pub limit: i64,
    pub total: i64,
    pub pages: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RadioStationList {
    pub pagination: RadioStationPagination,
    #[serde(default)]
    pub stations: Vec<RadioStation>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct NewRadioStation<'a> {
    pub name: &'a str,
    pub url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genre: Option<&'a str>,
    #[serde(rename = "isActive", skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RadioStationResponse {
    pub(crate) station: RadioStation,
}

// ── Announcements ────────────────────────────────────────────────────

/// A community announcement, from `formatAnnouncement`'s field set.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Announcement {
    pub id: i64,
    pub community_id: String,
    pub title: String,
    pub content: String,
    pub announcement_type: String,
    pub status: String,
    pub is_pinned: bool,
    #[serde(default)]
    pub created_by: Option<i64>,
    #[serde(default)]
    pub created_by_name: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_by: Option<i64>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub published_at: Option<String>,
    #[serde(default)]
    pub archived_at: Option<String>,
}

/// Pagination metadata as `getAnnouncements` shapes it: `totalPages`, not
/// `pages` — see [`RadioStationPagination`]'s doc comment.
#[derive(Debug, Clone, Deserialize)]
pub struct AnnouncementPagination {
    pub page: i64,
    pub limit: i64,
    pub total: i64,
    #[serde(rename = "totalPages")]
    pub total_pages: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnnouncementList {
    #[serde(rename = "data", default)]
    pub announcements: Vec<Announcement>,
    pub pagination: AnnouncementPagination,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AnnouncementEnvelope {
    pub(crate) data: Announcement,
}

/// A new announcement. Request-body field names are snake_case here — the
/// one write endpoint in this crate where the hub's request casing doesn't
/// match its response casing (`createAnnouncement` destructures
/// `announcement_type`/`is_pinned` from `req.body`, but `formatAnnouncement`
/// answers back with `announcementType`/`isPinned`).
#[derive(Debug, Clone, Serialize, Default)]
pub struct NewAnnouncement<'a> {
    pub title: &'a str,
    pub content: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announcement_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_pinned: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<&'a str>,
}
