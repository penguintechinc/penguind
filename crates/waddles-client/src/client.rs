//! [`WaddlesClient`]: one typed async method per hub endpoint this crate
//! covers.
//!
//! `workflows` and `loyalty` are opaque JSON proxies on the hub side —
//! `workflowController.js`/`loyaltyController.js` forward the request body
//! and response verbatim to their own backing microservices (`workflow-core`,
//! `loyalty`) rather than shaping a hub-owned schema — so those methods
//! take/return [`serde_json::Value`] instead of typed structs.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::config::{WaddlesConfig, is_valid_uuid};
use crate::error::{WaddlesError, parse_error_body};
use crate::models::{
    Announcement, AnnouncementEnvelope, AnnouncementList, BrowserSource, BrowserSourcesResponse,
    CatList, CommunitiesResponse, Community, MessageResponse, MusicProvider,
    MusicProvidersResponse, MusicSettings, MusicSettingsResponse, MusicSettingsUpdate,
    NewAnnouncement, NewCatRequest, NewRadioStation, NewToken, PermissionScope, RadioStation,
    RadioStationList, RadioStationResponse, RegenerateBrowserSourcesRequest, ScopesResponse,
};

/// An async REST client for one community's slice of the waddlebot hub
/// API. Holds its own `reqwest::Client` internally (cheap to reuse), so a
/// `WaddlesClient` is meant to be built once and shared across calls, not
/// rebuilt per request.
pub struct WaddlesClient {
    http: reqwest::Client,
    base_url: String,
    community_id: String,
    token: String,
}

impl WaddlesClient {
    /// Builds a client. Fails only if the HTTP/TLS stack can't be
    /// constructed — never touches the network.
    pub fn new(config: WaddlesConfig) -> Result<WaddlesClient, WaddlesError> {
        let tls_config = crate::tls::build_tls_config();
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls_config)
            .timeout(config.timeout)
            .build()
            .map_err(|err| WaddlesError::Setup(err.to_string()))?;

        Ok(WaddlesClient {
            http,
            base_url: config.base_url.trim_end_matches('/').to_string(),
            community_id: config.community_id,
            token: config.token,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// A `/admin/{community_id}` scoped URL — every admin endpoint this
    /// crate calls is namespaced this way (`<cuuid:community_id>`).
    fn admin_url(&self, suffix: &str) -> Result<String, WaddlesError> {
        if !is_valid_uuid(&self.community_id) {
            return Err(WaddlesError::Setup(
                "invalid community_id: expected non-empty UUID".to_string(),
            ));
        }
        Ok(self.url(&format!("/admin/{}{suffix}", self.community_id)))
    }

    /// Sends `builder`, adding the `Authorization: Bearer <cat>` header
    /// first, then decodes the body: JSON into `T` on any 2xx status,
    /// otherwise a typed [`WaddlesError`] carrying the parsed error body.
    async fn execute<T: DeserializeOwned>(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<T, WaddlesError> {
        let response = builder
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|err| WaddlesError::Transport(err.to_string()))?;

        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|err| WaddlesError::Transport(err.to_string()))?;

        if status.is_success() {
            let value: T = serde_json::from_slice(&bytes)
                .map_err(|err| WaddlesError::Decode(err.to_string()))?;
            return Ok(value);
        }

        let body = parse_error_body(&bytes);
        let status_code = status.as_u16();
        if status_code == 401 || status_code == 403 {
            return Err(WaddlesError::Auth {
                status: status_code,
                body,
            });
        }
        Err(WaddlesError::Status {
            status: status_code,
            body,
        })
    }

    async fn get<T: DeserializeOwned>(&self, url: String) -> Result<T, WaddlesError> {
        let builder = self.http.get(url);
        self.execute(builder).await
    }

    async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        url: String,
        body: &B,
    ) -> Result<T, WaddlesError> {
        let builder = self.http.post(url).json(body);
        self.execute(builder).await
    }

    async fn put_json<B: Serialize, T: DeserializeOwned>(
        &self,
        url: String,
        body: &B,
    ) -> Result<T, WaddlesError> {
        let builder = self.http.put(url).json(body);
        self.execute(builder).await
    }

    async fn delete<T: DeserializeOwned>(&self, url: String) -> Result<T, WaddlesError> {
        let builder = self.http.delete(url);
        self.execute(builder).await
    }

    // ── Communities ──────────────────────────────────────────────────

    /// `GET /communities/my` — communities this CAT/session can act on.
    pub async fn list_my_communities(&self) -> Result<Vec<Community>, WaddlesError> {
        let response: CommunitiesResponse = self.get(self.url("/communities/my")).await?;
        Ok(response.communities)
    }

    // ── Browser sources (OBS overlay URLs) ──────────────────────────

    /// `GET /admin/{community}/browser-sources`
    pub async fn list_browser_sources(&self) -> Result<Vec<BrowserSource>, WaddlesError> {
        let response: BrowserSourcesResponse =
            self.get(self.admin_url("/browser-sources")?).await?;
        Ok(response.sources)
    }

    /// `POST /admin/{community}/browser-sources/regenerate` — `source_type`
    /// of `None` regenerates every source type, matching the hub's own
    /// "no `sourceType` in the body" default. Returns the hub's status
    /// message.
    pub async fn regenerate_browser_sources(
        &self,
        source_type: Option<&str>,
    ) -> Result<String, WaddlesError> {
        let request = RegenerateBrowserSourcesRequest { source_type };
        let response: MessageResponse = self
            .post_json(self.admin_url("/browser-sources/regenerate")?, &request)
            .await?;
        Ok(response.message)
    }

    // ── CAT/token management ─────────────────────────────────────────

    /// `GET /admin/{community}/tokens/scopes` — the permission-scope
    /// catalog CATs can be minted with.
    pub async fn list_scopes(&self) -> Result<Vec<PermissionScope>, WaddlesError> {
        let response: ScopesResponse = self.get(self.admin_url("/tokens/scopes")?).await?;
        Ok(response.scopes)
    }

    /// `GET /admin/{community}/tokens/cats`
    pub async fn list_cats(&self) -> Result<CatList, WaddlesError> {
        self.get(self.admin_url("/tokens/cats")?).await
    }

    /// `POST /admin/{community}/tokens/cats` — mints a new CAT. The
    /// returned [`NewToken::token`] is shown exactly once; the hub only
    /// ever stores its hash afterward.
    pub async fn create_cat(
        &self,
        name: &str,
        scopes: &[String],
        expires_at: Option<&str>,
    ) -> Result<NewToken, WaddlesError> {
        let request = NewCatRequest {
            name,
            scopes,
            expires_at,
        };
        self.post_json(self.admin_url("/tokens/cats")?, &request)
            .await
    }

    /// `DELETE /admin/{community}/tokens/cats/{token_id}`
    pub async fn revoke_cat(&self, token_id: i64) -> Result<String, WaddlesError> {
        let response: MessageResponse = self
            .delete(self.admin_url(&format!("/tokens/cats/{token_id}"))?)
            .await?;
        Ok(response.message)
    }

    /// Rotates a CAT: there is no dedicated rotate endpoint on the hub, so
    /// this is [`Self::revoke_cat`] followed by [`Self::create_cat`] —
    /// two requests, strictly in that order (revoke is awaited before
    /// create is attempted, so a revoke failure never leaves the caller
    /// holding two live tokens for the same purpose).
    pub async fn rotate_cat(
        &self,
        revoke_token_id: i64,
        new_name: &str,
        scopes: &[String],
        expires_at: Option<&str>,
    ) -> Result<NewToken, WaddlesError> {
        self.revoke_cat(revoke_token_id).await?;
        self.create_cat(new_name, scopes, expires_at).await
    }

    // ── Music ─────────────────────────────────────────────────────────

    /// `GET /admin/{community}/music/settings`
    pub async fn get_music_settings(&self) -> Result<MusicSettings, WaddlesError> {
        let response: MusicSettingsResponse = self.get(self.admin_url("/music/settings")?).await?;
        Ok(response.settings)
    }

    /// `PUT /admin/{community}/music/settings`
    pub async fn update_music_settings(
        &self,
        update: &MusicSettingsUpdate,
    ) -> Result<MusicSettings, WaddlesError> {
        let response: MusicSettingsResponse = self
            .put_json(self.admin_url("/music/settings")?, update)
            .await?;
        Ok(response.settings)
    }

    /// `GET /admin/{community}/music/providers`
    pub async fn list_music_providers(&self) -> Result<Vec<MusicProvider>, WaddlesError> {
        let response: MusicProvidersResponse =
            self.get(self.admin_url("/music/providers")?).await?;
        Ok(response.providers)
    }

    /// `DELETE /admin/{community}/music/providers/{provider}`
    pub async fn disconnect_music_provider(&self, provider: &str) -> Result<String, WaddlesError> {
        let response: MessageResponse = self
            .delete(self.admin_url(&format!("/music/providers/{provider}"))?)
            .await?;
        Ok(response.message)
    }

    /// `GET /admin/{community}/music/radio-stations`
    pub async fn list_radio_stations(
        &self,
        page: Option<u32>,
        limit: Option<u32>,
    ) -> Result<RadioStationList, WaddlesError> {
        let mut query_pairs = Vec::new();
        if let Some(page) = page {
            query_pairs.push(("page", page.to_string()));
        }
        if let Some(limit) = limit {
            query_pairs.push(("limit", limit.to_string()));
        }
        let builder = self
            .http
            .get(self.admin_url("/music/radio-stations")?)
            .query(&query_pairs);
        self.execute(builder).await
    }

    /// `POST /admin/{community}/music/radio-stations`
    pub async fn add_radio_station(
        &self,
        station: &NewRadioStation<'_>,
    ) -> Result<RadioStation, WaddlesError> {
        let response: RadioStationResponse = self
            .post_json(self.admin_url("/music/radio-stations")?, station)
            .await?;
        Ok(response.station)
    }

    /// `DELETE /admin/{community}/music/radio-stations/{id}`
    pub async fn remove_radio_station(&self, station_id: i64) -> Result<String, WaddlesError> {
        let response: MessageResponse = self
            .delete(self.admin_url(&format!("/music/radio-stations/{station_id}"))?)
            .await?;
        Ok(response.message)
    }

    // ── Announcements ────────────────────────────────────────────────

    /// `GET /admin/{community}/announcements` — `status` filters to
    /// `draft`/`published`/`archived` when given; omitted lists all.
    pub async fn list_announcements(
        &self,
        status: Option<&str>,
    ) -> Result<AnnouncementList, WaddlesError> {
        let mut query_pairs = Vec::new();
        if let Some(status) = status {
            query_pairs.push(("status", status));
        }
        let builder = self
            .http
            .get(self.admin_url("/announcements")?)
            .query(&query_pairs);
        self.execute(builder).await
    }

    /// `GET /admin/{community}/announcements/{id}`
    pub async fn get_announcement(
        &self,
        announcement_id: i64,
    ) -> Result<Announcement, WaddlesError> {
        let response: AnnouncementEnvelope = self
            .get(self.admin_url(&format!("/announcements/{announcement_id}"))?)
            .await?;
        Ok(response.data)
    }

    /// `POST /admin/{community}/announcements`
    pub async fn create_announcement(
        &self,
        new_announcement: &NewAnnouncement<'_>,
    ) -> Result<Announcement, WaddlesError> {
        let response: AnnouncementEnvelope = self
            .post_json(self.admin_url("/announcements")?, new_announcement)
            .await?;
        Ok(response.data)
    }

    /// `POST /admin/{community}/announcements/{id}/publish`
    pub async fn publish_announcement(
        &self,
        announcement_id: i64,
    ) -> Result<Announcement, WaddlesError> {
        let builder = self
            .http
            .post(self.admin_url(&format!("/announcements/{announcement_id}/publish"))?);
        let response: AnnouncementEnvelope = self.execute(builder).await?;
        Ok(response.data)
    }

    // ── Workflows (opaque JSON proxy) ────────────────────────────────

    /// `GET /admin/{community}/workflows`
    pub async fn list_workflows(&self) -> Result<Value, WaddlesError> {
        self.get(self.admin_url("/workflows")?).await
    }

    /// `GET /admin/{community}/workflows/{id}`
    pub async fn get_workflow(&self, workflow_id: &str) -> Result<Value, WaddlesError> {
        self.get(self.admin_url(&format!("/workflows/{workflow_id}"))?)
            .await
    }

    /// `POST /admin/{community}/workflows`
    pub async fn create_workflow(&self, payload: &Value) -> Result<Value, WaddlesError> {
        self.post_json(self.admin_url("/workflows")?, payload).await
    }

    /// `PUT /admin/{community}/workflows/{id}`
    pub async fn update_workflow(
        &self,
        workflow_id: &str,
        payload: &Value,
    ) -> Result<Value, WaddlesError> {
        self.put_json(
            self.admin_url(&format!("/workflows/{workflow_id}"))?,
            payload,
        )
        .await
    }

    /// `DELETE /admin/{community}/workflows/{id}`
    pub async fn delete_workflow(&self, workflow_id: &str) -> Result<Value, WaddlesError> {
        self.delete(self.admin_url(&format!("/workflows/{workflow_id}"))?)
            .await
    }

    // ── Loyalty (opaque JSON proxy) ──────────────────────────────────

    /// `GET /admin/{community}/loyalty/config`
    pub async fn get_loyalty_config(&self) -> Result<Value, WaddlesError> {
        self.get(self.admin_url("/loyalty/config")?).await
    }

    /// `PUT /admin/{community}/loyalty/config`
    pub async fn update_loyalty_config(&self, payload: &Value) -> Result<Value, WaddlesError> {
        self.put_json(self.admin_url("/loyalty/config")?, payload)
            .await
    }

    /// `PUT /admin/{community}/loyalty/user/{platform_user_id}/balance`
    pub async fn adjust_loyalty_balance(
        &self,
        user_id: &str,
        payload: &Value,
    ) -> Result<Value, WaddlesError> {
        if user_id.is_empty()
            || user_id.contains('/')
            || user_id.contains('\\')
            || user_id.contains('?')
            || user_id.contains('#')
            || user_id == "."
            || user_id == ".."
        {
            return Err(WaddlesError::Setup(
                "invalid user_id: expected non-empty platform user id".to_string(),
            ));
        }
        self.put_json(
            self.admin_url(&format!("/loyalty/user/{user_id}/balance"))?,
            payload,
        )
        .await
    }
}
