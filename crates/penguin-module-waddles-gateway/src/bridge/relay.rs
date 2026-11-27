//! Dispatches one already-scope-checked [`Operation`] to the module's
//! [`waddles_client::WaddlesClient`] and shapes the result as JSON — the
//! only place in the bridge that ever calls the hub.
//!
//! # The CAT never leaves this function unmasked
//!
//! Every path out of [`relay`] — the success value and the error message
//! alike — is run through [`scrub_value`]/[`scrub_string`] before it
//! returns, substituting [`crate::mask::mask_secret`]'s rendering for any
//! occurrence of the module's live CAT. In the ordinary case this scrubs
//! nothing, because every success path here is built from typed
//! `waddles-client` model fields (never an echoed raw response body), so
//! the CAT — sent only as a request header, never a response field — has no
//! path into a success value at all. The defensive scrub exists for the
//! error path: [`waddles_client::WaddlesError::Status`]/`Auth` can carry
//! an [`waddles_client::ErrorBody::Unparsed`] body, which keeps a
//! non-JSON hub response *verbatim* — if a misbehaving proxy or debug error
//! page ever echoed request headers into its body, that raw text would
//! otherwise flow straight into this bridge's response and logs. See
//! `bridge`'s test module for the end-to-end proof.

use serde_json::{Value, json};

use waddles_client::WaddlesError;
use waddles_client::models::{
    Announcement, BrowserSource, Community, MusicSettings, MusicSettingsUpdate, NewAnnouncement,
};

use crate::bridge::scope::Operation;
use crate::mask::mask_secret;
use crate::module::WaddlesGatewayModule;

/// Everything [`relay`] can fail with — already scrubbed, safe to log or
/// return verbatim.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// The request's `params` didn't carry what this operation needs.
    #[error("invalid params: {0}")]
    InvalidParams(String),
    /// The hub call itself failed (transport, auth, status, decode).
    #[error("hub error: {0}")]
    Hub(String),
}

/// Relays `op` to the hub via `module`'s current client, scrubbing `cat`
/// (the module's live Community Access Token) out of both the success value
/// and any error message before returning either. `module.call(..)` is used
/// for every hub request, so a relayed call counts toward
/// `waddles_gateway_api_requests_total`/`_errors_total` exactly like a CLI command
/// does — one choke point, no separate bookkeeping for the bridge.
pub async fn relay(
    module: &WaddlesGatewayModule,
    cat: &str,
    op: Operation,
    params: &Value,
) -> Result<Value, RelayError> {
    match dispatch(module, op, params).await {
        Ok(value) => Ok(scrub_value(value, cat)),
        Err(RelayError::InvalidParams(message)) => {
            Err(RelayError::InvalidParams(scrub_string(&message, cat)))
        }
        Err(RelayError::Hub(message)) => Err(RelayError::Hub(scrub_string(&message, cat))),
    }
}

async fn dispatch(
    module: &WaddlesGatewayModule,
    op: Operation,
    params: &Value,
) -> Result<Value, RelayError> {
    let client = module.client();
    match op {
        Operation::GetStatus => {
            let communities = module
                .call(client.list_my_communities())
                .await
                .map_err(hub_error)?;
            let rendered: Vec<Value> = communities.iter().map(community_json).collect();
            Ok(json!({ "communities": rendered }))
        }
        Operation::GetMusicSettings => {
            let settings = module
                .call(client.get_music_settings())
                .await
                .map_err(hub_error)?;
            Ok(music_settings_json(&settings))
        }
        Operation::UpdateMusicSettings => {
            let update = music_settings_update_from_params(params)?;
            let settings = module
                .call(client.update_music_settings(&update))
                .await
                .map_err(hub_error)?;
            Ok(music_settings_json(&settings))
        }
        Operation::ListAnnouncements => {
            let status = params.get("status").and_then(Value::as_str);
            let list = module
                .call(client.list_announcements(status))
                .await
                .map_err(hub_error)?;
            let rendered: Vec<Value> = list.announcements.iter().map(announcement_json).collect();
            Ok(json!({ "announcements": rendered }))
        }
        Operation::CreateAnnouncement => {
            let params = AnnouncementParams::from_value(params)?;
            let new_announcement = NewAnnouncement {
                title: &params.title,
                content: &params.content,
                announcement_type: params.announcement_type.as_deref(),
                is_pinned: params.is_pinned,
                status: params.status.as_deref(),
            };
            let announcement = module
                .call(client.create_announcement(&new_announcement))
                .await
                .map_err(hub_error)?;
            Ok(announcement_json(&announcement))
        }
        Operation::ListBrowserSources => {
            let sources = module
                .call(client.list_browser_sources())
                .await
                .map_err(hub_error)?;
            let rendered: Vec<Value> = sources.iter().map(browser_source_json).collect();
            Ok(json!({ "sources": rendered }))
        }
    }
}

fn hub_error(err: WaddlesError) -> RelayError {
    RelayError::Hub(err.to_string())
}

fn community_json(community: &Community) -> Value {
    json!({
        "id": community.id,
        "name": community.name,
        "display_name": community.display_name,
        "role": community.role,
    })
}

fn music_settings_json(settings: &MusicSettings) -> Value {
    json!({
        "default_provider": settings.default_provider,
        "autoplay_enabled": settings.autoplay_enabled,
        "volume_limit": settings.volume_limit,
        "allowed_genres": settings.allowed_genres,
        "blocked_artists": settings.blocked_artists,
        "require_dj_approval": settings.require_dj_approval,
        "is_active": settings.is_active,
    })
}

fn announcement_json(announcement: &Announcement) -> Value {
    json!({
        "id": announcement.id,
        "title": announcement.title,
        "content": announcement.content,
        "status": announcement.status,
        "announcement_type": announcement.announcement_type,
        "is_pinned": announcement.is_pinned,
    })
}

fn browser_source_json(source: &BrowserSource) -> Value {
    json!({
        "source_type": source.source_type,
        "url": source.url,
        "is_active": source.is_active,
    })
}

/// Builds a partial [`MusicSettingsUpdate`] from whichever fields `params`
/// actually names — mirrors `commands::music_settings`'s own flag-driven
/// construction, just reading JSON fields instead of CLI flags.
fn music_settings_update_from_params(params: &Value) -> Result<MusicSettingsUpdate, RelayError> {
    let mut update = MusicSettingsUpdate::default();
    if let Some(value) = params.get("default_provider").and_then(Value::as_str) {
        update.default_provider = Some(value.to_string());
    }
    if let Some(value) = params.get("autoplay_enabled").and_then(Value::as_bool) {
        update.autoplay_enabled = Some(value);
    }
    if let Some(value) = params.get("volume_limit").and_then(Value::as_i64) {
        update.volume_limit = Some(value);
    }
    if let Some(value) = params.get("require_dj_approval").and_then(Value::as_bool) {
        update.require_dj_approval = Some(value);
    }
    if let Some(value) = params.get("is_active").and_then(Value::as_bool) {
        update.is_active = Some(value);
    }
    if let Some(array) = params.get("allowed_genres").and_then(Value::as_array) {
        update.allowed_genres = Some(string_array(array));
    }
    if let Some(array) = params.get("blocked_artists").and_then(Value::as_array) {
        update.blocked_artists = Some(string_array(array));
    }
    Ok(update)
}

fn string_array(values: &[Value]) -> Vec<String> {
    values
        .iter()
        .filter_map(Value::as_str)
        .map(String::from)
        .collect()
}

/// The fields [`Operation::CreateAnnouncement`] needs, pulled out of a raw
/// `params` [`Value`] up front so [`NewAnnouncement`]'s borrowed fields can
/// point at owned, locally-alive `String`s.
#[derive(Debug)]
struct AnnouncementParams {
    title: String,
    content: String,
    announcement_type: Option<String>,
    is_pinned: Option<bool>,
    status: Option<String>,
}

impl AnnouncementParams {
    fn from_value(params: &Value) -> Result<AnnouncementParams, RelayError> {
        let Some(title) = params.get("title").and_then(Value::as_str) else {
            return Err(RelayError::InvalidParams(
                "\"title\" is required".to_string(),
            ));
        };
        let Some(content) = params.get("content").and_then(Value::as_str) else {
            return Err(RelayError::InvalidParams(
                "\"content\" is required".to_string(),
            ));
        };
        Ok(AnnouncementParams {
            title: title.to_string(),
            content: content.to_string(),
            announcement_type: params
                .get("announcement_type")
                .and_then(Value::as_str)
                .map(String::from),
            is_pinned: params.get("is_pinned").and_then(Value::as_bool),
            status: params
                .get("status")
                .and_then(Value::as_str)
                .map(String::from),
        })
    }
}

/// Replaces every occurrence of `secret` inside `input` with
/// [`mask_secret`]'s rendering. A no-op when `secret` is empty — matching an
/// unset CAT — since replacing occurrences of an empty substring would
/// otherwise corrupt every string it touches.
pub fn scrub_string(input: &str, secret: &str) -> String {
    if secret.is_empty() || !input.contains(secret) {
        return input.to_string();
    }
    input.replace(secret, &mask_secret(secret))
}

/// Recursively applies [`scrub_string`] to every string reachable from
/// `value` — the belt to [`relay`]'s typed-fields-only suspenders.
pub fn scrub_value(value: Value, secret: &str) -> Value {
    match value {
        Value::String(text) => Value::String(scrub_string(&text, secret)),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| scrub_value(item, secret))
                .collect(),
        ),
        Value::Object(map) => {
            let mut scrubbed = serde_json::Map::with_capacity(map.len());
            for (key, item) in map {
                scrubbed.insert(key, scrub_value(item, secret));
            }
            Value::Object(scrubbed)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::WaddlesGatewayModule;
    use crate::testutil::{FakeHost, MockHub, MockResponse};
    use penguin_sdk::{Module, SecretStore};
    use std::sync::Arc;

    /// The CAT every `dispatch`/`relay` test below authenticates with —
    /// realistic enough (`wdl_c_` prefix, matching the module's real
    /// tokens) that a scrub-failure would be obvious, not a coincidence of
    /// a short/generic test string.
    const CAT: &str = "wdl_c_supersecrettoken";

    async fn init_module(hub: &MockHub) -> WaddlesGatewayModule {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.secrets.set("cat", CAT.as_bytes()).await.unwrap();
        host.config = serde_json::to_vec(&json!({
            "hub": {"base_url": hub.base_url},
            "community_id": "11111111-1111-4111-8111-111111111111",
        }))
        .unwrap();
        let module = WaddlesGatewayModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");
        module
    }

    #[tokio::test]
    async fn dispatch_get_status_renders_every_community() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/communities/my",
            MockResponse::json(
                200,
                r#"{"communities":[{"id":"11111111-1111-4111-8111-111111111111","name":"c","displayName":"Community","role":"admin"}]}"#,
            ),
        )
        .await;
        let module = init_module(&hub).await;

        let value = dispatch(&module, Operation::GetStatus, &json!({}))
            .await
            .expect("dispatch succeeds");
        assert_eq!(value["communities"][0]["name"], "c");
        assert_eq!(value["communities"][0]["role"], "admin");

        hub.stop().await;
    }

    #[tokio::test]
    async fn dispatch_get_music_settings_renders_the_settings() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/admin/11111111-1111-4111-8111-111111111111/music/settings",
            MockResponse::json(
                200,
                r#"{"settings":{"id":1,"communityId":"11111111-1111-4111-8111-111111111111","defaultProvider":"spotify","autoplayEnabled":true,"volumeLimit":80,"allowedGenres":["pop"],"blockedArtists":[],"requireDjApproval":false,"isActive":true}}"#,
            ),
        )
        .await;
        let module = init_module(&hub).await;

        let value = dispatch(&module, Operation::GetMusicSettings, &json!({}))
            .await
            .expect("dispatch succeeds");
        assert_eq!(value["default_provider"], "spotify");
        assert_eq!(value["volume_limit"], 80);

        hub.stop().await;
    }

    #[tokio::test]
    async fn dispatch_update_music_settings_sends_only_the_named_fields() {
        let hub = MockHub::start().await;
        hub.respond(
            "PUT",
            "/admin/11111111-1111-4111-8111-111111111111/music/settings",
            MockResponse::json(
                200,
                r#"{"settings":{"id":1,"communityId":"11111111-1111-4111-8111-111111111111","defaultProvider":"spotify","autoplayEnabled":true,"volumeLimit":42,"allowedGenres":[],"blockedArtists":[],"requireDjApproval":false,"isActive":true}}"#,
            ),
        )
        .await;
        let module = init_module(&hub).await;

        let value = dispatch(
            &module,
            Operation::UpdateMusicSettings,
            &json!({"volume_limit": 42}),
        )
        .await
        .expect("dispatch succeeds");
        assert_eq!(value["volume_limit"], 42);

        let requests = hub.requests().await;
        let sent = requests[0].json_body();
        assert_eq!(sent["volumeLimit"], 42);
        assert!(sent.get("defaultProvider").is_none());

        hub.stop().await;
    }

    #[tokio::test]
    async fn dispatch_list_announcements_forwards_the_status_filter() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/admin/11111111-1111-4111-8111-111111111111/announcements",
            MockResponse::json(
                200,
                r#"{"data":[{"id":1,"communityId":"11111111-1111-4111-8111-111111111111","title":"t","content":"c","announcementType":"general","status":"draft","isPinned":false}],"pagination":{"page":1,"limit":20,"total":1,"totalPages":1}}"#,
            ),
        )
        .await;
        let module = init_module(&hub).await;

        let value = dispatch(
            &module,
            Operation::ListAnnouncements,
            &json!({"status": "draft"}),
        )
        .await
        .expect("dispatch succeeds");
        assert_eq!(value["announcements"][0]["title"], "t");

        let requests = hub.requests().await;
        assert!(requests[0].path.contains("status=draft"));

        hub.stop().await;
    }

    #[tokio::test]
    async fn dispatch_create_announcement_requires_title_and_content() {
        let hub = MockHub::start().await;
        let module = init_module(&hub).await;

        let err = dispatch(&module, Operation::CreateAnnouncement, &json!({}))
            .await
            .expect_err("missing title/content must fail");
        assert!(matches!(err, RelayError::InvalidParams(_)));

        hub.stop().await;
    }

    #[tokio::test]
    async fn dispatch_create_announcement_posts_the_new_announcement() {
        let hub = MockHub::start().await;
        hub.respond(
            "POST",
            "/admin/11111111-1111-4111-8111-111111111111/announcements",
            MockResponse::json(
                200,
                r#"{"data":{"id":9,"communityId":"11111111-1111-4111-8111-111111111111","title":"Hi","content":"Body","announcementType":"general","status":"draft","isPinned":true}}"#,
            ),
        )
        .await;
        let module = init_module(&hub).await;

        let value = dispatch(
            &module,
            Operation::CreateAnnouncement,
            &json!({"title": "Hi", "content": "Body", "is_pinned": true}),
        )
        .await
        .expect("dispatch succeeds");
        assert_eq!(value["title"], "Hi");
        assert_eq!(value["is_pinned"], true);

        let requests = hub.requests().await;
        let sent = requests[0].json_body();
        assert_eq!(sent["title"], "Hi");
        assert_eq!(sent["is_pinned"], true);

        hub.stop().await;
    }

    #[tokio::test]
    async fn dispatch_list_browser_sources_renders_every_source() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/admin/11111111-1111-4111-8111-111111111111/browser-sources",
            MockResponse::json(
                200,
                r#"{"sources":[{"sourceType":"chat","url":"https://x/chat","token":"tok","isActive":true}]}"#,
            ),
        )
        .await;
        let module = init_module(&hub).await;

        let value = dispatch(&module, Operation::ListBrowserSources, &json!({}))
            .await
            .expect("dispatch succeeds");
        assert_eq!(value["sources"][0]["source_type"], "chat");

        hub.stop().await;
    }

    #[tokio::test]
    async fn dispatch_wraps_a_hub_failure_as_a_hub_error() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/communities/my",
            MockResponse::json(500, r#"{"error":"boom"}"#),
        )
        .await;
        let module = init_module(&hub).await;

        let err = dispatch(&module, Operation::GetStatus, &json!({}))
            .await
            .expect_err("a 500 must surface as a hub error");
        assert!(matches!(err, RelayError::Hub(_)));

        hub.stop().await;
    }

    #[tokio::test]
    async fn relay_scrubs_the_cat_out_of_an_echoed_error_body() {
        let hub = MockHub::start().await;
        // Simulates a misbehaving proxy/debug page echoing the request's
        // Authorization header verbatim into a non-JSON error body — the
        // exact scenario this file's module doc calls out as the reason
        // `scrub_value`/`scrub_string` exist at all.
        hub.respond(
            "GET",
            "/communities/my",
            MockResponse::json(
                502,
                format!("<html>Bad Gateway — Authorization: Bearer {CAT}</html>"),
            ),
        )
        .await;
        let module = init_module(&hub).await;

        let err = relay(&module, CAT, Operation::GetStatus, &json!({}))
            .await
            .expect_err("a 502 must surface as an error");
        let rendered = err.to_string();
        assert!(!rendered.contains(CAT));
        assert!(rendered.contains(&mask_secret(CAT)));

        hub.stop().await;
    }

    #[tokio::test]
    async fn relay_passes_a_successful_value_through_untouched() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/communities/my",
            MockResponse::json(
                200,
                r#"{"communities":[{"id":"11111111-1111-4111-8111-111111111111","name":"c","displayName":"Community","role":"admin"}]}"#,
            ),
        )
        .await;
        let module = init_module(&hub).await;

        let value = relay(&module, CAT, Operation::GetStatus, &json!({}))
            .await
            .expect("relay succeeds");
        assert_eq!(value["communities"][0]["name"], "c");

        hub.stop().await;
    }

    #[test]
    fn scrub_string_masks_every_occurrence() {
        let secret = "wdl_c_supersecrettoken";
        let input = format!("saw header Authorization: Bearer {secret} twice: {secret}");
        let scrubbed = scrub_string(&input, secret);
        assert!(!scrubbed.contains(secret));
        assert!(scrubbed.contains(&mask_secret(secret)));
    }

    #[test]
    fn scrub_string_is_a_no_op_for_an_empty_secret() {
        assert_eq!(scrub_string("hello world", ""), "hello world");
    }

    #[test]
    fn scrub_string_leaves_unrelated_text_untouched() {
        assert_eq!(scrub_string("hello world", "wdl_c_x"), "hello world");
    }

    #[test]
    fn scrub_value_walks_nested_arrays_and_objects() {
        let secret = "wdl_c_deeply_nested_secret";
        let value = json!({
            "outer": { "inner": [secret, "safe", { "leaf": secret }] },
        });
        let scrubbed = scrub_value(value, secret);
        let rendered = scrubbed.to_string();
        assert!(!rendered.contains(secret));
        assert!(rendered.contains("safe"));
    }

    #[test]
    fn announcement_params_requires_title_and_content() {
        let err = AnnouncementParams::from_value(&json!({})).unwrap_err();
        assert!(matches!(err, RelayError::InvalidParams(_)));

        let err = AnnouncementParams::from_value(&json!({"title": "t"})).unwrap_err();
        assert!(matches!(err, RelayError::InvalidParams(_)));

        let params = AnnouncementParams::from_value(&json!({"title": "t", "content": "c"}))
            .expect("minimal params succeed");
        assert_eq!(params.title, "t");
        assert_eq!(params.content, "c");
    }

    #[test]
    fn music_settings_update_from_params_only_sets_named_fields() {
        let update = music_settings_update_from_params(&json!({"volume_limit": 42})).unwrap();
        assert_eq!(update.volume_limit, Some(42));
        assert_eq!(update.autoplay_enabled, None);
        assert_eq!(update.default_provider, None);
    }
}
