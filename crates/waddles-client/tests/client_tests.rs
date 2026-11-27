//! Integration tests for [`WaddlesClient`] against a hand-rolled local
//! mock server — no test ever contacts a real waddlebot hub.

mod mock_http;

use mock_http::{MockResponse, MockServer};
use serde_json::json;
use waddles_client::models::NewAnnouncement;
use waddles_client::{WaddlesClient, WaddlesConfig};

const TEST_COMMUNITY_UUID: &str = "11111111-1111-4111-8111-111111111111";
const OTHER_COMMUNITY_UUID: &str = "22222222-2222-4222-8222-222222222222";

fn config(base_url: &str, community_id: &str, token: &str) -> WaddlesConfig {
    WaddlesConfig {
        base_url: base_url.to_string(),
        community_id: community_id.to_string(),
        token: token.to_string(),
        ..WaddlesConfig::default()
    }
}

#[tokio::test]
async fn list_my_communities_parses_a_typed_response() {
    let server = MockServer::start(vec![MockResponse::json(
        200,
        r#"{"success":true,"communities":[{"id":"11111111-1111-4111-8111-111111111111","name":"waddle-community","displayName":"Waddle Community","description":"desc","logoUrl":null,"platform":"discord","memberCount":523,"role":"admin","joinedAt":"2024-01-15T10:30:00Z"}]}"#,
    )])
    .await;

    let client =
        WaddlesClient::new(config(&server.base_url, TEST_COMMUNITY_UUID, "wdl_c_test")).unwrap();
    let communities = client.list_my_communities().await.unwrap();

    assert_eq!(communities.len(), 1);
    assert_eq!(communities[0].id, TEST_COMMUNITY_UUID);
    assert_eq!(communities[0].display_name, "Waddle Community");
    assert_eq!(communities[0].member_count, 523);
    assert_eq!(communities[0].role, "admin");

    server.stop().await;
}

#[tokio::test]
async fn every_request_carries_the_cat_bearer_header() {
    let server = MockServer::start(vec![MockResponse::json(
        200,
        r#"{"success":true,"communities":[]}"#,
    )])
    .await;

    let client = WaddlesClient::new(config(
        &server.base_url,
        TEST_COMMUNITY_UUID,
        "wdl_c_deadbeef",
    ))
    .unwrap();
    client.list_my_communities().await.unwrap();

    let requests = server.requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer wdl_c_deadbeef")
    );

    server.stop().await;
}

#[tokio::test]
async fn base_url_composition_strips_a_trailing_slash_and_keeps_the_full_path() {
    let server = MockServer::start(vec![MockResponse::json(
        200,
        r#"{"success":true,"sources":[]}"#,
    )])
    .await;
    // A trailing slash on base_url must not produce a doubled slash in the
    // request path.
    let base_url_with_trailing_slash = format!("{}/", server.base_url);

    let client = WaddlesClient::new(config(
        &base_url_with_trailing_slash,
        OTHER_COMMUNITY_UUID,
        "wdl_c_x",
    ))
    .unwrap();
    client.list_browser_sources().await.unwrap();

    let requests = server.requests().await;
    assert_eq!(
        requests[0].path,
        format!("/admin/{OTHER_COMMUNITY_UUID}/browser-sources")
    );

    server.stop().await;
}

#[tokio::test]
async fn create_announcement_round_trips_its_request_body() {
    let server = MockServer::start(vec![MockResponse::json(
        201,
        r#"{"success":true,"data":{"id":9,"communityId":"11111111-1111-4111-8111-111111111111","title":"New Feature","content":"We just launched...","announcementType":"general","status":"draft","isPinned":false,"createdBy":1,"createdByName":"admin","createdAt":"2024-03-01T10:00:00Z","updatedBy":null,"updatedAt":null,"publishedAt":null,"archivedAt":null}}"#,
    )])
    .await;

    let client =
        WaddlesClient::new(config(&server.base_url, TEST_COMMUNITY_UUID, "wdl_c_x")).unwrap();
    let new_announcement = NewAnnouncement {
        title: "New Feature",
        content: "We just launched...",
        announcement_type: Some("general"),
        is_pinned: Some(false),
        status: Some("draft"),
    };
    let announcement = client.create_announcement(&new_announcement).await.unwrap();

    assert_eq!(announcement.id, 9);
    assert_eq!(announcement.title, "New Feature");
    assert_eq!(announcement.status, "draft");

    let requests = server.requests().await;
    assert_eq!(requests[0].method, "POST");
    assert_eq!(
        requests[0].path,
        format!("/admin/{TEST_COMMUNITY_UUID}/announcements")
    );
    assert_eq!(
        requests[0].json_body(),
        json!({
            "title": "New Feature",
            "content": "We just launched...",
            "announcement_type": "general",
            "is_pinned": false,
            "status": "draft",
        })
    );

    server.stop().await;
}

#[tokio::test]
async fn rotate_cat_revokes_then_creates_in_order() {
    let server = MockServer::start(vec![
        MockResponse::json(200, r#"{"message":"CAT revoked"}"#),
        MockResponse::json(
            201,
            r#"{"token":"wdl_c_freshsecret","message":"Store this token securely — it will not be shown again."}"#,
        ),
    ])
    .await;

    let client =
        WaddlesClient::new(config(&server.base_url, TEST_COMMUNITY_UUID, "wdl_c_old")).unwrap();
    let scopes = vec!["music:read".to_string(), "music:write".to_string()];
    let new_token = client
        .rotate_cat(42, "obs-bot", &scopes, None)
        .await
        .unwrap();

    assert_eq!(new_token.token, "wdl_c_freshsecret");

    let requests = server.requests().await;
    assert_eq!(requests.len(), 2, "rotate must issue exactly two requests");
    assert_eq!(requests[0].method, "DELETE");
    assert_eq!(
        requests[0].path,
        format!("/admin/{TEST_COMMUNITY_UUID}/tokens/cats/42")
    );
    assert_eq!(requests[1].method, "POST");
    assert_eq!(
        requests[1].path,
        format!("/admin/{TEST_COMMUNITY_UUID}/tokens/cats")
    );
    assert_eq!(
        requests[1].json_body(),
        json!({"name": "obs-bot", "scopes": ["music:read", "music:write"]})
    );

    server.stop().await;
}

#[tokio::test]
async fn rotate_cat_does_not_create_when_revoke_fails() {
    let server = MockServer::start(vec![MockResponse::json(
        404,
        r#"{"error":"Token not found"}"#,
    )])
    .await;

    let client =
        WaddlesClient::new(config(&server.base_url, TEST_COMMUNITY_UUID, "wdl_c_old")).unwrap();
    let scopes = vec!["music:read".to_string()];
    let err = client
        .rotate_cat(999, "obs-bot", &scopes, None)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        waddles_client::WaddlesError::Status { status: 404, .. }
    ));
    assert_eq!(
        server.requests().await.len(),
        1,
        "create must never be attempted once revoke fails"
    );

    server.stop().await;
}

#[tokio::test]
async fn list_radio_stations_sends_page_and_limit_as_query_params() {
    let server = MockServer::start(vec![MockResponse::json(
        200,
        r#"{"success":true,"pagination":{"page":2,"limit":10,"total":25,"pages":3},"stations":[]}"#,
    )])
    .await;

    let client =
        WaddlesClient::new(config(&server.base_url, TEST_COMMUNITY_UUID, "wdl_c_x")).unwrap();
    let list = client.list_radio_stations(Some(2), Some(10)).await.unwrap();

    assert_eq!(list.pagination.page, 2);
    assert_eq!(list.pagination.pages, 3);

    let requests = server.requests().await;
    assert_eq!(
        requests[0].path,
        format!("/admin/{TEST_COMMUNITY_UUID}/music/radio-stations?page=2&limit=10")
    );

    server.stop().await;
}

#[tokio::test]
async fn workflows_and_loyalty_round_trip_opaque_json() {
    let server = MockServer::start(vec![
        MockResponse::json(
            200,
            r#"{"anything":"the workflow-core service decides", "nested": {"a": 1}}"#,
        ),
        MockResponse::json(200, r#"{"balance":250}"#),
    ])
    .await;

    let client =
        WaddlesClient::new(config(&server.base_url, TEST_COMMUNITY_UUID, "wdl_c_x")).unwrap();
    let value = client.list_workflows().await.unwrap();

    assert_eq!(value["anything"], "the workflow-core service decides");
    assert_eq!(value["nested"]["a"], 1);

    let adjusted = client
        .adjust_loyalty_balance("discord_user_42", &json!({"delta": 50}))
        .await
        .unwrap();
    assert_eq!(adjusted["balance"], 250);

    let requests = server.requests().await;
    assert_eq!(
        requests[1].path,
        format!("/admin/{TEST_COMMUNITY_UUID}/loyalty/user/discord_user_42/balance")
    );

    server.stop().await;
}

#[tokio::test]
async fn invalid_community_uuid_and_user_id_fail_before_network() {
    let client = WaddlesClient::new(config(
        "https://waddles.app/api/v1",
        "not-a-uuid",
        "wdl_c_x",
    ))
    .unwrap();
    let err = client.list_browser_sources().await.unwrap_err();
    assert!(matches!(err, waddles_client::WaddlesError::Setup(_)));

    let valid_client = WaddlesClient::new(config(
        "https://waddles.app/api/v1",
        TEST_COMMUNITY_UUID,
        "wdl_c_x",
    ))
    .unwrap();
    let err = valid_client
        .adjust_loyalty_balance("../bad", &json!({"delta": 1}))
        .await
        .unwrap_err();
    assert!(matches!(err, waddles_client::WaddlesError::Setup(_)));
}
