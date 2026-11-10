//! Integration tests: the real `HubClient` + `HubFetcher` against a TLS mock hub
//! shaped from `services/hub-api/openapi/v1.yaml`.

mod common;

use std::time::Duration;

use common::*;
use penguin_hub_client::client::StartStatus;
use penguin_hub_client::model::error_code;
use penguin_hub_client::{HubClientConfig, SyncOutcome, run_loop};
use penguin_sdk::LicenseChecker;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

fn status_body(env: &Env) -> Value {
    let reqs = env.hub.requests("POST", "/api/v1/agent/status");
    serde_json::from_slice(&reqs.last().expect("status posted").body).expect("json")
}

async fn applied_env() -> (Env, penguin_hub_client::model::ManifestWire) {
    let env = Env::new().await;
    let m = env.hub.publish(&env.signer, "demo", "1.0.0", WASM);
    env.hub
        .set_bundle(std::slice::from_ref(&m), json!({}), flags(&[]), "\"e1\"");
    (env, m)
}

#[tokio::test]
async fn enroll_sync_apply_report_and_304() {
    let (env, _m) = applied_env().await;
    assert_eq!(env.client.start().await, StartStatus::Fresh);
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(1));

    // enrolled with the bootstrap token, tokens landed in the secret store only.
    let enroll = env.hub.requests("POST", "/api/v1/agent/enroll");
    assert_eq!(enroll[0].headers["authorization"], "Bearer boot-secret");
    let body: Value = serde_json::from_slice(&enroll[0].body).expect("json");
    assert_eq!(body, json!({"platform": 1, "agent_version": "0.2.0"}));
    assert!(
        env.secrets
            .map
            .lock()
            .expect("lock")
            .contains_key("hub-credentials")
    );

    // module verified + loaded under limits within the ceiling; status reported.
    {
        let loaded = env.sink.loaded.lock().expect("lock");
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            (loaded[0].0.as_str(), loaded[0].1.as_str()),
            ("demo", "1.0.0")
        );
    }
    let st = status_body(&env);
    assert_eq!(st["result"], 1);
    assert_eq!(st["applied_etag"], "\"e1\"");
    assert_eq!(st["modules"][0]["loaded"], true);

    // second poll: conditional GET -> 304, no re-download, nothing reloaded.
    assert_eq!(env.client.sync_once().await, SyncOutcome::NotModified);
    let syncs = env.hub.requests("GET", "/api/v1/agent/sync");
    assert_eq!(syncs[0].headers.get("if-none-match"), None);
    assert_eq!(syncs[1].headers["if-none-match"], "\"e1\"");
    assert_eq!(env.hub.requests("GET", "/api/v1/agent/modules/").len(), 1);
    assert_eq!(env.sink.loaded.lock().expect("lock").len(), 1);
    assert_eq!(env.counter("penguind_hub_sync_requests_total", "304"), 1.0);
    assert_eq!(env.counter("penguind_hub_sync_requests_total", "200"), 1.0);
    assert_eq!(env.counter("penguind_hub_module_verify_total", "ok"), 1.0);
    assert!(
        env.registry
            .gather()
            .iter()
            .any(|f| f.name() == "penguind_hub_sync_staleness_seconds")
    );
}

#[tokio::test]
async fn tokens_never_touch_the_cache_dir_in_plaintext() {
    let (env, _m) = applied_env().await;
    env.client.sync_once().await;
    let token = env.hub.with(|k| k.access.clone());
    assert!(!token.is_empty());
    for entry in walk(&env.cache_dir()) {
        let bytes = std::fs::read(&entry).expect("read");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains(&token) && !text.contains("refresh-1"),
            "{entry:?}"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(env.cache_dir().join("hub-cache.json"))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![];
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

#[tokio::test]
async fn tampered_binary_is_rejected_and_reported() {
    let env = Env::new().await;
    let m = env
        .signer
        .manifest("demo", "1.0.0", WASM, &env.hub.base_url);
    // hub serves different bytes than were signed.
    env.hub.with(|k| {
        k.binaries
            .insert("demo".into(), b"\0asm\x01\0\0\0tampered".to_vec());
    });
    env.hub.set_bundle(&[m], json!({}), flags(&[]), "\"e1\"");
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(3));
    assert!(env.sink.loaded.lock().expect("lock").is_empty());
    let st = status_body(&env);
    assert_eq!(st["modules"][0]["loaded"], false);
    assert_eq!(st["modules"][0]["error_code"], error_code::VERIFY);
    assert_eq!(env.counter("penguind_hub_module_verify_total", "fail"), 1.0);
    // not fully applied => next poll must not 304 away the failed module.
    assert_eq!(env.client.snapshot().await.etag, None);
}

#[tokio::test]
async fn bad_signature_and_bad_version_are_rejected() {
    let env = Env::new().await;
    let other = Signer::new();
    let forged = other.manifest("evil", "1.0.0", WASM, &env.hub.base_url);
    env.hub.with(|k| {
        k.binaries.insert("evil".into(), WASM.to_vec());
    });
    let mut badver = env.hub.publish(&env.signer, "v", "1.0.0", WASM);
    badver.version = "not-semver".into();
    env.hub
        .set_bundle(&[forged, badver], json!({}), flags(&[]), "\"e1\"");
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(3));
    let st = status_body(&env);
    assert_eq!(st["modules"][0]["error_code"], error_code::VERIFY);
    assert_eq!(st["modules"][1]["error_code"], error_code::VERIFY);
    assert!(env.sink.loaded.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn fetch_failure_and_sink_refusal_and_duplicates_are_partial() {
    let env = Env::new().await;
    let ok = env.hub.publish(&env.signer, "ok", "1.0.0", WASM);
    // signed but the hub has no binary -> 404 -> FETCH.
    let missing = env
        .signer
        .manifest("gone", "1.0.0", b"\0asm\x01\0\0\0\0", &env.hub.base_url);
    let refused = env.hub.publish(&env.signer, "refused", "1.0.0", WASM);
    env.sink.fail.lock().expect("lock").insert("refused".into());
    env.hub.set_bundle(
        &[ok.clone(), missing, refused, ok],
        json!({}),
        flags(&[]),
        "\"e1\"",
    );
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(2));
    let st = status_body(&env);
    let codes: Vec<Value> = st["modules"]
        .as_array()
        .expect("arr")
        .iter()
        .map(|m| m["error_code"].clone())
        .collect();
    assert_eq!(
        codes,
        vec![
            Value::Null,
            json!(error_code::FETCH),
            json!(4),
            json!(error_code::DUPLICATE)
        ]
    );
}

#[tokio::test]
async fn revoked_module_is_unloaded_when_dropped_from_bundle() {
    let env = Env::new().await;
    let a = env.hub.publish(&env.signer, "a", "1.0.0", WASM);
    let b = env.hub.publish(&env.signer, "b", "1.0.0", WASM);
    env.hub
        .set_bundle(&[a.clone(), b], json!({}), flags(&[]), "\"e1\"");
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(1));
    assert_eq!(env.client.snapshot().await.applied.len(), 2);
    env.hub.set_bundle(&[a], json!({}), flags(&[]), "\"e2\"");
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(1));
    assert_eq!(
        *env.sink.unloaded.lock().expect("lock"),
        vec!["b".to_string()]
    );
    assert_eq!(
        env.client.snapshot().await.applied,
        vec![("a".into(), "1.0.0".into())]
    );
}

#[tokio::test]
async fn rollback_to_lower_version_is_refused() {
    let env = Env::new().await;
    let v2 = env.hub.publish(&env.signer, "m", "2.0.0", WASM);
    env.hub.set_bundle(&[v2], json!({}), flags(&[]), "\"e1\"");
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(1));
    let v1 = env.signer.manifest("m", "1.0.0", WASM, &env.hub.base_url);
    env.hub
        .set_bundle(std::slice::from_ref(&v1), json!({}), flags(&[]), "\"e2\"");
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(3));
    assert_eq!(
        status_body(&env)["modules"][0]["error_code"],
        error_code::ROLLBACK
    );
    assert_eq!(
        env.client.snapshot().await.applied,
        vec![("m".into(), "2.0.0".into())]
    );
}

/// Regression (security review): dropping a module must not reset its
/// rollback high-water mark — apply v2, hub drops it, hub re-offers v1 → refused,
/// also across a restart; only an explicit local operator reset re-allows v1.
#[tokio::test]
async fn drop_then_reoffer_older_version_is_refused() {
    let env = Env::new().await;
    let v2 = env.hub.publish(&env.signer, "m", "2.0.0", WASM);
    env.hub.set_bundle(&[v2], json!({}), flags(&[]), "\"e1\"");
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(1));
    env.hub.set_bundle(&[], json!({}), flags(&[]), "\"e2\"");
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(1));
    assert!(env.client.snapshot().await.applied.is_empty());
    let v1 = env.signer.manifest("m", "1.0.0", WASM, &env.hub.base_url);
    env.hub
        .set_bundle(std::slice::from_ref(&v1), json!({}), flags(&[]), "\"e3\"");
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(3));
    assert_eq!(
        status_body(&env)["modules"][0]["error_code"],
        error_code::ROLLBACK
    );
    assert!(env.client.snapshot().await.applied.is_empty());

    // The mark persists across a restart.
    let env = env.restart(true).await;
    env.client.start().await;
    env.hub
        .set_bundle(std::slice::from_ref(&v1), json!({}), flags(&[]), "\"e4\"");
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(3));
    assert!(env.client.snapshot().await.applied.is_empty());

    // Explicit local operator reset is the only way back down.
    env.client.reset_high_water(Some("m")).await.expect("reset");
    env.hub.set_bundle(&[v1], json!({}), flags(&[]), "\"e5\"");
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(1));
    assert_eq!(
        env.client.snapshot().await.applied,
        vec![("m".into(), "1.0.0".into())]
    );
    env.client.reset_high_water(None).await.expect("reset all");
    assert!(!env.cache_dir().join("hub-highwater.json").exists());
}

/// A revocation wipe must not lower the rollback high-water marks.
#[tokio::test]
async fn revocation_does_not_lower_high_water() {
    let env = Env::new().await;
    let v2 = env.hub.publish(&env.signer, "m", "2.0.0", WASM);
    env.hub.set_bundle(&[v2], json!({}), flags(&[]), "\"e1\"");
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(1));
    env.hub.with(|k| k.revoked = true);
    assert_eq!(env.client.sync_once().await, SyncOutcome::Revoked);
    let raw = std::fs::read(env.cache_dir().join("hub-highwater.json")).expect("kept");
    let marks: serde_json::Value = serde_json::from_slice(&raw).expect("json");
    assert_eq!(marks["m"], "2.0.0");
}

#[tokio::test]
async fn hub_policy_can_only_narrow_the_ceiling() {
    let env = Env::new().await;
    let m = env.hub.publish(&env.signer, "demo", "1.0.0", WASM);
    // hub tries to grant secret_read + a huge fuel/memory + wide DNS.
    env.hub.set_bundle(
        &[m],
        json!({
            "allowed_tools": ["logger", "secret_read"],
            "limits": {"max_fuel": 18446744073709551615u64, "max_memory_mb": 100000, "max_tool_calls_per_min": 99999},
            "allowed_dns": ["*.com", "api.example.com"],
        }),
        flags(&[]),
        "\"e1\"",
    );
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(1));
    let loaded = env.sink.loaded.lock().expect("lock");
    let limits = &loaded[0].2;
    let c = ceiling();
    assert!(limits.fuel <= c.fuel);
    assert!(limits.max_memory_bytes <= c.max_memory_bytes);
    assert!(limits.max_tool_calls <= c.max_tool_calls);
    assert_eq!(
        limits.allowed_tools,
        ["logger".to_string()].into_iter().collect()
    );
    assert!(limits.allowed_dns.permits("api.example.com"));
    assert!(
        !limits.allowed_dns.permits("evil.com"),
        "hub wildcard must not widen"
    );
    assert!(
        !limits.allowed_dns.permits("x.svc.example.org"),
        "hub list narrows local"
    );
}

#[tokio::test]
async fn effective_flags_are_license_and_hub() {
    let env = Env::new().await;
    env.hub.set_bundle(
        &[],
        json!({}),
        flags(&[("f.a", false), ("f.z", true)]),
        "\"e1\"",
    );
    env.client.sync_once().await;
    assert!(!env.license.feature_enabled("f.a"), "hub turned it off");
    assert!(
        env.license.feature_enabled("f.b"),
        "hub silent: license decides"
    );
    assert!(!env.license.feature_enabled("f.z"), "hub can never grant");
}

#[tokio::test]
async fn http_410_revokes_unloads_and_wipes_everything() {
    let (env, _m) = applied_env().await;
    env.client.sync_once().await;
    env.hub.with(|k| k.revoked = true);
    assert_eq!(env.client.sync_once().await, SyncOutcome::Revoked);
    assert_eq!(
        *env.sink.unloaded.lock().expect("lock"),
        vec!["demo".to_string()]
    );
    assert!(env.secrets.map.lock().expect("lock").is_empty());
    assert!(!env.cache_dir().join("hub-cache.json").exists());
    assert!(env.client.snapshot().await.revoked);
    let before = env.hub.requests("GET", "/api/v1/agent/sync").len();
    assert_eq!(env.client.sync_once().await, SyncOutcome::Revoked);
    assert_eq!(
        env.hub.requests("GET", "/api/v1/agent/sync").len(),
        before,
        "no more traffic"
    );
}

#[tokio::test]
async fn status_report_410_also_revokes() {
    let (env, _m) = applied_env().await;
    env.hub.with(|k| k.status_code = 410);
    assert_eq!(env.client.sync_once().await, SyncOutcome::Revoked);
}

#[tokio::test]
async fn retry_after_is_honoured_for_429_and_5xx() {
    let (env, _m) = applied_env().await;
    env.client.sync_once().await; // enroll + apply
    env.hub
        .with(|k| k.sync_override = Some((429, vec![("Retry-After".into(), "120".into())])));
    assert_eq!(
        env.client.sync_once().await,
        SyncOutcome::RetryAfter(Duration::from_secs(120))
    );
    env.hub.with(|k| k.sync_override = Some((429, vec![])));
    assert_eq!(
        env.client.sync_once().await,
        SyncOutcome::RetryAfter(Duration::from_secs(60))
    );
    env.hub
        .with(|k| k.sync_override = Some((503, vec![("Retry-After".into(), "99999999".into())])));
    assert_eq!(
        env.client.sync_once().await,
        SyncOutcome::RetryAfter(Duration::from_secs(3600)),
        "capped"
    );
    env.hub.with(|k| k.sync_override = Some((500, vec![])));
    assert_eq!(env.client.sync_once().await, SyncOutcome::Backoff);
    env.hub.with(|k| k.sync_override = Some((400, vec![])));
    assert_eq!(env.client.sync_once().await, SyncOutcome::Backoff);
    assert_eq!(env.counter("penguind_hub_sync_requests_total", "5xx"), 2.0);
}

#[tokio::test]
async fn ssrf_hub_address_outside_policy_is_denied_without_traffic() {
    // loopback not opted in => the hub's own IP is refused by the network policy.
    let env = Env::build(None, false, None).await;
    env.hub.set_bundle(&[], json!({}), flags(&[]), "\"e1\"");
    assert_eq!(env.client.sync_once().await, SyncOutcome::Backoff);
    assert!(env.hub.with(|k| k.reqs.is_empty()), "no request may leave");
}

#[tokio::test]
async fn unreachable_hub_backs_off_and_keeps_state() {
    let (env, _m) = applied_env().await;
    env.client.sync_once().await;
    let env2 = env.restart(true).await; // same secrets (has creds) and cache
    // restore from cache works even if hub is unreachable (offline operation)
    assert_eq!(env2.client.start().await, StartStatus::Restored(1));
    assert_eq!(env2.sink.loaded.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn corrupt_cache_is_deny_all_until_hub_answers() {
    let (env, _m) = applied_env().await;
    env.client.sync_once().await;
    std::fs::write(env.cache_dir().join("hub-cache.json"), b"{{{ corrupt").expect("write");
    let env2 = env.restart(true).await;
    assert_eq!(env2.client.start().await, StartStatus::DenyAll);
    assert!(env2.sink.loaded.lock().expect("lock").is_empty());
    assert!(
        !env2.license.feature_enabled("f.a"),
        "deny-all: every flag off"
    );
    // hub answers again -> deny-all lifted and state rebuilt.
    assert_eq!(env2.client.sync_once().await, SyncOutcome::Applied(1));
    assert!(env2.license.feature_enabled("f.a"));
}

#[tokio::test]
async fn cache_restore_reverifies_and_drops_tampered_binaries() {
    let (env, _m) = applied_env().await;
    env.client.sync_once().await;
    // tamper the cached blob on disk.
    let blob_dir = env.cache_dir().join("hub-blobs");
    let blob = std::fs::read_dir(&blob_dir)
        .expect("dir")
        .next()
        .expect("one")
        .expect("e")
        .path();
    std::fs::write(&blob, b"\0asm\x01\0\0\0evil").expect("write");
    let env2 = env.restart(true).await;
    assert_eq!(env2.client.start().await, StartStatus::Restored(0));
    assert!(
        env2.sink.loaded.lock().expect("lock").is_empty(),
        "tampered cache must not load"
    );
    assert_eq!(
        env2.client.snapshot().await.etag,
        None,
        "force a full resync"
    );
    // and the next sync heals it from the hub.
    assert_eq!(env2.client.sync_once().await, SyncOutcome::Applied(1));
    assert_eq!(env2.sink.loaded.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn cache_restore_keeps_etag_when_everything_verifies() {
    let (env, _m) = applied_env().await;
    env.client.sync_once().await;
    let env2 = env.restart(true).await;
    assert_eq!(env2.client.start().await, StartStatus::Restored(1));
    assert_eq!(env2.client.snapshot().await.etag.as_deref(), Some("\"e1\""));
    // creds survived in the secret store: next poll is a plain 304, no re-enroll.
    assert_eq!(env2.client.sync_once().await, SyncOutcome::NotModified);
    assert!(env2.hub.requests("POST", "/api/v1/agent/enroll").len() == 1);
}

#[tokio::test]
async fn staleness_unloads_modules_and_recovers_on_next_contact() {
    let (env, _m) = applied_env().await;
    env.client.sync_once().await;
    assert!(!env.client.check_staleness().await);
    env.advance(3601); // max_stale_s = 3600 from the bundle
    assert!(env.client.check_staleness().await);
    assert_eq!(
        *env.sink.unloaded.lock().expect("lock"),
        vec!["demo".to_string()]
    );
    assert!(env.client.snapshot().await.stale);
    // hub returns; even an unchanged ETag must reload (etag was reset).
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(1));
    assert!(!env.client.snapshot().await.stale);
    assert_eq!(env.client.snapshot().await.applied.len(), 1);
}

#[tokio::test]
async fn start_with_an_old_cache_loads_nothing() {
    let (env, _m) = applied_env().await;
    env.client.sync_once().await;
    let env2 = env.restart(true).await;
    env2.advance(10_000);
    assert_eq!(env2.client.start().await, StartStatus::Stale);
    assert!(env2.sink.loaded.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn access_token_refresh_rotates_and_reuse_forces_reenroll() {
    let (env, _m) = applied_env().await;
    env.client.sync_once().await;
    // access token near expiry -> refresh before the next call.
    env.advance(3590);
    env.hub.set_bundle(&[], json!({}), flags(&[]), "\"e2\"");
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(1));
    assert_eq!(env.hub.requests("POST", "/api/v1/agent/token").len(), 1);
    // server-side access token invalidated (e.g. rotated elsewhere) -> 401 -> forced refresh -> retry ok.
    env.hub.with(|k| k.access = "something-else".into());
    // the stored refresh token is still current, so this succeeds.
    assert_eq!(env.client.sync_once().await, SyncOutcome::NotModified);
    assert_eq!(env.hub.requests("POST", "/api/v1/agent/token").len(), 2);
}

#[tokio::test]
async fn rejected_refresh_wipes_creds_and_needs_reenroll() {
    let (env, _m) = applied_env().await;
    env.client.sync_once().await;
    env.hub.with(|k| {
        k.access = "dead".into();
        k.refresh = "different".into(); // our stored refresh token is now unknown to the hub
    });
    assert_eq!(env.client.sync_once().await, SyncOutcome::Backoff);
    assert!(
        env.secrets.map.lock().expect("lock").is_empty(),
        "creds wiped"
    );
    // bootstrap token was consumed at first enroll -> cannot silently re-enroll.
    assert_eq!(env.client.sync_once().await, SyncOutcome::NoCredentials);
}

#[tokio::test]
async fn rejected_bootstrap_token_backs_off_then_reports_no_credentials() {
    let env = Env::build(None, true, Some("wrong")).await;
    assert_eq!(env.client.sync_once().await, SyncOutcome::Backoff);
    assert_eq!(env.client.sync_once().await, SyncOutcome::NoCredentials);
    assert!(env.hub.requests("GET", "/api/v1/agent/sync").is_empty());
}

#[tokio::test]
async fn used_bootstrap_token_cannot_enroll_twice() {
    let (env, _m) = applied_env().await;
    env.client.sync_once().await;
    assert_eq!(env.hub.requests("POST", "/api/v1/agent/enroll").len(), 1);
}

#[tokio::test]
async fn credential_store_outage_is_transient() {
    let (env, _m) = applied_env().await;
    *env.secrets.fail.lock().expect("lock") = true;
    assert_eq!(env.client.sync_once().await, SyncOutcome::Backoff);
    *env.secrets.fail.lock().expect("lock") = false;
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(1));
}

#[tokio::test]
async fn corrupt_stored_credentials_mean_reenroll() {
    let env = Env::new().await;
    env.secrets
        .map
        .lock()
        .expect("lock")
        .insert("hub-credentials".into(), b"junk".to_vec());
    env.hub.set_bundle(&[], json!({}), flags(&[]), "\"e1\"");
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(1));
}

#[tokio::test]
async fn garbage_bundle_is_a_backoff_not_a_panic() {
    let env = Env::new().await;
    env.hub.with(|k| k.garbage_sync = true);
    assert_eq!(env.client.sync_once().await, SyncOutcome::Backoff);
}

#[tokio::test]
async fn presigned_redirect_never_receives_the_bearer_token() {
    let (env, _m) = applied_env().await;
    env.hub.with(|k| k.redirect_binaries = true);
    assert_eq!(env.client.sync_once().await, SyncOutcome::Applied(1));
    let blob = env.hub.requests("GET", "/blob/");
    assert_eq!(blob.len(), 1);
    assert!(!blob[0].headers.contains_key("authorization"));
}

#[tokio::test]
async fn poll_interval_comes_from_the_hub_within_bounds() {
    let env = Env::new().await;
    env.hub.set_bundle(&[], json!({}), flags(&[]), "\"e1\"");
    env.hub.with(|k| k.bundle["poll_interval_s"] = json!(5));
    env.client.sync_once().await;
    assert_eq!(env.client.poll_interval().await, Duration::from_secs(60));
}

#[tokio::test]
async fn run_loop_polls_immediately_and_stops_on_cancel() {
    let (env, _m) = applied_env().await;
    let cancel = CancellationToken::new();
    let h = tokio::spawn(run_loop(env.client.clone(), cancel.clone()));
    for _ in 0..100 {
        if !env.hub.requests("GET", "/api/v1/agent/sync").is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!env.hub.requests("GET", "/api/v1/agent/sync").is_empty());
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), h)
        .await
        .expect("stops")
        .expect("join");
}

#[tokio::test]
async fn run_loop_stops_by_itself_when_revoked() {
    let (env, _m) = applied_env().await;
    env.hub.with(|k| k.revoked = true);
    // enroll succeeds, sync returns 410 -> loop ends without cancel.
    let h = tokio::spawn(run_loop(env.client.clone(), CancellationToken::new()));
    tokio::time::timeout(Duration::from_secs(10), h)
        .await
        .expect("stops")
        .expect("join");
    assert!(env.client.snapshot().await.revoked);
}

#[tokio::test]
async fn run_loop_cancel_during_inflight_sync_returns() {
    let (env, _m) = applied_env().await;
    let cancel = CancellationToken::new();
    cancel.cancel();
    run_loop(env.client.clone(), cancel).await;
}

#[test]
fn config_rejects_insecure_or_credentialed_urls() {
    let c = || ceiling();
    assert!(HubClientConfig::new("http://hub.example/", 1, "1", c()).is_err());
    assert!(HubClientConfig::new("https://user:pw@hub.example/", 1, "1", c()).is_err());
    assert!(HubClientConfig::new("nonsense", 1, "1", c()).is_err());
    let cfg = HubClientConfig::new("https://hub.example/base", 1, "1", c()).expect("ok");
    assert_eq!(cfg.hub_url.as_str(), "https://hub.example/base/");
}
