//! `waddles-social` CLI command tree (pure data — see [`command_tree`]) and
//! its [`dispatch`] handlers for social/session operations:
//! - `status`
//! - `health`
//! - `auth status` / `auth set-token <token>` / `auth clear`
//! - `communities list` / `communities use <uuid>`
//!
//! Zero local bridge, OBS, or Community Access Token (`wdl_c_`) admin commands
//! live here — those belong in `penguin-module-waddles-gateway`.
//!
//! # Secrets in output
//!
//! User access tokens are never echoed in plaintext in either `output` or
//! `json`; [`mask_secret`] is applied before formatting any token hint.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::json;

use penguin_sdk::{
    CommandResult, CommandSpec, FlagSpec, FlagType, HealthLevel, Module, ModuleError,
};
use waddles_client::WaddlesError;
use waddles_client::config::is_valid_uuid;
use waddles_client::models::Community;

use crate::mask::mask_secret;
use crate::module::{ACCESS_TOKEN_SECRET_KEY, FALLBACK_TOKEN_SECRET_KEY, WaddlesSocialModule};

/// Declares `waddles-social`'s social and session CLI command tree.
pub fn command_tree() -> Vec<CommandSpec> {
    vec![
        CommandSpec {
            name: "status".to_string(),
            use_line: "status".to_string(),
            short: "Show hub connectivity, auth, and active community".to_string(),
            flags: vec![json_flag()],
            ..Default::default()
        },
        CommandSpec {
            name: "health".to_string(),
            use_line: "health".to_string(),
            short: "Show module health probe result".to_string(),
            flags: vec![json_flag()],
            ..Default::default()
        },
        CommandSpec {
            name: "auth".to_string(),
            use_line: "auth".to_string(),
            short: "Inspect or update the user session token".to_string(),
            subcommands: vec![
                CommandSpec {
                    name: "status".to_string(),
                    use_line: "status".to_string(),
                    short: "Show masked token status and hub auth state".to_string(),
                    flags: vec![json_flag()],
                    ..Default::default()
                },
                CommandSpec {
                    name: "set-token".to_string(),
                    use_line: "set-token <token>".to_string(),
                    short: "Store a user access token in the module secret store".to_string(),
                    flags: vec![json_flag()],
                    min_args: 1,
                    max_args: 1,
                    ..Default::default()
                },
                CommandSpec {
                    name: "clear".to_string(),
                    use_line: "clear".to_string(),
                    short: "Clear the stored user access token and active session".to_string(),
                    flags: vec![json_flag()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        CommandSpec {
            name: "communities".to_string(),
            use_line: "communities".to_string(),
            short: "List or select Waddles communities".to_string(),
            subcommands: vec![
                CommandSpec {
                    name: "list".to_string(),
                    use_line: "list".to_string(),
                    short: "List communities for the authenticated user".to_string(),
                    flags: vec![json_flag()],
                    ..Default::default()
                },
                CommandSpec {
                    name: "use".to_string(),
                    use_line: "use <uuid>".to_string(),
                    short: "Switch the active community UUID".to_string(),
                    flags: vec![json_flag()],
                    min_args: 1,
                    max_args: 1,
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
    ]
}

fn json_flag() -> FlagSpec {
    FlagSpec {
        name: "json".to_string(),
        shorthand: String::new(),
        flag_type: FlagType::Bool,
        default: "false".to_string(),
        usage: "Output machine-readable JSON".to_string(),
    }
}

fn wants_json(flags: &HashMap<String, String>) -> bool {
    flags
        .get("json")
        .is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1")
}

fn json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ModuleError> {
    serde_json::to_vec(value).map_err(|err| ModuleError::new(format!("encode json: {err}")))
}

fn ok_result(output: String, json: Option<Vec<u8>>) -> CommandResult {
    CommandResult {
        output,
        json: json.unwrap_or_default(),
        exit_code: 0,
    }
}

fn hub_error_to_module_error(err: WaddlesError) -> ModuleError {
    ModuleError::new(err.to_string())
}

/// Dispatches one CLI invocation against `module`.
pub async fn dispatch(
    module: &WaddlesSocialModule,
    path: &[String],
    flags: &HashMap<String, String>,
    args: &[String],
) -> Result<CommandResult, ModuleError> {
    let as_json = wants_json(flags);
    let parts: Vec<&str> = path.iter().map(String::as_str).collect();

    match parts.as_slice() {
        ["status"] => cmd_status(module, as_json).await,
        ["health"] => cmd_health(module, as_json).await,
        ["auth", "status"] => cmd_auth_status(module, as_json).await,
        ["auth", "set-token"] => cmd_auth_set_token(module, args, as_json).await,
        ["auth", "clear"] => cmd_auth_clear(module, as_json).await,
        ["communities", "list"] => cmd_communities_list(module, as_json).await,
        ["communities", "use"] => cmd_communities_use(module, args, as_json).await,
        _ => Err(ModuleError::new(format!(
            "unknown waddles-social command: {}",
            path.join(" ")
        ))),
    }
}

async fn cmd_status(
    module: &WaddlesSocialModule,
    as_json: bool,
) -> Result<CommandResult, ModuleError> {
    let status = module.status().await?;
    let hub = status.detail.get("hub").cloned().unwrap_or_default();
    let community = status.detail.get("community").cloned().unwrap_or_default();
    let auth = status.detail.get("auth").cloned().unwrap_or_default();
    let session_active = module.session_proxy().is_some_and(|p| p.token_rotated());

    let community_display = if community.is_empty() {
        "(none)".to_string()
    } else {
        community.clone()
    };

    let output = format!(
        "state: {:?}\nhub: {}\ncommunity: {}\nauth: {}\n",
        status.state, hub, community_display, auth
    );
    let json = if as_json {
        Some(json_bytes(&json!({
            "state": format!("{:?}", status.state),
            "hub": hub,
            "community_id": community,
            "auth": auth,
            "token_rotated": session_active,
        }))?)
    } else {
        None
    };

    Ok(ok_result(output, json))
}

async fn cmd_health(
    module: &WaddlesSocialModule,
    as_json: bool,
) -> Result<CommandResult, ModuleError> {
    let report = module.health().await;
    let level_str = match report.level {
        HealthLevel::Healthy => "healthy",
        HealthLevel::Degraded => "degraded",
        HealthLevel::Unhealthy => "unhealthy",
    };

    let output = format!("level: {}\nmessage: {}\n", level_str, report.message);
    let json = if as_json {
        Some(json_bytes(&json!({
            "level": level_str,
            "message": report.message,
        }))?)
    } else {
        None
    };

    Ok(ok_result(output, json))
}

async fn cmd_auth_status(
    module: &WaddlesSocialModule,
    as_json: bool,
) -> Result<CommandResult, ModuleError> {
    let token = module.token();
    let configured = !token.is_empty();
    let masked = mask_secret(&token);
    let probe = module.probe_auth().await;

    let output = if configured {
        format!(
            "configured: true\ntoken: {}\nhub_auth: {}\n",
            masked,
            probe.state.as_str()
        )
    } else {
        format!(
            "configured: false\ntoken: (none)\nhub_auth: {}\n",
            probe.state.as_str()
        )
    };

    let json = if as_json {
        Some(json_bytes(&json!({
            "configured": configured,
            "token_masked": masked,
            "hub_auth": probe.state.as_str(),
        }))?)
    } else {
        None
    };

    Ok(ok_result(output, json))
}

async fn cmd_auth_set_token(
    module: &WaddlesSocialModule,
    args: &[String],
    as_json: bool,
) -> Result<CommandResult, ModuleError> {
    let token = args
        .first()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ModuleError::new("usage: auth set-token <token>"))?;

    module
        .host()
        .secrets()
        .set(ACCESS_TOKEN_SECRET_KEY, token.as_bytes())
        .await
        .map_err(|err| ModuleError::new(format!("store access token: {err}")))?;

    module.set_token(token.to_string())?;

    let masked = mask_secret(token);
    let output = format!("stored user access token ({masked})\n");
    let json = if as_json {
        Some(json_bytes(&json!({
            "stored": true,
            "token_masked": masked,
        }))?)
    } else {
        None
    };

    Ok(ok_result(output, json))
}

async fn cmd_auth_clear(
    module: &WaddlesSocialModule,
    as_json: bool,
) -> Result<CommandResult, ModuleError> {
    let _ = module
        .host()
        .secrets()
        .delete(ACCESS_TOKEN_SECRET_KEY)
        .await;
    let _ = module
        .host()
        .secrets()
        .delete(FALLBACK_TOKEN_SECRET_KEY)
        .await;

    module.set_token(String::new())?;
    if let Some(proxy) = module.session_proxy() {
        proxy.clear_session();
    }

    let output = "cleared user access token and session\n".to_string();
    let json = if as_json {
        Some(json_bytes(&json!({ "cleared": true }))?)
    } else {
        None
    };

    Ok(ok_result(output, json))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommunitySummary {
    id: String,
    name: String,
    display_name: String,
    member_count: i64,
    role: String,
}

impl From<&Community> for CommunitySummary {
    fn from(c: &Community) -> Self {
        CommunitySummary {
            id: c.id.clone(),
            name: c.name.clone(),
            display_name: c.display_name.clone(),
            member_count: c.member_count,
            role: c.role.clone(),
        }
    }
}

async fn cmd_communities_list(
    module: &WaddlesSocialModule,
    as_json: bool,
) -> Result<CommandResult, ModuleError> {
    let client = module.client();
    let communities = module
        .call(client.list_my_communities())
        .await
        .map_err(hub_error_to_module_error)?;

    let mut output = String::new();
    if communities.is_empty() {
        output.push_str("(no communities)\n");
    } else {
        for c in &communities {
            output.push_str(&format!(
                "{}  {} ({})  role={}  members={}\n",
                c.id, c.display_name, c.name, c.role, c.member_count
            ));
        }
    }

    let json = if as_json {
        let summaries: Vec<CommunitySummary> =
            communities.iter().map(CommunitySummary::from).collect();
        Some(json_bytes(&json!({ "communities": summaries }))?)
    } else {
        None
    };

    Ok(ok_result(output, json))
}

async fn cmd_communities_use(
    module: &WaddlesSocialModule,
    args: &[String],
    as_json: bool,
) -> Result<CommandResult, ModuleError> {
    let community_id = args
        .first()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ModuleError::new("usage: communities use <uuid>"))?;

    if !is_valid_uuid(community_id) {
        return Err(ModuleError::new(format!(
            "invalid community_id '{community_id}': expected UUID"
        )));
    }

    module.set_community(community_id.to_string())?;

    let output = format!("active community set to {community_id}\n");
    let json = if as_json {
        Some(json_bytes(&json!({ "community_id": community_id }))?)
    } else {
        None
    };

    Ok(ok_result(output, json))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::testutil::{FakeHost, MockHub, MockResponse};
    use penguin_sdk::SecretStore;

    const UUID_A: &str = "11111111-1111-4111-8111-111111111111";
    const UUID_B: &str = "22222222-2222-4222-8222-222222222222";

    fn path(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    fn json_flags() -> HashMap<String, String> {
        let mut flags = HashMap::new();
        flags.insert("json".to_string(), "true".to_string());
        flags
    }

    async fn setup_module(hub: &MockHub) -> WaddlesSocialModule {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.secrets
            .set(ACCESS_TOKEN_SECRET_KEY, b"jwt_super_secret_token_9876")
            .await
            .unwrap();
        host.config = serde_json::to_vec(&serde_json::json!({
            "hub": {"base_url": hub.base_url},
            "community_id": UUID_A,
        }))
        .unwrap();
        let module = WaddlesSocialModule::new();
        module.init(Arc::new(host)).await.unwrap();
        module
    }

    #[test]
    fn command_tree_contains_only_social_and_session_commands() {
        let tree = command_tree();
        let names: Vec<&str> = tree.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["status", "health", "auth", "communities"]);
        assert!(!names.contains(&"bridge"));
        assert!(!names.contains(&"browser-sources"));
        assert!(!names.contains(&"token"));
        assert!(!names.contains(&"music"));
    }

    #[tokio::test]
    async fn status_and_health_commands_return_json_and_text() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/communities/my",
            MockResponse::json(200, r#"{"success":true,"communities":[]}"#),
        )
        .await;

        let module = setup_module(&hub).await;
        module.start().await.unwrap();

        let status_res = dispatch(&module, &path(&["status"]), &json_flags(), &[])
            .await
            .unwrap();
        assert_eq!(status_res.exit_code, 0);
        assert!(status_res.output.contains("auth: ok"));
        let parsed: serde_json::Value = serde_json::from_slice(&status_res.json).unwrap();
        assert_eq!(parsed["community_id"], UUID_A);
        assert_eq!(parsed["auth"], "ok");

        let health_res = dispatch(&module, &path(&["health"]), &json_flags(), &[])
            .await
            .unwrap();
        assert_eq!(health_res.exit_code, 0);
        let parsed_health: serde_json::Value = serde_json::from_slice(&health_res.json).unwrap();
        assert_eq!(parsed_health["level"], "healthy");

        hub.stop().await;
    }

    #[tokio::test]
    async fn auth_status_masks_token_and_never_leaks_plaintext() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/communities/my",
            MockResponse::json(200, r#"{"success":true,"communities":[]}"#),
        )
        .await;

        let module = setup_module(&hub).await;
        let res = dispatch(&module, &path(&["auth", "status"]), &json_flags(), &[])
            .await
            .unwrap();
        assert!(!res.output.contains("jwt_super_secret_token_9876"));
        assert!(res.output.contains("****9876"));
        let parsed: serde_json::Value = serde_json::from_slice(&res.json).unwrap();
        assert_eq!(parsed["configured"], true);
        assert_eq!(parsed["token_masked"], "****9876");

        hub.stop().await;
    }

    #[tokio::test]
    async fn auth_set_token_and_clear_update_secrets_and_client() {
        let hub = MockHub::start().await;
        let module = setup_module(&hub).await;

        let set_res = dispatch(
            &module,
            &path(&["auth", "set-token"]),
            &json_flags(),
            &["new_jwt_token_4321".to_string()],
        )
        .await
        .unwrap();
        assert!(!set_res.output.contains("new_jwt_token_4321"));
        assert!(set_res.output.contains("****4321"));
        assert_eq!(module.token(), "new_jwt_token_4321");

        let secret = module
            .host()
            .secrets()
            .get(ACCESS_TOKEN_SECRET_KEY)
            .await
            .unwrap();
        assert_eq!(secret, b"new_jwt_token_4321");

        let clear_res = dispatch(&module, &path(&["auth", "clear"]), &json_flags(), &[])
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&clear_res.json).unwrap();
        assert_eq!(parsed["cleared"], true);
        assert!(module.token().is_empty());
        assert!(
            module
                .host()
                .secrets()
                .get(ACCESS_TOKEN_SECRET_KEY)
                .await
                .is_err()
        );

        hub.stop().await;
    }

    #[tokio::test]
    async fn communities_list_and_use_work_with_uuid_validation() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/communities/my",
            MockResponse::json(
                200,
                format!(
                    r#"{{"success":true,"communities":[{{"id":"{UUID_B}","name":"waddles","displayName":"Waddles HQ","memberCount":42,"role":"member"}}]}}"#
                ),
            ),
        )
        .await;

        let module = setup_module(&hub).await;
        let list_res = dispatch(&module, &path(&["communities", "list"]), &json_flags(), &[])
            .await
            .unwrap();
        assert!(list_res.output.contains("Waddles HQ"));
        let parsed: serde_json::Value = serde_json::from_slice(&list_res.json).unwrap();
        assert_eq!(parsed["communities"][0]["id"], UUID_B);

        // Invalid UUID must fail.
        let bad_use = dispatch(
            &module,
            &path(&["communities", "use"]),
            &HashMap::new(),
            &["not-a-uuid".to_string()],
        )
        .await;
        assert!(bad_use.is_err());

        // Valid UUID updates active community.
        let ok_use = dispatch(
            &module,
            &path(&["communities", "use"]),
            &json_flags(),
            &[UUID_B.to_string()],
        )
        .await
        .unwrap();
        assert_eq!(module.community_id(), UUID_B);
        let parsed_use: serde_json::Value = serde_json::from_slice(&ok_use.json).unwrap();
        assert_eq!(parsed_use["community_id"], UUID_B);

        hub.stop().await;
    }

    #[tokio::test]
    async fn unknown_command_returns_error() {
        let hub = MockHub::start().await;
        let module = setup_module(&hub).await;
        let err = dispatch(&module, &path(&["bridge", "status"]), &HashMap::new(), &[]).await;
        assert!(err.is_err());
        hub.stop().await;
    }
}
