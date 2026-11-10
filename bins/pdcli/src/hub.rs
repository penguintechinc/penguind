//! `pdcli hub ...` I/O shell: HTTP transport (rustls), OS-keychain token
//! storage and the OIDC device-flow loop. Every decision about what to send
//! and how to print it lives in `penguin_cli_core::hub`; this module only
//! moves bytes.

use std::future::Future;
use std::process::ExitCode;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::ArgMatches;
use penguin_cli_core::hub::{
    self, Body, HubAction, HubError, HubRequest, Kind, PollOutcome, StoredToken,
};
use serde_json::Value;
use url::Url;

/// Per-request timeout for hub and identity-provider calls.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Keychain service name under which hub tokens are stored.
const KEYCHAIN_SERVICE: &str = "pdcli-hub";
/// User agent sent to the hub.
const USER_AGENT: &str = concat!("pdcli/", env!("CARGO_PKG_VERSION"));

/// A raw HTTP response: status and body bytes.
#[derive(Debug, Clone)]
pub struct RawResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body.
    pub body: Vec<u8>,
}

/// Sends shaped requests; implemented over reqwest in production and
/// pointed at a mock server in tests.
pub trait HubTransport {
    /// Sends `req` to `url`, attaching `token` as a bearer credential.
    fn send(
        &self,
        url: Url,
        req: &HubRequest,
        token: Option<&str>,
    ) -> impl Future<Output = Result<RawResponse, HubError>> + Send;
}

/// Production transport: reqwest over rustls (aws-lc-rs + webpki roots).
pub struct ReqwestTransport {
    /// Shared client.
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Builds the client exactly like `penguin-update`: rustls with the
    /// aws-lc-rs provider and webpki roots, so `ring` never enters the graph.
    pub fn new() -> Result<ReqwestTransport, HubError> {
        static PROVIDER: OnceLock<()> = OnceLock::new();
        PROVIDER.get_or_init(|| {
            // Losing the install race to another initializer is fine: the
            // whole workspace uses aws-lc-rs.
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .user_agent(USER_AGENT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| HubError::Transport(format!("cannot build HTTP client: {e}")))?;
        Ok(ReqwestTransport { client })
    }
}

impl HubTransport for ReqwestTransport {
    /// Maps the shaped request onto reqwest and collects the response.
    fn send(
        &self,
        url: Url,
        req: &HubRequest,
        token: Option<&str>,
    ) -> impl Future<Output = Result<RawResponse, HubError>> + Send {
        let method = reqwest::Method::from_bytes(req.method.as_str().as_bytes())
            .unwrap_or(reqwest::Method::GET);
        let mut builder = self
            .client
            .request(method, url)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(t) = token {
            builder = builder.bearer_auth(t);
        }
        builder = match &req.body {
            Body::Empty => builder,
            Body::Json(v) => builder
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(v.to_string()),
            Body::Form(f) => builder
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(f.clone()),
            Body::Multipart {
                content_type,
                bytes,
            } => builder
                .header(reqwest::header::CONTENT_TYPE, content_type.as_str())
                .body(bytes.clone()),
        };
        async move {
            let resp = builder.send().await.map_err(|e| {
                if e.is_timeout() {
                    HubError::Transport("request timed out".into())
                } else {
                    HubError::Transport(e.without_url().to_string())
                }
            })?;
            let status = resp.status().as_u16();
            let body = resp
                .bytes()
                .await
                .map_err(|e| HubError::Transport(format!("reading response: {e}")))?;
            Ok(RawResponse {
                status,
                body: body.to_vec(),
            })
        }
    }
}

/// Persists hub credentials; the OS keychain in production.
pub trait TokenStore {
    /// Loads the token for `account`, `None` if absent.
    fn load(&self, account: &str) -> Result<Option<StoredToken>, HubError>;
    /// Saves the token for `account`.
    fn save(&self, account: &str, token: &StoredToken) -> Result<(), HubError>;
    /// Removes the token for `account`; true if one existed.
    fn delete(&self, account: &str) -> Result<bool, HubError>;
}

/// OS keychain (macOS Keychain, Windows Credential Manager, Secret Service)
/// via the `keyring` crate. Deliberately has no file fallback: no keychain
/// means login fails loudly rather than writing a token to disk.
pub struct KeychainStore;

impl KeychainStore {
    /// Opens the keychain entry for `account`.
    fn entry(account: &str) -> Result<keyring::Entry, HubError> {
        keyring::Entry::new(KEYCHAIN_SERVICE, account)
            .map_err(|e| HubError::Io(format!("OS keychain unavailable: {e}")))
    }
}

impl TokenStore for KeychainStore {
    /// Reads and decodes the stored JSON token.
    fn load(&self, account: &str) -> Result<Option<StoredToken>, HubError> {
        match Self::entry(account)?.get_password() {
            Ok(s) => serde_json::from_str(&s).map(Some).map_err(|_| {
                HubError::Auth("stored hub token is corrupt; run `pdcli hub login`".into())
            }),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(HubError::Io(format!("OS keychain read failed: {e}"))),
        }
    }

    /// Encodes the token as JSON into the keychain.
    fn save(&self, account: &str, token: &StoredToken) -> Result<(), HubError> {
        let s = serde_json::to_string(token)
            .map_err(|e| HubError::Io(format!("encoding token: {e}")))?;
        Self::entry(account)?
            .set_password(&s)
            .map_err(|e| HubError::Io(format!("OS keychain write failed: {e}")))
    }

    /// Deletes the keychain entry.
    fn delete(&self, account: &str) -> Result<bool, HubError> {
        match Self::entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(HubError::Io(format!("OS keychain delete failed: {e}"))),
        }
    }
}

/// Settings resolved from flags and environment for one invocation.
#[derive(Debug, Clone)]
pub struct Context {
    /// Hub base URL.
    pub hub: Url,
    /// `--json` output.
    pub json: bool,
    /// Issuer from `$PDCLI_OIDC_ISSUER`.
    pub env_issuer: Option<String>,
    /// Client id from `$PDCLI_OIDC_CLIENT_ID`.
    pub env_client_id: Option<String>,
}

/// Current Unix time in seconds.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Entry point from `cli::run` for the `hub` subcommand.
pub async fn run(root: &ArgMatches, hub_matches: &ArgMatches) -> ExitCode {
    let json = root.get_flag(penguin_cli_core::tree::JSON_ARG_ID);
    let result = async {
        let action = hub::parse_action(hub_matches)?;
        let env_url = std::env::var(hub::HUB_URL_ENV).ok();
        let flag_url = hub_matches.get_one::<String>("hub-url").map(String::as_str);
        let ctx = Context {
            hub: hub::resolve_hub_url(flag_url, env_url.as_deref())?,
            json,
            env_issuer: std::env::var(hub::ISSUER_ENV).ok(),
            env_client_id: std::env::var(hub::CLIENT_ID_ENV).ok(),
        };
        let transport = ReqwestTransport::new()?;
        execute(&ctx, action, &transport, &KeychainStore, read_file, |m| {
            eprintln!("{m}")
        })
        .await
    }
    .await;
    match result {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("pdcli: hub: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}

/// Reads a local input file into memory.
fn read_file(path: &str) -> Result<Vec<u8>, HubError> {
    std::fs::read(path).map_err(|e| HubError::Usage(format!("cannot read {path}: {e}")))
}

/// Reads a local input file as UTF-8 text.
fn read_text(
    read: &impl Fn(&str) -> Result<Vec<u8>, HubError>,
    path: &str,
) -> Result<String, HubError> {
    String::from_utf8(read(path)?).map_err(|_| HubError::Usage(format!("{path} is not UTF-8 text")))
}

/// Runs one action and returns the rendered output. Generic over transport,
/// token store, file reader and status printer so tests drive it end to end.
pub async fn execute<T, S, R, P>(
    ctx: &Context,
    action: HubAction,
    transport: &T,
    store: &S,
    read: R,
    status: P,
) -> Result<String, HubError>
where
    T: HubTransport + Sync,
    S: TokenStore,
    R: Fn(&str) -> Result<Vec<u8>, HubError>,
    P: Fn(&str),
{
    let account = hub::keychain_account(&ctx.hub);
    match action {
        HubAction::Login { issuer, client_id } => {
            let issuer = issuer.or_else(|| ctx.env_issuer.clone()).ok_or_else(|| {
                HubError::Config(format!(
                    "no issuer: pass --issuer or set {}",
                    hub::ISSUER_ENV
                ))
            })?;
            let client_id = client_id
                .or_else(|| ctx.env_client_id.clone())
                .unwrap_or_else(|| hub::DEFAULT_CLIENT_ID.to_string());
            let token = device_login(transport, &issuer, &client_id, &status).await?;
            store.save(&account, &token)?;
            let claims = hub::decode_claims(&token.access_token).unwrap_or(Value::Null);
            Ok(render_value(
                &hub::whoami_view(&claims, &ctx.hub),
                ctx.json,
                "logged in",
            ))
        }
        HubAction::Logout => {
            let existed = store.delete(&account)?;
            let msg = if existed {
                "logged out"
            } else {
                "not logged in"
            };
            Ok(render_value(
                &serde_json::json!({ "logged_out": existed }),
                ctx.json,
                msg,
            ))
        }
        HubAction::Whoami => {
            let token = store
                .load(&account)?
                .ok_or_else(|| HubError::Auth("not logged in; run `pdcli hub login`".into()))?;
            let claims = hub::decode_claims(&token.access_token)?;
            Ok(hub::render(
                Kind::Policy,
                &hub::whoami_view(&claims, &ctx.hub),
                ctx.json,
            ))
        }
        HubAction::Call(req, kind) => {
            let token = access_token(transport, store, &account).await?;
            let data = call(transport, ctx, &req, &token).await?;
            Ok(hub::render(kind, &data, ctx.json))
        }
        HubAction::Publish {
            wasm,
            manifest,
            pubkey,
        } => {
            let bytes = read(&wasm)?;
            let manifest_text = read_text(&read, &manifest)?;
            let pk = pubkey.map(|p| read_text(&read, &p)).transpose()?;
            let req = hub::build_publish(&bytes, &manifest_text, pk.as_deref())?;
            let token = access_token(transport, store, &account).await?;
            let data = call(transport, ctx, &req, &token).await?;
            Ok(hub::render(Kind::Module, &data, ctx.json))
        }
        HubAction::ConfigSet { target, file } => {
            let req = hub::build_config_set(&target, &read_text(&read, &file)?)?;
            let token = access_token(transport, store, &account).await?;
            let data = call(transport, ctx, &req, &token).await?;
            Ok(hub::render(Kind::Policy, &data, ctx.json))
        }
        HubAction::LimitsSet { target, limits } => {
            let token = access_token(transport, store, &account).await?;
            let current = call(transport, ctx, &hub::policy_read(&target), &token).await?;
            let req = hub::build_limits_write(&target, &current, &limits);
            let data = call(transport, ctx, &req, &token).await?;
            Ok(hub::render(Kind::Policy, &data, ctx.json))
        }
    }
}

/// Renders a local (non-API) result: JSON view or a one-line message.
fn render_value(v: &Value, json: bool, msg: &str) -> String {
    if json {
        hub::render(Kind::Policy, v, true)
    } else {
        msg.to_string()
    }
}

/// Sends an authenticated hub request and unwraps the envelope.
async fn call<T: HubTransport>(
    transport: &T,
    ctx: &Context,
    req: &HubRequest,
    token: &str,
) -> Result<Value, HubError> {
    let resp = transport.send(req.url(&ctx.hub)?, req, Some(token)).await?;
    hub::parse_response(resp.status, &resp.body)
}

/// Returns a valid access token, refreshing (and re-saving) it when expired.
async fn access_token<T: HubTransport, S: TokenStore>(
    transport: &T,
    store: &S,
    account: &str,
) -> Result<String, HubError> {
    let token = store
        .load(account)?
        .ok_or_else(|| HubError::Auth("not logged in; run `pdcli hub login`".into()))?;
    if !token.is_expired(now()) {
        return Ok(token.access_token);
    }
    let refresh = token
        .refresh_token
        .as_deref()
        .ok_or_else(|| HubError::Auth("hub token expired; run `pdcli hub login`".into()))?;
    let req = hub::refresh_request(&token.token_endpoint, &token.client_id, refresh);
    let url = Url::parse(&token.token_endpoint)
        .map_err(|e| HubError::Auth(format!("stored token endpoint invalid: {e}")))?;
    let resp = transport.send(url, &req, None).await?;
    match hub::parse_token_response(
        resp.status,
        &resp.body,
        &token.token_endpoint,
        &token.client_id,
        now(),
    )? {
        PollOutcome::Token(mut fresh) => {
            if fresh.refresh_token.is_none() {
                fresh.refresh_token = token.refresh_token.clone();
            }
            store.save(account, &fresh)?;
            Ok(fresh.access_token)
        }
        PollOutcome::Pending | PollOutcome::SlowDown => Err(HubError::Auth(
            "hub token expired; run `pdcli hub login`".into(),
        )),
    }
}

/// RFC 8628 device authorization grant: discover endpoints, show the user
/// code, poll until approved, denied or expired.
async fn device_login<T: HubTransport>(
    transport: &T,
    issuer: &str,
    client_id: &str,
    status: &impl Fn(&str),
) -> Result<StoredToken, HubError> {
    let disc_url = hub::discovery_url(issuer)?;
    let get = HubRequest {
        method: hub::Method::Get,
        path: disc_url.to_string(),
        query: Vec::new(),
        body: Body::Empty,
    };
    let resp = transport.send(disc_url, &get, None).await?;
    if resp.status != 200 {
        return Err(HubError::Auth(format!(
            "OIDC discovery failed (HTTP {})",
            resp.status
        )));
    }
    let disc = hub::parse_discovery(&resp.body)?;

    let req = hub::device_authorization_request(&disc.device_authorization_endpoint, client_id);
    let url = Url::parse(&disc.device_authorization_endpoint)
        .map_err(|e| HubError::Protocol(e.to_string()))?;
    let resp = transport.send(url, &req, None).await?;
    if !(200..300).contains(&resp.status) {
        return Err(HubError::Auth(format!(
            "device authorization failed (HTTP {})",
            resp.status
        )));
    }
    let auth: hub::DeviceAuthorization = serde_json::from_slice(&resp.body)
        .map_err(|e| HubError::Protocol(format!("device authorization response: {e}")))?;
    match &auth.verification_uri_complete {
        Some(u) => status(&format!("Open {u} and confirm code {}", auth.user_code)),
        None => status(&format!(
            "Open {} and enter code {}",
            auth.verification_uri, auth.user_code
        )),
    }

    let token_url =
        Url::parse(&disc.token_endpoint).map_err(|e| HubError::Protocol(e.to_string()))?;
    let deadline = now().saturating_add(auth.expires_in);
    let mut interval = auth.interval;
    loop {
        if now() > deadline {
            return Err(HubError::Auth(
                "device code expired; run `pdcli hub login` again".into(),
            ));
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let poll = hub::device_token_request(&disc.token_endpoint, client_id, &auth.device_code);
        let resp = transport.send(token_url.clone(), &poll, None).await?;
        match hub::parse_token_response(
            resp.status,
            &resp.body,
            &disc.token_endpoint,
            client_id,
            now(),
        )? {
            PollOutcome::Token(t) => return Ok(t),
            PollOutcome::Pending => {}
            PollOutcome::SlowDown => interval = interval.saturating_add(5),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use base64::Engine as _;
    use serde_json::json;
    use wiremock::matchers::{
        body_string_contains, header, header_regex, method, path, query_param,
    };
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const G: &str = "0b7f3c2e-1d4a-4c8e-9a6b-2f1e3d4c5b6a";
    const A: &str = "1c8e4d3f-2e5b-4d9f-8b7c-3a2f4e5d6c7b";
    const M: &str = "2d9f5e4a-3f6c-4e0a-9c8d-4b3a5f6e7d8c";

    #[derive(Default)]
    struct MemStore(Mutex<HashMap<String, StoredToken>>);

    impl TokenStore for MemStore {
        fn load(&self, a: &str) -> Result<Option<StoredToken>, HubError> {
            Ok(self.0.lock().expect("lock").get(a).cloned())
        }
        fn save(&self, a: &str, t: &StoredToken) -> Result<(), HubError> {
            self.0.lock().expect("lock").insert(a.into(), t.clone());
            Ok(())
        }
        fn delete(&self, a: &str) -> Result<bool, HubError> {
            Ok(self.0.lock().expect("lock").remove(a).is_some())
        }
    }

    fn jwt(claims: Value) -> String {
        format!(
            "h.{}.s",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    /// Envelope per v1.yaml `Envelope` + `Meta`.
    fn ok(data: Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "status": "success", "data": data,
            "meta": {"version": 1, "timestamp": "2026-11-10T00:00:00Z"}
        }))
    }

    /// Problem-details error envelope per v1.yaml `responses`.
    fn problem(status: u16, title: &str) -> ResponseTemplate {
        ResponseTemplate::new(status).set_body_json(json!({
            "status": "error",
            "data": {"type": "about:blank", "title": title, "status": status, "code": 1000 + status},
            "meta": {"version": 1, "timestamp": "2026-11-10T00:00:00Z"}
        }))
    }

    fn group(id: &str) -> Value {
        json!({"id": id, "name": "ops", "policy": {"allowed_tools": ["a"], "limits": {"max_fuel": 1}},
               "agent_count": 2, "created_at": "2026-11-10T00:00:00Z", "updated_at": "2026-11-10T00:00:00Z"})
    }

    async fn setup(token: Option<StoredToken>) -> (MockServer, Context, MemStore) {
        let server = MockServer::start().await;
        let hub = Url::parse(&server.uri()).expect("uri");
        let store = MemStore::default();
        if let Some(t) = token {
            store.save(&hub::keychain_account(&hub), &t).expect("save");
        }
        let ctx = Context {
            hub,
            json: false,
            env_issuer: None,
            env_client_id: None,
        };
        (server, ctx, store)
    }

    fn valid_token(endpoint: &str) -> StoredToken {
        StoredToken {
            access_token: "tok-1".into(),
            refresh_token: Some("ref-1".into()),
            expires_at: now() + 3600,
            token_endpoint: endpoint.into(),
            client_id: "pdcli".into(),
        }
    }

    fn act(args: &[&str]) -> HubAction {
        let mut full = vec!["pdcli", "hub"];
        full.extend_from_slice(args);
        let m = penguin_cli_core::tree::build_static_root()
            .try_get_matches_from(full)
            .expect("parse");
        hub::parse_action(m.subcommand().expect("hub").1).expect("action")
    }

    fn no_files(_: &str) -> Result<Vec<u8>, HubError> {
        Err(HubError::Usage("no files".into()))
    }

    async fn run_ok(ctx: &Context, store: &MemStore, args: &[&str]) -> Result<String, HubError> {
        let t = ReqwestTransport::new().expect("client");
        execute(ctx, act(args), &t, store, no_files, |_| {}).await
    }

    #[tokio::test]
    async fn list_groups_sends_bearer_and_renders_page() {
        let (server, ctx, store) = setup(Some(valid_token("http://127.0.0.1:1/t"))).await;
        Mock::given(method("GET"))
            .and(path("/api/v1/groups"))
            .and(query_param("name_prefix", "op"))
            .and(header("authorization", "Bearer tok-1"))
            .respond_with(ok(json!({"items": [group(G)], "next_cursor": null})))
            .expect(2)
            .mount(&server)
            .await;
        let out = run_ok(&ctx, &store, &["group", "list", "--name-prefix", "op"])
            .await
            .expect("ok");
        assert!(out.contains(G) && out.contains("ops"), "{out}");
        let json_ctx = Context {
            json: true,
            ..ctx.clone()
        };
        let out = run_ok(&json_ctx, &store, &["group", "list", "--name-prefix", "op"])
            .await
            .expect("ok");
        let v: Value = serde_json::from_str(&out).expect("json");
        assert_eq!(v["items"][0]["id"], G);
    }

    #[tokio::test]
    async fn json_flag_outputs_data_for_every_kind_of_call() {
        let (server, mut ctx, store) = setup(Some(valid_token("http://127.0.0.1:1/t"))).await;
        ctx.json = true;
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/agents/{A}")))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        Mock::given(method("PATCH")).and(path(format!("/api/v1/modules/{M}")))
            .and(body_string_contains("\"status\":2"))
            .respond_with(ok(json!({"id": M, "module_id": "waddleai", "version": "1.0.0", "sha256": "0".repeat(64),
                "signature": "s", "status": 2, "size_bytes": 8, "created_at": "2026-11-10T00:00:00Z"})))
            .mount(&server).await;
        let out = run_ok(&ctx, &store, &["agent", "disable", A])
            .await
            .expect("ok");
        assert_eq!(
            serde_json::from_str::<Value>(&out).expect("json"),
            json!({"ok": true})
        );
        let out = run_ok(&ctx, &store, &["module", "revoke", M])
            .await
            .expect("ok");
        assert_eq!(
            serde_json::from_str::<Value>(&out).expect("json")["status"],
            2
        );
        let out = run_ok(&ctx, &store, &["logout"]).await.expect("ok");
        assert_eq!(
            serde_json::from_str::<Value>(&out).expect("json"),
            json!({"logged_out": true})
        );
    }

    #[tokio::test]
    async fn http_errors_map_to_clear_messages() {
        let (server, ctx, store) = setup(Some(valid_token("http://127.0.0.1:1/t"))).await;
        for (status, title, needle) in [
            (401, "Unauthorized", "pdcli hub login"),
            (403, "Forbidden", "permission denied"),
            (404, "Not Found", "not found"),
            (500, "Boom", "server error"),
        ] {
            server.reset().await;
            Mock::given(method("GET"))
                .and(path(format!("/api/v1/groups/{G}")))
                .respond_with(problem(status, title))
                .mount(&server)
                .await;
            let e = run_ok(&ctx, &store, &["group", "show", G])
                .await
                .expect_err("err");
            let msg = e.to_string();
            assert!(msg.contains(needle) && msg.contains(title), "{msg}");
            assert_eq!(e.exit_code(), 1);
        }
    }

    #[tokio::test]
    async fn not_logged_in_and_unreachable_hub_fail_loudly() {
        let (_server, ctx, store) = setup(None).await;
        let e = run_ok(&ctx, &store, &["group", "list"])
            .await
            .expect_err("err");
        assert!(matches!(e, HubError::Auth(_)) && e.to_string().contains("login"));
        let e = run_ok(&ctx, &store, &["whoami"]).await.expect_err("err");
        assert!(matches!(e, HubError::Auth(_)));
        let dead = Context {
            hub: Url::parse("http://127.0.0.1:1").expect("u"),
            ..ctx
        };
        store
            .save(
                &hub::keychain_account(&dead.hub),
                &valid_token("http://127.0.0.1:1/t"),
            )
            .expect("save");
        let e = run_ok(&dead, &store, &["group", "list"])
            .await
            .expect_err("err");
        assert!(matches!(e, HubError::Transport(_)), "{e:?}");
    }

    #[tokio::test]
    async fn expired_token_is_refreshed_and_resaved() {
        let (server, ctx, store) = setup(None).await;
        let mut t = valid_token(&format!("{}/oidc/token", server.uri()));
        t.expires_at = 1;
        store
            .save(&hub::keychain_account(&ctx.hub), &t)
            .expect("save");
        Mock::given(method("POST"))
            .and(path("/oidc/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=ref-1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token": "tok-2", "expires_in": 3600})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET")).and(path("/api/v1/flags")).and(header("authorization", "Bearer tok-2"))
            .respond_with(ok(json!({"items": [{"id": G, "key": "penguind.hub-api", "enabled": false, "scope": 1}], "next_cursor": null})))
            .mount(&server).await;
        let out = run_ok(&ctx, &store, &["flags", "list"]).await.expect("ok");
        assert!(
            out.contains("penguind.hub-api") && out.contains("tenant"),
            "{out}"
        );
        let saved = store
            .load(&hub::keychain_account(&ctx.hub))
            .expect("load")
            .expect("some");
        assert_eq!(
            (saved.access_token.as_str(), saved.refresh_token.as_deref()),
            ("tok-2", Some("ref-1"))
        );
    }

    #[tokio::test]
    async fn device_login_polls_until_approved_and_stores_token() {
        let (server, mut ctx, store) = setup(None).await;
        let base = server.uri();
        ctx.env_issuer = Some(format!("{base}/realm"));
        Mock::given(method("GET")).and(path("/realm/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_authorization_endpoint": format!("{base}/device"), "token_endpoint": format!("{base}/token")})))
            .mount(&server).await;
        Mock::given(method("POST")).and(path("/device")).and(body_string_contains("client_id=pdcli"))
            .and(header_regex("content-type", "x-www-form-urlencoded"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_code": "dc", "user_code": "ABCD-EFGH", "verification_uri": "https://idp/verify",
                "expires_in": 60, "interval": 0})))
            .mount(&server).await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("device_code=dc"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(json!({"error": "authorization_pending"})),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let access = jwt(json!({"sub": A, "tenant": "t1", "scope": "hub:groups:read"}));
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"access_token": access, "refresh_token": "r", "expires_in": 3600}),
            ))
            .mount(&server)
            .await;
        let seen = Mutex::new(Vec::new());
        let t = ReqwestTransport::new().expect("client");
        let out = execute(&ctx, act(&["login"]), &t, &store, no_files, |m| {
            seen.lock().expect("l").push(m.to_string())
        })
        .await
        .expect("login");
        assert_eq!(out, "logged in");
        assert!(seen.lock().expect("l")[0].contains("ABCD-EFGH"));
        let who = run_ok(&ctx, &store, &["whoami"]).await.expect("whoami");
        assert!(who.contains("t1") && !who.contains(&access), "{who}");
    }

    #[tokio::test]
    async fn device_login_denied_is_an_error() {
        let (server, mut ctx, store) = setup(None).await;
        let base = server.uri();
        ctx.env_issuer = Some(base.clone());
        Mock::given(method("GET")).and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_authorization_endpoint": format!("{base}/device"), "token_endpoint": format!("{base}/token")})))
            .mount(&server).await;
        Mock::given(method("POST")).and(path("/device"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_code": "dc", "user_code": "U", "verification_uri": "https://v", "expires_in": 60, "interval": 0})))
            .mount(&server).await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(json!({"error": "access_denied"})),
            )
            .mount(&server)
            .await;
        let e = run_ok(&ctx, &store, &["login"]).await.expect_err("denied");
        assert!(e.to_string().contains("denied"));
        assert!(store.0.lock().expect("l").is_empty());
        ctx.env_issuer = None;
        assert!(matches!(
            run_ok(&ctx, &store, &["login"]).await,
            Err(HubError::Config(_))
        ));
    }

    #[tokio::test]
    async fn publish_uploads_multipart_and_limits_read_modify_write() {
        let (server, ctx, store) = setup(Some(valid_token("http://127.0.0.1:1/t"))).await;
        let wasm = b"\0asm\x01\0\0\0".to_vec();
        let digest = hub::sha256_hex(&wasm);
        let kp = minisign::KeyPair::generate_unencrypted_keypair().expect("kp");
        let msg = hub::signed_message("waddleai", "1.0.0", &digest);
        let sig = minisign::sign(
            Some(&kp.pk),
            &kp.sk,
            std::io::Cursor::new(msg.as_bytes()),
            None,
            None,
        )
        .expect("sign")
        .to_string();
        let pk = kp.pk.to_box().expect("pk").into_string();
        let manifest = json!({"id": "waddleai", "version": "1.0.0", "signature": sig}).to_string();
        Mock::given(method("POST")).and(path("/api/v1/modules"))
            .and(header_regex("content-type", "^multipart/form-data; boundary=pdcli-"))
            .and(body_string_contains(digest.as_str()))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"status": "success", "data": {
                "id": M, "module_id": "waddleai", "version": "1.0.0", "sha256": digest, "signature": "s",
                "status": 1, "size_bytes": 8, "created_at": "2026-11-10T00:00:00Z"},
                "meta": {"version": 1, "timestamp": "2026-11-10T00:00:00Z"}})))
            .expect(1).mount(&server).await;
        let files: HashMap<&str, Vec<u8>> = HashMap::from([
            ("m.wasm", wasm),
            ("m.json", manifest.into_bytes()),
            ("k.pub", pk.into_bytes()),
        ]);
        let read = |p: &str| {
            files
                .get(p)
                .cloned()
                .ok_or_else(|| HubError::Usage(format!("missing {p}")))
        };
        let t = ReqwestTransport::new().expect("client");
        let out = execute(
            &ctx,
            act(&[
                "module",
                "publish",
                "m.wasm",
                "--manifest",
                "m.json",
                "--pubkey",
                "k.pub",
            ]),
            &t,
            &store,
            read,
            |_| {},
        )
        .await
        .expect("publish");
        assert!(out.contains("available") && out.contains(M), "{out}");

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/groups/{G}")))
            .respond_with(ok(group(G)))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/groups/{G}")))
            .and(body_string_contains("\"allowed_tools\":[\"a\"]"))
            .and(body_string_contains("\"max_fuel\":7"))
            .respond_with(ok(group(G)))
            .expect(1)
            .mount(&server)
            .await;
        run_ok(
            &ctx,
            &store,
            &["limits", "set", "--group", G, "--max-fuel", "7"],
        )
        .await
        .expect("limits");
    }
}
