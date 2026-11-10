//! Hub transport + module fetcher: a sibling of [`GitHubFetcher`](super::GitHubFetcher)
//! that talks to a management hub instead of GitHub.
//!
//! It keeps every guarantee of the GitHub path (https only, network policy on
//! every resolved IP, connection pinned to the checked IP, no proxy, streamed
//! size cap, no automatic redirects) and adds what a hub needs: a bearer
//! machine JWT, an optional mTLS client identity, `If-None-Match` conditional
//! requests, and one manually-followed redirect to a presigned blob URL that
//! never receives the bearer token or the client certificate. Modules leave
//! this file only as a [`VerifiedModule`].

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{
    AUTHORIZATION, CONTENT_TYPE, ETAG, HeaderMap, HeaderValue, IF_NONE_MATCH, LOCATION, RETRY_AFTER,
};
use reqwest::{Client, Identity, Method, redirect};
use url::{Host, Url};

use super::fetcher::{
    DEFAULT_MAX_BINARY_BYTES, FetchError, ModuleManifest, Resolver, SystemResolver,
};
use super::network_gatekeeper::NetworkPolicy;
use super::verification::{
    ManifestClaims, VerificationError, VerifiedModule, signed_payload, verify_signature,
};

/// Hard cap on a non-binary hub response (sync bundle, token reply, problem body).
pub const MAX_HUB_JSON_BYTES: usize = 4 << 20;

/// HTTP methods the hub protocol uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubMethod {
    /// Read (sync, binary download).
    Get,
    /// Write (enroll, token refresh, status report).
    Post,
}

/// One request to the hub. Borrowed so callers never copy a token around.
pub struct HubRequest<'a> {
    /// HTTP method.
    pub method: HubMethod,
    /// Absolute https URL; checked against the network policy.
    pub url: &'a str,
    /// Bearer token (machine JWT or bootstrap token), sent as a sensitive header.
    pub bearer: Option<&'a str>,
    /// Strong ETag of the last applied state, sent as `If-None-Match`.
    pub if_none_match: Option<&'a str>,
    /// Pre-serialised JSON body for POSTs.
    pub json_body: Option<Vec<u8>>,
    /// Hard cap on the response body.
    pub max_response: usize,
}

/// A hub response with the headers the protocol cares about. Any status is
/// returned (the caller maps 304/401/410/429); only transport, policy and size
/// failures are errors.
#[derive(Debug)]
pub struct HubResponse {
    /// HTTP status code.
    pub status: u16,
    /// `ETag` header, if present.
    pub etag: Option<String>,
    /// `Retry-After` in whole seconds (HTTP-date form is ignored).
    pub retry_after: Option<Duration>,
    /// `Location` header, if present.
    pub location: Option<String>,
    /// Body, capped at the request's `max_response`.
    pub body: Vec<u8>,
}

/// Checked destination: the parsed URL plus the pinned address.
struct Target {
    url: Url,
    host_name: String,
    pinned: SocketAddr,
    is_domain: bool,
}

/// Talks to the hub under a [`NetworkPolicy`] and verifies modules against a
/// set of pinned minisign public keys (several, so keys can rotate).
pub struct HubFetcher {
    policy: NetworkPolicy,
    public_keys: Vec<String>,
    max_binary_bytes: usize,
    resolver: Arc<dyn Resolver>,
    identity_pem: Option<Vec<u8>>,
    extra_root_pems: Vec<Vec<u8>>,
    #[cfg(test)]
    allow_http: bool,
}

impl HubFetcher {
    /// Builds a fetcher bound by `policy` that accepts a module signed by any
    /// of the pinned `public_keys` (minisign pubkey text).
    pub fn new(policy: NetworkPolicy, public_keys: Vec<String>) -> Self {
        Self {
            policy,
            public_keys,
            max_binary_bytes: DEFAULT_MAX_BINARY_BYTES,
            resolver: Arc::new(SystemResolver),
            identity_pem: None,
            extra_root_pems: Vec::new(),
            #[cfg(test)]
            allow_http: false,
        }
    }

    /// Overrides the module binary size cap.
    pub fn with_max_binary_bytes(mut self, max: usize) -> Self {
        self.max_binary_bytes = max;
        self
    }

    /// Presents `pem` (client certificate chain + private key, concatenated)
    /// on hub requests for mTLS. Never sent to a presigned blob host.
    pub fn with_client_identity_pem(mut self, pem: Vec<u8>) -> Self {
        self.identity_pem = Some(pem);
        self
    }

    /// Trusts an additional root CA (PEM) for the hub, for private-CA deployments.
    pub fn with_extra_root_pem(mut self, pem: Vec<u8>) -> Self {
        self.extra_root_pems.push(pem);
        self
    }

    /// Swaps the DNS resolver (DNS-rebinding tests).
    pub fn with_resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Sends one request to the hub. Redirects are never followed here; the
    /// caller sees the 3xx and `Location`.
    pub async fn send(&self, req: HubRequest<'_>) -> Result<HubResponse, FetchError> {
        self.send_inner(req, true).await
    }

    /// Downloads, then verifies, the binary for `manifest`: a 200 body, or one
    /// redirect to a presigned blob URL fetched without credentials. The
    /// result is signature- and digest-verified against any pinned key.
    pub async fn fetch_module(
        &self,
        manifest: &ModuleManifest,
        bearer: Option<&str>,
    ) -> Result<VerifiedModule, FetchError> {
        let first = self
            .send(HubRequest {
                method: HubMethod::Get,
                url: &manifest.binary_url,
                bearer,
                if_none_match: None,
                json_body: None,
                max_response: self.max_binary_bytes,
            })
            .await?;
        let resp = match first.status {
            200 => first,
            301 | 302 | 303 | 307 | 308 => {
                let base = Url::parse(&manifest.binary_url)
                    .map_err(|e| FetchError::InvalidUrl(e.to_string()))?;
                let loc = first
                    .location
                    .ok_or_else(|| FetchError::InvalidUrl("redirect without Location".into()))?;
                let next = base
                    .join(&loc)
                    .map_err(|e| FetchError::InvalidUrl(e.to_string()))?;
                // Presigned URL: policy-checked like any other, but anonymous.
                let blob = self
                    .send_inner(
                        HubRequest {
                            method: HubMethod::Get,
                            url: next.as_str(),
                            bearer: None,
                            if_none_match: None,
                            json_body: None,
                            max_response: self.max_binary_bytes,
                        },
                        false,
                    )
                    .await?;
                if blob.status != 200 {
                    return Err(FetchError::Status(blob.status));
                }
                blob
            }
            other => return Err(FetchError::Status(other)),
        };
        self.verify_with_any_key(manifest, resp.body)
    }

    /// Picks the pinned key that signed the claimed id/version/sha256, then
    /// runs the full [`VerifiedModule::verify`] with it. Also used to
    /// re-verify cached binaries on load, so a tampered cache cannot run.
    pub fn verify_with_any_key(
        &self,
        manifest: &ModuleManifest,
        binary: Vec<u8>,
    ) -> Result<VerifiedModule, FetchError> {
        let sha = manifest.sha256.to_ascii_lowercase();
        let payload = signed_payload(&manifest.id, &manifest.version, &sha)?;
        let key = self
            .public_keys
            .iter()
            .find(|k| verify_signature(&payload, &manifest.signature, k).is_ok())
            .ok_or(VerificationError::InvalidSignature)?;
        Ok(VerifiedModule::verify(
            &manifest.id,
            &manifest.version,
            &ManifestClaims {
                id: &manifest.id,
                version: &manifest.version,
                sha256: &manifest.sha256,
                signature: &manifest.signature,
            },
            binary,
            key,
        )?)
    }

    /// Resolves `url`, applies scheme and network policy to every address and
    /// pins the first one so the HTTP client cannot re-resolve (rebinding).
    async fn check_target(&self, url: &str) -> Result<Target, FetchError> {
        let url = Url::parse(url).map_err(|e| FetchError::InvalidUrl(e.to_string()))?;
        if url.scheme() != "https" && !self.http_allowed(&url) {
            return Err(FetchError::InsecureScheme(url.scheme().to_string()));
        }
        let host = url
            .host()
            .ok_or_else(|| FetchError::InvalidUrl("missing host".into()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| FetchError::InvalidUrl("missing port".into()))?;
        let (name, addrs, is_domain) = match host {
            Host::Ipv4(a) => (a.to_string(), vec![IpAddr::V4(a)], false),
            Host::Ipv6(a) => (a.to_string(), vec![IpAddr::V6(a)], false),
            Host::Domain(d) => {
                let addrs = self
                    .resolver
                    .resolve(d)
                    .await
                    .map_err(|e| FetchError::Resolve(e.to_string()))?;
                (d.to_string(), addrs, true)
            }
        };
        let Some(first) = addrs.first().copied() else {
            return Err(FetchError::Resolve(format!("no addresses for {name}")));
        };
        // Every resolved address must pass, so a mixed answer cannot smuggle one in.
        if let Some(bad) = addrs
            .iter()
            .find(|ip| !self.policy.is_allowed(&name, Some(**ip)))
        {
            return Err(FetchError::PolicyDenied(format!("{name} -> {bad}")));
        }
        Ok(Target {
            url,
            host_name: name,
            pinned: SocketAddr::new(first, port),
            is_domain,
        })
    }

    /// Builds the pinned, redirect-less, proxy-less client for `target`.
    fn build_client(&self, target: &Target, with_identity: bool) -> Result<Client, FetchError> {
        crate::tls::ensure_crypto_provider();
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(redirect::Policy::none())
            .no_proxy();
        if target.is_domain {
            builder = builder.resolve(&target.host_name, target.pinned);
        }
        if !self.extra_root_pems.is_empty() {
            let mut roots = Vec::new();
            for pem in &self.extra_root_pems {
                roots.push(
                    reqwest::Certificate::from_pem(pem)
                        .map_err(|e| FetchError::Client(format!("bad root cert: {e}")))?,
                );
            }
            builder = builder.tls_certs_merge(roots);
        }
        if with_identity && let Some(pem) = &self.identity_pem {
            let id = Identity::from_pem(pem)
                .map_err(|e| FetchError::Client(format!("bad client identity: {e}")))?;
            builder = builder.identity(id);
        }
        builder
            .build()
            .map_err(|e| FetchError::Client(e.to_string()))
    }

    /// Shared request path; `with_identity` is false for presigned blob hosts.
    async fn send_inner(
        &self,
        req: HubRequest<'_>,
        with_identity: bool,
    ) -> Result<HubResponse, FetchError> {
        let target = self.check_target(req.url).await?;
        let client = self.build_client(&target, with_identity)?;
        let method = match req.method {
            HubMethod::Get => Method::GET,
            HubMethod::Post => Method::POST,
        };
        let mut headers = HeaderMap::new();
        if let Some(token) = req.bearer {
            let mut v = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| FetchError::Client("bearer token is not a valid header".into()))?;
            v.set_sensitive(true);
            headers.insert(AUTHORIZATION, v);
        }
        if let Some(etag) = req.if_none_match {
            let v = HeaderValue::from_str(etag)
                .map_err(|_| FetchError::Client("etag is not a valid header".into()))?;
            headers.insert(IF_NONE_MATCH, v);
        }
        let mut builder = client.request(method, target.url).headers(headers);
        if let Some(body) = req.json_body {
            builder = builder.header(CONTENT_TYPE, "application/json").body(body);
        }
        let mut resp = builder.send().await?;
        let status = resp.status().as_u16();
        let etag = header_string(resp.headers(), ETAG);
        let location = header_string(resp.headers(), LOCATION);
        let retry_after = header_string(resp.headers(), RETRY_AFTER)
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        if resp
            .content_length()
            .is_some_and(|n| n > req.max_response as u64)
        {
            return Err(FetchError::TooLarge(req.max_response));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > req.max_response {
                return Err(FetchError::TooLarge(req.max_response));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(HubResponse {
            status,
            etag,
            retry_after,
            location,
            body,
        })
    }

    #[cfg(test)]
    fn http_allowed(&self, url: &Url) -> bool {
        self.allow_http && url.scheme() == "http"
    }

    #[cfg(not(test))]
    fn http_allowed(&self, _url: &Url) -> bool {
        false
    }
}

/// Reads a header as an owned UTF-8 string, if present and valid.
fn header_string(headers: &HeaderMap, name: reqwest::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::super::verification::fixtures::*;
    use super::*;

    /// A canned route: path -> (status line, extra header block, body).
    type Route = (&'static str, &'static str, String, Vec<u8>);

    /// Serves canned routes and records the raw request text of every hit.
    async fn serve(routes: Vec<Route>) -> (u16, Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                if let Ok(mut g) = seen2.lock() {
                    g.push(req);
                }
                let (status, hdr, body) = routes
                    .iter()
                    .find(|r| r.0 == path)
                    .map(|r| (r.1, r.2.clone(), r.3.clone()))
                    .unwrap_or(("404 Not Found", String::new(), Vec::new()));
                let head = format!(
                    "HTTP/1.1 {status}\r\n{hdr}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
            }
        });
        (port, seen)
    }

    fn fetcher() -> HubFetcher {
        let mut f = HubFetcher::new(
            NetworkPolicy::default().with_loopback(true),
            vec![PUB_B_UNRELATED.into(), PUB_A.into()],
        );
        f.allow_http = true;
        f
    }

    /// A syntactically valid key that did not sign the fixtures.
    const PUB_B_UNRELATED: &str = "untrusted comment: other\nRWQLDA0ODxAREm9dsCNLFMArSiLVdTUjNwxpRFxjycKQO0YfnXTCNtqn6pswzQw7";

    fn manifest(url: String, sig: &str) -> ModuleManifest {
        ModuleManifest {
            id: "demo".into(),
            version: "1.0.0".into(),
            sha256: SHA.into(),
            signature: sig.into(),
            binary_url: url,
        }
    }

    fn get<'a>(url: &'a str, bearer: Option<&'a str>, inm: Option<&'a str>) -> HubRequest<'a> {
        HubRequest {
            method: HubMethod::Get,
            url,
            bearer,
            if_none_match: inm,
            json_body: None,
            max_response: 1024,
        }
    }

    #[tokio::test]
    async fn http_is_rejected_by_default() {
        let f = HubFetcher::new(NetworkPolicy::default().with_loopback(true), vec![]);
        let err = f.send(get("http://127.0.0.1:1/x", None, None)).await;
        assert!(matches!(err, Err(FetchError::InsecureScheme(_))), "{err:?}");
    }

    #[tokio::test]
    async fn conditional_get_sends_headers_and_surfaces_304_and_retry_after() {
        let (port, seen) = serve(vec![
            (
                "/nm",
                "304 Not Modified",
                "ETag: \"abc\"\r\n".into(),
                vec![],
            ),
            (
                "/rl",
                "429 Too Many Requests",
                "Retry-After: 42\r\n".into(),
                vec![],
            ),
        ])
        .await;
        let f = fetcher();
        let r = f
            .send(get(
                &format!("http://127.0.0.1:{port}/nm"),
                Some("tok123"),
                Some("\"abc\""),
            ))
            .await
            .expect("304");
        assert_eq!((r.status, r.etag.as_deref()), (304, Some("\"abc\"")));
        let req = seen.lock().expect("lock")[0].to_ascii_lowercase();
        assert!(req.contains("authorization: bearer tok123"), "{req}");
        assert!(req.contains("if-none-match: \"abc\""), "{req}");
        let r = f
            .send(get(&format!("http://127.0.0.1:{port}/rl"), None, None))
            .await
            .expect("429");
        assert_eq!(r.status, 429);
        assert_eq!(r.retry_after, Some(Duration::from_secs(42)));
    }

    #[tokio::test]
    async fn post_sends_json_body() {
        let (port, seen) = serve(vec![("/p", "204 No Content", String::new(), vec![])]).await;
        let r = fetcher()
            .send(HubRequest {
                method: HubMethod::Post,
                url: &format!("http://127.0.0.1:{port}/p"),
                bearer: None,
                if_none_match: None,
                json_body: Some(br#"{"a":1}"#.to_vec()),
                max_response: 1024,
            })
            .await
            .expect("post");
        assert_eq!(r.status, 204);
        let req = seen.lock().expect("lock")[0].to_ascii_lowercase();
        assert!(req.starts_with("post /p"), "{req}");
        assert!(req.contains("content-type: application/json"), "{req}");
        assert!(req.contains(r#"{"a":1}"#), "{req}");
    }

    #[tokio::test]
    async fn oversize_body_is_capped() {
        let (port, _) = serve(vec![("/big", "200 OK", String::new(), vec![0u8; 4096])]).await;
        let err = fetcher()
            .send(get(&format!("http://127.0.0.1:{port}/big"), None, None))
            .await;
        assert!(matches!(err, Err(FetchError::TooLarge(1024))), "{err:?}");
    }

    #[tokio::test]
    async fn valid_module_verifies_with_second_pinned_key() {
        let (port, _) = serve(vec![("/bin", "200 OK", String::new(), BINARY.to_vec())]).await;
        let m = manifest(format!("http://127.0.0.1:{port}/bin"), SIG_A);
        let v = fetcher().fetch_module(&m, Some("t")).await.expect("ok");
        assert_eq!(v.as_bytes(), BINARY);
    }

    #[tokio::test]
    async fn tampered_binary_and_bad_signature_are_rejected() {
        let (port, _) = serve(vec![(
            "/bin",
            "200 OK",
            String::new(),
            b"tampered".to_vec(),
        )])
        .await;
        let url = format!("http://127.0.0.1:{port}/bin");
        let err = fetcher()
            .fetch_module(&manifest(url.clone(), SIG_A), None)
            .await;
        assert!(
            matches!(
                err,
                Err(FetchError::Verification(VerificationError::HashMismatch))
            ),
            "{err:?}"
        );
        let err = fetcher().fetch_module(&manifest(url, SIG_B), None).await;
        assert!(
            matches!(
                err,
                Err(FetchError::Verification(
                    VerificationError::InvalidSignature
                ))
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn redirect_is_followed_without_credentials() {
        let (blob_port, blob_seen) =
            serve(vec![("/blob", "200 OK", String::new(), BINARY.to_vec())]).await;
        let (hub_port, _) = serve(vec![(
            "/bin",
            "302 Found",
            format!("Location: http://127.0.0.1:{blob_port}/blob\r\n"),
            vec![],
        )])
        .await;
        let m = manifest(format!("http://127.0.0.1:{hub_port}/bin"), SIG_A);
        let v = fetcher()
            .fetch_module(&m, Some("secret-jwt"))
            .await
            .expect("ok");
        assert_eq!(v.as_bytes(), BINARY);
        let req = blob_seen.lock().expect("lock")[0].to_ascii_lowercase();
        assert!(!req.contains("authorization"), "bearer leaked: {req}");
    }

    #[tokio::test]
    async fn redirect_edge_cases_fail_closed() {
        let (hub_port, _) = serve(vec![
            ("/noloc", "302 Found", String::new(), vec![]),
            ("/gone", "410 Gone", String::new(), vec![]),
            (
                "/evil",
                "302 Found",
                "Location: http://10.0.0.5/x\r\n".into(),
                vec![],
            ),
            (
                "/blob404",
                "302 Found",
                "Location: /nothing\r\n".into(),
                vec![],
            ),
        ])
        .await;
        let base = format!("http://127.0.0.1:{hub_port}");
        let f = fetcher();
        let e = f
            .fetch_module(&manifest(format!("{base}/noloc"), SIG_A), None)
            .await;
        assert!(matches!(e, Err(FetchError::InvalidUrl(_))), "{e:?}");
        let e = f
            .fetch_module(&manifest(format!("{base}/gone"), SIG_A), None)
            .await;
        assert!(matches!(e, Err(FetchError::Status(410))), "{e:?}");
        // Redirect into private space is refused by the policy (SSRF).
        let e = f
            .fetch_module(&manifest(format!("{base}/evil"), SIG_A), None)
            .await;
        assert!(matches!(e, Err(FetchError::PolicyDenied(_))), "{e:?}");
        let e = f
            .fetch_module(&manifest(format!("{base}/blob404"), SIG_A), None)
            .await;
        assert!(matches!(e, Err(FetchError::Status(404))), "{e:?}");
    }

    struct Fixed(IpAddr);
    #[async_trait::async_trait]
    impl Resolver for Fixed {
        async fn resolve(&self, _: &str) -> std::io::Result<Vec<IpAddr>> {
            Ok(vec![self.0])
        }
    }

    #[tokio::test]
    async fn hub_host_resolving_to_internal_ip_is_denied() {
        // regression: allowlisted hub FQDN rebinding to loopback/private/metadata.
        for bad in ["127.0.0.1", "10.0.0.5", "169.254.169.254"] {
            let policy = NetworkPolicy::new(vec!["hub.example".into()], vec![]).expect("policy");
            let f = HubFetcher::new(policy, vec![PUB_A.into()])
                .with_resolver(Arc::new(Fixed(bad.parse().expect("ip"))));
            let e = f.send(get("https://hub.example/api", None, None)).await;
            assert!(
                matches!(e, Err(FetchError::PolicyDenied(_))),
                "{bad}: {e:?}"
            );
        }
    }

    #[tokio::test]
    async fn host_outside_policy_and_bad_inputs_are_errors() {
        let f = HubFetcher::new(NetworkPolicy::default(), vec![PUB_A.into()]);
        let e = f.send(get("https://93.184.216.34/m", None, None)).await;
        assert!(matches!(e, Err(FetchError::PolicyDenied(_))), "{e:?}");
        let e = f.send(get("not a url", None, None)).await;
        assert!(matches!(e, Err(FetchError::InvalidUrl(_))), "{e:?}");
        let policy = NetworkPolicy::new(vec!["hub.example".into()], vec![]).expect("p");
        let f2 = HubFetcher::new(policy, vec![PUB_A.into()])
            .with_resolver(Arc::new(Fixed("93.184.216.34".parse().expect("ip"))));
        let e = f2
            .send(get("https://hub.example/", Some("bad\ntoken"), None))
            .await;
        assert!(matches!(e, Err(FetchError::Client(_))), "{e:?}");
        let e = f2
            .send(get("https://hub.example/", None, Some("bad\netag")))
            .await;
        assert!(matches!(e, Err(FetchError::Client(_))), "{e:?}");
    }
}
