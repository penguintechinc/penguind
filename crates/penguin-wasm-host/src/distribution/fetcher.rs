//! Downloads a module manifest + binary over pinned, policy-checked HTTPS and
//! returns it only as a [`VerifiedModule`].

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Client, redirect};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

use super::network_gatekeeper::NetworkPolicy;
use super::verification::{ManifestClaims, VerificationError, VerifiedModule};

/// Hard cap on the manifest body.
pub const MAX_MANIFEST_BYTES: usize = 1 << 20;
/// Default hard cap on the binary body.
pub const DEFAULT_MAX_BINARY_BYTES: usize = 64 << 20;

/// Fetch failures; verification failures are never downgraded to warnings.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The HTTP request failed.
    #[error("network request failed: {0}")]
    Request(#[from] reqwest::Error),
    /// The HTTP client could not be built.
    #[error("client setup failed: {0}")]
    Client(String),
    /// The URL is malformed or has no host.
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    /// Only `https` is accepted.
    #[error("insecure url scheme `{0}`; https required")]
    InsecureScheme(String),
    /// DNS resolution failed or returned nothing.
    #[error("dns resolution failed: {0}")]
    Resolve(String),
    /// The network policy refused the host or a resolved address.
    #[error("network policy denied {0}")]
    PolicyDenied(String),
    /// The server answered with a non-success status (redirects are not followed).
    #[error("unexpected http status {0}")]
    Status(u16),
    /// The body exceeded its hard size cap.
    #[error("response body exceeds {0} bytes")]
    TooLarge(usize),
    /// The manifest is not valid JSON of the expected shape.
    #[error("bad manifest: {0}")]
    BadManifest(String),
    /// The downloaded module failed verification.
    #[error("module verification failed: {0}")]
    Verification(#[from] VerificationError),
}

/// The signed description of a published module (untrusted until verified).
#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleManifest {
    /// Module id.
    pub id: String,
    /// Module version.
    pub version: String,
    /// Lowercase-hex SHA-256 of the binary.
    pub sha256: String,
    /// Minisign signature over `signed_payload(id, version, sha256)`.
    pub signature: String,
    /// Where the binary lives.
    pub binary_url: String,
}

/// DNS lookup seam so rebinding can be tested without a network.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolves `host` to its addresses.
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}

struct SystemResolver;

#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok(tokio::net::lookup_host((host, 0))
            .await?
            .map(|a| a.ip())
            .collect())
    }
}

/// Fetches module artifacts over HTTPS under a [`NetworkPolicy`] and a pinned
/// minisign public key.
pub struct GitHubFetcher {
    policy: NetworkPolicy,
    public_key: String,
    max_binary_bytes: usize,
    resolver: Arc<dyn Resolver>,
    #[cfg(test)]
    allow_http: bool,
}

impl GitHubFetcher {
    /// Builds a fetcher pinned to `public_key` (minisign pubkey text) and
    /// bound by `policy` for every request.
    pub fn new(policy: NetworkPolicy, public_key: String) -> Self {
        Self {
            policy,
            public_key,
            max_binary_bytes: DEFAULT_MAX_BINARY_BYTES,
            resolver: Arc::new(SystemResolver),
            #[cfg(test)]
            allow_http: false,
        }
    }

    /// Overrides the binary size cap.
    pub fn with_max_binary_bytes(mut self, max: usize) -> Self {
        self.max_binary_bytes = max;
        self
    }

    /// Fetches the manifest and binary, then verifies that the pinned key
    /// signed exactly `expected_id`/`expected_version`/sha256 of the binary.
    pub async fn fetch_module(
        &self,
        manifest_url: &str,
        expected_id: &str,
        expected_version: &str,
    ) -> Result<VerifiedModule, FetchError> {
        let raw = self.get_capped(manifest_url, MAX_MANIFEST_BYTES).await?;
        let manifest: ModuleManifest =
            serde_json::from_slice(&raw).map_err(|e| FetchError::BadManifest(e.to_string()))?;
        let binary = self
            .get_capped(&manifest.binary_url, self.max_binary_bytes)
            .await?;
        Ok(VerifiedModule::verify(
            expected_id,
            expected_version,
            &ManifestClaims {
                id: &manifest.id,
                version: &manifest.version,
                sha256: &manifest.sha256,
                signature: &manifest.signature,
            },
            binary,
            &self.public_key,
        )?)
    }

    /// GETs `url`: https only, policy-checked on every resolved IP, connection
    /// pinned to the checked IP, no redirects, no proxy, streamed with a cap.
    async fn get_capped(&self, url: &str, max: usize) -> Result<Vec<u8>, FetchError> {
        let url = Url::parse(url).map_err(|e| FetchError::InvalidUrl(e.to_string()))?;
        let scheme_ok = url.scheme() == "https" || self.http_allowed(&url);
        if !scheme_ok {
            return Err(FetchError::InsecureScheme(url.scheme().to_string()));
        }
        let host = url
            .host()
            .ok_or_else(|| FetchError::InvalidUrl("missing host".into()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| FetchError::InvalidUrl("missing port".into()))?;
        let (name, addrs) = match host {
            Host::Ipv4(a) => (a.to_string(), vec![IpAddr::V4(a)]),
            Host::Ipv6(a) => (a.to_string(), vec![IpAddr::V6(a)]),
            Host::Domain(d) => {
                let addrs = self
                    .resolver
                    .resolve(d)
                    .await
                    .map_err(|e| FetchError::Resolve(e.to_string()))?;
                (d.to_string(), addrs)
            }
        };
        if addrs.is_empty() {
            return Err(FetchError::Resolve(format!("no addresses for {name}")));
        }
        // Every resolved address must pass, so a mixed answer cannot smuggle one in.
        if let Some(bad) = addrs
            .iter()
            .find(|ip| !self.policy.is_allowed(&name, Some(**ip)))
        {
            return Err(FetchError::PolicyDenied(format!("{name} -> {bad}")));
        }

        crate::tls::ensure_crypto_provider();
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(redirect::Policy::none())
            .no_proxy();
        if matches!(host, Host::Domain(_)) {
            // Connect to the IP we just checked; the client re-resolving would reopen rebinding.
            builder = builder.resolve(&name, SocketAddr::new(addrs[0], port));
        }
        let client = builder
            .build()
            .map_err(|e| FetchError::Client(e.to_string()))?;

        let mut resp = client.get(url).send().await?;
        if !resp.status().is_success() {
            return Err(FetchError::Status(resp.status().as_u16()));
        }
        if resp.content_length().is_some_and(|n| n > max as u64) {
            return Err(FetchError::TooLarge(max));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > max {
                return Err(FetchError::TooLarge(max));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
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

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::super::verification::fixtures::*;
    use super::*;

    /// Serves canned `(status line, extra headers, body)` per request path.
    async fn serve(routes: Vec<(&'static str, &'static str, String, Vec<u8>)>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
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
        port
    }

    fn local_fetcher() -> GitHubFetcher {
        let policy = NetworkPolicy::default().with_loopback(true);
        let mut f = GitHubFetcher::new(policy, PUB_A.to_string());
        f.allow_http = true;
        f
    }

    fn manifest(port: u16, version: &str, sig: &str) -> Vec<u8> {
        serde_json::to_vec(&ModuleManifest {
            id: "demo".into(),
            version: version.into(),
            sha256: SHA.into(),
            signature: sig.into(),
            binary_url: format!("http://127.0.0.1:{port}/bin"),
        })
        .expect("json")
    }

    /// Starts a server for a manifest (which must embed its own port) plus binary.
    async fn module_server(version: &str, sig: &str, bin: Vec<u8>) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = l.local_addr().expect("addr").port();
        drop(l);
        let m = manifest(port, version, sig);
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("rebind");
        drop(listener);
        serve_on(
            port,
            vec![
                ("/m", "200 OK", String::new(), m),
                ("/bin", "200 OK", String::new(), bin),
            ],
        )
        .await;
        port
    }

    async fn serve_on(port: u16, routes: Vec<(&'static str, &'static str, String, Vec<u8>)>) {
        let listener = TcpListener::bind(("127.0.0.1", port)).await.expect("bind");
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let r = routes.iter().find(|r| r.0 == path);
                let (status, body) = r
                    .map(|r| (r.1, r.3.clone()))
                    .unwrap_or(("404 Not Found", vec![]));
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
            }
        });
    }

    #[tokio::test]
    async fn http_url_is_rejected_by_default() {
        let f = GitHubFetcher::new(NetworkPolicy::default().with_loopback(true), PUB_A.into());
        let err = f
            .fetch_module("http://127.0.0.1:1/m", "demo", "1.0.0")
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::InsecureScheme(_)), "{err:?}");
    }

    #[tokio::test]
    async fn valid_module_round_trips() {
        let port = module_server("1.0.0", SIG_A, BINARY.to_vec()).await;
        let m = local_fetcher()
            .fetch_module(&format!("http://127.0.0.1:{port}/m"), "demo", "1.0.0")
            .await
            .expect("fetch");
        assert_eq!(m.as_bytes(), BINARY);
    }

    #[tokio::test]
    async fn replayed_and_badly_signed_modules_fail() {
        let port = module_server("1.0.0", SIG_A, BINARY.to_vec()).await;
        let url = format!("http://127.0.0.1:{port}/m");
        let replay = local_fetcher()
            .fetch_module(&url, "demo", "2.0.0")
            .await
            .unwrap_err();
        assert!(matches!(
            replay,
            FetchError::Verification(VerificationError::ManifestMismatch)
        ));
        let port = module_server("1.0.0", SIG_B, BINARY.to_vec()).await;
        let bad = local_fetcher()
            .fetch_module(&format!("http://127.0.0.1:{port}/m"), "demo", "1.0.0")
            .await
            .unwrap_err();
        assert!(matches!(
            bad,
            FetchError::Verification(VerificationError::InvalidSignature)
        ));
    }

    #[tokio::test]
    async fn oversize_body_is_capped() {
        let port = serve(vec![("/big", "200 OK", String::new(), vec![0u8; 4096])]).await;
        let f = local_fetcher();
        let err = f
            .get_capped(&format!("http://127.0.0.1:{port}/big"), 100)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::TooLarge(100)), "{err:?}");
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let port = serve(vec![(
            "/r",
            "302 Found",
            "Location: http://127.0.0.1:1/x\r\n".into(),
            vec![],
        )])
        .await;
        let err = local_fetcher()
            .get_capped(&format!("http://127.0.0.1:{port}/r"), 100)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Status(302)), "{err:?}");
    }

    struct Fixed(IpAddr);
    #[async_trait]
    impl Resolver for Fixed {
        async fn resolve(&self, _: &str) -> std::io::Result<Vec<IpAddr>> {
            Ok(vec![self.0])
        }
    }

    #[tokio::test]
    async fn dns_rebinding_to_internal_ip_is_denied() {
        // regression: allowlisted FQDN that resolves to loopback/private/metadata.
        for bad in ["127.0.0.1", "10.0.0.5", "169.254.169.254"] {
            let policy = NetworkPolicy::new(vec!["good.example".into()], vec![]).expect("policy");
            let mut f = GitHubFetcher::new(policy, PUB_A.into());
            f.resolver = Arc::new(Fixed(bad.parse().expect("ip")));
            let err = f
                .fetch_module("https://good.example/m", "demo", "1.0.0")
                .await
                .unwrap_err();
            assert!(matches!(err, FetchError::PolicyDenied(_)), "{bad}: {err:?}");
        }
    }

    #[tokio::test]
    async fn host_outside_policy_is_denied() {
        let f = GitHubFetcher::new(NetworkPolicy::default(), PUB_A.into());
        let err = f
            .fetch_module("https://93.184.216.34/m", "demo", "1.0.0")
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::PolicyDenied(_)), "{err:?}");
    }
}
