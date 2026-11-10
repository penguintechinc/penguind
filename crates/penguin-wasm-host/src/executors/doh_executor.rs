//! `doh_query`: DNS-over-HTTPS lookups via the JSON API (`application/dns-json`).

use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use serde_json::Value;
use url::Url;

use super::ToolExecutor;

/// Resolver used unless the host configures another.
pub const DEFAULT_DOH_ENDPOINT: &str = "https://cloudflare-dns.com/dns-query";
/// Largest DoH response body accepted.
pub const MAX_DOH_RESPONSE_BYTES: usize = 64 * 1024;
/// Record types a module may ask for.
const QUERY_TYPES: [&str; 6] = ["A", "AAAA", "CNAME", "MX", "TXT", "SRV"];

/// Backs `doh_query` with an HTTPS JSON-DoH resolver. The endpoint is fixed by
/// the host, never by the guest, so a module cannot aim it at arbitrary hosts.
pub struct DohQueryExecutor {
    client: Client,
    endpoint: Url,
}

impl DohQueryExecutor {
    /// Builds an executor for `endpoint`. Plain `http` is accepted only for
    /// loopback hosts (local resolvers and tests); anything else needs `https`.
    pub fn new(endpoint: &str) -> Result<Self, String> {
        let endpoint = Url::parse(endpoint).map_err(|e| format!("bad DoH endpoint: {e}"))?;
        let loopback = matches!(
            endpoint.host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]")
        );
        match endpoint.scheme() {
            "https" => {}
            "http" if loopback => {}
            other => return Err(format!("DoH endpoint scheme {other} is not allowed")),
        }
        crate::tls::ensure_crypto_provider();
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("DoH client setup failed: {e}"))?;
        Ok(Self { client, endpoint })
    }
}

/// Checks a DNS name: 1..=253 bytes of letters, digits, `.`, `-`, `_`.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

#[async_trait]
impl ToolExecutor for DohQueryExecutor {
    fn id(&self) -> &str {
        "doh_query"
    }

    async fn execute(&self, args: Value) -> Result<Value, String> {
        let name = args["name"].as_str().unwrap_or("");
        if !valid_name(name) {
            return Err("invalid DNS name".into());
        }
        let qtype = args["query_type"].as_str().unwrap_or("").to_uppercase();
        if !QUERY_TYPES.contains(&qtype.as_str()) {
            return Err(format!("unsupported query_type {qtype:?}"));
        }
        let mut url = self.endpoint.clone();
        url.query_pairs_mut()
            .append_pair("name", name)
            .append_pair("type", &qtype);
        let mut resp = self
            .client
            .get(url)
            .header("accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| format!("DoH request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("DoH resolver returned {}", resp.status()));
        }
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| format!("DoH read failed: {e}"))?
        {
            if body.len() + chunk.len() > MAX_DOH_RESPONSE_BYTES {
                return Err("DoH response too large".into());
            }
            body.extend_from_slice(&chunk);
        }
        let parsed: Value =
            serde_json::from_slice(&body).map_err(|e| format!("DoH response not JSON: {e}"))?;
        if parsed.is_object() {
            Ok(parsed)
        } else {
            Err("DoH response was not a JSON object".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Serves one canned HTTP response on loopback and returns the endpoint
    /// plus a handle yielding the request line the server saw.
    fn serve(status: &str, body: String) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let status = status.to_string();
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 2048];
            let n = sock.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let resp = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/dns-json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes());
            req.lines().next().unwrap_or("").to_string()
        });
        (
            format!("http://127.0.0.1:{}/dns-query", addr.port()),
            handle,
        )
    }

    #[test]
    fn endpoint_scheme_rules() {
        assert!(DohQueryExecutor::new("https://dns.example/dns-query").is_ok());
        assert!(DohQueryExecutor::new("http://127.0.0.1:1/x").is_ok());
        assert!(DohQueryExecutor::new("http://dns.example/x").is_err());
        assert!(DohQueryExecutor::new("ftp://127.0.0.1/x").is_err());
        assert!(DohQueryExecutor::new("not a url").is_err());
        assert!(DohQueryExecutor::new(DEFAULT_DOH_ENDPOINT).is_ok());
    }

    #[tokio::test]
    async fn resolves_through_the_json_api() {
        let (ep, req) = serve(
            "200 OK",
            r#"{"Status":0,"Answer":[{"data":"1.2.3.4"}]}"#.into(),
        );
        let e = DohQueryExecutor::new(&ep).expect("exec");
        let out = e
            .execute(json!({"name":"a.example","query_type":"a"}))
            .await
            .expect("ok");
        assert_eq!(out["Answer"][0]["data"], "1.2.3.4");
        let line = req.join().expect("join");
        assert!(
            line.contains("name=a.example") && line.contains("type=A"),
            "{line}"
        );
    }

    #[tokio::test]
    async fn rejects_bad_input_before_any_request() {
        let e = DohQueryExecutor::new("http://127.0.0.1:1/dns-query").expect("exec");
        assert!(
            e.execute(json!({"name":"","query_type":"A"}))
                .await
                .is_err()
        );
        assert!(
            e.execute(json!({"name":"bad name","query_type":"A"}))
                .await
                .is_err()
        );
        assert!(
            e.execute(json!({"name":"a.example","query_type":"ANY"}))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn resolver_failures_are_errors() {
        let (ep, h) = serve("500 Internal Server Error", "{}".into());
        let e = DohQueryExecutor::new(&ep).expect("exec");
        let err = e
            .execute(json!({"name":"a.example","query_type":"A"}))
            .await
            .expect_err("500");
        assert!(err.contains("500"), "{err}");
        let _ = h.join();

        let (ep, h) = serve("200 OK", "not json".into());
        let e = DohQueryExecutor::new(&ep).expect("exec");
        assert!(
            e.execute(json!({"name":"a.example","query_type":"A"}))
                .await
                .is_err()
        );
        let _ = h.join();

        let (ep, h) = serve("200 OK", "[1]".into());
        let e = DohQueryExecutor::new(&ep).expect("exec");
        assert!(
            e.execute(json!({"name":"a.example","query_type":"A"}))
                .await
                .is_err()
        );
        let _ = h.join();

        let (ep, h) = serve("200 OK", "x".repeat(MAX_DOH_RESPONSE_BYTES + 10));
        let e = DohQueryExecutor::new(&ep).expect("exec");
        let err = e
            .execute(json!({"name":"a.example","query_type":"A"}))
            .await
            .expect_err("big");
        assert!(err.contains("too large"), "{err}");
        let _ = h.join();

        let e = DohQueryExecutor::new("http://127.0.0.1:1/dns-query").expect("exec");
        assert!(
            e.execute(json!({"name":"a.example","query_type":"A"}))
                .await
                .is_err()
        );
    }
}
