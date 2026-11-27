//! A minimal, single-purpose mock HTTP/1.1 server for exercising
//! [`waddlebot_client::WaddlebotClient`] without a real network call.
//!
//! Extends the shape of squawk-client's `tests/mock_http` (a bare
//! `tokio::net::TcpListener` rather than a mocking crate, so this crate's
//! `cargo tree -i ring` gate only ever accounts for waddlebot-client's own
//! dependency graph) with one addition: this copy also records the request
//! *body*, not just method/path/headers — waddlebot-client's write
//! endpoints need to be tested for round-tripping their JSON body, which
//! squawk-client's DoH/license clients never needed to assert on.
//!
//! Shared verbatim (via `mod mock_http;`) by every integration test binary
//! in this crate — each binary compiles its own copy, and no single binary
//! exercises every helper here, so `dead_code` warnings are expected and
//! allowed rather than a sign of genuinely unused code.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

/// One canned HTTP response the mock server hands back for a request.
pub struct MockResponse {
    status: u16,
    body: String,
}

impl MockResponse {
    pub fn json(status: u16, body: &str) -> Self {
        MockResponse {
            status,
            body: body.to_string(),
        }
    }

    pub fn text(status: u16, body: &str) -> Self {
        MockResponse {
            status,
            body: body.to_string(),
        }
    }
}

/// One request the mock server received, for assertions.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    /// The request-line target, including any query string
    /// (`/admin/1/music/radio-stations?page=2&limit=10`).
    pub path: String,
    /// Header names lowercased, values as sent.
    pub headers: HashMap<String, String>,
    /// The raw request body, empty when none was sent.
    pub body: Vec<u8>,
}

impl RecordedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// Parses the recorded body as JSON, for asserting a write endpoint
    /// sent the expected fields.
    pub fn json_body(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("recorded request body must be valid JSON")
    }
}

/// A running mock server bound to an ephemeral localhost port.
pub struct MockServer {
    pub base_url: String,
    accept_loop: Option<JoinHandle<()>>,
    calls: Arc<AtomicUsize>,
    requests: Arc<AsyncMutex<Vec<RecordedRequest>>>,
}

impl MockServer {
    /// Starts a server that hands back `responses[call_index]` for the Nth
    /// accepted connection, repeating the last entry forever once the list
    /// is exhausted.
    pub async fn start(responses: Vec<MockResponse>) -> MockServer {
        assert!(
            !responses.is_empty(),
            "MockServer needs at least one response"
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server listener");
        let base_url = format!("http://{}", listener.local_addr().expect("local addr"));

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_loop = Arc::clone(&calls);
        let responses = Arc::new(responses);
        let requests = Arc::new(AsyncMutex::new(Vec::new()));
        let requests_for_loop = Arc::clone(&requests);

        let accept_loop = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let responses = Arc::clone(&responses);
                let calls = Arc::clone(&calls_for_loop);
                let requests = Arc::clone(&requests_for_loop);
                tokio::spawn(async move {
                    let index = calls.fetch_add(1, Ordering::SeqCst);
                    let response = &responses[index.min(responses.len() - 1)];
                    if let Some(recorded) = serve_one(stream, response).await {
                        requests.lock().await.push(recorded);
                    }
                });
            }
        });

        MockServer {
            base_url,
            accept_loop: Some(accept_loop),
            calls,
            requests,
        }
    }

    /// A base URL bound to a port nothing is listening on — the listener is
    /// created (to reserve a real, otherwise-unused port) then immediately
    /// dropped, so a connection attempt fails fast instead of hanging.
    pub async fn unreachable_base_url() -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind throwaway listener");
        let base_url = format!("http://{}", listener.local_addr().expect("local addr"));
        drop(listener);
        base_url
    }

    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub async fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().await.clone()
    }

    /// Stops accepting connections and waits for the accept loop to fully
    /// exit, so the port is guaranteed closed before this returns.
    pub async fn stop(mut self) {
        let Some(handle) = self.accept_loop.take() else {
            return;
        };
        handle.abort();
        let _ = handle.await;
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(handle) = self.accept_loop.take() {
            handle.abort();
        }
    }
}

/// Reads one HTTP/1.1 request off `stream` (request line, headers, and an
/// optional `Content-Length` body — the body is captured, not discarded),
/// writes `response`, and closes the connection. Returns `None` if the
/// connection closed before a full request line arrived (e.g. a bare TCP
/// probe).
async fn serve_one(stream: TcpStream, response: &MockResponse) -> Option<RecordedRequest> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let mut request_line = String::new();
    let bytes_read = reader.read_line(&mut request_line).await.ok()?;
    if bytes_read == 0 {
        return None;
    }
    let mut parts = request_line.trim_end().splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        let Ok(bytes_read) = reader.read_line(&mut line).await else {
            break;
        };
        if bytes_read == 0 || line == "\r\n" {
            break;
        }
        let trimmed = line.trim_end();
        let Some((name, value)) = trimmed.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        if name == "content-length" {
            content_length = value.parse().unwrap_or(0);
        }
        headers.insert(name, value);
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        let _ = reader.read_exact(&mut body).await;
    }

    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        status_text(response.status),
        response.body.len(),
    );
    let _ = writer.write_all(head.as_bytes()).await;
    let _ = writer.write_all(response.body.as_bytes()).await;
    let _ = writer.shutdown().await;

    Some(RecordedRequest {
        method,
        path,
        headers,
        body,
    })
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Status",
    }
}
