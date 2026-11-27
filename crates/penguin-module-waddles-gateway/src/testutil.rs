//! Test doubles shared by this crate's test modules: a minimal
//! [`HostServices`] implementation (mirroring
//! `penguin-module-tobogganing`'s own `FakeHost`) and a path-routed mock
//! HTTP server standing in for the waddlebot hub.
//!
//! `MockHub` is intentionally the same shape as
//! `penguin-module-tobogganing::testutil::MockManager` (and, more distantly,
//! `waddles-client`'s own `tests/mock_http`): a bare
//! `tokio::net::TcpListener` rather than a mocking crate, extended with
//! per-route response queues since this crate's commands drive several
//! distinct hub paths across one test. A real [`waddles_client::WaddlesClient`]
//! is built against this server's `base_url` in every test — the crate's own
//! integration tests already prove a plain `reqwest` client happily talks
//! `http://` to a mock without any TLS involved, so there is no need for a
//! second, fake client implementation here.
//!
//! Only compiled for tests (`#[cfg(test)] mod testutil;` in `lib.rs`), so
//! nothing here ships in the built module.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use penguin_sdk::{
    Event, EventSink, HostServices, LicenseChecker, LogLevel, Logger, Metrics, MetricsError,
    SecretError, SecretStore,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

/// A trivial in-memory [`SecretStore`].
#[derive(Default)]
pub struct InMemorySecretStore {
    values: Mutex<HashMap<String, Vec<u8>>>,
}

#[async_trait]
impl SecretStore for InMemorySecretStore {
    async fn get(&self, key: &str) -> Result<Vec<u8>, SecretError> {
        self.values
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or(SecretError::NotFound)
    }

    async fn set(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
        self.values
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_vec());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), SecretError> {
        let mut values = self.values.lock().unwrap();
        values.remove(key).map(|_| ()).ok_or(SecretError::NotFound)
    }
}

/// A [`Logger`] that discards every record.
#[derive(Default)]
pub struct NoopLogger;

impl Logger for NoopLogger {
    fn log(&self, _level: LogLevel, _message: &str, _fields: &[(&str, &str)]) {}
}

/// A [`Logger`] recording every emitted record as one rendered line
/// (`"LEVEL message key=value ..."`), so a test can assert on log content —
/// chiefly the bridge's tests proving a Community Access Token never reaches
/// a log line, not just a response body.
#[derive(Default)]
pub struct RecordingLogger {
    lines: Mutex<Vec<String>>,
}

impl Logger for RecordingLogger {
    fn log(&self, level: LogLevel, message: &str, fields: &[(&str, &str)]) {
        let mut rendered = format!("{} {message}", level.as_str());
        for (key, value) in fields {
            rendered.push_str(&format!(" {key}={value}"));
        }
        self.lines.lock().unwrap().push(rendered);
    }
}

impl RecordingLogger {
    /// Every rendered line recorded so far, in order.
    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }
}

/// A [`LicenseChecker`] double reporting everything enabled — waddlebot's
/// `info().license_feature` is empty, so nothing in this crate actually
/// consults this, but every [`HostServices`] implementation needs one.
pub struct FakeLicenseChecker {
    pub feature_enabled: bool,
    pub tier: String,
}

impl Default for FakeLicenseChecker {
    fn default() -> FakeLicenseChecker {
        FakeLicenseChecker {
            feature_enabled: true,
            tier: "professional".to_string(),
        }
    }
}

impl LicenseChecker for FakeLicenseChecker {
    fn feature_enabled(&self, _key: &str) -> bool {
        self.feature_enabled
    }

    fn tier(&self) -> String {
        self.tier.clone()
    }
}

/// An [`EventSink`] recording every published event.
#[derive(Default)]
pub struct FakeEventSink {
    events: Mutex<Vec<Event>>,
}

impl EventSink for FakeEventSink {
    fn publish(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// A [`Metrics`] registerer backed by a fresh, private
/// `prometheus::Registry` — every test gets its own registry, so tests never
/// collide over duplicate collector names.
pub struct RecordingMetrics {
    registry: prometheus::Registry,
}

impl Default for RecordingMetrics {
    fn default() -> RecordingMetrics {
        RecordingMetrics {
            registry: prometheus::Registry::new(),
        }
    }
}

impl Metrics for RecordingMetrics {
    fn register(
        &self,
        collector: Box<dyn prometheus::core::Collector>,
    ) -> Result<(), MetricsError> {
        self.registry
            .register(collector)
            .map_err(|err| MetricsError(err.to_string()))
    }
}

/// A minimal [`HostServices`] test double. `config` is a plain public field
/// tests set directly before wrapping this in an `Arc<dyn HostServices>`.
pub struct FakeHost {
    pub config: Vec<u8>,
    pub secrets: Arc<InMemorySecretStore>,
    /// Defaults to [`NoopLogger`]; a test swaps in an [`Arc<RecordingLogger>`]
    /// (cloning it first) when it needs to assert on log content.
    pub logger: Arc<dyn Logger>,
    license: Arc<FakeLicenseChecker>,
    metrics: Arc<RecordingMetrics>,
    data_dir: PathBuf,
    events: Arc<FakeEventSink>,
}

impl FakeHost {
    /// Builds a fake host rooted at `data_dir` (a test's own `TempDir`),
    /// with no config set yet.
    pub fn new(data_dir: PathBuf) -> FakeHost {
        FakeHost {
            config: Vec::new(),
            secrets: Arc::new(InMemorySecretStore::default()),
            logger: Arc::new(NoopLogger),
            license: Arc::new(FakeLicenseChecker::default()),
            metrics: Arc::new(RecordingMetrics::default()),
            data_dir,
            events: Arc::new(FakeEventSink::default()),
        }
    }
}

impl HostServices for FakeHost {
    fn logger(&self) -> Arc<dyn Logger> {
        self.logger.clone()
    }

    fn secrets(&self) -> Arc<dyn SecretStore> {
        self.secrets.clone()
    }

    fn license(&self) -> Arc<dyn LicenseChecker> {
        self.license.clone()
    }

    fn metrics(&self) -> Arc<dyn Metrics> {
        self.metrics.clone()
    }

    fn config(&self) -> Vec<u8> {
        self.config.clone()
    }

    fn data_dir(&self) -> PathBuf {
        self.data_dir.clone()
    }

    fn events(&self) -> Arc<dyn EventSink> {
        self.events.clone()
    }
}

/// One canned HTTP response [`MockHub`] hands back for a route.
#[derive(Debug, Clone)]
pub struct MockResponse {
    status: u16,
    body: String,
}

impl MockResponse {
    pub fn json(status: u16, body: impl Into<String>) -> MockResponse {
        MockResponse {
            status,
            body: body.into(),
        }
    }
}

/// One request [`MockHub`] received, for assertions.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    /// Request-line target including any query string.
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

impl RecordedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// Parses the recorded body as JSON — for asserting a write endpoint
    /// (`music settings`, `music station add`, ...) sent the expected
    /// fields.
    pub fn json_body(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).expect("recorded request body must be valid JSON")
    }
}

/// `(method, path-without-query) -> queued responses`.
type RouteMap = HashMap<(String, String), VecDeque<MockResponse>>;
type RouteTable = Arc<AsyncMutex<RouteMap>>;

/// A minimal mock hub server: understands just enough HTTP/1.1 to receive
/// one request per connection and route it by `(method, path-without-query)`
/// to a queue of canned [`MockResponse`]s, repeating the last queued
/// response forever once exhausted. An unmatched route answers 404, so a
/// test only needs to seed the paths it actually exercises.
pub struct MockHub {
    pub base_url: String,
    accept_loop: Option<JoinHandle<()>>,
    routes: RouteTable,
    requests: Arc<AsyncMutex<Vec<RecordedRequest>>>,
}

impl MockHub {
    /// Starts a server with no routes registered yet.
    pub async fn start() -> MockHub {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock hub listener");
        let base_url = format!("http://{}", listener.local_addr().expect("local addr"));

        let routes: RouteTable = Arc::new(AsyncMutex::new(HashMap::new()));
        let requests = Arc::new(AsyncMutex::new(Vec::new()));

        let routes_for_loop = Arc::clone(&routes);
        let requests_for_loop = Arc::clone(&requests);
        let accept_loop = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let routes = Arc::clone(&routes_for_loop);
                let requests = Arc::clone(&requests_for_loop);
                tokio::spawn(async move {
                    serve_one(stream, &routes, &requests).await;
                });
            }
        });

        MockHub {
            base_url,
            accept_loop: Some(accept_loop),
            routes,
            requests,
        }
    }

    /// A `base_url` bound to a port nothing is listening on — the listener
    /// is created (to reserve a real, otherwise-unused port) then
    /// immediately dropped, so a connection attempt fails fast instead of
    /// hanging.
    pub async fn unreachable_base_url() -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind throwaway listener");
        let base_url = format!("http://{}", listener.local_addr().expect("local addr"));
        drop(listener);
        base_url
    }

    /// Queues `response` as the next answer for `method`/`path` (exact
    /// match, no query string). The last response queued for a route
    /// repeats forever once the queue is exhausted.
    pub async fn respond(&self, method: &str, path: &str, response: MockResponse) {
        let mut routes = self.routes.lock().await;
        routes
            .entry((method.to_string(), path.to_string()))
            .or_default()
            .push_back(response);
    }

    /// Every request received so far, in order.
    pub async fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().await.clone()
    }

    /// How many requests matched `method`/`path` (path prefix before any
    /// `?`) so far.
    pub async fn request_count(&self, method: &str, path: &str) -> usize {
        self.requests
            .lock()
            .await
            .iter()
            .filter(|req| req.method == method && path_without_query(&req.path) == path)
            .count()
    }

    /// Stops accepting connections and waits for the accept loop to exit.
    pub async fn stop(mut self) {
        let Some(handle) = self.accept_loop.take() else {
            return;
        };
        handle.abort();
        let _ = handle.await;
    }
}

impl Drop for MockHub {
    fn drop(&mut self) {
        if let Some(handle) = self.accept_loop.take() {
            handle.abort();
        }
    }
}

fn path_without_query(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

async fn serve_one(
    stream: TcpStream,
    routes: &AsyncMutex<RouteMap>,
    requests: &AsyncMutex<Vec<RecordedRequest>>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let mut request_line = String::new();
    let Ok(bytes_read) = reader.read_line(&mut request_line).await else {
        return;
    };
    if bytes_read == 0 {
        return;
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

    let mut body_bytes = vec![0u8; content_length];
    if content_length > 0 && reader.read_exact(&mut body_bytes).await.is_err() {
        return;
    }
    let body = String::from_utf8_lossy(&body_bytes).into_owned();

    let key = (method.clone(), path_without_query(&path).to_string());
    let response = {
        let mut routes = routes.lock().await;
        match routes.get_mut(&key) {
            Some(queue) if queue.len() > 1 => queue.pop_front().unwrap(),
            Some(queue) => queue.front().cloned().unwrap(),
            None => MockResponse {
                status: 404,
                body: r#"{"error":"not found"}"#.to_string(),
            },
        }
    };

    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        status_text(response.status),
        response.body.len(),
    );
    let _ = writer.write_all(head.as_bytes()).await;
    let _ = writer.write_all(response.body.as_bytes()).await;
    let _ = writer.shutdown().await;

    requests.lock().await.push(RecordedRequest {
        method,
        path,
        headers,
        body,
    });
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
        _ => "Status",
    }
}
