//! Port of `pkg/forwarder`: a local `:53` DNS server that decodes incoming
//! UDP/TCP DNS messages, answers them via [`crate::doh::DohClient`], and
//! re-encodes a response — with the deadlock fixed and a real cache added.
//!
//! ## The deadlock (see `docs/PARITY.md` §1.15)
//!
//! Go's `Start(ctx)` binds its listeners and then **blocks** on a `select`
//! that only returns when `ctx` is cancelled. The squawk module calls it
//! synchronously from `Module.Start`, *while holding its own mutex*, using a
//! module-lifetime context cancelled only on unload — so with the forwarder
//! enabled, `Supervisor::load` never returns, and `Stop`/`Unload` then block
//! forever trying to take the mutex `Start` still holds (which is also what
//! would have cancelled the context and unblocked it). The Go test bounds
//! this with a 5-second context and asserts only that `Start` "completes
//! without panic" — it never asserts `Start` returns *promptly*, so the hang
//! reads as a pass.
//!
//! Here, [`Forwarder::start`] binds both sockets **synchronously** (so a
//! bind failure still surfaces immediately and honestly, not as a background
//! task's silent log line), then spawns the UDP/TCP serve loops as
//! background tasks and returns. It never blocks on serving.
//! [`Forwarder::stop`] signals those tasks via a [`CancellationToken`] and
//! awaits their exit, so the listening ports are guaranteed released before
//! `stop()` returns.
//!
//! ## The cache Go doesn't have
//!
//! Go's forwarder has no cache at all — every query round-trips upstream —
//! despite the module advertising `cache.enabled` and shipping `cache
//! stats`/`cache flush` commands that just print canned text. See
//! [`Cache`] for the real, TTL-respecting, bounded cache this port adds.
//!
//! ## Answer conversion fixes over Go's `convertAnswerToRR`
//!
//! * **MX priority**: Go's `dns.MX{Mx: ...}` never sets `Preference` — a
//!   `// Priority would need to be parsed from Data if available` TODO left
//!   in place. [`parse_mx_data`] actually parses it.
//! * **Per-answer name and type**: Go builds every returned RR using the
//!   *question's* type and owner name (`question.Qtype`, `question.Name`)
//!   for every entry in the answer list. That silently drops any answer
//!   whose own type differs from the question type — which is exactly what
//!   a CNAME chain looks like (a query for `A` on `www.example.com`
//!   commonly gets back a `CNAME` answer followed by an `A` answer owned by
//!   the CNAME's target, not by `www.example.com`). This port converts each
//!   answer using *its own* `type`/`name` fields instead, so CNAME chains
//!   survive the round trip and are correctly owned.

mod cache;

pub use cache::{Cache, CacheConfig, CacheStats, CachedAnswer};

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::doh::{DnsRecord, DohClient};

/// How long a single upstream DoH round trip (including its own internal
/// retries) is allowed before this forwarder gives up and answers
/// `SERVFAIL` — matches Go's `context.WithTimeout(context.Background(), 30
/// * time.Second)` around the `dohClient.Query` call.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);
/// Receive buffer for one UDP datagram. Comfortably larger than the
/// historical 512-byte no-EDNS limit; this forwarder does not implement
/// EDNS0 buffer-size negotiation or response truncation (`TC`), which is
/// out of scope here — a response that would not fit is simply written in
/// full, same as Go (which also implements no truncation logic).
const MAX_UDP_MESSAGE_SIZE: usize = 4096;

/// Listener configuration, ported from Go's `pkg/forwarder.Config`. Defaults
/// match the *forwarder package's own* nil-config fallback in
/// `NewForwarderWithMetrics` (`ListenUDP`/`ListenTCP: true`) rather than
/// `pkg/config.DefaultConfig`'s more conservative `false`/`false` — that
/// distinction belongs to the caller composing the module's overall config,
/// not to this type's own zero value.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub udp_address: String,
    #[serde(default = "default_bind_address")]
    pub tcp_address: String,
    #[serde(default = "default_listen")]
    pub listen_udp: bool,
    #[serde(default = "default_listen")]
    pub listen_tcp: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            udp_address: default_bind_address(),
            tcp_address: default_bind_address(),
            listen_udp: true,
            listen_tcp: true,
        }
    }
}

fn default_bind_address() -> String {
    "127.0.0.1:53".to_string()
}

fn default_listen() -> bool {
    true
}

/// Every way starting/stopping a [`Forwarder`] can fail.
#[derive(Debug, thiserror::Error)]
pub enum ForwarderError {
    #[error("forwarder is already running")]
    AlreadyRunning,
    #[error("forwarder is not running")]
    NotRunning,
    #[error("failed to bind UDP socket on {addr}: {source}")]
    UdpBind {
        addr: String,
        source: std::io::Error,
    },
    #[error("failed to bind TCP listener on {addr}: {source}")]
    TcpBind {
        addr: String,
        source: std::io::Error,
    },
}

struct RunState {
    cancel: Option<CancellationToken>,
    udp_task: Option<JoinHandle<()>>,
    tcp_task: Option<JoinHandle<()>>,
    udp_local_addr: Option<SocketAddr>,
    tcp_local_addr: Option<SocketAddr>,
}

/// The local `:53` DNS forwarder: decodes incoming UDP/TCP DNS messages,
/// answers via DoH (through [`Cache`] when possible), and re-encodes a
/// response. See the module doc comment for the two load-bearing departures
/// from the Go source.
pub struct Forwarder {
    doh: Arc<DohClient>,
    cache: Arc<Cache>,
    udp_address: String,
    tcp_address: String,
    listen_udp: bool,
    listen_tcp: bool,
    state: Mutex<RunState>,
}

impl Forwarder {
    pub fn new(doh: Arc<DohClient>, config: Config, cache_config: CacheConfig) -> Forwarder {
        Forwarder {
            doh,
            cache: Arc::new(Cache::new(cache_config)),
            udp_address: config.udp_address,
            tcp_address: config.tcp_address,
            listen_udp: config.listen_udp,
            listen_tcp: config.listen_tcp,
            state: Mutex::new(RunState {
                cancel: None,
                udp_task: None,
                tcp_task: None,
                udp_local_addr: None,
                tcp_local_addr: None,
            }),
        }
    }

    /// The answer cache backing this forwarder — for the module's `cache
    /// stats`/`cache flush` commands.
    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    /// Binds the configured listener(s) synchronously — a bind failure
    /// (e.g. the port is already in use) is returned immediately, never
    /// silently logged from a background task — then spawns their serve
    /// loops and returns. **Never blocks on serving**; see the module doc
    /// comment for why that is the entire point of this port.
    pub async fn start(&self) -> Result<(), ForwarderError> {
        if self.is_running() {
            return Err(ForwarderError::AlreadyRunning);
        }

        let cancel = CancellationToken::new();

        let mut udp_task = None;
        let mut udp_local_addr = None;
        if self.listen_udp {
            let socket = UdpSocket::bind(&self.udp_address).await.map_err(|source| {
                ForwarderError::UdpBind {
                    addr: self.udp_address.clone(),
                    source,
                }
            })?;
            udp_local_addr = socket.local_addr().ok();
            let doh = Arc::clone(&self.doh);
            let cache = Arc::clone(&self.cache);
            let task_cancel = cancel.clone();
            udp_task = Some(tokio::spawn(udp_serve_loop(
                socket,
                doh,
                cache,
                task_cancel,
            )));
        }

        let mut tcp_task = None;
        let mut tcp_local_addr = None;
        if self.listen_tcp {
            let listener = TcpListener::bind(&self.tcp_address)
                .await
                .map_err(|source| ForwarderError::TcpBind {
                    addr: self.tcp_address.clone(),
                    source,
                })?;
            tcp_local_addr = listener.local_addr().ok();
            let doh = Arc::clone(&self.doh);
            let cache = Arc::clone(&self.cache);
            let task_cancel = cancel.clone();
            tcp_task = Some(tokio::spawn(tcp_serve_loop(
                listener,
                doh,
                cache,
                task_cancel,
            )));
        }

        let mut state = self.lock_state();
        if state.cancel.is_some() {
            // Lost a race with a concurrent start() between the check above
            // and taking the lock. The sockets/tasks just created are
            // dropped here (closing the ports) rather than leaking.
            cancel.cancel();
            return Err(ForwarderError::AlreadyRunning);
        }
        state.cancel = Some(cancel);
        state.udp_task = udp_task;
        state.tcp_task = tcp_task;
        state.udp_local_addr = udp_local_addr;
        state.tcp_local_addr = tcp_local_addr;
        Ok(())
    }

    /// Signals the serve loops to stop and waits for them to fully exit, so
    /// both ports are guaranteed released before this returns.
    pub async fn stop(&self) -> Result<(), ForwarderError> {
        let (cancel, udp_task, tcp_task) = {
            let mut state = self.lock_state();
            let Some(cancel) = state.cancel.take() else {
                return Err(ForwarderError::NotRunning);
            };
            let udp_task = state.udp_task.take();
            let tcp_task = state.tcp_task.take();
            state.udp_local_addr = None;
            state.tcp_local_addr = None;
            (cancel, udp_task, tcp_task)
        };

        cancel.cancel();
        if let Some(task) = udp_task {
            let _ = task.await;
        }
        if let Some(task) = tcp_task {
            let _ = task.await;
        }

        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.lock_state().cancel.is_some()
    }

    /// The UDP socket's bound address once `start()` has succeeded — tests
    /// bind `"127.0.0.1:0"` and read this back to learn the ephemeral port.
    pub fn local_udp_addr(&self) -> Option<SocketAddr> {
        self.lock_state().udp_local_addr
    }

    pub fn local_tcp_addr(&self) -> Option<SocketAddr> {
        self.lock_state().tcp_local_addr
    }

    fn lock_state(&self) -> MutexGuard<'_, RunState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Accepts UDP datagrams until `cancel` fires, spawning a task per query so
/// one slow upstream lookup never blocks the next incoming datagram.
async fn udp_serve_loop(
    socket: UdpSocket,
    doh: Arc<DohClient>,
    cache: Arc<Cache>,
    cancel: CancellationToken,
) {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; MAX_UDP_MESSAGE_SIZE];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            result = socket.recv_from(&mut buf) => {
                let Ok((len, peer)) = result else { continue; };
                let request = buf[..len].to_vec();
                let socket = Arc::clone(&socket);
                let doh = Arc::clone(&doh);
                let cache = Arc::clone(&cache);
                let query_cancel = cancel.clone();
                tokio::spawn(async move {
                    let Some(response) = handle_query(&doh, &cache, &query_cancel, &request).await else {
                        return;
                    };
                    let _ = socket.send_to(&response, peer).await;
                });
            }
        }
    }
}

/// Accepts TCP connections until `cancel` fires, spawning a task per
/// connection.
async fn tcp_serve_loop(
    listener: TcpListener,
    doh: Arc<DohClient>,
    cache: Arc<Cache>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            result = listener.accept() => {
                let Ok((stream, _peer)) = result else { continue; };
                let doh = Arc::clone(&doh);
                let cache = Arc::clone(&cache);
                let connection_cancel = cancel.clone();
                tokio::spawn(async move {
                    serve_tcp_connection(stream, doh, cache, connection_cancel).await;
                });
            }
        }
    }
}

/// Serves one TCP connection: RFC 1035 §4.2.2 length-prefixed DNS messages,
/// looped until the peer closes the connection, `cancel` fires, or a
/// framing/decode error occurs.
async fn serve_tcp_connection(
    mut stream: TcpStream,
    doh: Arc<DohClient>,
    cache: Arc<Cache>,
    cancel: CancellationToken,
) {
    loop {
        let mut len_prefix = [0u8; 2];
        tokio::select! {
            _ = cancel.cancelled() => return,
            result = stream.read_exact(&mut len_prefix) => {
                if result.is_err() {
                    return;
                }
            }
        }

        let message_len = u16::from_be_bytes(len_prefix) as usize;
        let mut message = vec![0u8; message_len];
        if stream.read_exact(&mut message).await.is_err() {
            return;
        }

        let Some(response) = handle_query(&doh, &cache, &cancel, &message).await else {
            return;
        };
        let Ok(response_len) = u16::try_from(response.len()) else {
            return;
        };
        if stream.write_all(&response_len.to_be_bytes()).await.is_err() {
            return;
        }
        if stream.write_all(&response).await.is_err() {
            return;
        }
    }
}

/// Decodes one DNS message, resolves every question in it, and re-encodes
/// the response. `None` means the input didn't even decode as a DNS
/// message — deliberately dropped rather than answered, since there is no
/// reliable ID/opcode to build a response around (a real resolver's
/// message-framing layer would already have rejected it before it reached
/// application code; this forwarder is not a strict protocol validator).
async fn handle_query(
    doh: &DohClient,
    cache: &Cache,
    cancel: &CancellationToken,
    raw: &[u8],
) -> Option<Vec<u8>> {
    let request = Message::from_vec(raw).ok()?;

    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.recursion_available = true;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.add_queries(request.queries.iter().cloned());

    for query in &request.queries {
        resolve_one(doh, cache, cancel, query, &mut response).await;
    }

    response.to_vec().ok()
}

/// Resolves one question into `response`'s answer section (cache first,
/// then DoH on a miss), or sets a deliberate response code when it can't:
/// `NOTIMP` for a query type this forwarder doesn't convert at all,
/// `SERVFAIL` for an upstream/timeout/cancellation failure, `NXDOMAIN` when
/// DoH itself reports `Status == 3`.
async fn resolve_one(
    doh: &DohClient,
    cache: &Cache,
    cancel: &CancellationToken,
    query: &Query,
    response: &mut Message,
) {
    let Some(record_type) = supported_type_name(query.query_type()) else {
        tracing::warn!(
            query_type = ?query.query_type(),
            name = %query.name(),
            "unsupported query type; responding NOTIMP"
        );
        response.metadata.response_code = ResponseCode::NotImp;
        return;
    };

    let name_ascii = query.name().to_ascii();

    if let Some(cached) = cache.get(&name_ascii, record_type) {
        apply_doh_answer(cached.status, &cached.answers, response);
        return;
    }

    let lookup = doh.query(cancel, &name_ascii, record_type);
    let Ok(outcome) = tokio::time::timeout(UPSTREAM_TIMEOUT, lookup).await else {
        response.metadata.response_code = ResponseCode::ServFail;
        return;
    };
    let Ok(doh_response) = outcome else {
        response.metadata.response_code = ResponseCode::ServFail;
        return;
    };

    cache.insert(
        &name_ascii,
        record_type,
        doh_response.status,
        &doh_response.answer,
    );
    apply_doh_answer(doh_response.status, &doh_response.answer, response);
}

/// The record types this forwarder can convert into a DNS resource record —
/// matches Go's exact conversion set (A, AAAA, CNAME, MX, TXT, NS). A query
/// for any other type gets `NOTIMP` rather than a misleadingly-empty
/// `NOERROR`, since we genuinely cannot answer it, not merely choosing not
/// to.
fn supported_type_name(record_type: RecordType) -> Option<&'static str> {
    if record_type == RecordType::A {
        return Some("A");
    }
    if record_type == RecordType::AAAA {
        return Some("AAAA");
    }
    if record_type == RecordType::CNAME {
        return Some("CNAME");
    }
    if record_type == RecordType::MX {
        return Some("MX");
    }
    if record_type == RecordType::TXT {
        return Some("TXT");
    }
    if record_type == RecordType::NS {
        return Some("NS");
    }
    None
}

/// Applies a DoH JSON response's status/answers to `response`: maps DoH
/// `Status == 3` to `NXDOMAIN` and any other non-zero status to `SERVFAIL`
/// (matching Go), otherwise converts and appends every answer this
/// forwarder knows how to represent.
fn apply_doh_answer(status: i32, answers: &[DnsRecord], response: &mut Message) {
    if status == 3 {
        response.metadata.response_code = ResponseCode::NXDomain;
        return;
    }
    if status != 0 {
        response.metadata.response_code = ResponseCode::ServFail;
        return;
    }
    for answer in answers {
        if let Some(record) = convert_answer_to_record(answer) {
            response.add_answer(record);
        }
    }
}

/// Converts one DoH JSON answer into a DNS resource record, using *that
/// answer's own* `name`/`type` fields — see the module doc comment for why
/// that (not the question's type/owner name, which is what Go's
/// `convertAnswerToRR` uses) is necessary for CNAME chains to survive.
/// Returns `None` — logged, not silently swallowed — when the owner name
/// doesn't parse or the type isn't one of the six this forwarder converts.
fn convert_answer_to_record(answer: &DnsRecord) -> Option<Record> {
    let Ok(owner) = Name::from_ascii(&answer.name) else {
        tracing::warn!(name = %answer.name, "answer owner name failed to parse; dropping this answer");
        return None;
    };
    let ttl = clamp_ttl(answer.ttl);
    let type_str = answer.kind.as_type_str().to_ascii_uppercase();

    if type_str == "A" {
        let Ok(ip) = answer.data.parse::<Ipv4Addr>() else {
            return None;
        };
        return Some(Record::from_rdata(owner, ttl, RData::A(A(ip))));
    }
    if type_str == "AAAA" {
        let Ok(ip) = answer.data.parse::<Ipv6Addr>() else {
            return None;
        };
        return Some(Record::from_rdata(owner, ttl, RData::AAAA(AAAA(ip))));
    }
    if type_str == "CNAME" {
        let Ok(target) = Name::from_ascii(&answer.data) else {
            return None;
        };
        return Some(Record::from_rdata(owner, ttl, RData::CNAME(CNAME(target))));
    }
    if type_str == "NS" {
        let Ok(target) = Name::from_ascii(&answer.data) else {
            return None;
        };
        return Some(Record::from_rdata(owner, ttl, RData::NS(NS(target))));
    }
    if type_str == "MX" {
        let (preference, exchange) = parse_mx_data(&answer.data)?;
        return Some(Record::from_rdata(
            owner,
            ttl,
            RData::MX(MX::new(preference, exchange)),
        ));
    }
    if type_str == "TXT" {
        let txt = TXT::try_new(std::iter::once(answer.data.as_bytes())).ok()?;
        return Some(Record::from_rdata(owner, ttl, RData::TXT(txt)));
    }

    tracing::warn!(
        record_type = %type_str,
        name = %answer.name,
        "unsupported answer record type; dropping this answer"
    );
    None
}

/// Parses a DoH MX answer's `data` field (`"<preference> <exchange>"`) into
/// its two parts. **Fixes a Go TODO**: `pkg/forwarder`'s `convertAnswerToRR`
/// builds `dns.MX{Mx: ...}` and leaves `Preference` at its zero value with a
/// `// Priority would need to be parsed from Data if available` comment —
/// every MX record forwarded through Go's implementation silently reports
/// priority 0 regardless of what the server actually returned.
///
/// A missing preference prefix or a preference that isn't a valid `u16`
/// both degrade to preference `0` with a logged warning, rather than
/// failing the whole answer — the exchange name is still useful to the
/// client even when the preference can't be parsed.
fn parse_mx_data(data: &str) -> Option<(u16, Name)> {
    let trimmed = data.trim();
    let Some((preference_str, exchange_str)) = trimmed.split_once(char::is_whitespace) else {
        tracing::warn!(data = %trimmed, "MX answer has no preference prefix; defaulting preference to 0");
        let exchange = Name::from_ascii(trimmed).ok()?;
        return Some((0, exchange));
    };

    let preference: u16 = match preference_str.parse() {
        Ok(value) => value,
        Err(_) => {
            tracing::warn!(data = %trimmed, "MX preference is not a valid u16; defaulting to 0");
            0
        }
    };
    let exchange = Name::from_ascii(exchange_str.trim()).ok()?;
    Some((preference, exchange))
}

/// Clamps a possibly out-of-range signed TTL into a DNS RR's unsigned
/// 32-bit TTL field — matches Go's `safeUint32`.
fn clamp_ttl(ttl: i64) -> u32 {
    if ttl < 0 {
        0
    } else if ttl > u32::MAX as i64 {
        u32::MAX
    } else {
        ttl as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doh::RecordKind;

    fn record(name: &str, kind: &str, ttl: i64, data: &str) -> DnsRecord {
        DnsRecord {
            name: name.to_string(),
            kind: RecordKind::Text(kind.to_string()),
            ttl,
            data: data.to_string(),
        }
    }

    #[test]
    fn convert_a_record() {
        let rr = convert_answer_to_record(&record("example.com.", "A", 300, "192.0.2.1")).unwrap();
        assert_eq!(rr.record_type(), RecordType::A);
        assert_eq!(rr.ttl, 300);
    }

    #[test]
    fn convert_aaaa_record() {
        let rr =
            convert_answer_to_record(&record("example.com.", "AAAA", 300, "2001:db8::1")).unwrap();
        assert_eq!(rr.record_type(), RecordType::AAAA);
    }

    #[test]
    fn convert_uses_the_answers_own_name_not_a_borrowed_owner() {
        // Models a CNAME chain: the A record's owner is the CNAME target,
        // not the originally-queried name.
        let rr =
            convert_answer_to_record(&record("target.example.net.", "A", 60, "192.0.2.9")).unwrap();
        assert_eq!(rr.name.to_ascii(), "target.example.net.");
    }

    #[test]
    fn convert_mx_record_parses_preference() {
        let rr =
            convert_answer_to_record(&record("example.com.", "MX", 300, "10 mail.example.com."))
                .unwrap();
        let RData::MX(mx) = &rr.data else {
            panic!("expected RData::MX, got {:?}", rr.data);
        };
        assert_eq!(mx.preference, 10);
        assert_eq!(mx.exchange.to_ascii(), "mail.example.com.");
    }

    #[test]
    fn parse_mx_data_defaults_to_zero_on_missing_preference() {
        let (preference, exchange) = parse_mx_data("mail.example.com.").unwrap();
        assert_eq!(preference, 0);
        assert_eq!(exchange.to_ascii(), "mail.example.com.");
    }

    #[test]
    fn parse_mx_data_defaults_to_zero_on_unparseable_preference() {
        let (preference, exchange) = parse_mx_data("not-a-number mail.example.com.").unwrap();
        assert_eq!(preference, 0);
        assert_eq!(exchange.to_ascii(), "mail.example.com.");
    }

    #[test]
    fn convert_txt_record() {
        let rr =
            convert_answer_to_record(&record("example.com.", "TXT", 300, "hello world")).unwrap();
        let RData::TXT(txt) = &rr.data else {
            panic!("expected RData::TXT, got {:?}", rr.data);
        };
        assert_eq!(txt.txt_data[0].as_ref(), b"hello world");
    }

    #[test]
    fn convert_unsupported_type_returns_none() {
        assert!(
            convert_answer_to_record(&record("example.com.", "SOA", 300, "irrelevant")).is_none()
        );
    }

    #[test]
    fn convert_a_record_with_unparseable_ip_returns_none() {
        assert!(convert_answer_to_record(&record("example.com.", "A", 300, "not-an-ip")).is_none());
    }

    #[test]
    fn supported_type_name_covers_the_six_converted_types() {
        assert_eq!(supported_type_name(RecordType::A), Some("A"));
        assert_eq!(supported_type_name(RecordType::AAAA), Some("AAAA"));
        assert_eq!(supported_type_name(RecordType::CNAME), Some("CNAME"));
        assert_eq!(supported_type_name(RecordType::MX), Some("MX"));
        assert_eq!(supported_type_name(RecordType::TXT), Some("TXT"));
        assert_eq!(supported_type_name(RecordType::NS), Some("NS"));
        assert_eq!(supported_type_name(RecordType::SOA), None);
    }

    #[test]
    fn clamp_ttl_handles_negative_and_overflow() {
        assert_eq!(clamp_ttl(-5), 0);
        assert_eq!(clamp_ttl(300), 300);
        assert_eq!(clamp_ttl(i64::MAX), u32::MAX);
    }

    #[test]
    fn apply_doh_answer_maps_status_codes() {
        let mut nxdomain = Message::query();
        apply_doh_answer(3, &[], &mut nxdomain);
        assert_eq!(nxdomain.metadata.response_code, ResponseCode::NXDomain);

        let mut servfail = Message::query();
        apply_doh_answer(2, &[], &mut servfail);
        assert_eq!(servfail.metadata.response_code, ResponseCode::ServFail);

        let mut noerror = Message::query();
        apply_doh_answer(
            0,
            &[record("example.com.", "A", 300, "192.0.2.1")],
            &mut noerror,
        );
        assert_eq!(noerror.metadata.response_code, ResponseCode::NoError);
        assert_eq!(noerror.answers.len(), 1);
    }
}
