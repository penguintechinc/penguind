//! A bounded per-source ring buffer of log lines with a live-tail broadcast,
//! backing a real `TailLogs` RPC. The Go daemon returns `Unimplemented` for
//! `TailLogs` (see `go-client/internal/daemon/server.go`); this is what makes
//! it implementable.
//!
//! A "source" is a module name, with the empty string reserved for the
//! daemon's own log. Sources are fully independent: appending to one never
//! affects another's backlog or subscribers.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::SystemTime;

use tokio::sync::broadcast;

/// One log record: a timestamp, level, and message.
///
/// Mirrors the three fields the daemon proto's `TailLogs` response streams
/// (`at_unix_nano`, `level`, `message`); the wire conversion to/from that
/// proto type lives with the gRPC service, not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// When the line was recorded.
    pub at: SystemTime,
    /// The log level as a lowercase string (`"info"`, `"error"`, ...).
    pub level: String,
    /// The log message text.
    pub message: String,
}

/// The receiving half of a follow-mode (live-tail) subscription.
pub type LogReceiver = broadcast::Receiver<LogLine>;

/// One source's ring buffer plus its live-tail fan-out.
struct SourceLog {
    lines: VecDeque<LogLine>,
    tail: broadcast::Sender<LogLine>,
}

impl SourceLog {
    /// Creates an empty ring with a live-tail channel sized to `capacity`
    /// (or 1, whichever is larger — `broadcast::channel` panics on 0).
    fn new(capacity: usize) -> SourceLog {
        let (tail, _receiver) = broadcast::channel(capacity.max(1));
        SourceLog {
            lines: VecDeque::with_capacity(capacity),
            tail,
        }
    }
}

/// A bounded ring buffer of log lines per source, with live-tail
/// subscriptions.
///
/// Every source gets its own ring capped at the same `capacity`; once a
/// source's ring is full, appending drops the oldest line
/// ([`VecDeque::pop_front`]).
pub struct LogRing {
    capacity: usize,
    sources: Mutex<HashMap<String, SourceLog>>,
}

impl LogRing {
    /// Creates a ring holding up to `capacity` lines per source.
    pub fn new(capacity: usize) -> LogRing {
        LogRing {
            capacity,
            sources: Mutex::new(HashMap::new()),
        }
    }

    /// Appends one line to `source`'s ring and its live-tail subscribers,
    /// creating the source's ring on first use.
    ///
    /// Non-blocking for the same reason as [`crate::broker::EventBroker::publish`]:
    /// logging call sites may hold other locks, so this must never wait on a
    /// slow subscriber. The mutex here only ever guards a cheap in-memory
    /// map/deque mutation, never I/O, so it is held for a bounded, tiny time.
    pub fn append(&self, source: &str, line: LogLine) {
        let mut sources = self.sources.lock().expect("log ring mutex poisoned");
        let entry = source_entry(&mut sources, source, self.capacity);

        if entry.lines.len() >= self.capacity {
            entry.lines.pop_front();
        }
        entry.lines.push_back(line.clone());
        let _ = entry.tail.send(line);
    }

    /// Returns the most recent `lines` entries for `source`, oldest first.
    ///
    /// Returns fewer than `lines` if the source has fewer entries (including
    /// zero for a source that has never been appended to, or does not
    /// exist), and returns all of them if `lines` exceeds the ring's length.
    pub fn backlog(&self, source: &str, lines: usize) -> Vec<LogLine> {
        let sources = self.sources.lock().expect("log ring mutex poisoned");
        let Some(entry) = sources.get(source) else {
            return Vec::new();
        };

        let skip = entry.lines.len().saturating_sub(lines);
        let mut result = Vec::with_capacity(entry.lines.len() - skip);
        for line in entry.lines.iter().skip(skip) {
            result.push(line.clone());
        }
        result
    }

    /// Subscribes to future appends on `source` (follow mode), creating the
    /// source's ring on first use. The returned receiver sees nothing
    /// appended before this call.
    pub fn subscribe(&self, source: &str) -> LogReceiver {
        let mut sources = self.sources.lock().expect("log ring mutex poisoned");
        let entry = source_entry(&mut sources, source, self.capacity);
        entry.tail.subscribe()
    }
}

/// Returns a mutable handle to `source`'s ring within `sources`, inserting a
/// fresh empty one first if this is the first time `source` has been seen.
fn source_entry<'sources>(
    sources: &'sources mut HashMap<String, SourceLog>,
    source: &str,
    capacity: usize,
) -> &'sources mut SourceLog {
    if !sources.contains_key(source) {
        sources.insert(source.to_string(), SourceLog::new(capacity));
    }
    sources.get_mut(source).expect("just inserted above")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a log line with `message` set; the timestamp and level are
    /// fixed since these tests only care about ordering and identity.
    fn line(message: &str) -> LogLine {
        LogLine {
            at: SystemTime::now(),
            level: "info".to_string(),
            message: message.to_string(),
        }
    }

    fn messages(lines: &[LogLine]) -> Vec<&str> {
        lines.iter().map(|l| l.message.as_str()).collect()
    }

    #[test]
    fn append_then_backlog_returns_them_chronologically() {
        let ring = LogRing::new(10);
        ring.append("squawk", line("one"));
        ring.append("squawk", line("two"));
        ring.append("squawk", line("three"));

        assert_eq!(
            messages(&ring.backlog("squawk", 10)),
            vec!["one", "two", "three"]
        );
    }

    #[test]
    fn backlog_with_n_less_than_len_returns_the_last_n() {
        let ring = LogRing::new(10);
        for msg in ["a", "b", "c", "d"] {
            ring.append("squawk", line(msg));
        }

        assert_eq!(messages(&ring.backlog("squawk", 2)), vec!["c", "d"]);
    }

    #[test]
    fn backlog_with_n_greater_than_len_returns_all_of_them() {
        let ring = LogRing::new(10);
        ring.append("squawk", line("only"));

        assert_eq!(messages(&ring.backlog("squawk", 99)), vec!["only"]);
    }

    #[test]
    fn overflow_drops_the_oldest_line() {
        let ring = LogRing::new(2);
        ring.append("squawk", line("a"));
        ring.append("squawk", line("b"));
        ring.append("squawk", line("c"));

        assert_eq!(messages(&ring.backlog("squawk", 10)), vec!["b", "c"]);
    }

    #[test]
    fn sources_are_isolated_from_each_other() {
        let ring = LogRing::new(10);
        ring.append("squawk", line("squawk-line"));
        ring.append("waddles-gateway", line("waddles-gateway-line"));

        assert_eq!(messages(&ring.backlog("squawk", 10)), vec!["squawk-line"]);
        assert_eq!(
            messages(&ring.backlog("waddles-gateway", 10)),
            vec!["waddles-gateway-line"]
        );
    }

    #[test]
    fn backlog_for_an_unknown_source_is_empty() {
        let ring = LogRing::new(10);
        assert!(ring.backlog("never-appended", 10).is_empty());
    }

    #[test]
    fn empty_source_name_works_for_the_daemon_log() {
        let ring = LogRing::new(10);
        ring.append("", line("daemon started"));

        assert_eq!(messages(&ring.backlog("", 10)), vec!["daemon started"]);
    }

    #[tokio::test]
    async fn a_follow_subscriber_receives_appends_after_subscribing() {
        let ring = LogRing::new(10);
        ring.append("squawk", line("before"));

        let mut sub = ring.subscribe("squawk");
        ring.append("squawk", line("after"));

        assert_eq!(sub.recv().await.unwrap().message, "after");
    }
}
