//! [`DenylistCache`]: the on-disk, persisted copy of WaddleAI's Tier-1
//! denylist snapshot — the one piece of local state this module evaluates
//! against, and only when the server can't be reached.
//!
//! # Why this is not "policy logic"
//!
//! [`DenylistCache::contains`] is an exact-match lookup against entries the
//! server itself produced and this crate only ever stores verbatim (see
//! [`crate::client::WaddleAiClient::fetch_denylist`]) — it replays the
//! server's own last-synced answer for one specific subject, never
//! evaluates a rule this crate invented. Everything not on the cached list
//! is reported as "no cached answer", not silently allowed; see
//! `crate::commands::hook_command`'s doc for how that combines with each
//! ecosystem's own hook contract to fail closed.
//!
//! # Staleness
//!
//! A cache that is never refreshed is a real failure mode: a pattern added
//! to the server's denylist after the last successful sync would never be
//! enforced offline, and silently trusting a months-old snapshot forever
//! hides that gap from the operator. [`DenylistCache::is_stale`] flags a
//! snapshot older than `max_age` (surfaced through
//! `crate::module::WaddleAiModule::status`/`health`); once stale, this
//! crate stops treating "not on the list" as informative at all and the
//! `hook` command degrades exactly the same way it would with an empty
//! cache — see `crate::commands`.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fsutil;

/// How stale a cached denylist may be before [`DenylistCache::is_stale`]
/// reports it untrustworthy for the offline fail-closed path. 24 hours
/// bounds this to "missed at most one working day of sync attempts";
/// `crate::config::DenylistSection::max_age_secs` lets an operator narrow
/// or widen it.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// The persisted denylist snapshot: the entries themselves, the server's
/// opaque version token, and when this crate last synced them successfully.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenylistCache {
    /// The server's opaque version/etag for this snapshot; display-only.
    #[serde(default)]
    pub version: String,
    /// The denylist entries, verbatim from the server.
    #[serde(default)]
    pub entries: Vec<String>,
    /// Unix seconds of the last successful sync; `None` means never synced
    /// (a fresh install, or every sync attempt has failed so far).
    #[serde(default)]
    pub synced_at_unix: Option<u64>,
}

impl DenylistCache {
    /// A cache with no entries and no recorded sync — the state every fresh
    /// install starts from.
    pub fn empty() -> DenylistCache {
        DenylistCache::default()
    }

    /// The last successful sync time, if any.
    pub fn synced_at(&self) -> Option<SystemTime> {
        self.synced_at_unix
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs))
    }

    /// How long ago the cache was last synced, relative to `now`. `None`
    /// when never synced, or when the recorded sync time is somehow in the
    /// future (clock skew) — both are treated as "age unknown", which
    /// [`DenylistCache::is_stale`] maps to "stale".
    pub fn age(&self, now: SystemTime) -> Option<Duration> {
        self.synced_at()
            .and_then(|synced| now.duration_since(synced).ok())
    }

    /// Never synced, or last synced longer ago than `max_age`.
    pub fn is_stale(&self, now: SystemTime, max_age: Duration) -> bool {
        match self.age(now) {
            Some(age) => age > max_age,
            None => true,
        }
    }

    /// Whether `subject` matches any cached denylist pattern using
    /// case-insensitive glob search (`*`, `**`, `?` anywhere in `subject`) —
    /// see [`glob_search`].
    pub fn contains(&self, subject: &str) -> bool {
        self.entries
            .iter()
            .any(|pattern| glob_search(pattern, subject))
    }

    /// Flattens `tool_input` into its string leaves and returns the first
    /// cached denylist pattern that matches via [`glob_search`], if any.
    pub fn matches_tool_input(&self, tool_input: &Value) -> Option<&str> {
        let text = flatten_tool_input_text(tool_input);
        if text.is_empty() {
            return None;
        }
        self.entries
            .iter()
            .find(|pattern| glob_search(pattern, &text))
            .map(String::as_str)
    }

    /// Records a fresh successful sync, replacing the previous snapshot
    /// wholesale (the server's list is authoritative; this crate never
    /// merges old and new entries).
    pub fn record_sync(&mut self, version: String, entries: Vec<String>, now: SystemTime) {
        self.version = version;
        self.entries = entries;
        self.synced_at_unix = now.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
    }
}

/// Flattens all string leaf values in `tool_input` into one `\x1f`-delimited
/// string, matching `waddleai/shared/security/hooks_denylist.py`.
pub fn flatten_tool_input_text(tool_input: &Value) -> String {
    fn collect(val: &Value, out: &mut Vec<String>) {
        match val {
            Value::String(s) if !s.is_empty() => out.push(s.clone()),
            Value::Array(items) => {
                for item in items {
                    collect(item, out);
                }
            }
            Value::Object(map) => {
                for v in map.values() {
                    collect(v, out);
                }
            }
            _ => {}
        }
    }
    let mut leaves = Vec::new();
    collect(tool_input, &mut leaves);
    leaves.join("\x1f")
}

/// Case-insensitive shell-glob-like substring search (`*`, `**`, `?`),
/// matching `waddleai/shared/security/hooks_denylist.py::glob_search`.
/// `*` and `**` both match zero or more characters; `?` matches any single
/// character; matching is unanchored (searches anywhere in `text`).
pub fn glob_search(pattern: &str, text: &str) -> bool {
    if pattern.is_empty() || text.is_empty() {
        return false;
    }
    let pat: Vec<char> = pattern.chars().flat_map(char::to_lowercase).collect();
    let txt: Vec<char> = text.chars().flat_map(char::to_lowercase).collect();
    // Collapse consecutive `*` so `**` behaves identically to `*`.
    let mut collapsed = Vec::with_capacity(pat.len());
    for ch in pat {
        if ch == '*' && collapsed.last() == Some(&'*') {
            continue;
        }
        collapsed.push(ch);
    }

    // Standard two-pointer wildcard match for `*<collapsed>*` against `txt`.
    // Trying every start index in `txt` keeps unanchored semantics exact and
    // O(pat.len() * txt.len()) worst-case.
    for start in 0..txt.len() {
        if glob_match_prefix(&collapsed, &txt[start..]) {
            return true;
        }
    }
    false
}

fn glob_match_prefix(pat: &[char], txt: &[char]) -> bool {
    let (mut pi, mut ti) = (0, 0);
    let mut star_pi: Option<usize> = None;
    let mut star_ti: usize = 0;

    while pi < pat.len() {
        if pat[pi] == '*' {
            // Trailing `*` matches the rest of `txt`.
            if pi + 1 == pat.len() {
                return true;
            }
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if ti < txt.len() && (pat[pi] == '?' || pat[pi] == txt[ti]) {
            pi += 1;
            ti += 1;
        } else if let Some(sp) = star_pi {
            star_ti += 1;
            if star_ti > txt.len() {
                return false;
            }
            ti = star_ti;
            pi = sp + 1;
        } else {
            return false;
        }
    }
    true
}

/// Loads a [`DenylistCache`] from `path`. A missing file yields
/// [`DenylistCache::empty`] (not an error — every fresh install starts
/// here); a present-but-malformed file is an error, since silently
/// discarding it would also silently discard the `synced_at` staleness
/// signal.
pub fn load(path: &Path) -> Result<DenylistCache, std::io::Error> {
    match std::fs::read(path) {
        Ok(bytes) if bytes.is_empty() => Ok(DenylistCache::empty()),
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(DenylistCache::empty()),
        Err(err) => Err(err),
    }
}

/// Persists `cache` to `path` atomically via [`fsutil::write_atomic`].
pub fn save(path: &Path, cache: &DenylistCache) -> Result<(), std::io::Error> {
    let bytes = serde_json::to_vec_pretty(cache)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    fsutil::write_atomic(path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cache_has_no_entries_and_is_stale() {
        let cache = DenylistCache::empty();
        assert!(cache.entries.is_empty());
        assert!(cache.is_stale(SystemTime::now(), DEFAULT_MAX_AGE));
        assert_eq!(cache.age(SystemTime::now()), None);
    }

    #[test]
    fn contains_matches_glob_patterns_case_insensitively() {
        let mut cache = DenylistCache::empty();
        cache.record_sync(
            "1".to_string(),
            vec![
                "rm -rf /".to_string(),
                ".env*".to_string(),
                ".git/**".to_string(),
                "*.pem".to_string(),
            ],
            SystemTime::now(),
        );
        assert!(cache.contains("rm -rf /"));
        assert!(cache.contains("RM -RF /"));
        assert!(cache.contains("cat .env.production"));
        assert!(cache.contains("echo hi > .git/hooks/pre-commit"));
        assert!(cache.contains("openssl x509 -in server.PEM"));
        assert!(!cache.contains("ls -la src/main.rs"));
    }

    #[test]
    fn matches_tool_input_flattens_nested_strings_and_applies_globs() {
        let mut cache = DenylistCache::empty();
        cache.record_sync(
            "2".to_string(),
            vec![
                ".env*".to_string(),
                ".git/**".to_string(),
                "*.pem".to_string(),
            ],
            SystemTime::now(),
        );
        let input = serde_json::json!({
            "command": "cat",
            "args": ["--file", "/repo/.env.local"],
            "meta": {"cwd": "/repo"}
        });
        assert_eq!(cache.matches_tool_input(&input), Some(".env*"));

        let git_input = serde_json::json!({"file_path": "/repo/.git/config"});
        assert_eq!(cache.matches_tool_input(&git_input), Some(".git/**"));

        let pem_input = serde_json::json!({"path": "certs/client.pem"});
        assert_eq!(cache.matches_tool_input(&pem_input), Some("*.pem"));

        let safe_input = serde_json::json!({"file_path": "src/lib.rs"});
        assert_eq!(cache.matches_tool_input(&safe_input), None);
    }

    #[test]
    fn is_stale_respects_max_age() {
        let mut cache = DenylistCache::empty();
        let now = SystemTime::now();
        cache.record_sync("1".to_string(), vec![], now);
        assert!(!cache.is_stale(now, Duration::from_secs(60)));
        let later = now + Duration::from_secs(120);
        assert!(cache.is_stale(later, Duration::from_secs(60)));
    }

    #[test]
    fn load_of_a_missing_file_is_an_empty_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("denylist.json");
        let cache = load(&path).expect("load succeeds on a missing file");
        assert_eq!(cache, DenylistCache::empty());
    }

    #[test]
    fn load_of_a_malformed_file_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("denylist.json");
        std::fs::write(&path, b"not json").unwrap();
        assert!(load(&path).is_err());
    }

    #[test]
    fn save_then_load_round_trips_exactly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("denylist.json");
        let mut cache = DenylistCache::empty();
        cache.record_sync(
            "3".to_string(),
            vec!["a".to_string(), "b".to_string()],
            SystemTime::now(),
        );

        save(&path, &cache).expect("save succeeds");
        let loaded = load(&path).expect("load succeeds");
        assert_eq!(loaded, cache);
    }

    #[test]
    fn save_overwrites_a_previous_snapshot_atomically() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("denylist.json");
        let mut first = DenylistCache::empty();
        first.record_sync("1".to_string(), vec!["old".to_string()], SystemTime::now());
        save(&path, &first).unwrap();

        let mut second = DenylistCache::empty();
        second.record_sync("2".to_string(), vec!["new".to_string()], SystemTime::now());
        save(&path, &second).unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.entries, vec!["new".to_string()]);
        assert_eq!(loaded.version, "2");
    }
}
