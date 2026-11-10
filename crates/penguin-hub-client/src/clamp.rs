//! The limits clamp and the flag combiner. The hub can only *narrow* what the
//! local ceiling already permits: tools and DNS names intersect, numbers take
//! the minimum, and flags are `license && hub`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use penguin_sdk::LicenseChecker;
use penguin_wasm_host::ModuleLimits;
use std::sync::Arc;

use crate::model::HubPolicy;

/// Lowest poll interval the agent will ever use, whatever the hub asks.
pub const MIN_POLL_S: u64 = 60;
/// Highest poll interval the agent will accept from the hub.
pub const MAX_POLL_S: u64 = 86_400;

/// The local ceiling: what this agent permits with no hub at all. Comes from
/// local config only; the hub cannot raise any field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCeiling {
    /// Fuel ceiling.
    pub fuel: u64,
    /// Memory ceiling in bytes.
    pub max_memory_bytes: usize,
    /// Per-run tool-call ceiling.
    pub max_tool_calls: u32,
    /// Wall-clock ceiling.
    pub wall_timeout: Duration,
    /// Largest accepted `.wasm`.
    pub max_wasm_bytes: usize,
    /// Tools any hub-delivered module may ever call.
    pub allowed_tools: BTreeSet<String>,
    /// DNS names/`*.suffix` patterns any hub-delivered module may resolve.
    pub allowed_dns: Vec<String>,
    /// Longest staleness the local config tolerates.
    pub max_stale_s: u64,
}

impl LocalCeiling {
    /// Builds a ceiling from the wasm host's defaults with the given grants.
    pub fn with_grants<T, D>(tools: T, dns: D) -> Self
    where
        T: IntoIterator<Item = String>,
        D: IntoIterator<Item = String>,
    {
        let d = ModuleLimits::default();
        Self {
            fuel: d.fuel,
            max_memory_bytes: d.max_memory_bytes,
            max_tool_calls: d.max_tool_calls,
            wall_timeout: d.wall_timeout,
            max_wasm_bytes: d.max_wasm_bytes,
            allowed_tools: tools.into_iter().collect(),
            allowed_dns: dns.into_iter().map(|e| norm(&e)).collect(),
            max_stale_s: 7 * 86_400,
        }
    }
}

/// Limits after the clamp; comparable so a policy change is detectable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveLimits {
    /// Fuel.
    pub fuel: u64,
    /// Memory bytes.
    pub max_memory_bytes: usize,
    /// Per-run tool calls.
    pub max_tool_calls: u32,
    /// Wall clock.
    pub wall_timeout: Duration,
    /// Largest `.wasm`.
    pub max_wasm_bytes: usize,
    /// Permitted tools.
    pub allowed_tools: BTreeSet<String>,
    /// Permitted DNS entries.
    pub allowed_dns: BTreeSet<String>,
}

impl EffectiveLimits {
    /// Converts to the wasm host's limits type.
    pub fn to_module_limits(&self) -> ModuleLimits {
        ModuleLimits {
            fuel: self.fuel,
            max_memory_bytes: self.max_memory_bytes,
            wall_timeout: self.wall_timeout,
            max_tool_calls: self.max_tool_calls,
            max_wasm_bytes: self.max_wasm_bytes,
            ..ModuleLimits::default()
        }
        .allowing(self.allowed_tools.iter().cloned())
        .allowing_dns(self.allowed_dns.iter())
    }
}

/// Lowercases and drops one trailing dot, like the host's DNS matcher.
fn norm(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

/// A well-formed entry: non-empty, `*` only as a leading `*.` label.
fn valid_entry(e: &str) -> bool {
    match e.strip_prefix("*.") {
        Some(rest) => !rest.is_empty() && !rest.contains('*'),
        None => !e.is_empty() && !e.contains('*'),
    }
}

/// Whether `list` grants everything `entry` grants (exact, or under a wildcard,
/// or a wildcard no wider than one in `list`).
fn covers(list: &[String], entry: &str) -> bool {
    match entry.strip_prefix("*.") {
        Some(suf) => list.iter().any(|l| {
            l.strip_prefix("*.")
                .is_some_and(|ls| suf == ls || suf.ends_with(&format!(".{ls}")))
        }),
        None => list.iter().any(|l| match l.strip_prefix("*.") {
            Some(ls) => entry.ends_with(&format!(".{ls}")),
            None => l == entry,
        }),
    }
}

/// Intersection of two DNS entry lists (each entry kept only if the other
/// side covers it), so the result never grants more than either input.
fn intersect_dns(local: &[String], hub: &[String]) -> BTreeSet<String> {
    let local: Vec<String> = local
        .iter()
        .map(|e| norm(e))
        .filter(|e| valid_entry(e))
        .collect();
    let hub: Vec<String> = hub
        .iter()
        .map(|e| norm(e))
        .filter(|e| valid_entry(e))
        .collect();
    let mut out = BTreeSet::new();
    for l in &local {
        if covers(&hub, l) {
            out.insert(l.clone());
        }
    }
    for h in &hub {
        if covers(&local, h) {
            out.insert(h.clone());
        }
    }
    out
}

/// Applies the hub's policy to the local ceiling. Every result field is
/// `<=` the ceiling: tools/DNS intersect, numbers take `min`, and a hub value
/// of 0 is raised to 1 rather than producing an unrunnable limit.
pub fn clamp_policy(ceiling: &LocalCeiling, policy: &HubPolicy) -> EffectiveLimits {
    let narrow = |local: u64, hub: Option<u64>| hub.map_or(local, |h| local.min(h.max(1)));
    let mem_bytes = policy
        .limits
        .max_memory_mb
        .map(|mb| mb.max(1).saturating_mul(1024 * 1024));
    let max_memory_bytes = match mem_bytes {
        Some(b) => ceiling
            .max_memory_bytes
            .min(usize::try_from(b).unwrap_or(usize::MAX)),
        None => ceiling.max_memory_bytes,
    };
    let max_tool_calls = narrow(
        u64::from(ceiling.max_tool_calls),
        policy.limits.max_tool_calls_per_min,
    );
    let allowed_tools = match &policy.allowed_tools {
        None => ceiling.allowed_tools.clone(),
        Some(hub) => hub
            .iter()
            .filter(|t| ceiling.allowed_tools.contains(*t))
            .cloned()
            .collect(),
    };
    let allowed_dns = match &policy.allowed_dns {
        None => ceiling
            .allowed_dns
            .iter()
            .map(|e| norm(e))
            .filter(|e| valid_entry(e))
            .collect(),
        Some(hub) => intersect_dns(&ceiling.allowed_dns, hub),
    };
    EffectiveLimits {
        fuel: narrow(ceiling.fuel, policy.limits.max_fuel),
        max_memory_bytes,
        max_tool_calls: u32::try_from(max_tool_calls).unwrap_or(ceiling.max_tool_calls),
        wall_timeout: ceiling.wall_timeout,
        max_wasm_bytes: ceiling.max_wasm_bytes,
        allowed_tools,
        allowed_dns,
    }
}

/// Poll interval after the clamp: the hub's ask, kept within sane bounds.
pub fn clamp_poll_interval(hub_s: u64) -> u64 {
    hub_s.clamp(MIN_POLL_S, MAX_POLL_S)
}

/// Staleness bound after the clamp: the hub may only shorten the local one.
pub fn clamp_max_stale(ceiling: &LocalCeiling, hub_s: u64) -> u64 {
    ceiling.max_stale_s.min(hub_s.max(300))
}

/// `LicenseChecker` that enforces `effective = license && hub`: a flag is on
/// only when the licence says so AND the hub has not turned it off. A flag the
/// hub never mentioned stays as the licence has it (the hub can never grant).
/// In deny-all (corrupt cache) every flag is off.
pub struct ClampedLicense {
    inner: Arc<dyn LicenseChecker>,
    hub_flags: RwLock<BTreeMap<String, bool>>,
    deny_all: AtomicBool,
}

impl ClampedLicense {
    /// Wraps `inner`; with no hub flags set it is a pass-through.
    pub fn new(inner: Arc<dyn LicenseChecker>) -> Self {
        Self {
            inner,
            hub_flags: RwLock::new(BTreeMap::new()),
            deny_all: AtomicBool::new(false),
        }
    }

    /// Replaces the hub's flag restrictions (an empty map removes them all).
    pub fn set_hub_flags(&self, flags: BTreeMap<String, bool>) {
        if let Ok(mut g) = self.hub_flags.write() {
            *g = flags;
        }
    }

    /// Forces every flag off (corrupt offline cache) or lifts that.
    pub fn set_deny_all(&self, deny: bool) {
        self.deny_all.store(deny, Ordering::SeqCst);
    }
}

impl LicenseChecker for ClampedLicense {
    /// `license && hub`; a poisoned lock fails closed.
    fn feature_enabled(&self, key: &str) -> bool {
        if self.deny_all.load(Ordering::SeqCst) || !self.inner.feature_enabled(key) {
            return false;
        }
        self.hub_flags
            .read()
            .map(|g| g.get(key).copied().unwrap_or(true))
            .unwrap_or(false)
    }

    /// Tier is the licence's alone; the hub never changes it.
    fn tier(&self) -> String {
        self.inner.tier()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::HubLimits;

    fn ceiling() -> LocalCeiling {
        LocalCeiling::with_grants(
            ["logger".to_string(), "doh_query".to_string()],
            [
                "api.example.com".to_string(),
                "*.svc.example.org".to_string(),
            ],
        )
    }

    fn within(e: &EffectiveLimits, c: &LocalCeiling) -> bool {
        e.fuel <= c.fuel
            && e.max_memory_bytes <= c.max_memory_bytes
            && e.max_tool_calls <= c.max_tool_calls
            && e.allowed_tools.is_subset(&c.allowed_tools)
    }

    #[test]
    fn empty_policy_equals_ceiling() {
        let c = ceiling();
        let e = clamp_policy(&c, &HubPolicy::default());
        assert_eq!(e.fuel, c.fuel);
        assert_eq!(e.allowed_tools, c.allowed_tools);
        assert_eq!(e.allowed_dns.len(), 2);
    }

    #[test]
    fn hub_cannot_exceed_ceiling() {
        let c = ceiling();
        let p = HubPolicy {
            allowed_tools: Some(vec!["logger".into(), "secret_read".into(), "x".into()]),
            limits: HubLimits {
                max_fuel: Some(u64::MAX),
                max_memory_mb: Some(u64::MAX),
                max_tool_calls_per_min: Some(u64::MAX),
                ..HubLimits::default()
            },
            allowed_dns: Some(vec!["*.example.com".into(), "evil.net".into()]),
            ..HubPolicy::default()
        };
        let e = clamp_policy(&c, &p);
        assert!(within(&e, &c), "{e:?}");
        assert_eq!(e.allowed_tools, BTreeSet::from(["logger".to_string()]));
        // wider hub wildcard does not widen; local exact survives, evil.net dropped.
        assert_eq!(
            e.allowed_dns,
            BTreeSet::from(["api.example.com".to_string()])
        );
    }

    #[test]
    fn hub_narrows_numbers_and_tools() {
        let c = ceiling();
        let p = HubPolicy {
            allowed_tools: Some(vec![]),
            limits: HubLimits {
                max_fuel: Some(1000),
                max_memory_mb: Some(1),
                max_tool_calls_per_min: Some(0),
                ..HubLimits::default()
            },
            allowed_dns: Some(vec![]),
            ..HubPolicy::default()
        };
        let e = clamp_policy(&c, &p);
        assert_eq!(e.fuel, 1000);
        assert_eq!(e.max_memory_bytes, 1024 * 1024);
        assert_eq!(e.max_tool_calls, 1, "0 is raised to 1");
        assert!(e.allowed_tools.is_empty() && e.allowed_dns.is_empty());
        let ml = e.to_module_limits();
        assert!(ml.allowed_tools.is_empty());
        assert!(!ml.allowed_dns.permits("api.example.com"));
    }

    #[test]
    fn dns_wildcard_narrowing_both_directions() {
        let local: Vec<String> = vec!["*.example.com".into(), "Exact.Other.org.".into()];
        let got = intersect_dns(
            &local,
            &[
                "a.example.com".into(),
                "*.b.example.com".into(),
                "exact.other.org".into(),
                "*".into(),
                "".into(),
            ],
        );
        assert_eq!(
            got,
            BTreeSet::from([
                "a.example.com".to_string(),
                "*.b.example.com".to_string(),
                "exact.other.org".to_string()
            ])
        );
        // wildcard equal on both sides survives.
        let got = intersect_dns(&["*.a.com".into()], &["*.a.com".into()]);
        assert_eq!(got, BTreeSet::from(["*.a.com".to_string()]));
    }

    #[test]
    fn invalid_local_dns_entries_are_dropped_without_hub() {
        let mut c = ceiling();
        c.allowed_dns.push("a*b.com".into());
        let e = clamp_policy(&c, &HubPolicy::default());
        assert!(!e.allowed_dns.contains("a*b.com"));
    }

    #[test]
    fn poll_and_stale_clamps() {
        assert_eq!(clamp_poll_interval(1), MIN_POLL_S);
        assert_eq!(clamp_poll_interval(10_000_000), MAX_POLL_S);
        assert_eq!(clamp_poll_interval(600), 600);
        let c = ceiling();
        assert_eq!(clamp_max_stale(&c, 1), 300);
        assert_eq!(clamp_max_stale(&c, u64::MAX), c.max_stale_s);
    }

    struct Lic(BTreeSet<&'static str>);
    impl LicenseChecker for Lic {
        fn feature_enabled(&self, k: &str) -> bool {
            self.0.contains(k)
        }
        fn tier(&self) -> String {
            "pro".into()
        }
    }

    #[test]
    fn flags_are_license_and_hub() {
        let l = ClampedLicense::new(Arc::new(Lic(BTreeSet::from(["a", "b"]))));
        assert!(l.feature_enabled("a") && l.feature_enabled("b"));
        assert!(
            !l.feature_enabled("c"),
            "hub-silent but unlicensed stays off"
        );
        l.set_hub_flags(BTreeMap::from([
            ("b".to_string(), false),
            ("c".to_string(), true),
        ]));
        assert!(l.feature_enabled("a"), "missing hub key = true");
        assert!(!l.feature_enabled("b"), "hub off wins");
        assert!(!l.feature_enabled("c"), "hub can never grant");
        l.set_deny_all(true);
        assert!(!l.feature_enabled("a"));
        l.set_deny_all(false);
        l.set_hub_flags(BTreeMap::new());
        assert!(l.feature_enabled("b"));
        assert_eq!(l.tier(), "pro");
    }
}
