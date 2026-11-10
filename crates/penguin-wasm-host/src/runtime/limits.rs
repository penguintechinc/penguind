//! Per-module resource limits: fuel, memory, wall clock, call budget, allowlist.

use std::collections::HashSet;
use std::time::Duration;

use wasmtime::ResourceLimiter;

/// Resource and capability limits for one module run.
#[derive(Debug, Clone)]
pub struct ModuleLimits {
    /// Fuel (roughly instructions) before the guest traps with out-of-fuel.
    pub fuel: u64,
    /// Maximum linear memory in bytes; exceeding it fails the run.
    pub max_memory_bytes: usize,
    /// Wall-clock cap for instantiate + run.
    pub wall_timeout: Duration,
    /// Maximum tool calls per run.
    pub max_tool_calls: u32,
    /// Tools the module may call. Deny-all by default: an empty set permits
    /// nothing, so every capability (including `config_read`) is opt-in.
    pub allowed_tools: HashSet<String>,
    /// Largest accepted `.wasm` size in bytes; bigger input is refused before
    /// any compilation work is done.
    pub max_wasm_bytes: usize,
    /// Names `doh_query` may resolve. Deny-all by default, even when
    /// `doh_query` is in `allowed_tools`, so DNS cannot become an
    /// exfiltration channel without an explicit grant.
    pub allowed_dns: DnsAllowlist,
}

/// Per-module DNS name grants: exact names plus `*.suffix` patterns
/// (a wildcard matches subdomains only, never the bare suffix).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsAllowlist {
    exact: HashSet<String>,
    suffixes: Vec<String>,
}

impl DnsAllowlist {
    /// Builds an allowlist from entries such as `api.example.com` or
    /// `*.example.com`; matching is case-insensitive and ignores a trailing dot.
    pub fn new<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = Self::default();
        for entry in entries {
            let entry = normalize(entry.as_ref());
            if let Some(suffix) = entry.strip_prefix("*.") {
                if !suffix.is_empty() {
                    out.suffixes.push(format!(".{suffix}"));
                }
            } else if !entry.is_empty() && !entry.contains('*') {
                out.exact.insert(entry);
            }
        }
        out
    }

    /// Whether `name` is granted.
    pub fn permits(&self, name: &str) -> bool {
        let name = normalize(name);
        if name.is_empty() || name.contains('*') {
            return false;
        }
        self.exact.contains(&name) || self.suffixes.iter().any(|s| name.ends_with(s.as_str()))
    }
}

/// Lowercases and drops one trailing dot.
fn normalize(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

impl ModuleLimits {
    /// Returns these limits with the allowlist replaced by `tools`.
    /// This is the only way to grant a module capabilities.
    pub fn allowing<I, S>(mut self, tools: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_tools = tools.into_iter().map(Into::into).collect();
        self
    }

    /// Returns these limits with the DNS allowlist replaced by `entries`.
    pub fn allowing_dns<I, S>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.allowed_dns = DnsAllowlist::new(entries);
        self
    }
}

impl Default for ModuleLimits {
    fn default() -> Self {
        Self {
            fuel: 50_000_000,
            max_memory_bytes: 16 * 1024 * 1024,
            wall_timeout: super::DEFAULT_WALL,
            max_tool_calls: 256,
            allowed_tools: HashSet::new(),
            max_wasm_bytes: 4 * 1024 * 1024,
            allowed_dns: DnsAllowlist::default(),
        }
    }
}

/// Enforces the memory cap; refusing growth is an error (trap), not a quiet
/// `-1`, and the trip is remembered so the failure can be classified.
pub(crate) struct StoreLimiter {
    max_memory: usize,
    tripped: bool,
}

impl StoreLimiter {
    pub(crate) fn new(max_memory: usize) -> Self {
        Self {
            max_memory,
            tripped: false,
        }
    }

    pub(crate) fn tripped(&self) -> bool {
        self.tripped
    }
}

impl ResourceLimiter for StoreLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.max_memory {
            self.tripped = true;
            return Err(wasmtime::Error::msg("memory limit exceeded"));
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= 100_000)
    }

    fn instances(&self) -> usize {
        1
    }

    fn memories(&self) -> usize {
        1
    }

    fn tables(&self) -> usize {
        4
    }
}

#[cfg(test)]
mod dns_tests {
    use super::*;

    #[test]
    fn dns_allowlist_is_deny_all_by_default() {
        let d = ModuleLimits::default().allowed_dns;
        assert!(!d.permits("example.com"));
        assert!(!d.permits(""));
    }

    #[test]
    fn exact_and_wildcard_matching() {
        let d = DnsAllowlist::new(["API.example.com", "*.svc.example.org"]);
        assert!(d.permits("api.example.com"));
        assert!(d.permits("api.example.com."));
        assert!(!d.permits("x.api.example.com"));
        assert!(!d.permits("example.com"));
        assert!(d.permits("a.svc.example.org"));
        assert!(d.permits("b.a.svc.example.org"));
        assert!(!d.permits("svc.example.org"), "wildcard excludes apex");
        assert!(!d.permits("evilsvc.example.org"));
        assert!(!d.permits("secret.attacker.net"));
    }
}
