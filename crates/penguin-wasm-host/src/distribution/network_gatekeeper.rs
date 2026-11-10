//! Outbound allowlist: FQDNs and real CIDR prefix matching.

use std::collections::HashSet;
use std::net::IpAddr;

/// What a module may reach. Default-deny, including loopback (opt-in only).
#[derive(Debug, Clone, Default)]
pub struct NetworkPolicy {
    allowed_fqdns: HashSet<String>,
    allowed_cidrs: Vec<(IpAddr, u8)>,
    allow_loopback: bool,
}

impl NetworkPolicy {
    /// Builds a policy; a malformed CIDR is an error, never silently dropped.
    pub fn new(fqdns: Vec<String>, cidrs: Vec<String>) -> Result<Self, String> {
        let mut parsed = Vec::new();
        for cidr in cidrs {
            parsed.push(parse_cidr(&cidr)?);
        }
        Ok(Self {
            allowed_fqdns: fqdns.into_iter().map(|f| f.to_lowercase()).collect(),
            allowed_cidrs: parsed,
            allow_loopback: false,
        })
    }

    /// Opts in to loopback destinations (local development/tests only).
    pub fn with_loopback(mut self, allow: bool) -> Self {
        self.allow_loopback = allow;
        self
    }

    /// Whether a request to `host` (resolving to `ip`, if known) is allowed.
    ///
    /// A resolved IP is always checked, even when the FQDN is allowlisted: an
    /// allowed name resolving to loopback, link-local/metadata, unspecified,
    /// multicast or private space is refused unless loopback is opted in or a
    /// CIDR explicitly covers it (DNS rebinding defence).
    pub fn is_allowed(&self, host: &str, ip: Option<IpAddr>) -> bool {
        let Some(addr) = ip else {
            return self.allowed_fqdns.contains(&host.to_lowercase());
        };
        if addr.is_loopback() {
            return self.allow_loopback;
        }
        let in_cidr_list = self
            .allowed_cidrs
            .iter()
            .any(|(net, bits)| in_cidr(addr, *net, *bits));
        if in_cidr_list {
            return true;
        }
        self.allowed_fqdns.contains(&host.to_lowercase()) && !is_internal(addr)
    }
}

/// Non-public destinations an FQDN match must never reach on its own.
fn is_internal(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            a.is_private()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_multicast()
                || a.is_broadcast()
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_internal(IpAddr::V4(v4)) || v4.is_loopback();
            }
            let first = a.segments()[0];
            a.is_unspecified()
                || a.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
        }
    }
}

fn parse_cidr(text: &str) -> Result<(IpAddr, u8), String> {
    let (addr, bits) = text.split_once('/').unwrap_or((text, ""));
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| format!("bad CIDR address: {text}"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let bits = if bits.is_empty() {
        max
    } else {
        bits.parse::<u8>()
            .map_err(|_| format!("bad CIDR prefix: {text}"))?
    };
    if bits > max {
        return Err(format!("CIDR prefix too long: {text}"));
    }
    Ok((ip, bits))
}

fn in_cidr(addr: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (addr, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            prefix_eq(u32::from(a).into(), u32::from(n).into(), bits, 32)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => prefix_eq(u128::from(a), u128::from(n), bits, 128),
        _ => false,
    }
}

fn prefix_eq(a: u128, b: u128, bits: u8, width: u32) -> bool {
    if bits == 0 {
        return true;
    }
    let shift = width - u32::from(bits);
    (a >> shift) == (b >> shift)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().expect("ip"))
    }

    #[test]
    fn cidr_and_fqdn_matching() {
        let p =
            NetworkPolicy::new(vec!["Example.com".into()], vec!["10.0.0.0/8".into()]).expect("ok");
        assert!(p.is_allowed("example.com", None));
        assert!(p.is_allowed("example.com", ip("93.184.216.34")));
        assert!(p.is_allowed("x", ip("10.1.2.3")));
        assert!(!p.is_allowed("x", ip("11.1.2.3")));
        assert!(NetworkPolicy::new(vec![], vec!["nope".into()]).is_err());
    }

    #[test]
    fn loopback_is_opt_in() {
        let p = NetworkPolicy::new(vec!["localhost".into()], vec![]).expect("ok");
        assert!(!p.is_allowed("x", ip("127.0.0.1")));
        assert!(!p.is_allowed("localhost", ip("::1")));
        assert!(p.with_loopback(true).is_allowed("x", ip("127.0.0.1")));
    }

    #[test]
    fn allowed_fqdn_resolving_internal_is_denied() {
        // regression: rebinding an allowlisted name to internal space.
        let p = NetworkPolicy::new(vec!["good.example".into()], vec![]).expect("ok");
        for bad in [
            "127.0.0.1",
            "10.0.0.5",
            "169.254.169.254",
            "0.0.0.0",
            "fd00::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!p.is_allowed("good.example", ip(bad)), "{bad}");
        }
    }
}
