//! Outbound allowlist: FQDNs and real CIDR prefix matching.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
        if is_loopback(addr) {
            return self.allow_loopback;
        }
        let in_cidr_list = self
            .allowed_cidrs
            .iter()
            .any(|(net, bits)| in_cidr(addr, *net, *bits));
        if in_cidr_list {
            return true;
        }
        self.allowed_fqdns.contains(&host.to_lowercase()) && is_global(addr)
    }
}

/// Loopback in either family, including loopback embedded in IPv6.
fn is_loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => a.is_loopback(),
        IpAddr::V6(a) => a.is_loopback() || embedded_v4(a).is_some_and(|v4| v4.is_loopback()),
    }
}

/// `true` when `a` sits in `net/bits`.
fn v4_in(a: Ipv4Addr, net: [u8; 4], bits: u8) -> bool {
    prefix_eq(
        u32::from(a).into(),
        u32::from(Ipv4Addr::from(net)).into(),
        bits,
        32,
    )
}

/// `true` when `a` sits in `net/bits`.
fn v6_in(a: Ipv6Addr, net: u128, bits: u8) -> bool {
    prefix_eq(u128::from(a), net, bits, 128)
}

/// Allow-only-global for IPv4: every IANA special-purpose block is refused.
fn is_global_v4(a: Ipv4Addr) -> bool {
    const DENY: &[([u8; 4], u8)] = &[
        ([0, 0, 0, 0], 8),       // "this network"
        ([10, 0, 0, 0], 8),      // private
        ([100, 64, 0, 0], 10),   // CGNAT shared space
        ([127, 0, 0, 0], 8),     // loopback
        ([169, 254, 0, 0], 16),  // link-local / cloud metadata
        ([172, 16, 0, 0], 12),   // private
        ([192, 0, 0, 0], 24),    // IETF protocol assignments
        ([192, 0, 2, 0], 24),    // TEST-NET-1
        ([192, 88, 99, 0], 24),  // deprecated 6to4 relay anycast
        ([192, 168, 0, 0], 16),  // private
        ([198, 18, 0, 0], 15),   // benchmarking
        ([198, 51, 100, 0], 24), // TEST-NET-2
        ([203, 0, 113, 0], 24),  // TEST-NET-3
        ([224, 0, 0, 0], 4),     // multicast
        ([240, 0, 0, 0], 4),     // reserved, incl. 255.255.255.255 broadcast
    ];
    !DENY.iter().any(|(net, bits)| v4_in(a, *net, *bits))
}

/// The IPv4 address an IPv6 address embeds, for every transition format a
/// guest could use to smuggle an internal v4 target past the v6 checks.
fn embedded_v4(a: Ipv6Addr) -> Option<Ipv4Addr> {
    let bits = u128::from(a);
    let low32 = Ipv4Addr::from((bits & 0xffff_ffff) as u32);
    if v6_in(a, 0xffff_0000_0000, 96) // ::ffff:0:0/96 v4-mapped
        || v6_in(a, 0x0064_ff9b_0000_0000_0000_0000_0000_0000, 96)
    // NAT64
    {
        return Some(low32);
    }
    // ::/96 v4-compatible (deprecated); `::` and `::1` are handled as v6.
    if v6_in(a, 0, 96) && bits > 1 {
        return Some(low32);
    }
    if v6_in(a, 0x2002 << 112, 16) {
        // 6to4: 2002:VVVV:VVVV::/48.
        return Some(Ipv4Addr::from(((bits >> 80) & 0xffff_ffff) as u32));
    }
    if v6_in(a, 0x2001_0000 << 96, 32) {
        // Teredo: the client address is the low 32 bits, bit-inverted.
        return Some(Ipv4Addr::from(!((bits & 0xffff_ffff) as u32)));
    }
    None
}

/// Allow-only-global for IPv6: embedded v4 is unwrapped and judged as v4,
/// then only 2000::/3 global unicast outside special-purpose blocks passes.
fn is_global_v6(a: Ipv6Addr) -> bool {
    if let Some(v4) = embedded_v4(a) {
        if !is_global_v4(v4) {
            return false;
        }
        // Teredo server address (bits 32..64) must be global too.
        if v6_in(a, 0x2001_0000 << 96, 32) {
            let server = Ipv4Addr::from(((u128::from(a) >> 64) & 0xffff_ffff) as u32);
            return is_global_v4(server);
        }
        // Mapped/compatible/NAT64/6to4 carrying a global v4 is that v4.
        return true;
    }
    const DENY: &[(u128, u8)] = &[
        (0x0064_ff9b_0001 << 80, 48), // local-use NAT64
        (0x0100 << 112, 64),          // discard-only
        (0x2001 << 112, 23),          // IETF protocol assignments
        (0x2001_0db8 << 96, 32),      // documentation
        (0x3fff << 112, 20),          // documentation (RFC 9637)
        (0x5f00 << 112, 16),          // SRv6 SIDs
        (0xfc00 << 112, 7),           // unique local
        (0xfe80 << 112, 10),          // link-local
        (0xfec0 << 112, 10),          // deprecated site-local
        (0xff00 << 112, 8),           // multicast
    ];
    v6_in(a, 0x2000 << 112, 3) && !DENY.iter().any(|(net, bits)| v6_in(a, *net, *bits))
}

/// Whether `addr` is publicly routable; anything else is refused unless an
/// explicit CIDR entry (or the loopback opt-in) covers it.
fn is_global(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => is_global_v4(a),
        IpAddr::V6(a) => is_global_v6(a),
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

    #[test]
    fn every_non_global_v4_range_is_denied_for_fqdns() {
        let p = NetworkPolicy::new(vec!["good.example".into()], vec![]).expect("ok");
        for bad in [
            "0.1.2.3",
            "10.255.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "127.8.8.8",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!p.is_allowed("good.example", ip(bad)), "{bad}");
        }
        for good in [
            "8.8.8.8",
            "100.128.0.1",
            "172.32.0.1",
            "198.20.0.1",
            "1.1.1.1",
        ] {
            assert!(p.is_allowed("good.example", ip(good)), "{good}");
        }
    }

    #[test]
    fn embedded_v4_in_v6_is_unwrapped() {
        let p = NetworkPolicy::new(vec!["good.example".into()], vec![]).expect("ok");
        for bad in [
            "::ffff:169.254.169.254", // v4-mapped
            "::ffff:127.0.0.1",
            "::10.0.0.1",         // v4-compatible
            "::a9fe:a9fe",        // v4-compatible metadata
            "64:ff9b::a9fe:a9fe", // NAT64 -> 169.254.169.254
            "64:ff9b::10.1.1.1",
            "64:ff9b:1::8.8.8.8",                   // local-use NAT64
            "2002:a9fe:a9fe::1",                    // 6to4 -> 169.254.169.254
            "2002:c0a8:0101::1",                    // 6to4 -> 192.168.1.1
            "2001:0:4136:e378:8000:63bf:f5ff:fffe", // Teredo client 10.0.0.1
            "2001:0:0a00:0001:8000:63bf:f7f7:f7f7", // Teredo server 10.0.0.1
        ] {
            assert!(!p.is_allowed("good.example", ip(bad)), "{bad}");
        }
        for good in ["::ffff:8.8.8.8", "64:ff9b::808:808", "2002:0808:0808::1"] {
            assert!(p.is_allowed("good.example", ip(good)), "{good}");
        }
    }

    #[test]
    fn every_non_global_v6_range_is_denied_for_fqdns() {
        let p = NetworkPolicy::new(vec!["good.example".into()], vec![]).expect("ok");
        for bad in [
            "::",
            "::1",
            "100::1",
            "2001:2::1",
            "2001:db8::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fdff::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "ff02::1",
            "4000::1", // outside 2000::/3
            "1::1",
        ] {
            assert!(!p.is_allowed("good.example", ip(bad)), "{bad}");
        }
        for good in ["2606:4700:4700::1111", "2a00:1450::1"] {
            assert!(p.is_allowed("good.example", ip(good)), "{good}");
        }
    }

    #[test]
    fn explicit_cidr_and_loopback_opt_in_still_override() {
        let p = NetworkPolicy::new(
            vec![],
            vec![
                "100.64.0.0/10".into(),
                "fd00::/8".into(),
                "192.0.2.5".into(),
            ],
        )
        .expect("ok");
        assert!(p.is_allowed("x", ip("100.64.1.1")));
        assert!(p.is_allowed("x", ip("fd00::5")));
        assert!(p.is_allowed("x", ip("192.0.2.5")));
        assert!(!p.is_allowed("x", ip("192.0.2.6")));
        let lo = p.with_loopback(true);
        assert!(lo.is_allowed("x", ip("127.0.0.1")));
        assert!(lo.is_allowed("x", ip("::1")));
        assert!(lo.is_allowed("x", ip("::ffff:127.0.0.1")));
    }
}
