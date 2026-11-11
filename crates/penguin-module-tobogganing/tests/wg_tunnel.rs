//! M6 gate: prove the real [`KernelBackend`] brings up an actual kernel
//! WireGuard tunnel against a controlled peer and tears it down cleanly —
//! the assertion no unit test can make, and the one Go's `realWGController`
//! (`return nil`, never touching the kernel at all) could never have passed.
//!
//! # Running
//!
//! ```sh
//! PENGUIN_INTEGRATION=1 cargo test -p penguin-module-tobogganing --test wg_tunnel \
//!     --features integration-test -- --ignored --nocapture
//! ```
//!
//! `--features integration-test` is required: `wireguard` is a private
//! module in the shipped crate, made `pub` only under that feature so this
//! file can reach [`KernelBackend`] directly — see the feature's doc in
//! `Cargo.toml`. `scripts/wg-tunnel/run.sh` and the integration CI workflow
//! both pass it.
//!
//! Every test here is `#[ignore]` *and* separately checks
//! `PENGUIN_INTEGRATION=1` at runtime (same convention as
//! `penguin-daemon/tests/external_plugin.rs`), so neither a plain
//! `cargo test` nor a bare `cargo test -- --ignored` ever touches real
//! network state. On top of that, [`missing_precondition`] self-skips (with
//! a printed reason, not a failure) when this process cannot actually
//! exercise a kernel tunnel: not root/`CAP_NET_ADMIN`, no `wireguard` kernel
//! module, or no `ip`/`wg` on `PATH`.
//!
//! # Topology
//!
//! Our side ([`KernelBackend`], driven directly — never `setns`) stays in
//! this process's main network namespace for its entire lifetime, so there
//! is no async-runtime-vs-netns interaction to worry about. Only the PEER
//! lives in a child namespace (`pwgpeer`), reached exclusively through
//! `ip`/`wg` subprocesses:
//!
//! ```text
//! main netns                          pwgpeer netns
//! ┌─────────────────────┐             ┌─────────────────────┐
//! │ pwgveth0 10.0.0.2/24 │─────────────│ pwgveth1 10.0.0.1/24 │  underlay
//! │ pwgtest0 (KernelBackend)           │ pwgpeer0 (wg CLI)     │  WireGuard
//! │   10.100.0.2/32      │  UDP:51820  │   10.100.0.1/24       │
//! └─────────────────────┘             └─────────────────────┘
//! ```
//!
//! # A namespace pitfall worth documenting
//!
//! The peer's `wg` device is created with `ip netns exec pwgpeer ip link add
//! ... type wireguard` — i.e. by a process whose *current* namespace already
//! is `pwgpeer` — deliberately never via `ip link add ... netns pwgpeer` nor
//! `ip link add` followed by `ip link set ... netns pwgpeer`. The in-kernel
//! WireGuard driver binds its UDP socket to the namespace active at
//! `RTM_NEWLINK` time (`creating_net`) and does **not** rebind it if the
//! device is later moved to a different namespace — a deliberate WireGuard
//! design choice (a tunnel handed into a container keeps routing its own
//! transport traffic over the namespace that created it). Get the creation
//! order wrong and the peer's `wg set` reports success, `wg show` reports
//! the configured listen port, and the interface looks entirely normal —
//! but no UDP socket is ever bound (confirmed against this exact kernel with
//! a raw ICMP capture: the peer namespace answers with a real port-unreachable),
//! so the handshake can never arrive. `KernelBackend::apply` itself needs no
//! such care: it never calls `setns`, so every interface it creates is
//! always created in whatever namespace this process is already in.
//!
//! [`KernelBackend::apply`] also never calls `configure_peer_routing` (see
//! `kernel.rs`'s module doc — AllowedIPs is cryptokey routing, not an IP
//! route), so this test adds the one route a real deployment's `AllowedIPs`
//! would otherwise need some other mechanism to install, before it can
//! prove traffic actually flows.

#![cfg(target_os = "linux")]

use std::io::{ErrorKind, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use defguard_wireguard_rs::key::Key;
use penguin_module_tobogganing::wireguard::kernel::KernelBackend;
use penguin_module_tobogganing::wireguard::{PeerStats, TunnelSpec, WireGuardBackend};
use tempfile::NamedTempFile;

/// Namespace + interface names, kept short and fixed on purpose: a run that
/// panics mid-test leaves the SAME names behind, so the next run's
/// best-effort pre-clean (see the test body) reliably finds and removes
/// them instead of accumulating garbage across crashed attempts.
const NETNS: &str = "pwgpeer";
const CLIENT_IFACE: &str = "pwgtest0";
const PEER_IFACE: &str = "pwgpeer0";
const VETH_HOST: &str = "pwgveth0";
const VETH_PEER: &str = "pwgveth1";

/// The peer's WireGuard UDP listen port, and the underlay address our side
/// reaches it at (the veth pair's peer-side address, not the tunnel
/// address).
const PEER_LISTEN_PORT: u16 = 51820;
const UNDERLAY_PEER_IP: &str = "10.0.0.1";
const TUNNEL_PEER_IP: &str = "10.100.0.1";

/// Skips the calling test (with a message) unless the integration tier is
/// explicitly opted into. Kept separate from `#[ignore]`: a bare
/// `--ignored` run must still not touch real network state — same
/// convention as `penguin-daemon/tests/external_plugin.rs`.
macro_rules! require_integration {
    () => {
        if std::env::var("PENGUIN_INTEGRATION").as_deref() != Ok("1") {
            eprintln!("SKIP: set PENGUIN_INTEGRATION=1 to run wg_tunnel tests");
            return;
        }
    };
}

/// True when the caller demands the M6 gate actually run: an unmet
/// precondition then fails the test instead of self-skipping, so a
/// mis-provisioned CI runner cannot pass by skipping.
fn require_net_admin() -> bool {
    require_net_admin_from(std::env::var("PENGUIN_REQUIRE_NET_ADMIN").ok().as_deref())
}

/// Pure decision for [`require_net_admin`]: only the exact value `"1"`
/// enables it. Split out so the gate is unit-testable without mutating env.
fn require_net_admin_from(value: Option<&str>) -> bool {
    value == Some("1")
}

/// Unit test of the `PENGUIN_REQUIRE_NET_ADMIN` gate; runs in the default
/// (non-ignored) tier because it touches no network state.
#[test]
fn require_net_admin_env_gate() {
    assert!(require_net_admin_from(Some("1")));
    for v in [
        None,
        Some(""),
        Some("0"),
        Some("true"),
        Some("yes"),
        Some(" 1"),
    ] {
        assert!(!require_net_admin_from(v), "{v:?} must not enable the gate");
    }
}

/// True if `CAP_NET_ADMIN` (bit 12) is set in this process's effective
/// capability mask, per `/proc/self/status`'s `CapEff` hex field. Covers a
/// root or non-root process; a root process inside a container started with
/// `--cap-drop` may lack it, so this is the only privilege check used.
fn has_cap_net_admin() -> bool {
    const CAP_NET_ADMIN_BIT: u32 = 12;
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        let Some(hex) = line.strip_prefix("CapEff:") else {
            continue;
        };
        let Ok(mask) = u64::from_str_radix(hex.trim(), 16) else {
            return false;
        };
        return mask & (1u64 << CAP_NET_ADMIN_BIT) != 0;
    }
    false
}

/// Returns why this environment cannot run the M6 gate for real, or `None`
/// if every precondition — privilege, kernel module, and required tools —
/// is met. Checked once, up front, so the test prints one clear reason and
/// self-skips instead of failing deep inside setup.
fn missing_precondition() -> Option<String> {
    if !has_cap_net_admin() {
        return Some("CAP_NET_ADMIN is not in the effective capability set (CapEff)".to_string());
    }
    if !Path::new("/sys/module/wireguard").exists() {
        return Some(
            "kernel wireguard module is not loaded (/sys/module/wireguard absent)".to_string(),
        );
    }
    for tool in ["ip", "wg"] {
        let spawned = Command::new(tool).arg("--version").output();
        let Err(err) = spawned else {
            continue;
        };
        if err.kind() == ErrorKind::NotFound {
            return Some(format!("`{tool}` not found on PATH"));
        }
    }
    None
}

/// Runs `program args…` to completion and returns captured stdout on a zero
/// exit status, or an `Err` describing exactly what failed. Every
/// netns/veth/peer setup step in this test goes through this one place so a
/// failure is diagnosable from the panic message alone, without rerunning
/// under `--nocapture` to guess which step broke.
fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let joined_args = args.join(" ");
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| format!("spawn `{program} {joined_args}`: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "`{program} {joined_args}` failed ({}): {stderr}",
            output.status
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Same shape as [`run`] but swallows the result entirely — used only for
/// best-effort cleanup, where "the thing being deleted is already gone" is
/// success, not an error worth surfacing.
fn run_best_effort(program: &str, args: &[&str]) {
    let _ = Command::new(program).args(args).output();
}

/// `true` if `ip link show <iface>` succeeds — i.e. the interface exists in
/// this (the main) network namespace right now.
fn interface_exists(iface: &str) -> bool {
    let status = Command::new("ip")
        .args(["link", "show", iface])
        .status()
        .expect("spawn `ip link show`");
    status.success()
}

/// RAII cleanup: best-effort removes [`CLIENT_IFACE`] and the [`NETNS`]
/// namespace (which cascades to the peer's `wg` device and its veth end) on
/// drop — which Rust runs even when a panicking assertion unwinds the
/// stack. Without this, a failed assertion partway through the test would
/// leak a namespace or interface into the next run. Idempotent by
/// construction: both cleanup commands are harmless no-ops if the test's
/// own explicit teardown (assertions C/D) already ran them.
struct TeardownGuard;

impl Drop for TeardownGuard {
    fn drop(&mut self) {
        eprintln!("TeardownGuard: removing {CLIENT_IFACE} and netns {NETNS} (best effort)");
        run_best_effort("ip", &["link", "del", CLIENT_IFACE]);
        run_best_effort("ip", &["netns", "del", NETNS]);
    }
}

/// Best-effort removes anything a prior crashed run of this exact test
/// might have left behind, under the same fixed names this run is about to
/// reuse. Safe to call unconditionally: every command here is a harmless
/// no-op when there is nothing to remove.
fn preclean_stale_state() {
    run_best_effort("ip", &["link", "del", CLIENT_IFACE]);
    run_best_effort("ip", &["netns", "del", NETNS]);
}

/// Builds the underlay: the `pwgpeer` namespace and a veth pair connecting
/// it to the main namespace, both ends addressed and up. This is the
/// "physical" network the WireGuard UDP handshake travels over — separate
/// from the tunnel (`10.100.0.0/24`) addresses the WireGuard peers
/// negotiate on top of it.
fn setup_underlay() {
    run("ip", &["netns", "add", NETNS]).expect("create the peer network namespace");
    run(
        "ip",
        &[
            "link", "add", VETH_HOST, "type", "veth", "peer", "name", VETH_PEER, "netns", NETNS,
        ],
    )
    .expect("create the underlay veth pair");
    run("ip", &["addr", "add", "10.0.0.2/24", "dev", VETH_HOST]).expect("address the host veth");
    run("ip", &["link", "set", VETH_HOST, "up"]).expect("bring up the host veth");
    run(
        "ip",
        &["-n", NETNS, "addr", "add", "10.0.0.1/24", "dev", VETH_PEER],
    )
    .expect("address the peer veth");
    run("ip", &["-n", NETNS, "link", "set", VETH_PEER, "up"]).expect("bring up the peer veth");
    run("ip", &["-n", NETNS, "link", "set", "lo", "up"]).expect("bring up peer netns loopback");
}

/// Brings up the peer's real kernel WireGuard interface — via `ip`/`wg`
/// only, never through [`KernelBackend`], since the peer is test
/// scaffolding, not the thing under test. `client_public_key` is what the
/// peer allows traffic from; returns the peer's own public key so the test
/// can hand it to [`KernelBackend::apply`] as `TunnelSpec::peer_public_key`.
///
/// The returned [`NamedTempFile`] must be kept alive by the caller for as
/// long as the peer interface exists: dropping it deletes the private-key
/// file `wg set` was pointed at, which is fine once `wg set` has already
/// read it, but keeping it alive avoids any doubt about ordering.
fn setup_peer_wireguard(client_public_key: &Key) -> (Key, NamedTempFile) {
    let peer_private_key = Key::generate();
    let peer_public_key = peer_private_key.public_key();

    let mut key_file = NamedTempFile::new().expect("create a temp file for the peer private key");
    write!(key_file, "{peer_private_key}").expect("write the peer private key to the temp file");
    let key_path = key_file
        .path()
        .to_str()
        .expect("temp file path is valid UTF-8");

    // Created from a process whose CURRENT namespace already is `pwgpeer`
    // (`ip netns exec`, not `netns pwgpeer` as a trailing `ip link add`
    // argument) — see this file's module doc for exactly why that ordering
    // matters to which namespace the driver binds its UDP socket in.
    run(
        "ip",
        &[
            "netns",
            "exec",
            NETNS,
            "ip",
            "link",
            "add",
            PEER_IFACE,
            "type",
            "wireguard",
        ],
    )
    .expect("create the peer wireguard interface inside its namespace");
    run(
        "ip",
        &[
            "-n",
            NETNS,
            "addr",
            "add",
            "10.100.0.1/24",
            "dev",
            PEER_IFACE,
        ],
    )
    .expect("address the peer tunnel interface");

    let listen_port = PEER_LISTEN_PORT.to_string();
    let client_public_key_b64 = client_public_key.to_string();
    run(
        "ip",
        &[
            "netns",
            "exec",
            NETNS,
            "wg",
            "set",
            PEER_IFACE,
            "listen-port",
            &listen_port,
            "private-key",
            key_path,
            "peer",
            &client_public_key_b64,
            "allowed-ips",
            "10.100.0.2/32",
        ],
    )
    .expect("configure the peer's wireguard listener and allowed client");
    run("ip", &["-n", NETNS, "link", "set", PEER_IFACE, "up"]).expect("bring up the peer wg iface");

    (peer_public_key, key_file)
}

/// The [`TunnelSpec`] our side hands to the real [`KernelBackend`]: our
/// freshly generated client key, the peer's public key and underlay
/// endpoint, and the one route (`10.100.0.1/32`, the peer's tunnel address)
/// we are allowed to reach through it.
fn build_client_tunnel_spec(client_private_key: Key, peer_public_key: Key) -> TunnelSpec {
    let underlay_peer_ip: IpAddr = UNDERLAY_PEER_IP
        .parse()
        .expect("valid underlay peer address");
    TunnelSpec {
        private_key: client_private_key,
        client_address: "10.100.0.2/32".parse().expect("valid client address"),
        peer_public_key,
        endpoint: SocketAddr::new(underlay_peer_ip, PEER_LISTEN_PORT),
        allowed_ips: vec!["10.100.0.1/32".parse().expect("valid allowed ip")],
        dns: Vec::new(),
        mtu: 1420,
        keepalive: None,
    }
}

/// Polls `peer_stats` until it reports a real handshake with real,
/// non-zero byte counts in both directions, or `timeout` elapses. A genuine
/// kernel handshake over a local veth completes in well under a second; the
/// generous ceiling absorbs container scheduling jitter, not protocol
/// latency.
async fn wait_for_real_handshake(
    backend: &KernelBackend,
    interface: &str,
    timeout: Duration,
) -> Result<PeerStats, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let stats = backend
            .peer_stats(interface)
            .await
            .map_err(|err| format!("peer_stats: {err}"))?;
        let handshaked = stats.last_handshake.is_some() && stats.rx_bytes > 0 && stats.tx_bytes > 0;
        if handshaked {
            return Ok(stats);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "no real handshake within {timeout:?}: last_handshake={:?} rx_bytes={} tx_bytes={}",
                stats.last_handshake, stats.rx_bytes, stats.tx_bytes
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The M6 gate itself. Current-thread runtime: our side never calls
/// `setns`, so there is nothing to isolate by pinning to one OS thread —
/// this just keeps the test's execution deterministic and simple.
#[tokio::test(flavor = "current_thread")]
#[ignore]
async fn kernel_backend_establishes_and_tears_down_real_tunnel() {
    require_integration!();

    if let Some(reason) = missing_precondition() {
        if require_net_admin() {
            panic!("PENGUIN_REQUIRE_NET_ADMIN=1 but wg_tunnel precondition unmet: {reason}");
        }
        eprintln!("SKIP: wg_tunnel cannot run here: {reason}");
        return;
    }

    preclean_stale_state();
    let _teardown_guard = TeardownGuard;

    setup_underlay();

    let client_private_key = Key::generate();
    let client_public_key = client_private_key.public_key();
    let (peer_public_key, _peer_key_file) = setup_peer_wireguard(&client_public_key);

    let spec = build_client_tunnel_spec(client_private_key, peer_public_key);
    let backend = KernelBackend::new();
    backend
        .apply(CLIENT_IFACE, &spec)
        .await
        .expect("KernelBackend::apply must bring up a real interface");

    // --- Assertion A: anti-no-op control -----------------------------
    // Immediately after apply, before any traffic, a REAL backend has not
    // handshaked yet. A backend that faked success (Go stamped
    // `time.Now()` at connect — see `wireguard/mod.rs`'s module doc) would
    // show a handshake right here.
    let stats_before = backend
        .peer_stats(CLIENT_IFACE)
        .await
        .expect("peer_stats immediately after apply");
    eprintln!("assertion A: peer_stats immediately after apply = {stats_before:?}");
    assert!(
        stats_before.last_handshake.is_none(),
        "assertion A failed: last_handshake was Some before any traffic: {stats_before:?}"
    );
    assert_eq!(
        stats_before.rx_bytes, 0,
        "assertion A failed: rx_bytes nonzero before any traffic"
    );
    assert_eq!(
        stats_before.tx_bytes, 0,
        "assertion A failed: tx_bytes nonzero before any traffic"
    );

    // --- Assertion B: real handshake + real bytes ---------------------
    // KernelBackend::apply deliberately never installs an IP route for
    // AllowedIPs (see kernel.rs's module doc: AllowedIPs is cryptokey
    // routing, not an IP route) — a real deployment needs some other layer
    // to do this; here, the test does, so a ping actually has a path to
    // take through CLIENT_IFACE.
    run(
        "ip",
        &[
            "route",
            "add",
            &format!("{TUNNEL_PEER_IP}/32"),
            "dev",
            CLIENT_IFACE,
        ],
    )
    .expect("route the peer's tunnel address through the client interface");

    let ping = Command::new("ping")
        .args(["-c", "3", "-W", "2", TUNNEL_PEER_IP])
        .output()
        .expect("spawn ping");
    eprintln!(
        "ping {TUNNEL_PEER_IP}: exit={:?}\n{}",
        ping.status.code(),
        String::from_utf8_lossy(&ping.stdout)
    );

    let stats_after = wait_for_real_handshake(&backend, CLIENT_IFACE, Duration::from_secs(10))
        .await
        .expect("assertion B failed");
    eprintln!("assertion B: peer_stats after real traffic = {stats_after:?}");
    assert!(
        stats_after.last_handshake.is_some(),
        "assertion B failed: no handshake recorded: {stats_after:?}"
    );
    assert!(
        stats_after.rx_bytes > 0 && stats_after.tx_bytes > 0,
        "assertion B failed: zero bytes on one direction: {stats_after:?}"
    );

    println!(
        "M6 gate: real WireGuard tunnel established — before={stats_before:?} after={stats_after:?}"
    );

    // --- Assertion C: teardown is real, and idempotent -----------------
    backend
        .teardown(CLIENT_IFACE)
        .await
        .expect("assertion C failed: first teardown of a live interface");
    assert!(
        !interface_exists(CLIENT_IFACE),
        "assertion C failed: {CLIENT_IFACE} still exists after teardown"
    );
    let stats_after_teardown = backend
        .peer_stats(CLIENT_IFACE)
        .await
        .expect("assertion C failed: peer_stats on an absent interface must be Ok(default)");
    assert_eq!(
        stats_after_teardown,
        PeerStats::default(),
        "assertion C failed: peer_stats did not read back to default() once torn down"
    );
    backend
        .teardown(CLIENT_IFACE)
        .await
        .expect("assertion C failed: teardown must be idempotent on an already-absent interface");

    // --- Assertion D: no leaks -----------------------------------------
    run("ip", &["netns", "del", NETNS]).expect("remove the scaffold peer namespace");
    let netns_list = run("ip", &["netns", "list"]).unwrap_or_default();
    assert!(
        !netns_list.contains(NETNS),
        "assertion D failed: netns {NETNS} still listed: {netns_list}"
    );
    assert!(
        !interface_exists(CLIENT_IFACE),
        "assertion D failed: {CLIENT_IFACE} reappeared after cleanup"
    );
    eprintln!("assertion D: no leaked netns or interface");
}
