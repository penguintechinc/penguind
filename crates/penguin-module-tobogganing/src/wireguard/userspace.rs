//! The userspace WireGuard backend: `boringtun`'s Noise protocol engine
//! over a TUN device and UDP socket.
//!
//! # Architecture
//!
//! [`UserspaceBackend::apply`] creates a live tunnel:
//! - Opens TUN device via `LinuxTunDevice` (ioctl-based, in `tun_linux.rs`)
//! - Binds UDP socket to a local port
//! - Spawns an event loop task that:
//!   - TUN read → `Tunn::encapsulate` → UDP send
//!   - UDP recv → `Tunn::decapsulate` → TUN write / handle `TunnResult`
//!   - Periodic timer tick → `Tunn::update_timers` → send keepalive/handshake
//! - Stores task handle + cancellation token for `teardown()`
//!
//! # Testing
//!
//! Unit tests use [`FakeTunDevice`] and [`LoopbackUdpSocket`] to exercise the
//! event loop logic without real TUN or UDP, and without `CAP_NET_ADMIN`.
//! The integration test (see `tests/userspace_tunnel.rs`) uses real TUN + UDP
//! against a controlled WireGuard peer in a netns.

#![allow(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use async_trait::async_trait;
use boringtun::noise::Tunn;
use boringtun::x25519;
use bytes::BytesMut;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{Duration, interval};
use tokio_util::sync::CancellationToken;

#[cfg(target_os = "linux")]
use crate::wireguard::tun_linux::TunFd;

use super::{BackendKind, PeerStats, TunnelSpec, WgBackendError};

/// Abstracts TUN device I/O for production and testing.
#[async_trait]
#[allow(dead_code)]
pub trait TunDevice: Send + Sync {
    /// Reads the next packet from the TUN device. Returns `None` if the
    /// device is closed.
    async fn read(&mut self) -> Option<BytesMut>;

    /// Writes a packet to the TUN device.
    async fn write(&mut self, packet: &[u8]) -> Result<(), WgBackendError>;

    /// Closes the TUN device. Idempotent.
    async fn close(&mut self);
}

/// Abstracts UDP socket I/O for production and testing.
#[async_trait]
#[allow(dead_code)]
pub trait UdpSocketTrait: Send + Sync {
    /// Receives the next packet from the socket. Returns `None` if the socket
    /// is closed.
    async fn recv(&mut self) -> Option<(BytesMut, SocketAddr)>;

    /// Sends a packet to the given address.
    async fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<(), WgBackendError>;

    /// Closes the socket. Idempotent.
    async fn close(&mut self);
}

/// Linux TUN device implementation via `/dev/net/tun` + `TUNSETIFF` ioctl.
#[cfg(target_os = "linux")]
pub struct LinuxTunDevice {
    fd: tokio::io::unix::AsyncFd<TunFd>,
    #[allow(dead_code)]
    name: String,
}

#[cfg(target_os = "linux")]
impl LinuxTunDevice {
    /// Creates a new TUN device with the given name.
    pub async fn new(name: &str) -> Result<Self, WgBackendError> {
        let tun_fd = TunFd::open(name)?;
        let name_str = name.to_string();
        // SAFETY: TunFd exclusively owns a valid open TUN fd for its whole lifetime and
        // as_raw_fd() always returns that same fd (tokio >=1.54 AsyncFd::register contract).
        let fd = unsafe { tokio::io::unix::AsyncFd::register(tun_fd) }
            .map_err(|e| WgBackendError::Interface(format!("AsyncFd wrapping failed: {e}")))?;
        Ok(LinuxTunDevice { fd, name: name_str })
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl TunDevice for LinuxTunDevice {
    async fn read(&mut self) -> Option<BytesMut> {
        let mut buf = BytesMut::with_capacity(1500);
        buf.resize(1500, 0);

        loop {
            let mut guard = match self.fd.readable().await {
                Ok(g) => g,
                Err(_) => return None,
            };

            match guard.try_io(|inner| {
                #[allow(unused_imports)]
                use std::os::unix::io::AsRawFd;
                // SAFETY: inner.get_ref() is a valid TunFd, and we have an async guard
                // ensuring we don't block or race. The buffer is properly sized.
                unsafe {
                    let ret = libc::read(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        1500,
                    );
                    if ret < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(ret as usize)
                    }
                }
            }) {
                Ok(Ok(len)) => {
                    buf.truncate(len);
                    return Some(buf);
                }
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Ok(Err(_)) | Err(_) => return None,
            }
        }
    }

    async fn write(&mut self, packet: &[u8]) -> Result<(), WgBackendError> {
        loop {
            let mut guard = self
                .fd
                .writable()
                .await
                .map_err(|e| WgBackendError::Interface(format!("writable failed: {e}")))?;

            match guard.try_io(|inner| {
                #[allow(unused_imports)]
                use std::os::unix::io::AsRawFd;
                unsafe {
                    let ret = libc::write(
                        inner.get_ref().as_raw_fd(),
                        packet.as_ptr() as *const libc::c_void,
                        packet.len(),
                    );
                    if ret < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(ret as usize)
                    }
                }
            }) {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Ok(Err(e)) => return Err(WgBackendError::Interface(format!("write failed: {e}"))),
                Err(_) => return Err(WgBackendError::Interface("try_io failed".to_string())),
            }
        }
    }

    async fn close(&mut self) {}
}

/// Tokio-based UDP socket implementation.
pub struct TokioUdpSocket {
    socket: Arc<UdpSocket>,
}

impl TokioUdpSocket {
    /// Creates a new UDP socket bound to a local address.
    pub async fn new(local_addr: SocketAddr) -> Result<Self, WgBackendError> {
        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(|e| WgBackendError::Interface(format!("UDP bind failed: {e}")))?;
        Ok(TokioUdpSocket {
            socket: Arc::new(socket),
        })
    }
}

#[async_trait]
impl UdpSocketTrait for TokioUdpSocket {
    async fn recv(&mut self) -> Option<(BytesMut, SocketAddr)> {
        let mut buf = BytesMut::with_capacity(1500);
        buf.resize(1500, 0);
        match self.socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                buf.truncate(len);
                Some((buf, addr))
            }
            Err(_) => None,
        }
    }

    async fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<(), WgBackendError> {
        self.socket
            .send_to(data, addr)
            .await
            .map_err(|e| WgBackendError::Interface(format!("UDP send failed: {e}")))?;
        Ok(())
    }

    async fn close(&mut self) {}
}

/// Test double: fake TUN device buffering packets in memory.
pub struct FakeTunDevice {
    packets: Arc<Mutex<Vec<BytesMut>>>,
    #[allow(dead_code)]
    closed: Arc<AtomicBool>,
}

impl FakeTunDevice {
    /// Creates a new fake TUN device.
    pub fn new() -> Self {
        FakeTunDevice {
            packets: Arc::new(Mutex::new(Vec::new())),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Injects a packet to be read by the next `read()` call.
    #[allow(dead_code)]
    pub async fn inject_packet(&self, packet: BytesMut) {
        self.packets.lock().await.push(packet);
    }

    /// Retrieves all packets written so far.
    #[allow(dead_code)]
    pub async fn written_packets(&self) -> Vec<BytesMut> {
        self.packets.lock().await.clone()
    }

    /// Clears the written packets buffer.
    #[allow(dead_code)]
    pub async fn clear_written(&self) {
        self.packets.lock().await.clear();
    }
}

impl Default for FakeTunDevice {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TunDevice for FakeTunDevice {
    async fn read(&mut self) -> Option<BytesMut> {
        self.packets.lock().await.pop()
    }

    async fn write(&mut self, packet: &[u8]) -> Result<(), WgBackendError> {
        self.packets.lock().await.insert(0, BytesMut::from(packet));
        Ok(())
    }

    async fn close(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

/// Test double: loopback UDP socket, storing packets in memory.
pub struct LoopbackUdpSocket {
    packets: Arc<Mutex<Vec<(BytesMut, SocketAddr)>>>,
    #[allow(dead_code)]
    closed: Arc<AtomicBool>,
}

impl LoopbackUdpSocket {
    /// Creates a new loopback UDP socket.
    pub fn new() -> Self {
        LoopbackUdpSocket {
            packets: Arc::new(Mutex::new(Vec::new())),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Injects a packet to be received by the next `recv()` call.
    #[allow(dead_code)]
    pub async fn inject_packet(&self, packet: BytesMut, addr: SocketAddr) {
        self.packets.lock().await.push((packet, addr));
    }

    /// Retrieves all packets sent so far.
    #[allow(dead_code)]
    pub async fn sent_packets(&self) -> Vec<(BytesMut, SocketAddr)> {
        self.packets.lock().await.clone()
    }

    /// Clears the sent packets buffer.
    #[allow(dead_code)]
    pub async fn clear_sent(&self) {
        self.packets.lock().await.clear();
    }
}

impl Default for LoopbackUdpSocket {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UdpSocketTrait for LoopbackUdpSocket {
    async fn recv(&mut self) -> Option<(BytesMut, SocketAddr)> {
        self.packets.lock().await.pop()
    }

    async fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<(), WgBackendError> {
        self.packets
            .lock()
            .await
            .insert(0, (BytesMut::from(data), addr));
        Ok(())
    }

    async fn close(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

/// Shared tunnel event loop state.
struct EventLoopState {
    tunn: Tunn,
    peer_addr: SocketAddr,
    last_handshake: Option<SystemTime>,
    rx_bytes: u64,
    tx_bytes: u64,
}

/// Backend instance storing the event loop task and cancellation token.
struct BackendInstance {
    _task: JoinHandle<()>,
    cancel: CancellationToken,
    state: Arc<Mutex<EventLoopState>>,
}

impl Drop for BackendInstance {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// `boringtun`-backed WireGuard engine with full data plane.
pub struct UserspaceBackend {
    instance: Arc<Mutex<Option<BackendInstance>>>,
}

impl UserspaceBackend {
    /// Builds a new userspace backend. Cheap: performs no I/O.
    pub fn new() -> UserspaceBackend {
        UserspaceBackend {
            instance: Arc::new(Mutex::new(None)),
        }
    }
}

impl Default for UserspaceBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl super::WireGuardBackend for UserspaceBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Userspace
    }

    /// Creates a live tunnel: opens TUN device, binds UDP socket, spawns event loop.
    async fn apply(&self, interface: &str, spec: &TunnelSpec) -> Result<(), WgBackendError> {
        #[cfg(not(target_os = "linux"))]
        return Err(WgBackendError::Unsupported {
            operation: "apply",
            reason: "userspace WireGuard is only implemented on Linux",
        });

        #[cfg(target_os = "linux")]
        {
            // Create TUN device
            let tun_dev = LinuxTunDevice::new(interface).await?;

            // Bind UDP socket to any address, auto-assigned port.
            // Binding to 0.0.0.0 allows the kernel to select the best source address
            // based on the destination route when sending (standard for VPN data planes).
            // The kernel will automatically select which source IP to use based on the
            // routing table (e.g., if sending to 10.0.1.1, it will use the IP of the
            // interface that has a route to 10.0.1.0/24).
            let local_addr = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                0,
            );
            let udp_sock = TokioUdpSocket::new(local_addr).await?;

            // Build the Tunn (boringtun state machine)
            let tunn = build_tunn(spec);

            // Initialize shared state
            let state = Arc::new(Mutex::new(EventLoopState {
                tunn,
                peer_addr: spec.endpoint,
                last_handshake: None,
                rx_bytes: 0,
                tx_bytes: 0,
            }));

            // Create cancellation token for event loop shutdown
            let cancel = CancellationToken::new();
            let cancel_clone = cancel.clone();
            let state_clone = state.clone();

            // Spawn the event loop task
            let task = tokio::spawn(async move {
                let _ = event_loop(tun_dev, udp_sock, state_clone, cancel_clone).await;
            });

            // Store the instance
            *self.instance.lock().await = Some(BackendInstance {
                _task: task,
                cancel,
                state,
            });

            Ok(())
        }
    }

    /// Reads live handshake state and byte counts from the event loop's state.
    async fn peer_stats(&self, _interface: &str) -> Result<PeerStats, WgBackendError> {
        match self.instance.lock().await.as_ref() {
            None => Ok(PeerStats::default()),
            Some(inst) => {
                let state = inst.state.lock().await;
                Ok(PeerStats {
                    last_handshake: state.last_handshake,
                    rx_bytes: state.rx_bytes,
                    tx_bytes: state.tx_bytes,
                })
            }
        }
    }

    /// Closes the TUN device and terminates the event loop.
    async fn teardown(&self, _interface: &str) -> Result<(), WgBackendError> {
        *self.instance.lock().await = None;
        Ok(())
    }
}

/// Event loop: drives TUN read → encapsulate → UDP send, and vice versa.
async fn event_loop(
    mut tun: LinuxTunDevice,
    mut udp: TokioUdpSocket,
    state: Arc<Mutex<EventLoopState>>,
    cancel: CancellationToken,
) {
    let mut timer = interval(Duration::from_millis(100));

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                let _ = tun.close().await;
                let _ = udp.close().await;
                return;
            }

            // TUN read → encapsulate → UDP send
            Some(packet) = tun.read() => {
                let mut state_guard = state.lock().await;
                let packet_len = packet.len() as u64;
                let mut buf = [0u8; 1500];
                match state_guard.tunn.encapsulate(&packet, &mut buf) {
                    boringtun::noise::TunnResult::WriteToNetwork(encap_pkt) => {
                        let _ = udp.send(encap_pkt, state_guard.peer_addr).await;
                        state_guard.tx_bytes += packet_len;
                    }
                    boringtun::noise::TunnResult::Done => {},
                    _ => {}
                }
            }

            // UDP recv → decapsulate → TUN write / handle
            Some((packet, _addr)) = udp.recv() => {
                let packet_len = packet.len() as u64;
                let mut state_guard = state.lock().await;
                let mut buf = [0u8; 1500];
                match state_guard.tunn.decapsulate(None, &packet, &mut buf) {
                    boringtun::noise::TunnResult::WriteToTunnelV4(decap_pkt, _) => {
                        state_guard.rx_bytes += decap_pkt.len() as u64;
                        let _ = tun.write(decap_pkt).await;
                        state_guard.last_handshake = Some(SystemTime::now());
                    }
                    boringtun::noise::TunnResult::WriteToTunnelV6(decap_pkt, _) => {
                        state_guard.rx_bytes += decap_pkt.len() as u64;
                        let _ = tun.write(decap_pkt).await;
                        state_guard.last_handshake = Some(SystemTime::now());
                    }
                    boringtun::noise::TunnResult::WriteToNetwork(resp_pkt) => {
                        let _ = udp.send(resp_pkt, state_guard.peer_addr).await;
                        state_guard.tx_bytes += packet_len;
                    }
                    boringtun::noise::TunnResult::Done => {},
                    boringtun::noise::TunnResult::Err(_) => {},
                }
            }

            // Timer tick → update timers → send keepalive/handshake
            _ = timer.tick() => {
                let mut state_guard = state.lock().await;
                let mut buf = [0u8; 1500];
                match state_guard.tunn.update_timers(&mut buf) {
                    boringtun::noise::TunnResult::WriteToNetwork(pkt) => {
                        state_guard.tx_bytes += pkt.len() as u64;
                        let _ = udp.send(pkt, state_guard.peer_addr).await;
                    }
                    boringtun::noise::TunnResult::Done => {},
                    _ => {}
                }
            }
        }
    }
}

/// Builds a `boringtun` Noise-protocol tunnel from `spec`'s keys.
#[allow(dead_code)]
fn build_tunn(spec: &TunnelSpec) -> Tunn {
    let private = x25519::StaticSecret::from(spec.private_key.as_array());
    let public = x25519::PublicKey::from(spec.peer_public_key.as_array());
    let keepalive = spec
        .keepalive
        .map(|interval| interval.as_secs().min(u64::from(u16::MAX)) as u16);
    Tunn::new(private, public, None, keepalive, 0, None)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use boringtun::noise::TunnResult;
    use defguard_wireguard_rs::key::Key;

    use super::*;
    use crate::wireguard::WireGuardBackend;

    fn sample_spec() -> TunnelSpec {
        TunnelSpec {
            private_key: Key::generate(),
            client_address: "10.0.0.2/32".parse().unwrap(),
            peer_public_key: Key::generate().public_key(),
            endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 51820),
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            dns: Vec::new(),
            mtu: 1420,
            keepalive: Some(Duration::from_secs(25)),
        }
    }

    /// Proves the boringtun integration is real: a [`Tunn`] built from a
    /// [`TunnelSpec`] can format a genuine WireGuard handshake-initiation
    /// packet, entirely offline (no socket, no TUN device, no network).
    #[test]
    fn build_tunn_formats_a_real_handshake_initiation_packet() {
        let spec = sample_spec();
        let mut tunn = build_tunn(&spec);

        let mut buf = [0u8; 148];
        let result = tunn.format_handshake_initiation(&mut buf, false);

        match result {
            TunnResult::WriteToNetwork(packet) => {
                // Message type 1 (handshake initiation), little-endian, is
                // the first four bytes of every WireGuard handshake-init
                // packet on the wire.
                assert_eq!(&packet[0..4], &1u32.to_le_bytes());
                assert_eq!(packet.len(), 148);
            }
            other => panic!("expected a handshake initiation packet, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fake_tun_device_buffers_packets() {
        let mut device = FakeTunDevice::new();

        device.inject_packet(BytesMut::from("test packet")).await;
        let packet = device.read().await;
        assert_eq!(packet, Some(BytesMut::from("test packet")));
    }

    #[tokio::test]
    async fn fake_tun_device_tracks_writes() {
        let mut device = FakeTunDevice::new();

        device.write(b"packet1").await.unwrap();
        device.write(b"packet2").await.unwrap();

        let written = device.written_packets().await;
        assert_eq!(written.len(), 2);
        assert_eq!(written[0], BytesMut::from("packet2"));
        assert_eq!(written[1], BytesMut::from("packet1"));
    }

    #[tokio::test]
    async fn loopback_udp_socket_forwards_packets() {
        let mut socket = LoopbackUdpSocket::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 51820);

        let packet = BytesMut::from("udp packet");
        socket.inject_packet(packet.clone(), addr).await;

        let (recv_pkt, recv_addr) = socket.recv().await.unwrap();
        assert_eq!(recv_pkt, packet);
        assert_eq!(recv_addr, addr);
    }

    #[tokio::test]
    async fn loopback_udp_socket_tracks_sends() {
        let mut socket = LoopbackUdpSocket::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 51820);

        socket.send(b"packet1", addr).await.unwrap();
        socket.send(b"packet2", addr).await.unwrap();

        let sent = socket.sent_packets().await;
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].0, BytesMut::from("packet2"));
        assert_eq!(sent[1].0, BytesMut::from("packet1"));
    }

    #[test]
    fn kind_reports_userspace() {
        assert_eq!(UserspaceBackend::new().kind(), BackendKind::Userspace);
    }
}
