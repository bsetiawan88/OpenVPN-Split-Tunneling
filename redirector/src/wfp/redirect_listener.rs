//! Loopback relay for ALE_CONNECT_REDIRECT (TCP) + DATAGRAM (UDP).
//!
//! Single shared numeric port P: TCP 127.0.0.1:P + UDP 127.0.0.1:P
//! (same P, different protocols — allowed on Windows). Published once via
//! IOCTL_SET_REDIRECT_TARGET. Driver keys flows by app SOURCE port
//! (IP_LOCAL_PORT at REDIRECT); the relay recovers it as the accepted
//! socket's PEER port (source preserved across redirect).
//!
//! Both relays pin outbound with IP_UNICAST_IF, matching divert.rs.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::adapter::VpnTarget;
use crate::process::Resolver;
use crate::status_server::StatusBus;
use crate::vpn_state::{self, VpnState};
use crate::wfp::device;
use ipc::status::EventKind;

/// Outbound connect cap, matching divert.rs's tcp_bridge: app data is
/// already queued when the relay starts, so a long cap only delays the
/// failure — 5s retires the flow and logs while still covering slow but
/// live destinations.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_BUF: usize = 65536;
/// Rate-limit for repeated "no original-dst" failures on the same app src,
/// so a chatty datagram loop cannot flood the log/UI bus. Windows: once.
const UDP_WARN_THROTTLE: Duration = Duration::from_secs(5);

fn short(s: &str) -> String {
    const MAX: usize = 180;
    if s.len() <= MAX {
        return s.to_string();
    }
    let mut out: String = s.chars().take(MAX).collect();
    out.push('…');
    out
}

async fn blocking_io<T, F>(label: &'static str, f: F) -> anyhow::Result<T>
where
    F: FnOnce() -> anyhow::Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| anyhow::anyhow!("{} join failed: {}", label, e))?
}

pub async fn run(
    vpn_state: VpnState,
    bus: Arc<StatusBus>,
    resolver: Arc<Resolver>,
) -> Result<()> {
    // Bind TCP ephemeral first to discover P, then bind UDP to the SAME P.
    let tcp = tokio::net::TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        0,
    )))
    .await
    .context("wfp relay: bind TCP 127.0.0.1:0 failed")?;
    let port = tcp.local_addr()?.port();

    let udp = match tokio::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        port,
    )))
    .await
    {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::warn!(
                "wfp relay: UDP bind 127.0.0.1:{} failed ({}) — unconnected UDP will miss until restart; TCP unaffected",
                port,
                short(&e.to_string())
            );
            Arc::new(
                tokio::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    0,
                )))
                .await
                .context("wfp relay: bind UDP fallback failed")?,
            )
        }
    };
    let udp_port = udp.local_addr()?.port();
    if udp_port != port {
        tracing::warn!(
            "wfp relay: TCP P={} but UDP P={} (shared-port bind failed) — driver was published P={}; UDP redirect will miss. Restart relay to retry shared bind.",
            port,
            udp_port,
            port
        );
    }
    publish_redirect_target(port).await;
    tracing::info!(
        "wfp relay listening TCP 127.0.0.1:{} UDP 127.0.0.1:{} (single published P={})",
        port,
        udp_port,
        port
    );

    let udp_task = tokio::spawn(udp_loop(udp.clone(), vpn_state.clone(), bus.clone(), resolver.clone()));
    let tcp_task = tokio::spawn(tcp_loop(tcp, vpn_state.clone(), bus.clone(), resolver.clone()));

    tokio::select! {
        r = tcp_task => r??,
        r = udp_task => r??,
    }
    #[allow(unreachable_code)]
    Ok::<(), anyhow::Error>(())
}

async fn publish_redirect_target(port: u16) {
    loop {
        let r = blocking_io("SET_REDIRECT_TARGET", move || {
            device::set_redirect_target(0x0100007F, port)
        })
        .await;
        match r {
            Ok(()) => {
                tracing::info!("wfp relay: redirect target 127.0.0.1:{} published", port);
                return;
            }
            Err(e) => {
                tracing::warn!(
                    "wfp relay: SET_REDIRECT_TARGET 127.0.0.1:{} failed ({:#}) — retry in 2s",
                    port,
                    e
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

async fn tcp_loop(
    listener: tokio::net::TcpListener,
    vpn_state: VpnState,
    bus: Arc<StatusBus>,
    resolver: Arc<Resolver>,
) -> Result<()> {
    loop {
        let (inbound, peer) = listener.accept().await?;
        let vpn_state = vpn_state.clone();
        let bus = bus.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            // CRITICAL: query by PEER port (app src port preserved across
            // redirect), NOT by listener local port (same P for all flows).
            let app_src_port = match peer {
                SocketAddr::V4(v4) => v4.port(),
                SocketAddr::V6(_) => 0,
            };
            if app_src_port == 0 {
                let detail = format!("wfp relay: peer {} has no usable src port — closing", peer);
                tracing::warn!("{}", detail);
                bus.emit(EventKind::BridgeFailed, detail);
                return;
            }
            let query = blocking_io("QUERY_ORIGINAL_DST", move || {
                device::query_original_dst(app_src_port, 6)
            })
            .await;
            let (dst, pid) = match query {
                Ok(r) => {
                    let ip = Ipv4Addr::from(u32::from_be(r.dst_ip_be));
                    (SocketAddr::V4(SocketAddrV4::new(ip, r.dst_port_host)), r.pid)
                }
                Err(e) => {
                    let detail = format!(
                        "wfp relay: no original-dst for app src port {} (peer {}) ({}) — closing",
                        app_src_port,
                        peer,
                        short(&e.to_string())
                    );
                    tracing::warn!("{}", detail);
                    bus.emit(EventKind::BridgeFailed, detail);
                    return;
                }
            };
            let target = vpn_state::current(&vpn_state);
            if target.is_none() {
                let detail = format!(
                    "wfp relay: VPN down — closing redirected socket for pid {} dst {} (app should reconnect via default route)",
                    pid, dst
                );
                tracing::warn!("{}", detail);
                bus.emit(EventKind::BridgeFailed, short(&detail));
                return;
            }
            let exe = resolver
                .resolve(pid)
                .map(|i| i.exe_name)
                .unwrap_or_else(|| format!("pid {}", pid));
            tracing::info!("wfp tcp bridge open: pid={} {} -> {} via VPN", pid, peer, dst);
            bus.emit(
                EventKind::BridgeOpened,
                format!("TCP \"{}\" (pid {}) {} -> {} via VPN (wfp)", exe, pid, peer, dst),
            );
            match tcp_relay(inbound, dst, target).await {
                Ok(n) => tracing::debug!("wfp tcp bridge closed: {} <-> {} ({} bytes)", peer, dst, n),
                Err(e) => {
                    let detail = format!("TCP \"{}\" (pid {}) to {} failed: {}", exe, pid, dst, short(&e.to_string()));
                    tracing::warn!("{}", detail);
                    bus.emit(EventKind::BridgeFailed, detail);
                }
            }
        });
    }
}

pub async fn tcp_relay(
    inbound: tokio::net::TcpStream,
    dst: SocketAddr,
    target: Option<VpnTarget>,
) -> Result<u64> {
    let outbound = match target {
        Some(t) => {
            let socket = tokio::net::TcpSocket::new_v4()?;
            set_unicast_if_v4(&socket, t.if_index)?;
            socket.bind(SocketAddr::V4(SocketAddrV4::new(t.ipv4, 0)))?;
            tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(dst))
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "wfp relay connect({}) via ifindex {} timed out",
                        dst,
                        t.if_index
                    )
                })?
                .with_context(|| format!("wfp relay connect({}) via ifindex {}", dst, t.if_index))?
        }
        None => tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(dst))
            .await
            .map_err(|_| anyhow::anyhow!("wfp relay connect({}) timed out", dst))?
            .with_context(|| format!("wfp relay connect({})", dst))?,
    };
    let (mut ri, mut wi) = inbound.into_split();
    let (mut ro, mut wo) = outbound.into_split();
    let c2s = tokio::io::copy(&mut ri, &mut wo);
    let s2c = tokio::io::copy(&mut ro, &mut wi);
    let (up, down) = tokio::join!(c2s, s2c);
    match (up, down) {
        (Ok(u), Ok(d)) => Ok(u + d),
        (Err(e), _) => Err(e.into()),
        (_, Err(e)) => Err(e.into()),
    }
}

fn set_unicast_if_v4<S: std::os::windows::io::AsRawSocket>(
    socket: &S,
    if_index: u32,
) -> Result<()> {
    use windows::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, SOCKET};
    let val = if_index.to_be();
    let bytes = val.to_ne_bytes();
    let s = SOCKET(socket.as_raw_socket() as usize);
    const IP_UNICAST_IF: i32 = 31;
    let rc = unsafe { setsockopt(s, IPPROTO_IP.0, IP_UNICAST_IF, Some(&bytes)) };
    if rc != 0 {
        anyhow::bail!(
            "setsockopt(IP_UNICAST_IF, ifindex={}) failed: {}",
            if_index,
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[allow(dead_code)]
pub fn current_target(vpn_state: &VpnState) -> Option<VpnTarget> {
    vpn_state::current(vpn_state)
}

// --- UDP: persistent per-dst recv loops (no 50ms poll) ---

struct UdpNatEntry {
    dst: SocketAddr,
    socket: Arc<tokio::net::UdpSocket>,
    last_active: Instant,
    pid: u32,
}

async fn udp_loop(
    listener: Arc<tokio::net::UdpSocket>,
    vpn_state: VpnState,
    bus: Arc<StatusBus>,
    resolver: Arc<Resolver>,
) -> Result<()> {
    let mut nat: HashMap<SocketAddr, UdpNatEntry> = HashMap::new();
    let mut warn_at: HashMap<SocketAddr, Instant> = HashMap::new();
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let now = Instant::now();
        nat.retain(|_, e| now.duration_since(e.last_active) < UDP_IDLE_TIMEOUT);
        warn_at.retain(|_, t| now.duration_since(*t) < UDP_IDLE_TIMEOUT);
        let (n, src) = listener.recv_from(&mut buf).await?;
        let payload = buf[..n].to_vec();
        let app_src_port = match src {
            SocketAddr::V4(v4) => v4.port(),
            SocketAddr::V6(_) => 0,
        };
        let q = blocking_io("QUERY_ORIGINAL_DST_UDP", move || {
            device::query_original_dst(app_src_port, 17)
        })
        .await;
        let (dst, pid) = match q {
            Ok(r) => {
                let ip = Ipv4Addr::from(u32::from_be(r.dst_ip_be));
                (SocketAddr::V4(SocketAddrV4::new(ip, r.dst_port_host)), r.pid)
            }
            Err(e) => {
                // Loud for BOTH cases (must not silently blackhole): when a
                // stale NAT entry exists the driver flow was lost (VPN
                // rotate / FLUSH_FLOWS / table eviction) and datagrams are
                // being vanishing with zero forensics. Never route via the
                // stale entry — an unconnected app may reuse the same src
                // port for a different dst.
                let throttled = matches!(warn_at.get(&src), Some(t) if now.duration_since(*t) < UDP_WARN_THROTTLE);
                if !throttled {
                    warn_at.insert(src, now);
                    let stale = if nat.contains_key(&src) {
                        " — stale NAT entry retained, will resume once the app reconnects its UDP socket or the entry evicts"
                    } else {
                        ""
                    };
                    let detail = format!(
                        "wfp udp: no original-dst for app src {} ({} bytes) ({}){} — dropping; use connected UDP or ensure driver DATAGRAM mapping",
                        src,
                        n,
                        short(&e.to_string()),
                        stale
                    );
                    tracing::warn!("{}", detail);
                    bus.emit(EventKind::BridgeFailed, short(&detail));
                }
                continue;
            }
        };
        let target = vpn_state::current(&vpn_state);
        if target.is_none() {
            tracing::warn!("wfp udp: VPN down, dropping {} bytes {} -> {}", n, src, dst);
            continue;
        }
        // Reuse NAT socket per (src,dst); spawn ONE persistent reply loop
        // per entry at creation (not per datagram).
        let is_new = !matches!(nat.get(&src), Some(e) if e.dst == dst);
        if is_new {
            let sock = make_vpn_udp_socket(dst, target).await?;
            let sock = Arc::new(sock);
            let exe = resolver.resolve(pid).map(|i| i.exe_name).unwrap_or_else(|| format!("pid {}", pid));
            tracing::info!("wfp udp bridge open: pid={} {} -> {} via VPN", pid, src, dst);
            bus.emit(EventKind::BridgeOpened, format!("UDP \"{}\" (pid {}) {} -> {} via VPN (wfp)", exe, pid, src, dst));
            let sock_c = sock.clone();
            let listener_c = listener.clone();
            let bus_c = bus.clone();
            tokio::spawn(async move {
                let mut rbuf = vec![0u8; UDP_BUF];
                loop {
                    match sock_c.recv(&mut rbuf).await {
                        Ok(nn) => {
                            bus_c.add_pid_in(pid, nn as u64);
                            if listener_c.send_to(&rbuf[..nn], src).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
            nat.insert(src, UdpNatEntry { dst, socket: sock, last_active: now, pid });
        }
        if let Some(entry) = nat.get_mut(&src) {
            entry.last_active = now;
            // Block the loop only on send (fast); replies flow on the task above.
            if let Err(e) = entry.socket.send(&payload).await {
                tracing::warn!("wfp udp: send {} -> {} failed: {}", src, dst, short(&e.to_string()));
            } else {
                bus.add_pid_out(entry.pid, n as u64);
            }
        }
    }
}

async fn make_vpn_udp_socket(dst: SocketAddr, target: Option<VpnTarget>) -> Result<tokio::net::UdpSocket> {
    let local = match target {
        Some(t) => SocketAddr::V4(SocketAddrV4::new(t.ipv4, 0)),
        None => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
    };
    let sock = tokio::net::UdpSocket::bind(local).await?;
    if let Some(t) = target {
        set_unicast_if_v4(&sock, t.if_index)?;
    }
    sock.connect(dst).await?;
    Ok(sock)
}
