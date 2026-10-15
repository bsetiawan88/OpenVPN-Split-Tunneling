use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use windivert::layer::NetworkLayer;
use windivert::prelude::*;
use windivert_sys::ChecksumFlags;

use crate::adapter::VpnTarget;
use crate::flows::{self, FlowEntry, FlowTable, LocalEndpoint, PROTO_TCP, PROTO_UDP};
use crate::pidlookup;
use crate::policy::{self, PolicyState};
use crate::process::Resolver;
use crate::stack::VirtualDevice;
use crate::status_server::StatusBus;
use crate::tunneled::{self, TunneledPaths};
use crate::vpn_state::{self, VpnState};

const BRIDGE_CHANNEL_DEPTH: usize = 64;
const SMOLTCP_CHUNK: usize = 16 * 1024;
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[allow(clippy::too_many_arguments)]
pub fn run(
    policy_state: PolicyState,
    flows: FlowTable,
    vpn_state: VpnState,
    bus: Arc<StatusBus>,
    resolver: Arc<Resolver>,
    tunneled_paths: TunneledPaths,
) -> Result<()> {
    let capture_filter = "outbound and ip and (tcp or udp) and !loopback";
    let capture = WinDivert::network(capture_filter, 1040, WinDivertFlags::new())
        .context("WinDivert::network capture handle failed (need admin)")?;
    let inject = WinDivert::network(
        "false",
        1039,
        WinDivertFlags::new().set_send_only(),
    )
    .context("WinDivert::network inject handle failed")?;

    tracing::info!(
        "divert: capture+inject open, filter={}, smoltcp mode",
        capture_filter
    );

    let tokio_handle = tokio::runtime::Handle::current();

    let mut device = VirtualDevice::new();
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        smoltcp::time::Instant::now(),
    );
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(0, 0, 0, 0)), 0));
    });
    iface.set_any_ip(true);

    let mut sockets: SocketSet<'static> = SocketSet::new(Vec::new());
    let mut tcp_flows: HashMap<TcpKey, TcpFlow> = HashMap::new();
    let mut udp_flows: HashMap<UdpKey, UdpFlow> = HashMap::new();

    let stats = Arc::new(Stats::new(bus.clone()));
    let stats_clone = stats.clone();
    std::thread::spawn(move || stats_clone.report_loop());

    let mut buffer = vec![0u8; 65535];
    let mut last_vpn = vpn_state::current(&vpn_state);

    loop {
        let now_vpn = vpn_state::current(&vpn_state);
        if now_vpn != last_vpn {
            on_vpn_change(last_vpn, now_vpn, &mut tcp_flows, &mut udp_flows, &mut sockets, &stats);
            last_vpn = now_vpn;
        }

        let recv_result = capture.recv_wait(&mut buffer, 50);
        if let Ok(Some(packet)) = recv_result {
            handle_capture(
                packet,
                &capture,
                &policy_state,
                &flows,
                &mut tcp_flows,
                &mut udp_flows,
                &mut sockets,
                &mut device,
                &tokio_handle,
                now_vpn,
                &stats,
                &resolver,
                &tunneled_paths,
                &bus,
            );
        }

        let _ = iface.poll(smoltcp::time::Instant::now(), &mut device, &mut sockets);
        drain_tx(&mut device, &inject, &stats);

        service_tcp_flows(&mut tcp_flows, &mut sockets, &tokio_handle, now_vpn, &stats);
        service_udp_flows(&mut udp_flows, &inject, &stats);

        let _ = iface.poll(smoltcp::time::Instant::now(), &mut device, &mut sockets);
        drain_tx(&mut device, &inject, &stats);
    }
}

fn on_vpn_change(
    prev: Option<VpnTarget>,
    now: Option<VpnTarget>,
    tcp_flows: &mut HashMap<TcpKey, TcpFlow>,
    udp_flows: &mut HashMap<UdpKey, UdpFlow>,
    sockets: &mut SocketSet<'static>,
    stats: &Stats,
) {
    // Any target change (down OR new IP/ifindex after rotate/reconnect)
    // invalidates existing bridges: their sockets are bound to the old
    // interface address / IP_UNICAST_IF index and would go dead. Drain them
    // so apps reconnect through the fresh tunnel on their next SYN.
    let changed = match (prev, now) {
        (Some(a), Some(b)) => a != b,
        (None, None) => false,
        _ => true,
    };
    if !changed {
        return;
    }
    if prev.is_some() && now.is_none() {
        let tcp_n = tcp_flows.len();
        let udp_n = udp_flows.len();
        if tcp_n + udp_n > 0 {
            tracing::warn!(
                "VPN down — closing {} TCP + {} UDP tunneled flows",
                tcp_n, udp_n
            );
        }
    } else if let (Some(old), Some(new)) = (prev, now) {
        let tcp_n = tcp_flows.len();
        let udp_n = udp_flows.len();
        if tcp_n + udp_n > 0 {
            tracing::warn!(
                "VPN target changed {} (ifindex {}) -> {} (ifindex {}) — recycling {} TCP + {} UDP tunneled flows",
                old.ipv4, old.if_index, new.ipv4, new.if_index, tcp_n, udp_n
            );
        }
    }
    if prev.is_some() {
        for (_, flow) in tcp_flows.drain() {
            sockets.remove(flow.handle);
            stats.bridges_closed.fetch_add(1, Ordering::Relaxed);
        }
        // dropping the UdpFlow values closes the channels, which causes the
        // bridge tasks to exit on the next recv attempt.
        let dropped = udp_flows.drain().count() as u64;
        stats.bridges_closed.fetch_add(dropped, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpKey {
    src_ip: Ipv4Addr,
    src_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpKey {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

struct TcpFlow {
    handle: SocketHandle,
    pid: u32,
    original_dst: SocketAddr,
    state: TcpState,
}

enum TcpState {
    Pending,
    Bridging {
        app_to_remote: mpsc::Sender<Vec<u8>>,
        remote_to_app: mpsc::Receiver<Vec<u8>>,
        app_half_closed: bool,
    },
    Closed,
}

struct UdpFlow {
    pid: u32,
    app_endpoint: (Ipv4Addr, u16),
    original_dst: (Ipv4Addr, u16),
    app_to_remote: mpsc::Sender<Vec<u8>>,
    remote_to_app: mpsc::Receiver<Vec<u8>>,
    last_active: Instant,
}

/// Resolve the owning PID for a freshly-seen flow. The fast path is the
/// observer-populated flow table; on miss we query the Windows TCP/UDP
/// table directly. On both-miss we tight-loop for ~1 ms because the kernel
/// builds the SYN packet *after* creating the TCB, so the TCP table is
/// guaranteed to have the row by the time we'd reasonably give up — but
/// IPHLPAPI may serve a stale snapshot for a few hundred microseconds.
/// Holding the packet here is fine: WinDivert has it queued and it doesn't
/// hit the wire until we call capture.send() or push it into smoltcp.
fn resolve_pid_with_retry(
    flows: &FlowTable,
    src_ip: Ipv4Addr,
    src_port: u16,
    proto: u8,
) -> Option<u32> {
    let lookup = |flows: &FlowTable| -> Option<u32> {
        flows::lookup_with_wildcard(flows, IpAddr::V4(src_ip), src_port, proto)
            .map(|e| e.pid)
            .or_else(|| pidlookup::pid_for_local_v4(src_ip, src_port, proto))
    };

    if let Some(p) = lookup(flows) {
        return Some(p);
    }
    for _ in 0..5 {
        std::thread::sleep(Duration::from_micros(200));
        if let Some(p) = lookup(flows) {
            return Some(p);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn handle_capture(
    packet: WinDivertPacket<'_, NetworkLayer>,
    capture: &WinDivert<NetworkLayer>,
    policy_state: &PolicyState,
    flows: &FlowTable,
    tcp_flows: &mut HashMap<TcpKey, TcpFlow>,
    udp_flows: &mut HashMap<UdpKey, UdpFlow>,
    sockets: &mut SocketSet<'static>,
    device: &mut VirtualDevice,
    tokio_handle: &tokio::runtime::Handle,
    vpn_target: Option<VpnTarget>,
    stats: &Stats,
    resolver: &Arc<Resolver>,
    tunneled_paths: &TunneledPaths,
    bus: &Arc<StatusBus>,
) {
    let parsed = match parse_ipv4_l4(&packet.data) {
        Some(p) => p,
        None => {
            let _ = capture.send(&packet);
            stats.passed.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    let (src_ip, src_port, dst_ip, dst_port, is_tcp) = match parsed {
        ParsedL4::Tcp { src_ip, src_port, dst_ip, dst_port, .. } => {
            (src_ip, src_port, dst_ip, dst_port, true)
        }
        ParsedL4::Udp { src_ip, src_port, dst_ip, dst_port, .. } => {
            (src_ip, src_port, dst_ip, dst_port, false)
        }
    };

    let proto = if is_tcp { PROTO_TCP } else { PROTO_UDP };
    let pid = resolve_pid_with_retry(flows, src_ip, src_port, proto);
    if let Some(p) = pid {
        flows::insert(
            flows,
            LocalEndpoint { addr: IpAddr::V4(src_ip), port: src_port, proto },
            FlowEntry { pid: p },
        );
    }

    // Three-step admission:
    //   1. PID already in policy → tunnel
    //   2. PID has a known exe path matching the tunnel list → admit now
    //      (this is the path that closes the proc_watcher race — fast
    //      launchers like STOVE make their first connection before any
    //      polling tick would catch them)
    //   3. PID is a child of a tunneled PID → inherit (launcher -> game)
    //   4. otherwise → pass through to the default route
    let is_tunneled = match pid {
        Some(p) if policy::contains(policy_state, p) => true,
        Some(p) => {
            if let Some(info) = resolver.resolve(p) {
                if tunneled::matches(tunneled_paths, std::path::Path::new(&info.exe_path)) {
                    tracing::info!(
                        "auto-tunnel (packet): pid={} matches {}",
                        p, info.exe_path
                    );
                    policy::add(policy_state, p);
                    bus.pid_paths.insert(p, info.exe_path);
                    true
                } else if let Some(ppid) = resolver.parent_of(p) {
                    if policy::contains(policy_state, ppid) {
                        tracing::info!(
                            "auto-tunnel (packet child): pid={} parent={} exe={}",
                            p, ppid, info.exe_path
                        );
                        policy::add(policy_state, p);
                        bus.pid_paths.insert(p, info.exe_path);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                // No exe path (yet) — still check parent inheritance so
                // short-lived children of tunneled parents don't escape.
                match resolver.parent_of(p) {
                    Some(ppid) if policy::contains(policy_state, ppid) => {
                        tracing::info!(
                            "auto-tunnel (packet child, no exe): pid={} parent={}",
                            p, ppid
                        );
                        policy::add(policy_state, p);
                        true
                    }
                    _ => false,
                }
            }
        }
        None => false,
    };

    if !is_tunneled {
        let _ = capture.send(&packet);
        stats.passed.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let pid = pid.unwrap();

    // Fail-open: if the VPN is down, send the packet out the default route
    // instead of dropping it. This trades the "no clear-text leak when VPN
    // disconnects mid-session" guarantee for "tunneled apps keep working
    // when the user has the VPN off." Existing smoltcp flows for this PID
    // were already torn down by on_vpn_change when the VPN went away, so
    // the app will see a RST and reconnect — and that reconnect goes
    // straight through here.
    if vpn_target.is_none() {
        let _ = capture.send(&packet);
        stats.passed.fetch_add(1, Ordering::Relaxed);
        return;
    }

    if is_tcp {
        let key = TcpKey { src_ip, src_port };
        if !tcp_flows.contains_key(&key) {
            let rx_buf = tcp::SocketBuffer::new(vec![0u8; 65536]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; 65536]);
            let mut sock = tcp::Socket::new(rx_buf, tx_buf);
            let endpoint = IpEndpoint::new(IpAddress::Ipv4(dst_ip.into()), dst_port);
            if let Err(e) = sock.listen(endpoint) {
                tracing::warn!("smoltcp tcp::listen({}) failed: {:?}", endpoint, e);
                return;
            }
            let handle = sockets.add(sock);
            tcp_flows.insert(
                key,
                TcpFlow {
                    handle,
                    pid,
                    original_dst: SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port)),
                    state: TcpState::Pending,
                },
            );
        }
        device.push_rx(packet.data.into_owned());
        stats.captured.fetch_add(1, Ordering::Relaxed);
    } else {
        let key = UdpKey { src_ip, src_port, dst_ip, dst_port };
        let payload = match extract_udp_payload(&packet.data) {
            Some(p) => p,
            None => {
                tracing::warn!("could not extract UDP payload");
                return;
            }
        };

        if !udp_flows.contains_key(&key) {
            let (a2r_tx, a2r_rx) = mpsc::channel::<Vec<u8>>(BRIDGE_CHANNEL_DEPTH);
            let (r2a_tx, r2a_rx) = mpsc::channel::<Vec<u8>>(BRIDGE_CHANNEL_DEPTH);

            tracing::info!(
                "udp bridge open: pid={} {}:{} -> {}:{}",
                pid, src_ip, src_port, dst_ip, dst_port
            );

            let dst = SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port));
            tokio_handle.spawn(async move {
                if let Err(e) = udp_bridge(dst, vpn_target, a2r_rx, r2a_tx).await {
                    tracing::warn!("udp bridge to {} failed: {:#}", dst, e);
                }
            });
            stats.bridges_opened.fetch_add(1, Ordering::Relaxed);

            udp_flows.insert(
                key,
                UdpFlow {
                    pid,
                    app_endpoint: (src_ip, src_port),
                    original_dst: (dst_ip, dst_port),
                    app_to_remote: a2r_tx,
                    remote_to_app: r2a_rx,
                    last_active: Instant::now(),
                },
            );
        }

        if let Some(flow) = udp_flows.get_mut(&key) {
            flow.last_active = Instant::now();
            let len = packet.data.len() as u64;
            if flow.app_to_remote.try_send(payload).is_ok() {
                stats.add_app_to_remote(len);
                stats.add_pid_out(flow.pid, len);
            }
        }
        stats.captured.fetch_add(1, Ordering::Relaxed);
        // packet consumed - do NOT reinject
    }
}

fn drain_tx(device: &mut VirtualDevice, inject: &WinDivert<NetworkLayer>, stats: &Stats) {
    while let Some(data) = device.pop_tx() {
        send_injected(inject, data, stats);
    }
}

fn send_injected(inject: &WinDivert<NetworkLayer>, data: Vec<u8>, stats: &Stats) {
    let mut addr = unsafe { WinDivertAddress::<NetworkLayer>::new() };
    addr.set_outbound(true);
    addr.set_ip_checksum(false);
    addr.set_tcp_checksum(false);
    addr.set_udp_checksum(false);
    let mut pkt = WinDivertPacket {
        address: addr,
        data: Cow::Owned(data),
    };
    if let Err(e) = pkt.recalculate_checksums(ChecksumFlags::new()) {
        tracing::warn!("inject checksum recalc failed: {}", e);
        return;
    }
    if let Err(e) = inject.send(&pkt) {
        tracing::warn!("inject send failed: {}", e);
        return;
    }
    stats.injected.fetch_add(1, Ordering::Relaxed);
}

fn service_tcp_flows(
    tcp_flows: &mut HashMap<TcpKey, TcpFlow>,
    sockets: &mut SocketSet<'static>,
    tokio_handle: &tokio::runtime::Handle,
    vpn_target: Option<VpnTarget>,
    stats: &Stats,
) {
    let mut to_remove = Vec::new();
    for (key, flow) in tcp_flows.iter_mut() {
        match &mut flow.state {
            TcpState::Pending => {
                let socket = sockets.get_mut::<tcp::Socket>(flow.handle);
                if socket.state() == tcp::State::Established {
                    let (a2r_tx, a2r_rx) = mpsc::channel::<Vec<u8>>(BRIDGE_CHANNEL_DEPTH);
                    let (r2a_tx, r2a_rx) = mpsc::channel::<Vec<u8>>(BRIDGE_CHANNEL_DEPTH);

                    tracing::info!(
                        "tcp bridge open: pid={} {}:{} -> {}",
                        flow.pid, key.src_ip, key.src_port, flow.original_dst
                    );

                    let dst = flow.original_dst;
                    tokio_handle.spawn(async move {
                        if let Err(e) = tcp_bridge(dst, vpn_target, a2r_rx, r2a_tx).await {
                            tracing::warn!("tcp bridge to {} failed: {:#}", dst, e);
                        }
                    });
                    stats.bridges_opened.fetch_add(1, Ordering::Relaxed);

                    flow.state = TcpState::Bridging {
                        app_to_remote: a2r_tx,
                        remote_to_app: r2a_rx,
                        app_half_closed: false,
                    };
                }
            }
            TcpState::Bridging { app_to_remote, remote_to_app, app_half_closed } => {
                let socket = sockets.get_mut::<tcp::Socket>(flow.handle);
                pump_tcp_app_to_remote(socket, app_to_remote, app_half_closed, flow.pid, stats);
                pump_tcp_remote_to_app(socket, remote_to_app, flow.pid, stats);
                if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) {
                    flow.state = TcpState::Closed;
                }
            }
            TcpState::Closed => to_remove.push(*key),
        }
    }
    for k in to_remove {
        if let Some(flow) = tcp_flows.remove(&k) {
            sockets.remove(flow.handle);
            stats.bridges_closed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn service_udp_flows(
    udp_flows: &mut HashMap<UdpKey, UdpFlow>,
    inject: &WinDivert<NetworkLayer>,
    stats: &Stats,
) {
    let now = Instant::now();
    let mut to_remove = Vec::new();

    for (key, flow) in udp_flows.iter_mut() {
        loop {
            match flow.remote_to_app.try_recv() {
                Ok(payload) => {
                    flow.last_active = now;
                    let pkt = build_udp_packet(
                        flow.original_dst.0,
                        flow.original_dst.1,
                        flow.app_endpoint.0,
                        flow.app_endpoint.1,
                        &payload,
                    );
                    stats.add_remote_to_app(payload.len() as u64);
                    stats.add_pid_in(flow.pid, payload.len() as u64);
                    send_injected(inject, pkt, stats);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    to_remove.push(*key);
                    break;
                }
            }
        }
        if now.duration_since(flow.last_active) > UDP_IDLE_TIMEOUT {
            to_remove.push(*key);
        }
    }

    for k in to_remove {
        if udp_flows.remove(&k).is_some() {
            stats.bridges_closed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn pump_tcp_app_to_remote(
    socket: &mut tcp::Socket,
    sender: &mpsc::Sender<Vec<u8>>,
    app_half_closed: &mut bool,
    pid: u32,
    stats: &Stats,
) {
    while socket.can_recv() {
        let mut buf = vec![0u8; SMOLTCP_CHUNK];
        let n = match socket.recv_slice(&mut buf) {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        buf.truncate(n);
        match sender.try_send(buf) {
            Ok(()) => {
                stats.add_app_to_remote(n as u64);
                stats.add_pid_out(pid, n as u64);
            }
            Err(_) => break,
        }
    }
    if !*app_half_closed && matches!(
        socket.state(),
        tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing
    ) {
        *app_half_closed = true;
    }
}

fn pump_tcp_remote_to_app(
    socket: &mut tcp::Socket,
    receiver: &mut mpsc::Receiver<Vec<u8>>,
    pid: u32,
    stats: &Stats,
) {
    while socket.can_send() {
        match receiver.try_recv() {
            Ok(data) => {
                let mut written = 0;
                while written < data.len() {
                    match socket.send_slice(&data[written..]) {
                        Ok(0) => break,
                        Ok(n) => {
                            written += n;
                            stats.add_remote_to_app(n as u64);
                            stats.add_pid_in(pid, n as u64);
                        }
                        Err(_) => return,
                    }
                }
            }
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                socket.close();
                break;
            }
        }
    }
}

/// Pin a TCP/UDP socket to a specific outgoing interface so the kernel ignores
/// the system routing table and egresses via the chosen NIC. Combined with
/// `--pull-filter ignore redirect-gateway` on the OpenVPN side, this is what
/// turns the tunnel into a true split-tunnel — only sockets we explicitly pin
/// land on the VPN, everything else stays on the default route.
fn set_unicast_if_v4<S: std::os::windows::io::AsRawSocket>(socket: &S, if_index: u32) -> Result<()> {
    use windows::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, SOCKET};

    // IP_UNICAST_IF wants the index in network byte order.
    let val = if_index.to_be();
    let bytes = val.to_ne_bytes();
    let s = SOCKET(socket.as_raw_socket() as usize);
    // IP_UNICAST_IF is not exposed as a constant in the windows crate at our
    // version — its numeric value is 31. Defined this way in the WinSock SDK.
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

async fn tcp_bridge(
    dst: SocketAddr,
    target: Option<VpnTarget>,
    mut from_app: mpsc::Receiver<Vec<u8>>,
    to_app: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let stream = match target {
        Some(t) => {
            let socket = tokio::net::TcpSocket::new_v4()?;
            set_unicast_if_v4(&socket, t.if_index)?;
            socket.bind(SocketAddr::V4(SocketAddrV4::new(t.ipv4, 0)))?;
            socket
                .connect(dst)
                .await
                .with_context(|| format!("tcp connect({}) via ifindex {}", dst, t.if_index))?
        }
        None => tokio::net::TcpStream::connect(dst)
            .await
            .with_context(|| format!("tcp connect({})", dst))?,
    };
    tracing::debug!("tcp bridge connected to {} (local={:?})", dst, stream.local_addr().ok());
    let (mut rd, mut wr) = stream.into_split();

    let write_task = tokio::spawn(async move {
        while let Some(data) = from_app.recv().await {
            if wr.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    let read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; SMOLTCP_CHUNK];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if to_app.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let _ = tokio::join!(write_task, read_task);
    Ok(())
}

async fn udp_bridge(
    dst: SocketAddr,
    target: Option<VpnTarget>,
    mut from_app: mpsc::Receiver<Vec<u8>>,
    to_app: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let local = match target {
        Some(t) => SocketAddr::V4(SocketAddrV4::new(t.ipv4, 0)),
        None => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
    };
    let socket = tokio::net::UdpSocket::bind(local)
        .await
        .with_context(|| format!("udp bind({})", local))?;
    if let Some(t) = target {
        set_unicast_if_v4(&socket, t.if_index)?;
    }
    socket.connect(dst).await
        .with_context(|| format!("udp connect({})", dst))?;
    tracing::debug!("udp bridge {} -> {} (local={:?})", local, dst, socket.local_addr().ok());
    let sock = Arc::new(socket);

    let send_sock = sock.clone();
    let send_task = tokio::spawn(async move {
        while let Some(data) = from_app.recv().await {
            if send_sock.send(&data).await.is_err() {
                break;
            }
        }
    });

    let recv_sock = sock;
    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match recv_sock.recv(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if to_app.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let _ = tokio::join!(send_task, recv_task);
    Ok(())
}

enum ParsedL4 {
    Tcp {
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    },
    Udp {
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    },
}

fn parse_ipv4_l4(data: &[u8]) -> Option<ParsedL4> {
    let sliced = SlicedPacket::from_ip(data).ok()?;
    let net = sliced.net?;
    let ipv4 = match net {
        NetSlice::Ipv4(ip) => ip,
        _ => return None,
    };
    let src_ip = ipv4.header().source_addr();
    let dst_ip = ipv4.header().destination_addr();
    match sliced.transport? {
        TransportSlice::Tcp(tcp) => Some(ParsedL4::Tcp {
            src_ip,
            src_port: tcp.source_port(),
            dst_ip,
            dst_port: tcp.destination_port(),
        }),
        TransportSlice::Udp(udp_slice) => Some(ParsedL4::Udp {
            src_ip,
            src_port: udp_slice.source_port(),
            dst_ip,
            dst_port: udp_slice.destination_port(),
        }),
        _ => None,
    }
}

fn extract_udp_payload(data: &[u8]) -> Option<Vec<u8>> {
    let sliced = SlicedPacket::from_ip(data).ok()?;
    match sliced.transport? {
        TransportSlice::Udp(udp_slice) => Some(udp_slice.payload().to_vec()),
        _ => None,
    }
}

fn build_udp_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let udp_len = 8 + payload.len();
    let mut buf = Vec::with_capacity(total_len);

    // IPv4 header (20 bytes, no options, IHL=5)
    buf.push(0x45);
    buf.push(0);
    buf.extend_from_slice(&(total_len as u16).to_be_bytes());
    buf.extend_from_slice(&[0, 0]); // identification
    buf.extend_from_slice(&[0, 0]); // flags + fragment offset
    buf.push(64); // ttl
    buf.push(17); // protocol = UDP
    buf.extend_from_slice(&[0, 0]); // header checksum (WinDivert will recompute)
    buf.extend_from_slice(&src_ip.octets());
    buf.extend_from_slice(&dst_ip.octets());

    // UDP header (8 bytes)
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf.extend_from_slice(&(udp_len as u16).to_be_bytes());
    buf.extend_from_slice(&[0, 0]); // checksum (WinDivert will recompute)

    buf.extend_from_slice(payload);
    buf
}

struct Stats {
    passed: AtomicU64,
    captured: AtomicU64,
    injected: AtomicU64,
    bridges_opened: AtomicU64,
    bridges_closed: AtomicU64,
    bus: Arc<StatusBus>,
}

impl Stats {
    fn new(bus: Arc<StatusBus>) -> Self {
        Self {
            passed: AtomicU64::new(0),
            captured: AtomicU64::new(0),
            injected: AtomicU64::new(0),
            bridges_opened: AtomicU64::new(0),
            bridges_closed: AtomicU64::new(0),
            bus,
        }
    }

    fn add_app_to_remote(&self, n: u64) {
        self.bus.bytes_out.fetch_add(n, Ordering::Relaxed);
    }
    fn add_remote_to_app(&self, n: u64) {
        self.bus.bytes_in.fetch_add(n, Ordering::Relaxed);
    }
    fn add_pid_out(&self, pid: u32, n: u64) {
        self.bus.add_pid_out(pid, n);
    }
    fn add_pid_in(&self, pid: u32, n: u64) {
        self.bus.add_pid_in(pid, n);
    }

    fn report_loop(&self) {
        let start = Instant::now();
        let mut last = [0u64; 7];
        loop {
            std::thread::sleep(Duration::from_secs(5));
            let cur = [
                self.passed.load(Ordering::Relaxed),
                self.captured.load(Ordering::Relaxed),
                self.injected.load(Ordering::Relaxed),
                self.bridges_opened.load(Ordering::Relaxed),
                self.bridges_closed.load(Ordering::Relaxed),
                self.bus.bytes_out.load(Ordering::Relaxed),
                self.bus.bytes_in.load(Ordering::Relaxed),
            ];
            let d: Vec<u64> = cur.iter().zip(&last).map(|(a, b)| a - b).collect();
            last = cur;
            tracing::info!(
                "divert 5s: pass={} cap={} inj={} bridges +{}/-{} a→r={}B r→a={}B (uptime {:?})",
                d[0], d[1], d[2], d[3], d[4], d[5], d[6], start.elapsed()
            );
        }
    }
}
