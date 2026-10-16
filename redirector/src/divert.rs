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
use windivert_sys::{ChecksumFlags, WinDivertParam};

use crate::adapter::VpnTarget;
use crate::flows::{self, FlowEntry, FlowTable, LocalEndpoint, PROTO_TCP, PROTO_UDP};
use crate::pidlookup;
use crate::policy::{self, PolicyState};
use ipc::status::EventKind;
use crate::process::Resolver;
use crate::stack::VirtualDevice;
use crate::status_server::StatusBus;
use crate::tunneled::{self, TunneledPaths};
use crate::vpn_state::{self, VpnState};

const BRIDGE_CHANNEL_DEPTH: usize = 128;
const SMOLTCP_CHUNK: usize = 16 * 1024;
/// Per-socket buffers. 64KB used to cap every flow at ~window/RTT
/// (≈10 Mbps at 50 ms); 256KB lets smoltcp advertise window scaling
/// (win_shift derives from rx capacity) and carry ~40+ Mbps per flow.
const SMOLTCP_BUF: usize = 256 * 1024;
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
    // NOTE on "why can't untunneled traffic fully bypass us": WinDivert's
    // NETWORK layer carries no PID, so the filter cannot exclude apps —
    // every matching packet MUST visit userspace for a verdict. The tax is
    // minimized instead: (a) this filter excludes ports that can never need
    // tunneling (DNS + link-local name chatter) so they skip the queue trip
    // entirely, (b) the divert loop batches + never blocks on verdicts, (c)
    // divert.rs still early-returns port 53 as backstop.
    let capture_filter = "outbound and ip and (tcp or udp) and !loopback \
        and not (tcp.DstPort == 53 or udp.DstPort == 53 \
        or udp.DstPort == 5353 or udp.DstPort == 5355)";
    let capture = WinDivert::network(capture_filter, 1040, WinDivertFlags::new())
        .context("WinDivert::network capture handle failed (need admin)")?;
    // Deepen the driver queue (default 4096 packets / 4MB; max 16384 / 32MB):
    // under flood (speedtest = tens of thousands of pps) a shallow queue
    // drops before our loop drains it. Best-effort: a failure here must not
    // kill the redirector.
    if let Err(e) = capture.set_param(WinDivertParam::QueueLength, 8192) {
        tracing::warn!("divert: QueueLength bump failed ({}), keeping driver default", e);
    }
    if let Err(e) = capture.set_param(WinDivertParam::QueueSize, 16 * 1024 * 1024) {
        tracing::warn!("divert: QueueSize bump failed ({}), keeping driver default", e);
    }
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
            // Drain the queue in batches: one poll+service cycle per packet
            // collapses under flood (service scans every flow per packet).
            // Batching amortizes each cycle over up to CAPTURE_BATCH packets
            // — this also unclogs UNTUNNELED traffic sharing the same queue.
            for _ in 1..CAPTURE_BATCH {
                match capture.recv_wait(&mut buffer, 0) {
                    Ok(Some(packet)) => handle_capture(
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
                    ),
                    _ => break,
                }
            }
        }

        let _ = iface.poll(smoltcp::time::Instant::now(), &mut device, &mut sockets);
        drain_tx(&mut device, &inject, &stats);

        service_tcp_flows(&mut tcp_flows, &mut sockets, &tokio_handle, now_vpn, &stats, &bus);
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

/// Packets handled per loop iteration (poll+service amortized across them).
/// 64 keeps per-iteration work bounded while draining floods.
const CAPTURE_BATCH: usize = 64;

/// Keyed on the FULL 4-tuple: without dst, an ephemeral port reused for a
/// different destination collides with the old flow and gets RST'd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpKey {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
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
    exe: String,
    original_dst: SocketAddr,
    state: TcpState,
    /// Last data movement or state transition. Feeds the GC sweep: a flow
    /// stuck in a half-closed state squats its key forever, so every future
    /// connection reusing the ephemeral port gets RST'd ("other side closed").
    last_active: Instant,
    /// Cumulative bytes per direction. Reported on close: a flow that dies
    /// with r2a==0 sent a request the server never answered (blackhole),
    /// while a2r==0 means the app never sent anything (app-side abort).
    a2r_bytes: u64,
    r2a_bytes: u64,
    /// Server→app bytes that did not fit smoltcp's window yet. Retried when
    /// can_send() reopens. Dropping these (as the old code did on partial
    /// send_slice) truncates responses mid-TLS-record: the app's TLS stack
    /// aborts the session and reports "other side closed". Bounded (cap
    /// below) so a never-reading app can't grow it without limit.
    r2a_pending: Vec<u8>,
}

/// Server→app staging cap. Past this, messages wait in the (bounded)
/// channel instead — which correctly back-pressures the server via the
/// bridge socket's receive window.
const R2A_PENDING_CAP: usize = 512 * 1024;

enum TcpState {
    Pending,
    Bridging {
        /// Option so the app-side half-close propagates: taking it drops the
        /// Sender, the bridge write-task observes recv()==None and FINs the
        /// remote leg instead of wedging the flow in CloseWait forever.
        app_to_remote: Option<mpsc::Sender<Vec<u8>>>,
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

/// Cap event detail length: anyhow chains can be long, the log panel only
/// shows one line per event.
fn short(s: &str) -> String {
    const MAX: usize = 180;
    if s.len() <= MAX {
        return s.to_string();
    }
    let mut out: String = s.chars().take(MAX).collect();
    out.push('…');
    out
}

/// One-line close summary for a retired TCP flow. Abnormal closes go to the
/// Activity panel (they explain app-visible failures); clean closes stay in
/// the trace log. The byte split is the discriminator: r2a==0 with a2r>0
/// means the request went out but the server never answered (blackhole or
/// connect stall), a2r==0 means the app never sent anything (app-side abort).
fn close_note(bus: &StatusBus, flow: &TcpFlow, key: &TcpKey, reason: &str) {
    let summary = format!(
        "TCP \"{}\" (pid {}) {}:{} -> {} closed ({}): app-sent={}B server-sent={}B",
        flow.exe, flow.pid, key.src_ip, key.src_port, flow.original_dst,
        reason, flow.a2r_bytes, flow.r2a_bytes,
    );
    let abnormal = (flow.r2a_bytes == 0 && flow.a2r_bytes > 0)
        || reason == "pending-timeout, handshake never completed"
        || reason == "halfclose-idle-timeout";
    if abnormal {
        tracing::warn!("{}", summary);
        bus.emit(EventKind::BridgeFailed, short(&summary));
    } else {
        tracing::debug!("{}", summary);
    }
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

/// Policy fast path with recycled-PID guard. Per-packet calls pass
/// is_new_flow=false (bare contains, one hash lookup). When the packet would
/// open a NEW bridge flow, the live exe is fresh-resolved and must match the
/// admitted identity — a PID recycled inside the GC window (or an exited
/// process) fails, gets evicted, and falls through to path/parent
/// re-qualification instead of inheriting tunnel membership.
fn policy_admit(
    policy_state: &PolicyState,
    resolver: &Arc<Resolver>,
    pid: u32,
    is_new_flow: bool,
) -> bool {
    if !policy::contains(policy_state, pid) {
        return false;
    }
    if !is_new_flow {
        return true;
    }
    match resolver.resolve_fresh(pid) {
        Some(info) if policy::exe_matches(policy_state, pid, &info.exe_path) => true,
        _ => {
            tracing::info!(
                "policy: pid {} identity changed (recycled/exited?) — evicting, re-qualifying",
                pid
            );
            policy::remove(policy_state, pid);
            false
        }
    }
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

    // DNS is never tunneled — in either mode. Rationale: with split's
    // dhcp-option ignored, the only resolvers are LAN ones (RFC1918); a
    // tunneled app's query forced through the bridge would exit the tunnel
    // toward a private address and blackhole (Proton drops it), leaving
    // tunneled apps with NO working DNS at all. Passing port-53 through to
    // the kernel routes it correctly in both modes (LAN direct in split,
    // tunnel default in full). Same for link-local name chatter (mDNS 5353,
    // LLMNR 5355): unroutable via VPN by nature, and skipping PID/admission
    // keeps the hot path short for constant Windows background noise.
    // Stated trade-off: DNS names leak to the LAN resolver even for
    // tunneled apps; their traffic stays in the tunnel.
    // (DoH/DoT ride 443/853 and are tunneled normally. IPv6 DNS is out of
    // scope here: the capture filter is IPv4-only, so v6 DNS already
    // bypasses the bridge entirely.)
    // Bonus: skipping PID resolution + admission here keeps the hot path
    // short for the highest-rate flow class on the box.
    if dst_port == 53 || dst_port == 5353 || dst_port == 5355 {
        let _ = capture.send(&packet);
        stats.passed.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let pid = resolve_pid_with_retry(flows, src_ip, src_port, proto);
    if let Some(p) = pid {
        flows::insert(
            flows,
            LocalEndpoint { addr: IpAddr::V4(src_ip), port: src_port, proto },
            FlowEntry { pid: p },
        );
    }

    // Three-step admission:
    //   1. PID already in policy → tunnel (identity-validated when the
    //      packet opens a NEW bridge flow — see policy_admit)
    //   2. PID has a known exe path matching the tunnel list → admit now
    //      (this is the path that closes the proc_watcher race — fast
    //      launchers like STOVE make their first connection before any
    //      polling tick would catch them)
    //   3. PID is a child of a tunneled PID → inherit (launcher -> game)
    //   4. otherwise → pass through to the default route
    //
    // Identity validation runs only for packets that would open a new flow
    // (cheap hash pre-check): per-packet fresh-resolves would stall the
    // loop, but new flows are rare enough for one OpenProcess each.
    let flow_key_exists = if is_tcp {
        tcp_flows.contains_key(&TcpKey { src_ip, src_port, dst_ip, dst_port })
    } else {
        udp_flows.contains_key(&UdpKey { src_ip, src_port, dst_ip, dst_port })
    };
    let is_new_flow = !flow_key_exists;
    let is_tunneled = match pid {
        Some(p) if policy_admit(policy_state, resolver, p, is_new_flow) => true,
        Some(p) => {
            if let Some(info) = resolver.resolve(p) {
                if tunneled::matches(tunneled_paths, std::path::Path::new(&info.exe_path)) {
                    tracing::info!(
                        "auto-tunnel (packet): pid={} matches {}",
                        p, info.exe_path
                    );
                    bus.emit(
                        EventKind::AppAdmitted,
                        format!("\"{}\" (pid {}) admitted — path match, connecting to {}:{}", info.exe_name, p, dst_ip, dst_port),
                    );
                    policy::add(policy_state, p, &info.exe_path);
                    bus.pid_paths.insert(p, info.exe_path);
                    true
                } else if let Some(ppid) = resolver.parent_of(p) {
                    if policy_admit(policy_state, resolver, ppid, true) {
                        tracing::info!(
                            "auto-tunnel (packet child): pid={} parent={} exe={}",
                            p, ppid, info.exe_path
                        );
                        bus.emit(
                            EventKind::AppAdmitted,
                            format!(
                                "\"{}\" (pid {}) admitted — child of pid {}, connecting to {}:{}",
                                info.exe_name, p, ppid, dst_ip, dst_port
                            ),
                        );
                        policy::add(policy_state, p, &info.exe_path);
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
                    Some(ppid) if policy_admit(policy_state, resolver, ppid, true) => {
                        tracing::info!(
                            "auto-tunnel (packet child, no exe): pid={} parent={}",
                            p, ppid
                        );
                        bus.emit(
                            EventKind::AppAdmitted,
                            format!("pid {} admitted — child of pid {}, connecting to {}:{}", p, ppid, dst_ip, dst_port),
                        );
                        policy::add_unvalidated(policy_state, p);
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
        let key = TcpKey { src_ip, src_port, dst_ip, dst_port };
        if !tcp_flows.contains_key(&key) {
            let rx_buf = tcp::SocketBuffer::new(vec![0u8; SMOLTCP_BUF]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; SMOLTCP_BUF]);
            let mut sock = tcp::Socket::new(rx_buf, tx_buf);
            let endpoint = IpEndpoint::new(IpAddress::Ipv4(dst_ip.into()), dst_port);
            if let Err(e) = sock.listen(endpoint) {
                tracing::warn!("smoltcp tcp::listen({}) failed: {:?}", endpoint, e);
                return;
            }
            let handle = sockets.add(sock);
            let exe = resolver
                .resolve(pid)
                .map(|i| i.exe_name)
                .unwrap_or_else(|| format!("pid {}", pid));
            tcp_flows.insert(
                key,
                TcpFlow {
                    handle,
                    pid,
                    exe,
                    original_dst: SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port)),
                    state: TcpState::Pending,
                    last_active: Instant::now(),
                    a2r_bytes: 0,
                    r2a_bytes: 0,
                    r2a_pending: Vec::new(),
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

            let exe = resolver
                .resolve(pid)
                .map(|i| i.exe_name)
                .unwrap_or_else(|| format!("pid {}", pid));
            bus.emit(
                EventKind::BridgeOpened,
                format!(
                    "UDP \"{}\" (pid {}) {}:{} -> {}:{} via VPN",
                    exe, pid, src_ip, src_port, dst_ip, dst_port
                ),
            );

            let dst = SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port));
            let bus_fail = bus.clone();
            let fail_exe = exe.clone();
            tokio_handle.spawn(async move {
                if let Err(e) = udp_bridge(dst, vpn_target, a2r_rx, r2a_tx).await {
                    let detail = format!("UDP \"{}\" (pid {}) to {} failed: {}", fail_exe, pid, dst, short(&e.to_string()));
                    tracing::warn!("{}", detail);
                    bus_fail.emit(EventKind::BridgeFailed, detail);
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
    bus: &Arc<StatusBus>,
) {
    let mut to_remove = Vec::new();
    let now = Instant::now();
    for (key, flow) in tcp_flows.iter_mut() {
        match &mut flow.state {
            TcpState::Pending => {
                // Half-open that never completes (blackholed SYN, app gave
                // up): free the key instead of burning the ephemeral port
                // forever — the next SYN for it must build a fresh listener.
                if now.duration_since(flow.last_active) > Duration::from_secs(30) {
                    close_note(
                        &bus,
                        flow,
                        key,
                        "pending-timeout, handshake never completed",
                    );
                    flow.state = TcpState::Closed;
                } else {
                    let socket = sockets.get_mut::<tcp::Socket>(flow.handle);
                    if matches!(socket.state(), tcp::State::Closed) {
                        // RST before the handshake completed: retire now
                        // instead of squatting the key for the 30s timeout.
                        close_note(&bus, flow, key, "rst-before-connect");
                        flow.state = TcpState::Closed;
                    } else if socket.state() == tcp::State::Established {
                        let (a2r_tx, a2r_rx) = mpsc::channel::<Vec<u8>>(BRIDGE_CHANNEL_DEPTH);
                        let (r2a_tx, r2a_rx) = mpsc::channel::<Vec<u8>>(BRIDGE_CHANNEL_DEPTH);

                        tracing::info!(
                            "tcp bridge open: pid={} {}:{} -> {}",
                            flow.pid, key.src_ip, key.src_port, flow.original_dst
                        );
                        bus.emit(
                            EventKind::BridgeOpened,
                            format!(
                                "TCP \"{}\" (pid {}) {}:{} -> {} via VPN",
                                flow.exe, flow.pid, key.src_ip, key.src_port, flow.original_dst
                            ),
                        );

                        let dst = flow.original_dst;
                        let bus_fail = bus.clone();
                        let fail_exe = flow.exe.clone();
                        let fail_pid = flow.pid;
                        tokio_handle.spawn(async move {
                            if let Err(e) = tcp_bridge(dst, vpn_target, a2r_rx, r2a_tx).await {
                                let detail =
                                    format!("TCP \"{}\" (pid {}) to {} failed: {}", fail_exe, fail_pid, dst, short(&e.to_string()));
                                tracing::warn!("{}", detail);
                                bus_fail.emit(EventKind::BridgeFailed, detail);
                            }
                        });
                        stats.bridges_opened.fetch_add(1, Ordering::Relaxed);

                        flow.last_active = now;
                        flow.state = TcpState::Bridging {
                            app_to_remote: Some(a2r_tx),
                            remote_to_app: r2a_rx,
                            app_half_closed: false,
                        };
                    }
                }
            }
            TcpState::Bridging { app_to_remote, remote_to_app, app_half_closed } => {
                let socket = sockets.get_mut::<tcp::Socket>(flow.handle);
                // Remote leg gone, its tail bytes drained, AND staged bytes
                // flushed (pending non-empty still has data for the app):
                // FIN our side so the app sees a clean close instead of
                // hanging, then retire.
                if remote_to_app.is_closed() && remote_to_app.is_empty() && flow.r2a_pending.is_empty() {
                    // Remote leg gone (outbound connect failed, or remote EOF
                    // with the write leg drained): summary first, then FIN
                    // our side so the app sees a clean close.
                    close_note(&bus, flow, key, "remote-done");
                    socket.close();
                    flow.state = TcpState::Closed;
                } else {
                    let mut moved_bytes = 0u64;
                    if let Some(tx) = app_to_remote {
                        let n = pump_tcp_app_to_remote(socket, tx, flow.pid, stats);
                        moved_bytes += n;
                        flow.a2r_bytes += n;
                    }
                    let pend_before = flow.r2a_pending.len();
                    let n = pump_tcp_remote_to_app(
                        socket,
                        remote_to_app,
                        &mut flow.r2a_pending,
                        flow.pid,
                        stats,
                    );
                    moved_bytes += n;
                    flow.r2a_bytes += n;
                    // Staged-but-unflushed bytes are progress too: without
                    // this, a half-closed app whose window momentarily shuts
                    // could hit the 120s idle timeout and discard live data.
                    if flow.r2a_pending.len() > pend_before {
                        flow.last_active = now;
                    }
                    if moved_bytes > 0 {
                        flow.last_active = now;
                    }
                    if !*app_half_closed
                        && matches!(
                            socket.state(),
                            tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing
                        )
                    {
                        *app_half_closed = true;
                        flow.last_active = now;
                    }
                    if *app_half_closed && app_to_remote.is_some() {
                        // Propagate the app FIN to the remote leg: dropping
                        // the sender ends the bridge write-task (which
                        // shutdown()s the remote socket) instead of wedging
                        // this flow in CloseWait forever.
                        *app_to_remote = None;
                    }
                    if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) {
                        close_note(&bus, flow, key, "closed");
                        flow.state = TcpState::Closed;
                    } else if *app_half_closed
                        && now.duration_since(flow.last_active) > Duration::from_secs(120)
                    {
                        // Wedged half-close (peer never FINs back): stop
                        // squatting the key. Fully-open idle flows are
                        // deliberately spared — those can be legit persistent
                        // streams (API SSE/WebSocket) quiet between messages.
                        close_note(&bus, flow, key, "halfclose-idle-timeout");
                        socket.close();
                        flow.state = TcpState::Closed;
                    }
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

/// Moves app bytes into the bridge channel. Returns bytes moved (feeds the
/// flow GC clock). Half-close detection lives in the caller, which owns the
/// Option<Sender> and propagates the FIN by dropping it.
fn pump_tcp_app_to_remote(
    socket: &mut tcp::Socket,
    sender: &mpsc::Sender<Vec<u8>>,
    pid: u32,
    stats: &Stats,
) -> u64 {
    let mut moved = 0u64;
    while socket.can_recv() {
        // Lossless backpressure: never consume from smoltcp unless the
        // bridge channel has room. Consuming-then-dropping on try_send
        // failure used to silently TRUNCATE uploads under load (opencode
        // ships large request bodies) — the server sees a cut request and
        // RSTs, surfacing as "other side closed". Leaving bytes in smoltcp
        // instead propagates standard TCP window backpressure to the app.
        if sender.capacity() == 0 {
            break;
        }
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
                moved += n as u64;
                stats.add_app_to_remote(n as u64);
                stats.add_pid_out(pid, n as u64);
            }
            Err(_) => break,
        }
    }
    moved
}

/// Moves server bytes into the app socket. Lossless: channel messages stage
/// into `pending` and partial window writes keep their remainder there for
/// the next poll — nothing is dropped between the channel and the socket.
/// `moved` counts bytes actually accepted by smoltcp (feeds flow counters
/// and the GC clock).
fn pump_tcp_remote_to_app(
    socket: &mut tcp::Socket,
    receiver: &mut mpsc::Receiver<Vec<u8>>,
    pending: &mut Vec<u8>,
    pid: u32,
    stats: &Stats,
) -> u64 {
    // Stage new arrivals while bounded; overflow waits in the channel (which
    // back-pressures the server through the bridge socket's window).
    while pending.len() < R2A_PENDING_CAP {
        match receiver.try_recv() {
            Ok(data) => pending.extend_from_slice(&data),
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => break,
        }
    }
    // Flush staged bytes while the socket has window.
    let mut moved = 0u64;
    while !pending.is_empty() && socket.can_send() {
        match socket.send_slice(pending) {
            Ok(0) => break,
            Ok(n) => {
                pending.drain(..n);
                moved += n as u64;
                stats.add_remote_to_app(n as u64);
                stats.add_pid_in(pid, n as u64);
            }
            Err(_) => break,
        }
    }
    // Bridge task gone (sender dropped): close our side, but ONLY once
    // staged bytes are fully flushed — closing early would truncate the
    // tail (the exact bug this buffer exists to fix). The caller gates
    // retirement on the same drained condition.
    if receiver.is_closed() && receiver.is_empty() && pending.is_empty() {
        socket.close();
    }
    moved
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
    // 15s connect cap: into a dead/blackholed tunnel, connect() would hang
    // for minutes with zero visibility (no BridgeFailed, app just stalls).
    // Failing fast retires the flow, frees the key, and tells the log why.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
    let stream = match target {
        Some(t) => {
            let socket = tokio::net::TcpSocket::new_v4()?;
            set_unicast_if_v4(&socket, t.if_index)?;
            socket.bind(SocketAddr::V4(SocketAddrV4::new(t.ipv4, 0)))?;
            tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(dst))
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "tcp connect({}) via ifindex {} timed out after {}s (tunnel blackhole?)",
                        dst,
                        t.if_index,
                        CONNECT_TIMEOUT.as_secs()
                    )
                })?
                .with_context(|| format!("tcp connect({}) via ifindex {}", dst, t.if_index))?
        }
        None => tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(dst))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "tcp connect({}) timed out after {}s",
                    dst,
                    CONNECT_TIMEOUT.as_secs()
                )
            })?
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
