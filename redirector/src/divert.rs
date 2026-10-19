use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
/// How long an app-side TCP handshake may stay incomplete (SYN consumed,
/// SYN-ACK sent, final ACK never seen) before the flow is retired. In
/// practice this state lasts milliseconds; a multi-second soak means the app
/// abandoned the socket while our SYN-ACK was in flight — Chrome opens
/// racing connections and closes the losers, and a never-established socket
/// closed by the app sends no RST, so nothing else would end this state.
/// 5s (was 30s) frees the 4-tuple six times sooner: the app's next SYN
/// retransmission then builds a FRESH listener → SYN-ACK → handshake
/// completes — recovery instead of squatting. Counted in the 5s report as
/// pending_timeout so a regression shows up without log spelunking.
const PENDING_TCP_TIMEOUT: Duration = Duration::from_secs(5);

/// WinDivert capture filter — NETWORK layer, outbound TCP/UDP. The DNS /
/// mDNS / LLMNR ports are excluded so that name chatter never pays the
/// userspace round-trip (see the NOTE in `run`).
///
/// GRAMMAR + SEMANTIC GOTCHAS (regression guards `capture_filter_compiles`
/// and `capture_filter_semantics`):
///
///   1. WinDivert 2.2 accepts `not` / `!` **only** as a prefix on a single
///      field (`!loopback`); `not (expr)` / `!(expr)` is a PARSE error, and a
///      parse error makes `WinDivertOpen` fail with ERROR_INVALID_PARAMETER
///      (87), aborting the backend. (A non-elevated run fails *earlier* with
///      ERROR_ACCESS_DENIED, hiding this until the process is elevated.)
///   2. A field of an ABSENT layer evaluates FALSE, not zero. On a UDP packet
///      `tcp.DstPort != 53` is therefore false, so flattening the negation
///      into `tcp.DstPort != 53 and udp.DstPort != 53` matches NOTHING (no
///      packet is both TCP and UDP). The negated group must be split into
///      per-protocol branches, each guarded by its own `tcp` / `udp` test.
pub(crate) const CAPTURE_FILTER: &str = "outbound and ip and !loopback and \
     ((tcp and tcp.DstPort != 53) \
      or (udp and udp.DstPort != 53 and udp.DstPort != 5353 and udp.DstPort != 5355))";

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
    // minimized instead: (a) CAPTURE_FILTER excludes ports that can never
    // need tunneling (DNS + link-local name chatter) so they skip the queue
    // trip entirely, (b) the divert loop batches + never blocks on verdicts,
    // (c) divert.rs still early-returns port 53 as backstop.
    let capture_filter = CAPTURE_FILTER;
    let capture = WinDivert::network(capture_filter, 1040, WinDivertFlags::new())
        .with_context(|| {
            format!(
                "WinDivert::network capture handle failed (elevated shell + valid filter required; \
                 filter={capture_filter})"
            )
        })?;
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

    let stats = Arc::new(Stats::new(bus.clone(), resolver.clone()));
    let stats_clone = stats.clone();
    std::thread::spawn(move || stats_clone.report_loop());

    let mut buffer = vec![0u8; CAPTURE_BUF];
    let mut admit_cache = AdmitCache::new();
    let mut last_vpn = vpn_state::current(&vpn_state);
    // Outer slot arrays are reused so the batch assembly doesn't grow; each
    // passthrough packet still gets its own owned Vec from into_owned(),
    // which is exactly the cost the batched send trades against its syscall
    // saving (see the flush site for the real ratio).
    let mut passthrough: Vec<Vec<u8>> = Vec::with_capacity(CAPTURE_BATCH);
    let mut send_batch: Vec<WinDivertPacket<'_, NetworkLayer>> =
        Vec::with_capacity(CAPTURE_BATCH);
    // Reused app→remote staging buffer (see pump_tcp_app_to_remote).
    let mut pump_scratch: Vec<u8> = Vec::with_capacity(MTU_PAYLOAD);

    loop {
        let now_vpn = vpn_state::current(&vpn_state);
        if now_vpn != last_vpn {
            on_vpn_change(last_vpn, now_vpn, &mut tcp_flows, &mut udp_flows, &mut sockets, &stats);
            last_vpn = now_vpn;
        }

        let t_recv = Instant::now();
        // ONE overlapped RecvEx per iteration for up to RECV_BATCH packets.
        // timeout_ms=50 blocks only when the queue is empty, and an expired
        // wait surfaces as Ok(empty) — never an error — so idle iterations
        // stay silent (no recv_err inflation). Packets beyond the batch are
        // left in the driver queue for the next iteration; poll+service run
        // once per batch regardless.
        match capture.recv_wait_ex(&mut buffer, RECV_BATCH as u8, 50) {
            Ok(packets) => {
                for packet in packets {
                    match handle_capture(
                        packet,
                        &policy_state,
                        &flows,
                        &mut admit_cache,
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
                    ) {
                        Captured::Passthrough(data) => passthrough.push(data),
                        Captured::Consumed => {}
                    }
                }
            }
            Err(_) => {
                stats.recv_err.fetch_add(1, Ordering::Relaxed);
            }
        }
        let t_flush = Instant::now();

        // One overlapped syscall for the whole batch instead of one per
        // packet: this is the dominant cost of untunneled traffic under
        // flood (a speedtest is ~20k pps of pure passthrough). WinDivert
        // copies the batch internally, so the honest trade is one syscall
        // per batch in exchange for one small alloc+memcpy per packet —
        // roughly 2-5x cheaper, not 50x.
        if !passthrough.is_empty() {
            send_batch.clear();
            let mut expected_bytes: u32 = 0;
            for data in passthrough.drain(..) {
                expected_bytes = expected_bytes.saturating_add(data.len() as u32);
                let mut addr = unsafe { WinDivertAddress::<NetworkLayer>::new() };
                addr.set_outbound(true);
                send_batch.push(WinDivertPacket {
                    address: addr,
                    data: Cow::Owned(data),
                });
            }
            stats
                .pass_bytes
                .fetch_add(expected_bytes as u64, Ordering::Relaxed);
            let count = send_batch.len();
            // send_ex returns TOTAL BYTES injected, not a packet count: a
            // short Ok(n) means the tail of the batch never hit the wire.
            // Without this check a partial inject loses packets silently.
            match inject.send_ex(&send_batch) {
                Ok(n) if n != expected_bytes => tracing::warn!(
                    "partial passthrough inject: {}/{} bytes for {} packets — tail dropped",
                    n, expected_bytes, count
                ),
                Ok(_) => {}
                Err(e) => {
                    // One bad packet would otherwise take the whole batch
                    // with it. Retry individually so a single poison frame
                    // costs one packet, not 64.
                    tracing::warn!(
                        "batched passthrough inject failed ({} packets): {} — retrying individually",
                        count, e
                    );
                    for pkt in send_batch.iter() {
                        if let Err(e2) = inject.send(pkt) {
                            tracing::warn!("passthrough inject failed for one packet: {}", e2);
                        }
                    }
                }
            }
            // Release the owned buffers now rather than holding them across
            // poll()/service_* until the next flush.
            send_batch.clear();
        }
        let t_svc = Instant::now();

        // Fast path: with no bridges and no sockets there is no smoltcp work
        // to do — poll() would walk an empty socket set, the service
        // scanners would walk empty maps, and the virtual-device queues can
        // only be filled by those same poll()/capture paths. Pure-passthrough
        // traffic (a speedtest, idle untunneled apps) therefore skips the
        // whole block; the phase timer still accounts for the (zero) cost.
        let have_bridges =
            !tcp_flows.is_empty() || !udp_flows.is_empty() || sockets.iter().next().is_some();
        if have_bridges {
            let _ = iface.poll(smoltcp::time::Instant::now(), &mut device, &mut sockets);
            drain_tx(&mut device, &inject, &stats);

            service_tcp_flows(
                &mut tcp_flows,
                &mut sockets,
                &tokio_handle,
                now_vpn,
                &stats,
                &bus,
                &mut pump_scratch,
            );
            service_udp_flows(&mut udp_flows, &inject, &stats);

            let _ = iface.poll(smoltcp::time::Instant::now(), &mut device, &mut sockets);
            drain_tx(&mut device, &inject, &stats);
        }

        // Where does each iteration actually go? Logged every 5s so a
        // throughput ceiling can be attributed to a phase instead of guessed.
        // us_recv includes the 50ms idle wait, so a large value means "idle".
        stats.loops.fetch_add(1, Ordering::Relaxed);
        stats.us_recv.fetch_add(
            t_flush.duration_since(t_recv).as_micros() as u64,
            Ordering::Relaxed,
        );
        stats.us_flush.fetch_add(
            t_svc.duration_since(t_flush).as_micros() as u64,
            Ordering::Relaxed,
        );
        stats.us_svc.fetch_add(
            Instant::now().duration_since(t_svc).as_micros() as u64,
            Ordering::Relaxed,
        );
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

/// Packet size we can ever accept into smoltcp. The tunnel MTU is 1500, so
/// a segment's payload is at most ~1460 bytes; sizing scratch to this keeps
/// recv_slice single-segment while avoiding the old 16KB zero-fill.
const MTU_PAYLOAD: usize = 1500;

/// Packets handled per loop iteration (poll+service amortized across them).
/// 64 keeps per-iteration work bounded while draining floods.
const CAPTURE_BATCH: usize = 64;
/// Packets per batched WinDivertRecvEx — the single recv syscall shape of the
/// loop: ONE call per iteration that waits up to 50 ms only when the queue is
/// empty and returns Ok(empty) on timeout (no error). The old shape paid the
/// outer wait per iteration PLUS up to 4 timeout=0 drain rounds, each with
/// its own WaitForSingleObject/CancelIo pair.
const RECV_BATCH: usize = 32;
/// Capture buffer sized for RECV_BATCH full-MTU frames (32 x 8 KiB): the
/// driver fills as many packets as fit, so undersizing silently caps the
/// batch instead of failing.
const CAPTURE_BUF: usize = RECV_BATCH * 8 * 1024;
/// How long a failed PID resolution suppresses further attempts for the same
/// local endpoint. Short enough that a flow which becomes resolvable is picked
/// up quickly; long enough that a bulk flow which can never be resolved does
/// not pay the ~1 ms wait on every packet.
const PID_NEG_TTL: Duration = Duration::from_millis(250);

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
    /// Whether the first app→remote chunk was already offered to http_log.
    /// One-shot per flow: keeps http.log to one line per connection and
    /// keeps the per-packet path free of parse/file cost.
    http_logged: bool,
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
/// hit the wire until we release it via inject.send_ex() or push it into
/// smoltcp.
fn resolve_pid_with_retry(
    flows: &FlowTable,
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    proto: u8,
    stats: &Stats,
) -> Option<u32> {
    // TCP rows carry the full 4-tuple, so hand the destination over for an
    // exact match. UDP rows have no remote to match on.
    let remote = if proto == PROTO_TCP {
        Some((dst_ip, dst_port))
    } else {
        None
    };
    let lookup = |flows: &FlowTable| -> Option<u32> {
        flows::lookup_with_wildcard(flows, IpAddr::V4(src_ip), src_port, proto)
            .map(|e| e.pid)
            .or_else(|| pidlookup::pid_for_local_v4(src_ip, src_port, proto, remote))
    };

    if let Some(p) = lookup(flows) {
        return Some(p);
    }
    // A flow that just failed is not retried for PID_NEG_TTL. Without this a
    // bulk flow whose owner can never be resolved (kernel-generated, or racing
    // the socket table) pays the ~1 ms wait on EVERY packet, which caps the
    // whole single-threaded loop.
    let neg_key = (proto, src_port, u32::from(src_ip));
    if let Ok(neg) = stats.neg_pid.lock() {
        if let Some(at) = neg.get(&neg_key) {
            if at.elapsed() < PID_NEG_TTL {
                return None;
            }
        }
    }
    // Missed both the observer flow table and the live IPHLPAPI tables: this
    // packet is about to sleep up to 5 x 200 us. Counted so the 5s report can
    // prove (or kill) the "PID stalls cap the loop" theory.
    stats.pid_stalls.fetch_add(1, Ordering::Relaxed);
    for _ in 0..5 {
        std::thread::sleep(Duration::from_micros(200));
        if let Some(p) = lookup(flows) {
            return Some(p);
        }
    }
    if let Ok(mut neg) = stats.neg_pid.lock() {
        if neg.len() >= 4096 {
            neg.retain(|_, at| at.elapsed() < PID_NEG_TTL);
        }
        neg.insert(neg_key, Instant::now());
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

/// How long a per-PID admission verdict is trusted on the per-packet path.
/// Membership flips only on a UI toggle (policy add/remove) or process
/// lifecycle, so 2s bounds the staleness to something the user never
/// perceives — new flows are exempt entirely (they always re-evaluate).
const ADMIT_TTL: Duration = Duration::from_secs(2);
const ADMIT_CACHE_MAX: usize = 4096;

/// PID → admission verdict, TTL-bounded. Why it exists: for a NON-tunneled
/// process (firefox under split), every pass-through packet re-ran
/// resolve() + `tunneled::matches` (which lowercases the candidate path —
/// two String allocations per packet!) + parent_of(). At speedtest rates
/// that was the dominant remaining cost of the passthrough hot path (the
/// divert-5s timers showed it). The verdict can only change via UI toggle
/// or PID lifecycle; both are covered by the short TTL plus the
/// is_new_flow re-evaluation.
struct AdmitCache {
    map: HashMap<u32, (bool, Instant)>,
}

impl AdmitCache {
    fn new() -> Self {
        Self { map: HashMap::new() }
    }

    /// Fresh verdict only; `None` forces full evaluation.
    fn get(&self, pid: u32) -> Option<bool> {
        self.map
            .get(&pid)
            .and_then(|(verdict, at)| (at.elapsed() < ADMIT_TTL).then_some(*verdict))
    }

    fn put(&mut self, pid: u32, verdict: bool) {
        if self.map.len() >= ADMIT_CACHE_MAX {
            let now = Instant::now();
            self.map
                .retain(|_, (_, at)| now.duration_since(*at) < ADMIT_TTL);
        }
        self.map.insert(pid, (verdict, Instant::now()));
    }
}

/// The full admission chain for one PID (steps 1-4 above). Runs on every
/// verdict-cache miss and for every NEW flow — where it also performs the
/// auto-tunnel side effects (policy::add + status events). Lives behind
/// AdmitCache so repeat packets never pay its cost.
fn evaluate_admission(
    policy_state: &PolicyState,
    resolver: &Arc<Resolver>,
    tunneled_paths: &TunneledPaths,
    bus: &Arc<StatusBus>,
    p: u32,
    is_new_flow: bool,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> bool {
    if policy_admit(policy_state, resolver, p, is_new_flow) {
        return true;
    }
    if let Some(info) = resolver.resolve(p) {
        if tunneled::matches(tunneled_paths, std::path::Path::new(&info.exe_path)) {
            tracing::info!("auto-tunnel (packet): pid={} matches {}", p, info.exe_path);
            bus.emit(
                EventKind::AppAdmitted,
                format!(
                    "\"{}\" (pid {}) admitted — path match, connecting to {}:{}",
                    info.exe_name, p, dst_ip, dst_port
                ),
            );
            policy::add(policy_state, p, &info.exe_path);
            bus.pid_paths.insert(p, info.exe_path);
            true
        } else if let Some(ppid) = resolver.parent_of(p) {
            if policy_admit(policy_state, resolver, ppid, true) {
                tracing::info!(
                    "auto-tunnel (packet child): pid={} parent={} exe={}",
                    p,
                    ppid,
                    info.exe_path
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
        // No exe path (yet) — still check parent inheritance so short-lived
        // children of tunneled parents don't escape.
        match resolver.parent_of(p) {
            Some(ppid) if policy_admit(policy_state, resolver, ppid, true) => {
                tracing::info!("auto-tunnel (packet child, no exe): pid={} parent={}", p, ppid);
                bus.emit(
                    EventKind::AppAdmitted,
                    format!(
                        "pid {} admitted — child of pid {}, connecting to {}:{}",
                        p, ppid, dst_ip, dst_port
                    ),
                );
                policy::add_unvalidated(policy_state, p);
                true
            }
            _ => false,
        }
    }
}

/// What handle_capture decided about a captured packet.
///
/// Passthrough packets are NOT sent here: they are handed back as owned
/// copies so the loop can emit them with ONE WinDivertSendEx call per batch
/// instead of one overlapped syscall per packet. Under flood (speedtest)
/// that per-packet syscall dominated the cost of untunneled traffic.
enum Captured {
    /// Release the packet back to the kernel unchanged (needs an owned copy
    /// because the shared capture buffer is reused by the next recv).
    Passthrough(Vec<u8>),
    /// Consumed by the bridge — do not reinject.
    Consumed,
}

#[allow(clippy::too_many_arguments)]
fn handle_capture(
    packet: WinDivertPacket<'_, NetworkLayer>,
    policy_state: &PolicyState,
    flows: &FlowTable,
    admit_cache: &mut AdmitCache,
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
) -> Captured {
    let parsed = match parse_ipv4_l4(&packet.data) {
        Some(p) => p,
        None => {
            stats.pass_malformed.fetch_add(1, Ordering::Relaxed);
            return Captured::Passthrough(packet.data.into_owned());
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
        stats.pass_dns.fetch_add(1, Ordering::Relaxed);
        return Captured::Passthrough(packet.data.into_owned());
    }

    let pid = resolve_pid_with_retry(flows, src_ip, src_port, dst_ip, dst_port, proto, stats);
    if let Some(p) = pid {
        // Only take the write lock when the cached PID actually differs.
        // Merely testing presence would freeze a stale entry forever (the
        // observer evicts wildcard-address UDP entries but not the
        // concrete-IP ones inserted here), so compare the value.
        let key = LocalEndpoint { addr: IpAddr::V4(src_ip), port: src_port, proto };
        if flows::lookup(flows, &key).map(|e| e.pid) != Some(p) {
            flows::insert(flows, key, FlowEntry { pid: p });
        }
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
    // (cheap hash pre-check): per-packet fresh-resolves would stall the loop,
    // but new flows are rare enough for one OpenProcess each. Repeat packets
    // are answered from AdmitCache (see there).
    let flow_key_exists = if is_tcp {
        tcp_flows.contains_key(&TcpKey { src_ip, src_port, dst_ip, dst_port })
    } else {
        udp_flows.contains_key(&UdpKey { src_ip, src_port, dst_ip, dst_port })
    };
    let is_new_flow = !flow_key_exists;
    // Verdict shape: a NEW flow always walks the full chain (identity
    // revalidation + auto-tunnel admission live there); repeat packets of an
    // open flow are served from the TTL cache, so the per-packet path pays
    // one hash lookup instead of resolve() + tunneled::matches() +
    // parent_of() (see AdmitCache).
    let is_tunneled = match pid {
        Some(p) if is_new_flow => {
            let verdict = evaluate_admission(
                policy_state, resolver, tunneled_paths, bus, p, true, dst_ip, dst_port,
            );
            admit_cache.put(p, verdict);
            verdict
        }
        Some(p) => match admit_cache.get(p) {
            Some(verdict) => verdict,
            None => {
                let verdict = evaluate_admission(
                    policy_state, resolver, tunneled_paths, bus, p, false, dst_ip, dst_port,
                );
                admit_cache.put(p, verdict);
                verdict
            }
        },
        None => false,
    };

    if !is_tunneled {
        // Opt-in packet trace: enable with RUST_LOG=pkt=debug. Deliberately a
        // target outside `redirector` so the default `redirector=debug` filter
        // does NOT turn on per-packet logging (that would flood the file).
        tracing::debug!(
            target: "pkt",
            "untun pid={:?} {}/{} -> {}:{}",
            pid,
            if is_tcp { "tcp" } else { "udp" },
            src_port,
            dst_ip,
            dst_port
        );
        stats.pass_untun.fetch_add(1, Ordering::Relaxed);
        stats.note_untun(proto, dst_port, dst_ip, pid);
        return Captured::Passthrough(packet.data.into_owned());
    }
    let pid = pid.unwrap();

    // Fail-open: if the VPN is down, send the packet out the default route
    // instead of dropping it. This trades "no clear-text leak when VPN
    // disconnects mid-session" for "tunneled apps keep working when the
    // user has the VPN off." Existing smoltcp flows for this PID were
    // already torn down by on_vpn_change when the VPN went away, so the app
    // will see a RST and reconnect — and that reconnect goes straight
    // through here.
    if vpn_target.is_none() {
        stats.pass_vpn_down.fetch_add(1, Ordering::Relaxed);
        return Captured::Passthrough(packet.data.into_owned());
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
                return Captured::Consumed;
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
                    http_logged: false,
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
                return Captured::Consumed;
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
    Captured::Consumed
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
    scratch: &mut Vec<u8>,
) {
    let mut to_remove = Vec::new();
    let mut local_scratch = std::mem::take(scratch);
    let now = Instant::now();
    for (key, flow) in tcp_flows.iter_mut() {
        match &mut flow.state {
            TcpState::Pending => {
                // Half-open that never completes (app abandoned the raced
                // socket, blackholed SYN): free the key instead of burning
                // the 4-tuple — the next SYN for it must build a fresh
                // listener (see PENDING_TCP_TIMEOUT).
                if now.duration_since(flow.last_active) > PENDING_TCP_TIMEOUT {
                    stats.pending_timeouts.fetch_add(1, Ordering::Relaxed);
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
                        // instead of waiting out PENDING_TCP_TIMEOUT.
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
                            if let Err(e) = tcp_bridge(dst, vpn_target, a2r_rx, r2a_tx, fail_pid, fail_exe.clone()).await {
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
                        let n = pump_tcp_app_to_remote(socket, tx, flow.pid, stats, &mut local_scratch, &flow.exe, &flow.original_dst, &mut flow.http_logged);
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
    *scratch = local_scratch;
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
    scratch: &mut Vec<u8>,
    http_exe: &str,
    http_dst: &SocketAddr,
    http_logged: &mut bool,
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
        // Reused MTU-sized scratch: the old per-iteration
        // `vec![0u8; SMOLTCP_CHUNK]` allocated AND zeroed 16KB to carry a
        // ~1.4KB segment — at 20k pps that memset alone dominated the pump.
        if scratch.len() < MTU_PAYLOAD {
            scratch.resize(MTU_PAYLOAD, 0);
        }
        let n = match socket.recv_slice(&mut scratch[..]) {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        match sender.try_send(scratch[..n].to_vec()) {
            Ok(()) => {
                moved += n as u64;
                stats.add_app_to_remote(n as u64);
                stats.add_pid_out(pid, n as u64);
                // Passive HTTP log: first chunk only, best-effort, never
                // blocks the pump. maybe_log self-gates on the flag file.
                if !*http_logged {
                    *http_logged = true;
                    crate::http_log::maybe_log(pid, http_exe, http_dst, &scratch[..n]);
                }
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
    pid: u32,
    exe: String,
) -> Result<()> {
    // 5s connect cap (was 15s): app-side data is already queued by the time
    // this runs, so a longer cap only delays the failure. A dead/blackholed
    // tunnel now retires the flow — and logs BridgeFailed — in 5s instead of
    // stalling the app for 15, while still covering slow but live
    // destinations (SYN-ACK RTT well under 5s is the norm even via VPN).
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
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
    // MITM gate: peek the first app chunk for a ClientHello BEFORE going
    // blind. Eligible (flag + app listed + SNI) → decrypt relay; anything
    // else → existing blind bridge with the peeked bytes forwarded first.
    // Bounded wait: a quiet keep-alive must not stall the bridge (the first
    // data usually arrives within ms — the pump queued it pre-spawn).
    let mut first: Vec<u8> = match tokio::time::timeout(
        crate::mitm::first_chunk_timeout(),
        from_app.recv(),
    )
    .await
    {
        Ok(Some(chunk)) => chunk,
        _ => Vec::new(),
    };
    // MITM gate (moves nothing on "no"): eligible = flag + app listed + SNI,
    // crypto_ready = CA loadable + SNI usable. Only then do the channels move
    // into the decrypt relay; otherwise the blind path stays byte-exact.
    if !first.is_empty() {
        if let Some(sni) = crate::mitm::eligible(&exe, &first) {
            if crate::mitm::crypto_ready(&sni) {
                tracing::info!("mitm: decrypting pid={} {} SNI={}", pid, exe, sni);
                match crate::mitm::try_mitm_divert(from_app, to_app, first, stream, pid, &exe, dst, &sni).await
                {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        tracing::warn!("mitm pid={} {} failed, closing: {}", pid, exe, e);
                        return Ok(());
                    }
                }
            }
        }
    }
    // Blind path (unchanged semantics): `first` (maybe empty) goes out first
    // so the server sees the exact byte stream, then plain copy both ways.
    let (mut rd, mut wr) = stream.into_split();
    if !first.is_empty() {
        if wr.write_all(&first).await.is_err() {
            return Ok(());
        }
    }

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
    /// Passthrough, split by the branch that decided it — a single "passed"
    /// counter could not tell malformed input from plain non-tunneled traffic,
    /// which is exactly what made the constant ~190 pps floor unreadable.
    pass_malformed: AtomicU64,
    pass_dns: AtomicU64,
    pass_untun: AtomicU64,
    pass_vpn_down: AtomicU64,
    /// Packets that missed the fast flow-table/pidlookup path and paid the
    /// ~1 ms retry loop (the prime suspect for a userspace pps ceiling).
    pid_stalls: AtomicU64,
    /// Local endpoints that recently failed PID resolution, keyed
    /// (proto, src_port, src_ip). See PID_NEG_TTL.
    neg_pid: Mutex<HashMap<(u8, u16, u32), Instant>>,
    /// Bytes handed back to the kernel as passthrough (all passthrough
    /// classes). The tunneled byte counters (bus.bytes_*) say nothing about
    /// untunneled throughput, so this is the only way to compare what we
    /// actually carried against what the browser reports.
    pass_bytes: AtomicU64,
    /// WinDivert recv errors. A full queue drops packets inside the driver
    /// where we cannot see them; a recv error at least proves starvation.
    recv_err: AtomicU64,
    /// Outer-loop iterations and the microseconds spent in each phase, summed
    /// since the last 5s report is derived from the totals.
    loops: AtomicU64,
    us_recv: AtomicU64,
    us_flush: AtomicU64,
    us_svc: AtomicU64,
    /// Untunneled packets attributed to (proto, dst_port, dst_ip) since the
    /// last 5s report. Naming the floor's owner is the whole point.
    untun_dst: Mutex<HashMap<(u8, u16, u32), u64>>,
    /// Same, by owning PID (0 = unresolved), so the report can name the app
    /// (e.g. firefox.exe) rather than only a destination.
    untun_pid: Mutex<HashMap<u32, u64>>,
    captured: AtomicU64,
    injected: AtomicU64,
    bridges_opened: AtomicU64,
    bridges_closed: AtomicU64,
    /// Flows retired by PENDING_TCP_TIMEOUT: the app never completed the
    /// local handshake. Chrome's racing losers dominate this count; a spike
    /// beyond "races observed" would implicate our SYN-ACK injection under
    /// load (see PENDING_TCP_TIMEOUT).
    pending_timeouts: AtomicU64,
    /// Used only by the 5s report to turn a top PID into an exe name.
    resolver: Arc<Resolver>,
    bus: Arc<StatusBus>,
}

impl Stats {
    fn new(bus: Arc<StatusBus>, resolver: Arc<Resolver>) -> Self {
        Self {
            pass_malformed: AtomicU64::new(0),
            pass_dns: AtomicU64::new(0),
            pass_untun: AtomicU64::new(0),
            pass_vpn_down: AtomicU64::new(0),
            pid_stalls: AtomicU64::new(0),
            neg_pid: Mutex::new(HashMap::new()),
            pass_bytes: AtomicU64::new(0),
            recv_err: AtomicU64::new(0),
            loops: AtomicU64::new(0),
            us_recv: AtomicU64::new(0),
            us_flush: AtomicU64::new(0),
            us_svc: AtomicU64::new(0),
            untun_dst: Mutex::new(HashMap::new()),
            untun_pid: Mutex::new(HashMap::new()),
            captured: AtomicU64::new(0),
            injected: AtomicU64::new(0),
            bridges_opened: AtomicU64::new(0),
            bridges_closed: AtomicU64::new(0),
            pending_timeouts: AtomicU64::new(0),
            resolver,
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

    /// Attribute an untunneled packet to its destination so the 5s report can
    /// name whatever produces the constant passthrough floor. The lock is
    /// uncontended: this runs only on the single divert thread.
    fn note_untun(&self, proto: u8, dst_port: u16, dst_ip: Ipv4Addr, pid: Option<u32>) {
        if let Ok(mut m) = self.untun_dst.lock() {
            *m.entry((proto, dst_port, u32::from(dst_ip))).or_insert(0) += 1;
        }
        if let Ok(mut m) = self.untun_pid.lock() {
            *m.entry(pid.unwrap_or(0)).or_insert(0) += 1;
        }
    }

    fn report_loop(&self) {
        let start = Instant::now();
        let mut last = [0u64; 7];
        let mut last2 = [0u64; 8];
        let mut last3 = [0u64; 4];
        loop {
            std::thread::sleep(Duration::from_secs(5));
            let cur = [
                self.pass_malformed.load(Ordering::Relaxed)
                    + self.pass_dns.load(Ordering::Relaxed)
                    + self.pass_untun.load(Ordering::Relaxed)
                    + self.pass_vpn_down.load(Ordering::Relaxed),
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
            // Passthrough breakdown (5s deltas): which branch produced the
            // floor, and how often the ~1 ms PID retry loop was paid.
            let cur2 = [
                self.pass_malformed.load(Ordering::Relaxed),
                self.pass_dns.load(Ordering::Relaxed),
                self.pass_untun.load(Ordering::Relaxed),
                self.pass_vpn_down.load(Ordering::Relaxed),
                self.pid_stalls.load(Ordering::Relaxed),
                self.recv_err.load(Ordering::Relaxed),
                self.pending_timeouts.load(Ordering::Relaxed),
                self.pass_bytes.load(Ordering::Relaxed),
            ];
            let e: Vec<u64> = cur2.iter().zip(&last2).map(|(a, b)| a - b).collect();
            last2 = cur2;
            tracing::info!(
                "divert 5s detail: malformed={} dns={} untunneled={} vpndown={} pid_stall={} recv_err={} pending_timeout={} passthrough={}B ({:.2} mbps)",
                e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7],
                (e[7] as f64) * 8.0 / 5.0 / 1_000_000.0
            );
            // Who owns the untunneled floor? Top 5 destinations this window.
            let mut top: Vec<((u8, u16, u32), u64)> = self
                .untun_dst
                .lock()
                .map(|mut m| m.drain().collect())
                .unwrap_or_default();
            top.sort_by(|a, b| b.1.cmp(&a.1));
            let top_str = top
                .iter()
                .take(5)
                .map(|((proto, port, ip), n)| {
                    format!(
                        "{}{}:{}={}",
                        if *proto == PROTO_TCP { "tcp/" } else { "udp/" },
                        Ipv4Addr::from(*ip),
                        port,
                        n
                    )
                })
                .collect::<Vec<_>>()
                .join(" ");
            tracing::info!("divert 5s untunneled top: {}", top_str);
            // And by owning process, so the floor is named (firefox.exe, ...).
            let mut topp: Vec<(u32, u64)> = self
                .untun_pid
                .lock()
                .map(|mut m| m.drain().collect())
                .unwrap_or_default();
            topp.sort_by(|a, b| b.1.cmp(&a.1));
            let topp_str = topp
                .iter()
                .take(5)
                .map(|(pid, n)| {
                    if *pid == 0 {
                        format!("unresolved={}", n)
                    } else {
                        let name = self
                            .resolver
                            .resolve(*pid)
                            .map(|i| i.exe_name)
                            .unwrap_or_else(|| format!("pid{}", pid));
                        format!("{}={}", name, n)
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            tracing::info!("divert 5s untunneled by pid: {}", topp_str);
            // Phase timing: if iters/s is pinned low while pkts/iter is ~1,
            // the loop itself (not the traffic) is the throughput ceiling.
            let cur3 = [
                self.loops.load(Ordering::Relaxed),
                self.us_recv.load(Ordering::Relaxed),
                self.us_flush.load(Ordering::Relaxed),
                self.us_svc.load(Ordering::Relaxed),
            ];
            let f: Vec<u64> = cur3.iter().zip(&last3).map(|(a, b)| a - b).collect();
            last3 = cur3;
            let handled = d[0] + d[1];
            tracing::info!(
                "divert 5s loop: iters={} handled={} pkts/iter={:.2} recv={}ms flush={}ms svc={}ms",
                f[0],
                handled,
                if f[0] > 0 { handled as f64 / f[0] as f64 } else { 0.0 },
                f[1] / 1000,
                f[2] / 1000,
                f[3] / 1000
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CAPTURE_FILTER;
    use crate::flows::{PROTO_TCP, PROTO_UDP};
    use std::ffi::{c_char, c_void, CStr, CString};

    /// Regression guard for the Oct-16 breakage: `not (...)` is a WinDivert
    /// parse error, which becomes ERROR_INVALID_PARAMETER (87) on
    /// `WinDivertOpen` and aborts the backend. `WinDivertHelperCompileFilter`
    /// validates the exact string we hand to WinDivert with no driver and no
    /// elevation, so this test fails loudly if the filter is ever made
    /// unparseable again.
    #[test]
    fn capture_filter_compiles() {
        let filter = CString::new(CAPTURE_FILTER).expect("filter has no NUL");
        let mut object: Vec<c_char> = vec![0; 8192];
        let mut error_str: *const c_char = std::ptr::null();
        let mut error_pos: u32 = 0;
        let ok = unsafe {
            windivert_sys::WinDivertHelperCompileFilter(
                filter.as_ptr(),
                windivert_sys::WinDivertLayer::Network,
                object.as_mut_ptr(),
                object.len() as u32,
                &mut error_str,
                &mut error_pos,
            )
        };
        let detail = if error_str.is_null() {
            "(no error string)".to_string()
        } else {
            unsafe { CStr::from_ptr(error_str) }
                .to_string_lossy()
                .into_owned()
        };
        assert_ne!(ok, 0, "WinDivert rejected CAPTURE_FILTER at pos {error_pos}: {detail}");
    }

    /// Regression guard for the follow-on breakage: a filter can compile yet
    /// match NOTHING. WinDivert evaluates an absent layer's field as false, so
    /// a flat `tcp.DstPort != 53 and udp.DstPort != 53` conjunction silently
    /// drops every packet. This evals crafted outbound IPv4 TCP/UDP frames
    /// against the real filter (no driver/elevation needed) and asserts the
    /// actual capture verdicts.
    #[test]
    fn capture_filter_semantics() {
        fn ipv4(proto: u8, dst_port: u16) -> Vec<u8> {
            let mut ip = vec![0u8; 20];
            ip[0] = 0x45; // IPv4, IHL 5
            ip[8] = 64; // TTL
            ip[9] = proto;
            ip[12..16].copy_from_slice(&[192, 168, 68, 100]);
            ip[16..20].copy_from_slice(&[1, 1, 1, 1]);
            let l4_len = if proto == PROTO_TCP { 20 } else { 8 };
            let mut l4 = vec![0u8; l4_len];
            l4[0..2].copy_from_slice(&51234u16.to_be_bytes());
            l4[2..4].copy_from_slice(&dst_port.to_be_bytes());
            if proto == PROTO_TCP {
                l4[12] = 0x50; // data offset 5
            }
            let total = (20 + l4_len) as u16;
            ip[2..4].copy_from_slice(&total.to_be_bytes());
            ip.extend_from_slice(&l4);
            ip
        }

        fn captured(pkt: &[u8]) -> bool {
            // WINDIVERT_ADDRESS: Timestamp(8) + bitfield(4) + reserved(4) +
            // union(48). Layer = NETWORK(0), Outbound = bit 17 → 0x00020000.
            let mut addr = [0u8; 64];
            addr[8..12].copy_from_slice(&(1u32 << 17).to_ne_bytes());
            let filter = CString::new(CAPTURE_FILTER).expect("filter has no NUL");
            let ok = unsafe {
                windivert_sys::WinDivertHelperEvalFilter(
                    filter.as_ptr(),
                    pkt.as_ptr() as *const c_void,
                    pkt.len() as u32,
                    addr.as_ptr() as *const windivert_sys::address::WINDIVERT_ADDRESS,
                )
            };
            ok != 0
        }

        // Tunneled-app traffic must be captured...
        assert!(captured(&ipv4(PROTO_TCP, 443)), "TCP:443 must be captured");
        assert!(captured(&ipv4(PROTO_UDP, 443)), "UDP:443 must be captured");
        // ...while DNS / mDNS / LLMNR is skipped.
        assert!(!captured(&ipv4(PROTO_TCP, 53)), "TCP:53 must be excluded");
        assert!(!captured(&ipv4(PROTO_UDP, 53)), "UDP:53 must be excluded");
        assert!(!captured(&ipv4(PROTO_UDP, 5353)), "UDP:5353 must be excluded");
        assert!(!captured(&ipv4(PROTO_UDP, 5355)), "UDP:5355 must be excluded");
    }
}
