use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use dashmap::DashMap;
use ipc::status::{status_message::Body, AppStats, Event, EventKind, PidStats, Snapshot, StatusMessage, Totals, VpnState};
use ipc::STATUS_PIPE_NAME;
use tokio::io::AsyncWriteExt;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::core::{w, BOOL};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

use crate::vpn_state::{self, VpnState as VpnStateHandle};

const TICK: Duration = Duration::from_millis(500);

pub struct StatusBus {
    pub bytes_out: Arc<AtomicU64>,
    pub bytes_in: Arc<AtomicU64>,
    pub vpn_up_since_ms: Arc<AtomicU64>,
    /// True when the high-metric split-tunnel route is installed. False means
    /// the adapter is up but tunneled bridges have no next-hop — the UI must
    /// show amber instead of green.
    pub route_ok: Arc<std::sync::atomic::AtomicBool>,
    /// Fan-out for activity-log events (VPN transitions, per-app admissions,
    /// bridge open/fail). Each status-pipe client holds its own receiver;
    /// senders never block — a lagging client drops, never stalls the hot path.
    pub event_tx: tokio::sync::broadcast::Sender<BusEvent>,
    /// Per-PID byte counters updated by bridges.
    pub pid_bytes_out: Arc<DashMap<u32, AtomicU64>>,
    pub pid_bytes_in: Arc<DashMap<u32, AtomicU64>>,
    /// PID → canonical exe path, populated by proc_watcher.
    pub pid_paths: Arc<DashMap<u32, String>>,
    /// Persistent activity log (same lines the UI panel shows). The UI
    /// clears it on app start; the redirector only appends (plus a marker
    /// per redirector start) so evidence survives UI restarts/crashes.
    /// Mutex because emit() fires from the divert loop AND spawned bridge
    /// tasks. None when the runtime dir is unavailable — logging must never
    /// break the hot path.
    activity_log: Mutex<Option<std::fs::File>>,
}

/// %LocalAppData%\VpnClient\runtime\activity.log — next to mode.txt and
/// openvpn.log. Shared convention with the UI (VpnConnector.ActivityLogPath).
fn activity_log_path() -> Option<PathBuf> {
    let local = std::env::var("LOCALAPPDATA").ok()?;
    Some(
        PathBuf::from(local)
            .join("VpnClient")
            .join("runtime")
            .join("activity.log"),
    )
}

fn local_timestamp() -> String {
    // windows crate is already a dependency; no chrono needed for one line.
    // (GetLocalTime returns SYSTEMTIME by value; the type lives in Foundation.)
    let st = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds
    )
}

/// ~8 MB cap: activity storms (opencode spawns hundreds of tools) must not
/// fill the disk. Truncates with a marker; total loss bounded, recency kept.
const ACTIVITY_LOG_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// One activity-log record. Small by construction (short detail strings).
#[derive(Debug, Clone)]
pub struct BusEvent {
    pub kind: EventKind,
    pub detail: String,
}

impl StatusBus {
    pub fn new() -> Self {
        // 256-deep broadcast: bursts of bridge events must not stall the
        // divert hot path; a lagging UI client simply skips.
        let (event_tx, _) = tokio::sync::broadcast::channel(256);
        let activity_log = Mutex::new(open_activity_log());
        let bus = Self {
            bytes_out: Arc::new(AtomicU64::new(0)),
            bytes_in: Arc::new(AtomicU64::new(0)),
            vpn_up_since_ms: Arc::new(AtomicU64::new(0)),
            route_ok: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            event_tx,
            pid_bytes_out: Arc::new(DashMap::new()),
            pid_bytes_in: Arc::new(DashMap::new()),
            pid_paths: Arc::new(DashMap::new()),
            activity_log,
        };
        // Marker (appended, never truncating): one UI session can restart
        // the redirector, and the earlier evidence must survive that.
        bus.append_activity_line("Redirector", "redirector started — appending to activity log");
        bus
    }

    pub fn add_pid_out(&self, pid: u32, n: u64) {
        self.pid_bytes_out
            .entry(pid)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_pid_in(&self, pid: u32, n: u64) {
        self.pid_bytes_in
            .entry(pid)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(n, Ordering::Relaxed);
    }

    /// Fire-and-forget activity-log event. Never blocks; failures (no
    /// receivers, lagging receivers) are silently dropped by design.
    /// Also appended to activity.log (best effort) so the session is
    /// analyzable from disk after the fact.
    pub fn emit(&self, kind: EventKind, detail: impl Into<String>) {
        let detail = detail.into();
        let _ = self.event_tx.send(BusEvent {
            kind,
            detail: detail.clone(),
        });
        self.append_activity_line(&format!("{:?}", kind), &detail);
    }

    fn append_activity_line(&self, kind: &str, detail: &str) {
        use std::io::Write;
        let Ok(mut guard) = self.activity_log.lock() else {
            return;
        };
        let Some(file) = guard.as_mut() else {
            return;
        };
        // Rotate by truncation (single file, no rename dance while held).
        if file.metadata().map(|m| m.len()).unwrap_or(0) > ACTIVITY_LOG_MAX_BYTES {
            let _ = file.set_len(0);
            use std::io::Seek;
            let _ = file.seek(std::io::SeekFrom::Start(0));
            let _ = writeln!(
                file,
                "[{}] [Redirector] activity.log rotated (>8MB) — older lines discarded",
                local_timestamp()
            );
        }
        let _ = writeln!(file, "[{}] [{}] {}", local_timestamp(), kind, oneline(detail));
        let _ = file.flush();
    }
}

/// One line per event: flatten embedded newlines so post-mortem parsing
/// (and the UI panel) never sees a multi-line record.
fn oneline(s: &str) -> String {
    s.replace("\r\n", " | ").replace('\n', " | ").replace('\r', " | ")
}

/// Open (creating dirs) the activity log in append mode. None on any
/// failure — every caller treats logging as best-effort.
fn open_activity_log() -> Option<std::fs::File> {
    let path = activity_log_path()?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
}

/// Standalone line writer for contexts without a StatusBus (notably the
/// panic hook). Opens-closes per call: crash-safe, never holds a handle.
pub fn append_raw_line(line: &str) {
    use std::io::Write;
    let Some(path) = activity_log_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "[{}] {}", local_timestamp(), oneline(line));
    }
}

struct SecurityDescriptor {
    psd: PSECURITY_DESCRIPTOR,
}

impl SecurityDescriptor {
    fn allow_authenticated_users() -> Result<Self> {
        let mut psd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w!("D:(A;;GA;;;AU)"),
                SDDL_REVISION_1 as u32,
                &mut psd,
                None,
            )
        }
        .context("ConvertStringSecurityDescriptorToSecurityDescriptorW failed")?;
        Ok(Self { psd })
    }

    fn attrs(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.psd.0,
            bInheritHandle: BOOL(0),
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.psd.0)));
        }
    }
}

unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

fn create_pipe(sd: &SecurityDescriptor, first: bool) -> Result<NamedPipeServer> {
    let attrs = sd.attrs();
    let mut opts = ServerOptions::new();
    if first {
        opts.first_pipe_instance(true);
    }
    unsafe {
        opts.create_with_security_attributes_raw(STATUS_PIPE_NAME, &attrs as *const _ as *mut _)
    }
    .context("create_with_security_attributes_raw failed")
}

pub async fn run(bus: Arc<StatusBus>, vpn_state: VpnStateHandle) -> Result<()> {
    let sd = SecurityDescriptor::allow_authenticated_users()?;
    // The FIRST pipe instance failing is fatal-and-loud (another redirector
    // holding it is the usual cause): say so in the activity file, then
    // exit. Every LATER failure is transient: warn, wait, recreate.
    // (Returning Err here used to exit the whole process via main's
    // select! — marker with zero follow-up lines, no VpnUp ever.)
    let mut server = match create_pipe(&sd, true) {
        Ok(s) => s,
        Err(e) => {
            append_raw_line(&format!(
                "FATAL: status pipe unavailable ({:#}) — another redirector running?",
                e
            ));
            return Err(e).context("status pipe first instance failed");
        }
    };
    tracing::info!("status pipe server listening on {}", STATUS_PIPE_NAME);

    loop {
        if let Err(e) = server.connect().await {
            tracing::warn!("status pipe accept failed ({:#}) — recreating", e);
            server = recreate_pipe(&sd).await;
            continue;
        }
        let connected = server;
        // Always succeeds eventually (warns + sleeps between attempts), so
        // `server` is valid at every loop top — the borrow checker can rely
        // on it, and so can we.
        server = recreate_pipe(&sd).await;

        let bus = bus.clone();
        let vpn_state = vpn_state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(connected, bus, vpn_state).await {
                tracing::warn!("status client disconnected: {}", e);
            }
        });
    }
}

/// Recreate a (non-first) pipe instance, retrying forever. Pipe creation
/// failing persistently means the process is wedged anyway; exiting (the
/// old `?` behavior) killed the bridge too, so waiting it out is strictly
/// better. Never returns Err.
async fn recreate_pipe(sd: &SecurityDescriptor) -> NamedPipeServer {
    loop {
        match create_pipe(sd, false) {
            Ok(s) => return s,
            Err(e) => {
                tracing::warn!("status pipe recreate failed ({:#}) — retrying", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

async fn handle_client(
    mut pipe: NamedPipeServer,
    bus: Arc<StatusBus>,
    vpn_state: VpnStateHandle,
) -> Result<()> {
    tracing::info!("status client connected");
    let mut frame_buf = Vec::with_capacity(256);
    let mut prev_pids: HashMap<u32, (u64, u64)> = HashMap::new();
    let mut prev_sample: Instant = Instant::now();
    let mut events = bus.event_tx.subscribe();
    // Drain backlog from before this client connected: only the newest few
    // matter (e.g. "VPN up 10.8.0.5"), ancient bridge lines are noise.
    while events.try_recv().is_ok() {}
    let mut ticker = tokio::time::interval(TICK);
    // Skip the immediate first tick: interval fires at once on creation and
    // we want the first snapshot after a full TICK of counter time.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                frame_buf.clear();
                let now = Instant::now();
                let elapsed = now.duration_since(prev_sample).as_secs_f64().max(0.001);
                let (msg, snapshot_pids) =
                    build_snapshot(&bus, &vpn_state, &prev_pids, elapsed);
                prev_pids = snapshot_pids;
                prev_sample = now;
                ipc::encode_status_frame(&msg, &mut frame_buf);
                match write_frame(&mut pipe, &frame_buf).await? {
                    WriteOutcome::Done => return Ok(()),
                    WriteOutcome::Continue => {}
                }
            }
            evt = events.recv() => {
                match evt {
                    Ok(e) => {
                        frame_buf.clear();
                        let msg = StatusMessage {
                            body: Some(Body::Event(Event {
                                kind: e.kind as i32,
                                detail: e.detail,
                            })),
                        };
                        ipc::encode_status_frame(&msg, &mut frame_buf);
                        match write_frame(&mut pipe, &frame_buf).await? {
                            WriteOutcome::Done => return Ok(()),
                            WriteOutcome::Continue => {}
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

enum WriteOutcome {
    Done,
    Continue,
}

/// Write one framed message; a broken pipe maps to Done (clean disconnect).
async fn write_frame(pipe: &mut NamedPipeServer, frame: &[u8]) -> Result<WriteOutcome> {
    use WriteOutcome::{Continue, Done};
    if let Err(e) = pipe.write_all(frame).await {
        if matches!(
            e.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof
        ) {
            return Ok(Done);
        }
        return Err(e.into());
    }
    if let Err(e) = pipe.flush().await {
        if matches!(e.kind(), std::io::ErrorKind::BrokenPipe) {
            return Ok(Done);
        }
        return Err(e.into());
    }
    Ok(Continue)
}

fn build_snapshot(
    bus: &StatusBus,
    vpn_state: &VpnStateHandle,
    prev_pids: &HashMap<u32, (u64, u64)>,
    elapsed_s: f64,
) -> (StatusMessage, HashMap<u32, (u64, u64)>) {
    let now = vpn_state::current(vpn_state);
    let (up, adapter_ip, uptime_ms) = match now {
        Some(target) => {
            let up_since = bus.vpn_up_since_ms.load(Ordering::Relaxed);
            let now_ms = unix_millis();
            let uptime = if up_since > 0 && now_ms >= up_since {
                now_ms - up_since
            } else {
                0
            };
            (true, target.ipv4.to_string(), uptime)
        }
        None => (false, String::new(), 0),
    };

    // First gather raw per-PID counters and compute per-PID rates by diffing
    // against the previous sample. Then group those into per-app AppStats.
    struct PidSnapshot {
        pid: u32,
        bytes_out: u64,
        bytes_in: u64,
        bps_out: u64,
        bps_in: u64,
    }
    let mut next_pids: HashMap<u32, (u64, u64)> = HashMap::new();
    let mut per_path_pids: HashMap<String, Vec<PidSnapshot>> = HashMap::new();
    for entry in bus.pid_paths.iter() {
        let pid = *entry.key();
        let path = entry.value().clone();
        let out = bus.pid_bytes_out.get(&pid).map(|c| c.load(Ordering::Relaxed)).unwrap_or(0);
        let in_ = bus.pid_bytes_in.get(&pid).map(|c| c.load(Ordering::Relaxed)).unwrap_or(0);
        let prev = prev_pids.get(&pid).copied().unwrap_or((out, in_));
        let bps_out = ((out.saturating_sub(prev.0)) as f64 / elapsed_s).max(0.0) as u64;
        let bps_in = ((in_.saturating_sub(prev.1)) as f64 / elapsed_s).max(0.0) as u64;
        next_pids.insert(pid, (out, in_));
        per_path_pids.entry(path).or_default().push(PidSnapshot {
            pid,
            bytes_out: out,
            bytes_in: in_,
            bps_out,
            bps_in,
        });
    }

    let apps: Vec<AppStats> = per_path_pids
        .into_iter()
        .map(|(path, mut pids)| {
            // Most-active first inside each app.
            pids.sort_by(|a, b| (b.bytes_out + b.bytes_in).cmp(&(a.bytes_out + a.bytes_in)));
            let active = pids.len() as u32;
            let total_out: u64 = pids.iter().map(|p| p.bytes_out).sum();
            let total_in: u64 = pids.iter().map(|p| p.bytes_in).sum();
            let total_bps_out: u64 = pids.iter().map(|p| p.bps_out).sum();
            let total_bps_in: u64 = pids.iter().map(|p| p.bps_in).sum();
            let pid_stats: Vec<PidStats> = pids
                .into_iter()
                .map(|p| PidStats {
                    pid: p.pid,
                    bytes_out: p.bytes_out,
                    bytes_in: p.bytes_in,
                    bytes_out_per_sec: p.bps_out,
                    bytes_in_per_sec: p.bps_in,
                })
                .collect();
            AppStats {
                exe_path: path,
                bytes_out: total_out,
                bytes_in: total_in,
                bytes_out_per_sec: total_bps_out,
                bytes_in_per_sec: total_bps_in,
                active_pids: active,
                pids: pid_stats,
            }
        })
        .collect();

    let msg = StatusMessage {
        body: Some(Body::Snapshot(Snapshot {
            vpn: Some(VpnState {
                up,
                adapter_ip,
                uptime_ms,
                adapter_name: String::new(),
                route_ok: bus.route_ok.load(Ordering::Relaxed),
            }),
            totals: Some(Totals {
                bytes_app_to_remote: bus.bytes_out.load(Ordering::Relaxed),
                bytes_remote_to_app: bus.bytes_in.load(Ordering::Relaxed),
                active_tcp_flows: 0,
                active_udp_flows: 0,
            }),
            apps,
        })),
    };
    (msg, next_pids)
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
