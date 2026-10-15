use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use dashmap::DashMap;
use ipc::status::{status_message::Body, AppStats, PidStats, Snapshot, StatusMessage, Totals, VpnState};
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
    /// Per-PID byte counters updated by bridges.
    pub pid_bytes_out: Arc<DashMap<u32, AtomicU64>>,
    pub pid_bytes_in: Arc<DashMap<u32, AtomicU64>>,
    /// PID → canonical exe path, populated by proc_watcher.
    pub pid_paths: Arc<DashMap<u32, String>>,
}

impl StatusBus {
    pub fn new() -> Self {
        Self {
            bytes_out: Arc::new(AtomicU64::new(0)),
            bytes_in: Arc::new(AtomicU64::new(0)),
            vpn_up_since_ms: Arc::new(AtomicU64::new(0)),
            route_ok: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            pid_bytes_out: Arc::new(DashMap::new()),
            pid_bytes_in: Arc::new(DashMap::new()),
            pid_paths: Arc::new(DashMap::new()),
        }
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
    let mut server = create_pipe(&sd, true)?;
    tracing::info!("status pipe server listening on {}", STATUS_PIPE_NAME);

    loop {
        server.connect().await.context("status pipe accept failed")?;
        let connected = server;
        server = create_pipe(&sd, false)?;

        let bus = bus.clone();
        let vpn_state = vpn_state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(connected, bus, vpn_state).await {
                tracing::warn!("status client disconnected: {}", e);
            }
        });
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
    loop {
        frame_buf.clear();
        let now = Instant::now();
        let elapsed = now.duration_since(prev_sample).as_secs_f64().max(0.001);
        let (msg, snapshot_pids) =
            build_snapshot(&bus, &vpn_state, &prev_pids, elapsed);
        prev_pids = snapshot_pids;
        prev_sample = now;
        ipc::encode_status_frame(&msg, &mut frame_buf);
        if let Err(e) = pipe.write_all(&frame_buf).await {
            if matches!(
                e.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof
            ) {
                return Ok(());
            }
            return Err(e.into());
        }
        if let Err(e) = pipe.flush().await {
            if matches!(e.kind(), std::io::ErrorKind::BrokenPipe) {
                return Ok(());
            }
            return Err(e.into());
        }
        tokio::time::sleep(TICK).await;
    }
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
