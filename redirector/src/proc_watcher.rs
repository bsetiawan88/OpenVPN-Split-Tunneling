use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

use crate::policy::{self, PolicyState};
use crate::status_server::StatusBus;
use crate::tunneled::{self, TunneledPaths};

// We still poll, but the *primary* admission path is now in divert.rs (it
// admits PIDs the instant their first packet shows up). This watcher exists
// mainly to (a) catch already-running processes when the user adds a path
// to the tunnel list, and (b) garbage-collect dead PIDs.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const CONFIG_RELOAD_INTERVAL: Duration = Duration::from_secs(2);

pub async fn run(
    policy_state: PolicyState,
    bus: Arc<StatusBus>,
    tunneled_paths: TunneledPaths,
) -> Result<()> {
    tracing::info!("proc watcher running (polls every {:?})", POLL_INTERVAL);

    let mut sys = System::new_all();
    let mut auto_tunneled: HashSet<u32> = HashSet::new();
    let mut last_config_load = std::time::Instant::now() - CONFIG_RELOAD_INTERVAL;

    loop {
        if last_config_load.elapsed() >= CONFIG_RELOAD_INTERVAL {
            let from_disk = tunneled::load_from_disk();
            tunneled::replace(&tunneled_paths, from_disk);
            last_config_load = std::time::Instant::now();
        }

        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::new().with_exe(sysinfo::UpdateKind::Always),
        );

        // Snapshot the path list so we don't hold the read lock during sysinfo
        // iteration (which can be a few ms on a busy box).
        let paths: Vec<PathBuf> = tunneled_paths.read().unwrap().clone();
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            if auto_tunneled.contains(&pid_u32) {
                continue;
            }
            // Child-process inheritance: anything spawned by an already
            // tunneled PID is tunneled too, even when the child exe path is
            // NOT in the user's list (launcher -> game is the classic case).
            // This closes the "koneksi tidak berjalan untuk aplikasi" gap
            // where the user lists the launcher but the real traffic comes
            // from a child with a different exe name.
            if let Some(parent) = process.parent() {
                let parent_u32 = parent.as_u32();
                if policy::contains(&policy_state, parent_u32) {
                    let path_str = process
                        .exe()
                        .map(|e| e.to_string_lossy().to_string())
                        .unwrap_or_default();
                    tracing::info!(
                        "auto-tunnel (child): pid={} parent={} exe={:?}",
                        pid_u32, parent_u32, process.exe()
                    );
                    policy::add(&policy_state, pid_u32);
                    if !path_str.is_empty() {
                        bus.pid_paths.insert(pid_u32, path_str);
                    }
                    auto_tunneled.insert(pid_u32);
                    continue;
                }
            }
            let Some(exe) = process.exe() else { continue };
            if !path_matches_any(exe, &paths) {
                continue;
            }
            let path_str = exe.to_string_lossy().to_string();
            tracing::info!("auto-tunnel (poll): pid={} matches {:?}", pid_u32, exe);
            policy::add(&policy_state, pid_u32);
            bus.pid_paths.insert(pid_u32, path_str);
            auto_tunneled.insert(pid_u32);
        }

        let still_alive: HashSet<u32> = sys
            .processes()
            .keys()
            .map(|p| p.as_u32())
            .collect();
        auto_tunneled.retain(|p| still_alive.contains(p));
        bus.pid_paths.retain(|p, _| still_alive.contains(p));
        bus.pid_bytes_out.retain(|p, _| still_alive.contains(p));
        bus.pid_bytes_in.retain(|p, _| still_alive.contains(p));

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn path_matches_any(candidate: &std::path::Path, list: &[PathBuf]) -> bool {
    let candidate_lower = candidate.to_string_lossy().to_lowercase();
    list.iter()
        .any(|p| p.to_string_lossy().to_lowercase() == candidate_lower)
}
