//! Push tunnel membership into the callout driver.
//!
//! Full replace per IOCTL (driver has no APPEND): >512 PIDs is refused
//! loudly instead of last-wins chunking (which would silently untunnel
//! apps). Realistic launcher+game trees are <50 PIDs.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use crate::policy::PolicyState;
use crate::status_server::StatusBus;
use crate::wfp::device;

pub const MAX_PIDS_PER_PUSH: usize = 512;

pub async fn run(policy_state: PolicyState, bus: Arc<StatusBus>) -> Result<()> {
    tracing::info!("wfp policy_sync running (DeviceIoControl SET_PID_ALLOWLIST)");
    let mut last_pushed: Vec<u32> = Vec::new();
    let mut backoff = Duration::from_secs(2);
    loop {
        let pids: Vec<u32> = policy_state
            .read()
            .map(|guard| guard.keys().copied().collect())
            .unwrap_or_default();
        if pids != last_pushed {
            // Driver is full-REPLACE per IOCTL: chunked multi-push would be
            // last-wins and silently drop apps. Reject loudly instead.
            if pids.len() > MAX_PIDS_PER_PUSH {
                tracing::error!(
                    "wfp policy_sync: {} pids exceed single-push {} — refusing partial push (would untunnel apps). Split policy or raise limit with new APPEND protocol.",
                    pids.len(),
                    MAX_PIDS_PER_PUSH
                );
                let _ = &bus;
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            match push_snapshot(&pids).await {
                Ok(()) => {
                    tracing::info!("wfp policy_sync: pushed {} pids", pids.len());
                    last_pushed = pids;
                    backoff = Duration::from_secs(2);
                    let _ = &bus;
                }
                Err(e) => {
                    tracing::warn!(
                        "wfp policy_sync: push {} pids failed ({:#}) — retry in {:?} (driver fail-open)",
                        pids.len(),
                        e,
                        backoff
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    continue;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn push_snapshot(pids: &[u32]) -> Result<()> {
    let owned = pids.to_vec();
    tokio::task::spawn_blocking(move || device::push_allowlist(&owned))
        .await
        .map_err(|e| anyhow::anyhow!("push join failed: {}", e))??;
    Ok(())
}
