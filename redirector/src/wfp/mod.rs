//! WFP backend — user-mode controller for VpnWfpCallout.sys.
//!
//! Full implementation: driver registers REDIRECT_V4/V6 + DATAGRAM_V4
//! callouts; PID comes from FWPS_METADATA_FIELD_PROCESS_ID, no
//! observer/pidlookup race, no smoltcp. TCP is redirected to a loopback
//! listener, UDP via the DATAGRAM flow table + NAT relay. Both relays
//! pin outbound sockets with IP_UNICAST_IF, matching divert.rs.
//!
//! Fail-open is preserved: VPN down -> redirected sockets get a clean
//! close (app reconnects via default route), and the driver CONTINUEs
//! when its allowlist/target is empty.

pub mod device;
pub mod policy_sync;
pub mod redirect_listener;

use std::sync::Arc;

use anyhow::Result;

use crate::flows::FlowTable;
use crate::policy::PolicyState;
use crate::status_server::StatusBus;
use crate::tunneled::TunneledPaths;
use crate::vpn_state::{self, VpnState};
use crate::process::Resolver;

/// Which packet path to use. `Default` lives in an impl below: it PROBES the
/// callout driver (installed + running + device openable) and picks WFP when
/// present, WinDivert otherwise. The fallback is deliberate, not
/// transitional: a machine without the attestation-signed driver must keep
/// capturing out of the box (WinDivert needs no install), and a machine with
/// it gets the better path (kernel PID attribution, no userspace tax).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    WindDivert,
    Wfp,
}

impl Default for Backend {
    fn default() -> Self {
        let st = device::status();
        if st.installed && st.running && st.device_openable {
            tracing::info!(
                "wfp: callout driver available (installed={} running={} device_openable={}) - auto-selecting WFP backend",
                st.installed, st.running, st.device_openable
            );
            Self::Wfp
        } else {
            tracing::info!(
                "wfp: callout driver unavailable (installed={} running={} device_openable={}) - using WinDivert backend",
                st.installed, st.running, st.device_openable
            );
            Self::WindDivert
        }
    }
}

impl Backend {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "windivert" | "divert" => Some(Self::WindDivert),
            "wfp" | "callout" => Some(Self::Wfp),
            _ => None,
        }
    }
}

/// Async core — awaited directly by `run_observe_wfp` on the existing runtime.
pub async fn run_async(
    policy_state: PolicyState,
    flows: FlowTable,
    vpn_state: VpnState,
    bus: Arc<StatusBus>,
    resolver: Arc<Resolver>,
    tunneled_paths: TunneledPaths,
) -> Result<()> {
    let _ = (flows, tunneled_paths);
    let status = device::status();
    tracing::info!(
        "wfp: driver installed={} running={} bfe_running={} device_openable={} dos_device={}",
        status.installed,
        status.running,
        status.bfe_running,
        status.device_openable,
        device::DOS_DEVICE
    );

    if !status.running {
        anyhow::bail!(
            "WFP callout driver '{}' is not running (installed={}). Install it with installer\\DriverInstall.ps1 -Install, or run with --backend=windivert. BFE running={}. See driver/README.md.",
            device::SERVICE_NAME,
            status.installed,
            status.bfe_running
        );
    }
    if !status.bfe_running {
        anyhow::bail!("BFE (Base Filtering Engine) is not running — WFP cannot filter. Start it: sc.exe start BFE.");
    }

    // Flush driver flows whenever the VPN target changes (down/rotate),
    // mirroring divert.rs::on_vpn_change which recycles bridges.
    let flush_task = {
        let vpn_state = vpn_state.clone();
        let bus = bus.clone();
        tokio::spawn(vpn_flush_watcher(vpn_state, bus))
    };
    let sync_task = tokio::spawn(policy_sync::run(policy_state.clone(), bus.clone()));
    let relay_task = tokio::spawn(redirect_listener::run(vpn_state.clone(), bus.clone(), resolver.clone()));
    tokio::select! {
        r = flush_task => r??,
        r = sync_task => r??,
        r = relay_task => r??,
    }
    #[allow(unreachable_code)]
    Ok::<(), anyhow::Error>(())
}

async fn vpn_flush_watcher(vpn_state: VpnState, bus: Arc<StatusBus>) -> Result<()> {
    use ipc::status::EventKind;
    let mut last = tokio::task::spawn_blocking({
        let vpn_state = vpn_state.clone();
        move || vpn_state::current(&vpn_state)
    })
    .await
    .unwrap_or(None);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let now = vpn_state::current(&vpn_state);
        if now != last {
            match (last, now) {
                (Some(_), None) => {
                    tracing::warn!("wfp: VPN down — flushing driver flows");
                    bus.emit(EventKind::VpnDown, "wfp: VPN down, driver flows flushed".to_string());
                }
                (None, Some(t)) => {
                    tracing::info!("wfp: VPN up at {} — flushing stale flows", t.ipv4);
                    bus.emit(EventKind::VpnUp, format!("wfp: VPN up at {} (ifindex {})", t.ipv4, t.if_index));
                }
                (Some(a), Some(b)) if a != b => {
                    tracing::warn!("wfp: VPN changed {} -> {} — flushing flows", a.ipv4, b.ipv4);
                    bus.emit(EventKind::VpnChanged, format!("wfp: VPN moved {} -> {}, flows flushed", a.ipv4, b.ipv4));
                }
                _ => {}
            }
            // DeviceIoControl is blocking — never run it directly on a
            // tokio worker. Offload to the blocking pool.
            let flush_r = tokio::task::spawn_blocking(device::flush_flows).await;
            match flush_r {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!("wfp: FLUSH_FLOWS failed ({:#}) — continuing", e),
                Err(e) => tracing::warn!("wfp: flush join failed ({}) — continuing", e),
            }
            last = now;
        }
    }
}

/// Blocking wrapper for callers that are not on a runtime.
#[allow(dead_code)]
pub fn run(
    policy_state: PolicyState,
    flows: FlowTable,
    vpn_state: VpnState,
    bus: Arc<StatusBus>,
    resolver: Arc<Resolver>,
    tunneled_paths: TunneledPaths,
) -> Result<()> {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        return handle.block_on(run_async(
            policy_state,
            flows,
            vpn_state,
            bus,
            resolver,
            tunneled_paths,
        ));
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run_async(
        policy_state,
        flows,
        vpn_state,
        bus,
        resolver,
        tunneled_paths,
    ))
}
