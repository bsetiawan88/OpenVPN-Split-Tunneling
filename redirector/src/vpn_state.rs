use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Result;

use crate::adapter::{self, VpnTarget};
use crate::status_server::StatusBus;

pub type VpnState = Arc<RwLock<Option<VpnTarget>>>;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

pub fn new() -> VpnState {
    Arc::new(RwLock::new(None))
}

pub fn current(state: &VpnState) -> Option<VpnTarget> {
    *state.read().unwrap()
}

pub async fn watcher(state: VpnState, bus: Arc<StatusBus>) -> Result<()> {
    let mut last: Option<VpnTarget> = None;
    let mut last_gateway: Option<Ipv4Addr> = None;
    loop {
        let adapters = tokio::task::spawn_blocking(adapter::enumerate).await??;
        let now = adapter::find_vpn_target(&adapters);
        let same = match (last, now) {
            (Some(a), Some(b)) => {
                a.ipv4 == b.ipv4 && a.if_index == b.if_index && a.gateway == b.gateway
            }
            (None, None) => true,
            _ => false,
        };
        if !same {
            match (last, now) {
                (None, Some(t)) => {
                    tracing::info!("VPN adapter UP at {} (ifindex {})", t.ipv4, t.if_index);
                    bus.vpn_up_since_ms.store(unix_millis(), Ordering::Relaxed);
                    last_gateway = ensure_split_tunnel_route(t).await;
                    bus.route_ok.store(
                        last_gateway.is_some(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    if last_gateway.is_none() {
                        // No route installed — tunneled bridges would fail with
                        // "network unreachable". Keep the VPN marked up (the
                        // adapter IS up) but flag route_ok=false so the UI
                        // shows amber instead of green. Retried below while
                        // the adapter stays up.
                        tracing::error!(
                            "split-tunnel route NOT installed for {} — tunneled apps will have no connectivity until the route is in place",
                            t.ipv4
                        );
                    }
                }
                (Some(old), None) => {
                    tracing::warn!("VPN adapter DOWN (was {})", old.ipv4);
                    bus.vpn_up_since_ms.store(0, Ordering::Relaxed);
                    bus.route_ok.store(true, std::sync::atomic::Ordering::Relaxed);
                    if let Some(gw) = last_gateway.take() {
                        remove_split_tunnel_route(gw, old.if_index).await;
                    }
                }
                (Some(old), Some(new)) => {
                    tracing::info!(
                        "VPN adapter changed: {} (ifindex {}) -> {} (ifindex {})",
                        old.ipv4, old.if_index, new.ipv4, new.if_index
                    );
                    bus.vpn_up_since_ms.store(unix_millis(), Ordering::Relaxed);
                    if let Some(gw) = last_gateway.take() {
                        remove_split_tunnel_route(gw, old.if_index).await;
                    }
                    last_gateway = ensure_split_tunnel_route(new).await;
                    bus.route_ok.store(
                        last_gateway.is_some(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
                _ => {}
            }
            *state.write().unwrap() = now;
            last = now;
        } else if let Some(t) = now {
            // Adapter steady but route missing (earlier ADD failed) — retry
            // the install instead of leaving the tunnel half-built forever.
            // No backoff beyond the 2s poll: route.exe is cheap and the
            // failure is usually a transient race with OpenVPN's own routes.
            if last_gateway.is_none() {
                tracing::info!(
                    "split-tunnel route still missing for {} — retrying install",
                    t.ipv4
                );
                last_gateway = ensure_split_tunnel_route(t).await;
                bus.route_ok.store(
                    last_gateway.is_some(),
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Adds a high-metric `0.0.0.0/0` route via the VPN gateway, pinned to the VPN
/// interface. Normal apps still prefer the Ethernet default route (lower
/// metric), but sockets pinned with IP_UNICAST_IF on the VPN's ifindex now
/// have a valid next-hop and the kernel routes them through the tunnel.
///
/// Gateway resolution order:
///   1. adapter-reported gateway (wintun exposes the peer here),
///   2. `route print -4` probe for a /32 whose Interface is the VPN IP
///      (retried — OpenVPN brings the address up before its routes),
///   3. the VPN IP itself (point-to-point TAP/wintun accepts the interface
///      address as an on-link next-hop).
///
/// Step 3 is the fix for "connected but no app has connectivity": previously
/// a missing gateway meant NO route was installed and every tunneled
/// connect() failed with network-unreachable.
async fn ensure_split_tunnel_route(target: VpnTarget) -> Option<Ipv4Addr> {
    let mut gateway = target.gateway;

    if gateway.is_none() {
        // OpenVPN configures the address first and installs routes a moment
        // later (DHCP / pushed routes). Retry briefly before giving up.
        for attempt in 0..10 {
            if let Some(gw) = find_vpn_gateway(target.ipv4).await {
                gateway = Some(gw);
                break;
            }
            if attempt == 0 {
                tracing::info!(
                    "split-tunnel: no gateway yet for {} — waiting for OpenVPN routes…",
                    target.ipv4
                );
            }
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    } else {
        tracing::info!(
            "split-tunnel: using adapter-reported gateway {} for {}",
            gateway.unwrap(),
            target.ipv4
        );
    }

    let gateway = gateway.unwrap_or_else(|| {
        tracing::warn!(
            "split-tunnel: no gateway discovered for {} — falling back to interface address as on-link next-hop",
            target.ipv4
        );
        target.ipv4
    });

    tracing::info!(
        "adding split-tunnel route: 0.0.0.0/0 via {} ifindex {} metric 9999",
        gateway, target.if_index
    );
    let output = tokio::process::Command::new("route.exe")
        .args([
            "ADD", "0.0.0.0", "MASK", "0.0.0.0",
            &gateway.to_string(),
            "METRIC", "9999",
            "IF", &target.if_index.to_string(),
        ])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Idempotent install: our own route from a previous run (unclean
        // teardown, redirector restart) makes ADD fail with "already
        // exists" — that means the path IS in place, not that it failed.
        if stdout.to_lowercase().contains("already")
            || stderr.to_lowercase().contains("already")
        {
            tracing::info!(
                "split-tunnel route already present via {} — treating as installed",
                gateway
            );
            return Some(gateway);
        }
        // Report failure as None so the watcher marks the route missing and
        // keeps the error visible — returning Some here used to mask a dead
        // tunnel behind a green "VPN connected" header.
        tracing::error!(
            "route ADD failed (gateway={} ifindex={}): stdout={} stderr={}",
            gateway,
            target.if_index,
            stdout,
            stderr
        );
        return None;
    }
    Some(gateway)
}

async fn remove_split_tunnel_route(gateway: Ipv4Addr, ifindex: u32) {
    tracing::info!("removing split-tunnel route: 0.0.0.0/0 via {}", gateway);
    let _ = tokio::process::Command::new("route.exe")
        .args([
            "DELETE",
            "0.0.0.0",
            "MASK",
            "0.0.0.0",
            &gateway.to_string(),
            "IF",
            &ifindex.to_string(),
        ])
        .output()
        .await;
}

/// Find the VPN's peer / next-hop by scanning `route print -4` for a /32 route
/// whose Interface column equals the VPN adapter's IP. The Gateway column on
/// that row is the next-hop OpenVPN installed at handshake time.
async fn find_vpn_gateway(vpn_ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let output = tokio::process::Command::new("route.exe")
        .args(["print", "-4"])
        .output()
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let vpn_ip_str = vpn_ip.to_string();

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        // Layout: Network Destination, Netmask, Gateway, Interface, Metric
        if parts[1] != "255.255.255.255" {
            continue;
        }
        if parts[3] != vpn_ip_str {
            continue;
        }
        if let Ok(gw) = parts[2].parse::<Ipv4Addr>() {
            if !gw.is_unspecified() && gw != vpn_ip {
                return Some(gw);
            }
        }
    }
    None
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
