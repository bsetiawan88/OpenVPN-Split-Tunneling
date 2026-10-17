use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Result;

use crate::adapter::{self, VpnTarget};
use crate::forward_table::{self, ForwardEntry};
use crate::status_server::StatusBus;
use ipc::status::EventKind;

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
    let mut ticks: u64 = 0;
    loop {
        ticks = ticks.wrapping_add(1);
        // enumerate() failing (or its thread panicking) used to exit the
        // whole process via main's select! with zero trace. Retry instead:
        // a fresh thread is spawned every tick, so nothing wedges.
        let adapters = match tokio::task::spawn_blocking(adapter::enumerate).await {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => {
                tracing::warn!("adapter enumerate failed ({:#}) — retrying", e);
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            Err(e) => {
                tracing::warn!("adapter enumerate task failed ({}) — retrying", e);
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        // Leaked def1 routes on a *down* VPN interface are orphaned by
        // definition (a down interface carries no legit traffic) and are
        // invisible to `route print`, so sweep them every tick. This is what
        // catches the leak before our adapter-up cleanup even runs — the
        // classic "openvpn connects, then dies with write UDP code=1232".
        sweep_orphan_def1_routes(&adapters, &bus).await;
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
                    bus.emit(
                        EventKind::VpnUp,
                        format!("VPN adapter up at {} (ifindex {})", t.ipv4, t.if_index),
                    );
                    // Stale full-tunnel leftovers (0.0.0.0/1 + 128.0.0.0/1
                    // from taskkill'd runs) would otherwise keep hijacking ALL
                    // traffic — including openvpn's own link socket — into a
                    // dead tunnel. Our split run installs no server /32 bypass
                    // (redirect was stripped), so those stale routes are pure
                    // poison here.
                    cleanup_stale_tunnel_routes(t, &bus).await;
                    last_gateway = ensure_split_tunnel_route(t).await;
                    bus.route_ok.store(
                        last_gateway.is_some(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    match last_gateway {
                        Some(gw) => bus.emit(
                            EventKind::RouteInstalled,
                            format!("split-tunnel route via {} installed", gw),
                        ),
                        None => {
                            bus.emit(
                                EventKind::RouteMissing,
                                format!(
                                    "split-tunnel route NOT installed for {} — tunneled apps have no path, retrying",
                                    t.ipv4
                                ),
                            );
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
                }
                (Some(old), None) => {
                    tracing::warn!("VPN adapter DOWN (was {})", old.ipv4);
                    bus.vpn_up_since_ms.store(0, Ordering::Relaxed);
                    bus.route_ok.store(true, std::sync::atomic::Ordering::Relaxed);
                    bus.emit(
                        EventKind::VpnDown,
                        format!("VPN adapter down (was {})", old.ipv4),
                    );
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
                    bus.emit(
                        EventKind::VpnChanged,
                        format!(
                            "VPN moved {} (ifindex {}) -> {} (ifindex {}), recycling tunneled flows",
                            old.ipv4, old.if_index, new.ipv4, new.if_index
                        ),
                    );
                    if let Some(gw) = last_gateway.take() {
                        remove_split_tunnel_route(gw, old.if_index).await;
                    }
                    cleanup_stale_tunnel_routes(new, &bus).await;
                    last_gateway = ensure_split_tunnel_route(new).await;
                    bus.route_ok.store(
                        last_gateway.is_some(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    match last_gateway {
                        Some(gw) => bus.emit(
                            EventKind::RouteInstalled,
                            format!("split-tunnel route via {} installed", gw),
                        ),
                        None => bus.emit(
                            EventKind::RouteMissing,
                            format!(
                                "split-tunnel route NOT installed for {} — tunneled apps have no path, retrying",
                                new.ipv4
                            ),
                        ),
                    }
                }
                _ => {}
            }
            *state.write().unwrap() = now;
            last = now;
        } else if let Some(t) = now {
            // Re-sweep while the tunnel is up, but only every ~10s:
            // resolve_gateway may read the openvpn log, which must not sit on
            // the 2s path. A def1 leak created after the up-transition cleanup
            // would otherwise hijack the freshly-built tunnel.
            if ticks % 5 == 0 {
                cleanup_stale_tunnel_routes(t, &bus).await;
            }

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
                let ok = last_gateway.is_some();
                bus.route_ok.store(ok, std::sync::atomic::Ordering::Relaxed);
                if ok {
                    bus.emit(
                        EventKind::RouteInstalled,
                        format!(
                            "split-tunnel route via {} installed (retry)",
                            last_gateway.unwrap()
                        ),
                    );
                }
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
    let mut gateway = resolve_gateway(target).await;

    if gateway.is_none() {
        // OpenVPN configures the address first and installs routes a moment
        // later (DHCP / pushed routes). Retry briefly before giving up.
        for attempt in 0..10 {
            if let Some(gw) = find_vpn_gateway(target.ipv4, target.if_index) {
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
    // API-based so a route on an already-down VPN interface is still
    // removable — `route.exe` cannot see such rows (same blindness as
    // `route print`), which used to leak our own 0.0.0.0/0 on teardown.
    let rows = match forward_table::list_v4() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("removing split-tunnel route: enumeration failed ({:#})", e);
            return;
        }
    };
    let ours = rows.iter().filter(|r| {
        r.dest.is_unspecified()
            && r.prefix_len == 0
            && r.if_index == ifindex
            && r.next_hop == gateway
    });
    for row in ours {
        match forward_table::delete(row) {
            Ok(()) => tracing::info!(
                "removed split-tunnel route: 0.0.0.0/0 via {} ifindex {}",
                gateway,
                ifindex
            ),
            Err(e) => tracing::warn!("removing split-tunnel route failed: {:#}", e),
        }
    }
}

/// Gateway resolution order:
///   1. adapter-reported gateway (when the driver exposes one),
///   2. `route-gateway` from the openvpn log's latest PUSH_REPLY
///      (provider-agnostic: works for topology-subnet setups like Proton
///      where the route table carries no usable next-hop in split mode),
///   3. `route print -4` probe (retried by the caller).
async fn resolve_gateway(target: VpnTarget) -> Option<Ipv4Addr> {
    if let Some(gw) = target.gateway {
        tracing::info!(
            "split-tunnel: using adapter-reported gateway {} for {}",
            gw, target.ipv4
        );
        return Some(gw);
    }
    if let Some(gw) = gateway_from_openvpn_log() {
        tracing::info!(
            "split-tunnel: using log route-gateway {} for {}",
            gw, target.ipv4
        );
        return Some(gw);
    }
    None
}

/// Latest `route-gateway <ip>` from the openvpn log tail. OpenVPN logs the
/// full PUSH_REPLY, so this reflects the live server's pushed topology even
/// when the Windows route table (split mode: redirect stripped) shows
/// nothing usable.
fn gateway_from_openvpn_log() -> Option<Ipv4Addr> {
    let Ok(local) = std::env::var("LOCALAPPDATA") else {
        return None;
    };
    let path = PathBuf::from(local)
        .join("VpnClient")
        .join("runtime")
        .join("openvpn.log");
    let bytes = std::fs::read(path).ok()?;
    const TAIL: usize = 64 * 1024;
    let start = bytes.len().saturating_sub(TAIL);
    let text = String::from_utf8_lossy(&bytes[start..]);

    // Last occurrence wins (latest PUSH_REPLY after rotates/reconnects).
    let mut found = None;
    for (i, _) in text.match_indices("route-gateway") {
        let rest = &text[i + "route-gateway".len()..];
        // Directive boundary: must be followed by space/tab (not e.g. a
        // longer option name that merely starts with the same words).
        if !rest.starts_with([' ', '\t']) {
            continue;
        }
        let token = rest
            .split([',', ' ', '\t', '\r', '\n'])
            .filter(|s| !s.is_empty())
            .next()
            .unwrap_or("")
            .trim_matches(|c| c == '"' || c == '\'');
        if let Ok(ip) = token.parse::<Ipv4Addr>() {
            found = Some(ip);
        }
    }
    found
}

/// Remove stale full-tunnel leftovers
/// (0.0.0.0/1 + 128.0.0.0/1) that crashed/killed runs leak. Those rows keep
/// hijacking ALL IPv4 — including openvpn's own link socket (hence the
/// post-handshake `write UDP ... code=1232` death) and every untunneled app —
/// into a dead tunnel, while our split run (redirect stripped) installs no
/// server /32 bypass that would save them.
///
/// Enumeration goes through the IP Helper API (see `forward_table`), NOT
/// `route print`: the netstat table omits rows on a down interface, which is
/// exactly where these leftovers sit while OpenVPN is idle. Only rows on our
/// VPN interface, or via our known gateway, are touched — a parallel
/// unrelated VPN on another interface is left alone.
///
/// PLUS: /32 rows via our VPN gateway. A server-bypass pointing INTO the
/// tunnel is circular by definition (openvpn never installs those; only
/// leaks/bugs create them) and kills the link socket the same way. Strict
/// gw-match only here — a public server is never legitimately on-link.
async fn cleanup_stale_tunnel_routes(target: VpnTarget, bus: &StatusBus) {
    let vpn_gw = resolve_gateway(target).await;
    let rows = match forward_table::list_v4() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("split cleanup: route enumeration failed ({:#})", e);
            return;
        }
    };
    let def1: Vec<&ForwardEntry> = rows
        .iter()
        .filter(|r| is_def1_row(r.dest, r.prefix_len))
        .collect();
    let circular: Vec<&ForwardEntry> = match vpn_gw {
        Some(gw) => rows
            .iter()
            .filter(|r| r.prefix_len == 32 && r.next_hop == gw)
            .collect(),
        None => Vec::new(),
    };
    if def1.is_empty() && circular.is_empty() {
        return;
    }
    let mut removed = 0;
    for row in def1 {
        // Guard the gw comparison: when our own gateway is unknown (None),
        // matching on it would hit ANY interface. Only touch rows on our VPN
        // interface, or rows via our known gateway.
        let ours =
            row.if_index == target.if_index || (vpn_gw.is_some() && Some(row.next_hop) == vpn_gw);
        if !ours {
            continue;
        }
        match forward_table::delete(row) {
            Ok(()) => {
                removed += 1;
                tracing::warn!(
                    "split cleanup: removed stale tunnel route {}/{} via {} (if{})",
                    row.dest,
                    row.prefix_len,
                    row.next_hop,
                    row.if_index
                );
            }
            Err(e) => tracing::info!(
                "split cleanup: delete {}/{} failed (may already be gone): {:#}",
                row.dest,
                row.prefix_len,
                e
            ),
        }
    }
    for row in circular {
        // Strict gateway match only: a /32 via OUR gateway is circular by
        // definition. No iface arm — a public server is never on-link.
        if Some(row.next_hop) != vpn_gw {
            continue;
        }
        match forward_table::delete(row) {
            Ok(()) => {
                removed += 1;
                tracing::warn!(
                    "split cleanup: removed circular host route {} via {}",
                    row.dest,
                    row.next_hop
                );
            }
            Err(e) => tracing::info!(
                "split cleanup: delete {} failed (may already be gone): {:#}",
                row.dest,
                e
            ),
        }
    }
    if removed > 0 {
        bus.emit(
            EventKind::SplitCleanup,
            format!(
                "split-tunnel cleanup: removed {} stale tunnel route(s)",
                removed
            ),
        );
    }
}

/// `redirect-gateway def1` installs exactly these two halves: 0.0.0.0/1 and
/// 128.0.0.0/1. Together they capture every IPv4 destination.
fn is_def1_row(dest: Ipv4Addr, prefix_len: u8) -> bool {
    prefix_len == 1 && (dest == Ipv4Addr::UNSPECIFIED || dest == Ipv4Addr::new(128, 0, 0, 0))
}

/// Sweep def1 leftovers on VPN-candidate interfaces that are currently DOWN.
/// A down interface carries no legitimate traffic, so any def1 row on it is an
/// orphan from a crashed/killed run — exactly the rows that hijack IPv4 and
/// kill OpenVPN's own link socket (`code=1232`) the moment it brings the
/// adapter up. Conservative by construction: candidate interfaces only, only
/// while down, only the def1 pair — our own split route (0.0.0.0/0) is never
/// touched.
async fn sweep_orphan_def1_routes(adapters: &[adapter::Adapter], bus: &StatusBus) {
    let down_vpn: std::collections::HashSet<u32> = adapters
        .iter()
        .filter(|a| a.is_vpn_candidate() && !a.is_up)
        .map(|a| a.if_index)
        .collect();
    if down_vpn.is_empty() {
        return;
    }
    let rows = match forward_table::list_v4() {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut removed = 0;
    for row in rows
        .iter()
        .filter(|r| is_def1_row(r.dest, r.prefix_len) && down_vpn.contains(&r.if_index))
    {
        match forward_table::delete(row) {
            Ok(()) => {
                removed += 1;
                tracing::warn!(
                    "split cleanup: removed orphan def1 route {}/{} via {} on down VPN if{}",
                    row.dest,
                    row.prefix_len,
                    row.next_hop,
                    row.if_index
                );
            }
            Err(e) => tracing::info!(
                "split cleanup: orphan delete {}/{} failed: {:#}",
                row.dest,
                row.prefix_len,
                e
            ),
        }
    }
    if removed > 0 {
        bus.emit(
            EventKind::SplitCleanup,
            format!(
                "split-tunnel cleanup: removed {} orphan tunnel route(s) on a down VPN interface",
                removed
            ),
        );
    }
}

/// Find the VPN's peer / next-hop: the gateway of a /32 route OpenVPN installs
/// on the VPN interface at handshake. Identified by interface INDEX (stable,
/// what the IP Helper API exposes) rather than the interface's IP column that
/// `route print` shows.
fn find_vpn_gateway(vpn_ip: Ipv4Addr, if_index: u32) -> Option<Ipv4Addr> {
    let rows = forward_table::list_v4().ok()?;
    for row in &rows {
        if row.if_index != if_index || row.prefix_len != 32 {
            continue;
        }
        if row.next_hop.is_unspecified() || row.next_hop == vpn_ip {
            continue;
        }
        return Some(row.next_hop);
    }
    None
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::is_def1_row;
    use std::net::Ipv4Addr;

    #[test]
    fn def1_pair_recognized() {
        assert!(is_def1_row(Ipv4Addr::UNSPECIFIED, 1));
        assert!(is_def1_row(Ipv4Addr::new(128, 0, 0, 0), 1));
        // Not the def1 magic: the default route (/0), a different /1, and the
        // pair at the wrong prefix length.
        assert!(!is_def1_row(Ipv4Addr::UNSPECIFIED, 0));
        assert!(!is_def1_row(Ipv4Addr::new(64, 0, 0, 0), 1));
        assert!(!is_def1_row(Ipv4Addr::new(128, 0, 0, 0), 2));
    }
}
