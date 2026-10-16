use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Result;

use crate::adapter::{self, VpnTarget};
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
                    bus.emit(
                        EventKind::VpnUp,
                        format!("VPN adapter up at {} (ifindex {})", t.ipv4, t.if_index),
                    );
                    // Split mode only: stale full-tunnel leftovers (0.0.0.0/1
                    // + 128.0.0.0/1 from taskkill'd runs) would otherwise keep
                    // hijacking ALL traffic — including openvpn's own link
                    // socket — into a dead tunnel. Our split run installs no
                    // server /32 bypass (redirect was stripped), so those
                    // stale routes are pure poison here. Full mode skips this:
                    // openvpn manages its own pushed routes.
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

/// UI-selected tunnel mode, written by the UI on every openvpn start to
/// %LocalAppData%\VpnClient\runtime\mode.txt ("full" | "split").
/// Missing/unreadable (old UI, never started) defaults to full: never touch
/// another manager's routes unless split was explicitly requested.
fn split_mode() -> bool {
    let Ok(local) = std::env::var("LOCALAPPDATA") else {
        return false;
    };
    let path = PathBuf::from(local)
        .join("VpnClient")
        .join("runtime")
        .join("mode.txt");
    matches!(
        std::fs::read_to_string(path).map(|s| s.trim().to_lowercase()),
        Ok(s) if s == "split"
    )
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

/// Split mode only: remove stale full-tunnel leftovers
/// (0.0.0.0/128.0.0.0 + 128.0.0.0/128.0.0.0) that taskkill'd runs leak.
/// Those rows keep hijacking ALL IPv4 — including openvpn's own link
/// socket (hence post-handshake `write UDP ... code=1232` death) and every
/// untunneled app — into a dead tunnel, while our split run (redirect
/// stripped) installs no server /32 bypass that would save them.
/// Only rows via our VPN gateway or on our VPN interface are touched, so a
/// parallel unrelated VPN on another interface is left alone.
///
/// PLUS: /32 rows via our VPN gateway. A server-bypass pointing INTO the
/// tunnel is circular by definition (openvpn never installs those; only
/// leaks/bugs create them) and kills the link socket the same way. Strict
/// gw-match only here — a public server is never legitimately on-link, so
/// the iface arm is deliberately not applied to /32s.
async fn cleanup_stale_tunnel_routes(target: VpnTarget, bus: &StatusBus) {
    if !split_mode() {
        return;
    }
    let vpn_gw = resolve_gateway(target).await;
    let rows = list_tunnel_routes().await;
    let host_rows = list_circular_host_routes(vpn_gw).await;
    if rows.is_empty() && host_rows.is_empty() {
        return;
    }
    let vpn_ip = target.ipv4.to_string();
    let mut removed = 0;
    for (dest, _gw_str, gw, iface) in rows {
        // Guard the gw comparison: when our own gateway is unknown (None),
        // `None == None` would match ANY on-link row — including a parallel
        // unrelated VPN's. Only touch rows on our interface, or rows via our
        // known gateway.
        let ours = iface == vpn_ip || (vpn_gw.is_some() && gw == vpn_gw);
        if !ours {
            continue;
        }
        let mut args = vec![
            "DELETE".to_string(),
            dest.clone(),
            "MASK".to_string(),
            "128.0.0.0".to_string(),
        ];
        if let Some(g) = gw {
            args.push(g.to_string());
        } else {
            // On-link row (no gateway): scope by interface index.
            args.push("IF".to_string());
            args.push(target.if_index.to_string());
        }
        let output = tokio::process::Command::new("route.exe")
            .args(&args)
            .output()
            .await;
        match output {
            Ok(o) if o.status.success() => {
                removed += 1;
                tracing::warn!(
                    "split cleanup: removed stale tunnel route {} via {}",
                    dest,
                    gw.map(|g| g.to_string()).unwrap_or_else(|| iface.clone())
                );
            }
            Ok(o) => {
                tracing::info!(
                    "split cleanup: route DELETE {} failed (may already be gone): {}",
                    dest,
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
            Err(e) => {
                tracing::warn!("split cleanup: route.exe failed: {}", e);
                break;
            }
        }
    }
    for (dest, _gw_str, gw, _iface) in host_rows {
        // Strict gateway match only (guarded by is_some, same None==None
        // lesson as above): a /32 via OUR gateway is circular by
        // definition. No iface arm — a public server is never on-link.
        let ours = vpn_gw.is_some() && gw == vpn_gw;
        if !ours {
            continue;
        }
        let gw = gw.unwrap();
        let output = tokio::process::Command::new("route.exe")
            .args([
                "DELETE",
                &dest,
                "MASK",
                "255.255.255.255",
                &gw.to_string(),
            ])
            .output()
            .await;
        match output {
            Ok(o) if o.status.success() => {
                removed += 1;
                tracing::warn!(
                    "split cleanup: removed circular host route {} via {}",
                    dest, gw
                );
            }
            Ok(o) => {
                tracing::info!(
                    "split cleanup: route DELETE {} failed (may already be gone): {}",
                    dest,
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
            Err(e) => {
                tracing::warn!("split cleanup: route.exe failed: {}", e);
                break;
            }
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

/// All (dest, gateway-str, gateway, interface-str) rows for the two
/// full-tunnel def1 destinations from `route print -4`.
async fn list_tunnel_routes() -> Vec<(String, String, Option<Ipv4Addr>, String)> {    let mut out = Vec::new();
    let Ok(output) = tokio::process::Command::new("route.exe")
        .args(["print", "-4"])
        .output()
        .await
    else {
        return out;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        // Layout: Network Destination, Netmask, Gateway, Interface, Metric
        let is_def1 = (parts[0] == "0.0.0.0" || parts[0] == "128.0.0.0")
            && parts[1] == "128.0.0.0";
        if !is_def1 {
            continue;
        }
        let gw = parts[2].parse::<Ipv4Addr>().ok();
        out.push((
            parts[0].to_string(),
            parts[2].to_string(),
            gw,
            parts[3].to_string(),
        ));
    }
    out
}
/// /32 host rows whose gateway is our VPN gateway: server traffic pointed
/// INTO the tunnel (circular — the link socket dies with 1232). OpenVPN
/// never installs these (its server bypass always points at the LAN
/// gateway); only leaks/bugs create them. Pre-filtered by gateway here;
/// the caller re-applies the strict is_some gw-match guard.
async fn list_circular_host_routes(
    vpn_gw: Option<Ipv4Addr>,
) -> Vec<(String, String, Option<Ipv4Addr>, String)> {
    let mut out = Vec::new();
    let Some(want) = vpn_gw else {
        return out;
    };
    let Ok(output) = tokio::process::Command::new("route.exe")
        .args(["print", "-4"])
        .output()
        .await
    else {
        return out;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        // Layout: Network Destination, Netmask, Gateway, Interface, Metric
        if parts[1] != "255.255.255.255" {
            continue;
        }
        if parts[2].parse::<Ipv4Addr>().ok() != Some(want) {
            continue;
        }
        out.push((
            parts[0].to_string(),
            parts[2].to_string(),
            Some(want),
            parts[3].to_string(),
        ));
    }
    out
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
