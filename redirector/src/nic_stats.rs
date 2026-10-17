//! Per-adapter byte counters from the IP Helper API (GetIfTable2), sampled
//! every 5s and logged alongside the divert report. The bridge's own
//! counters say what the LOOP carried; these say what the ADAPTERS moved —
//! so a speedtest can be attributed (VPN vs LAN) without external tools, and
//! "traffic bypassing the bridge" becomes visible as NIC bytes with no
//! matching loop counters.

use std::collections::HashMap;
use std::time::Duration;

use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;

/// Sample cadence, aligned with the divert 5s report.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
/// IF_TYPE_SOFTWARE_LOOPBACK — loopback bytes never reach the wire and would
/// only double-count the bridge's own relay traffic.
const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

/// Detached sampler thread; first line appears on the second tick (the first
/// only fills the delta baseline).
pub fn spawn() {
    let _ = std::thread::Builder::new()
        .name("nic-stats".into())
        .spawn(run);
}

fn run() {
    let mut prev: HashMap<String, (u64, u64)> = HashMap::new();
    loop {
        std::thread::sleep(SAMPLE_INTERVAL);
        let rows = sample();
        if rows.is_empty() {
            continue; // transient API failure — try again next window
        }
        let mut parts = Vec::new();
        for (alias, rx, tx) in &rows {
            if let Some((prx, ptx)) = prev.get(alias) {
                let drx = rx.saturating_sub(*prx);
                let dtx = tx.saturating_sub(*ptx);
                if drx == 0 && dtx == 0 {
                    continue; // idle interface: not worth a log slot
                }
                parts.push(format!(
                    "{} down={:.2} up={:.2} Mbps",
                    alias,
                    drx as f64 * 8.0 / SAMPLE_INTERVAL.as_secs_f64() / 1_000_000.0,
                    dtx as f64 * 8.0 / SAMPLE_INTERVAL.as_secs_f64() / 1_000_000.0,
                ));
            }
        }
        prev = rows.into_iter().map(|(a, r, t)| (a, (r, t))).collect();
        if !parts.is_empty() {
            tracing::info!("nic 5s: {}", parts.join(" | "));
        }
    }
}

fn sample() -> Vec<(String, u64, u64)> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    let rc = unsafe { GetIfTable2(&mut table) };
    if rc.0 != 0 || table.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    unsafe {
        let n = (*table).NumEntries as usize;
        // The struct declares `Table: [MIB_IF_ROW2; 1]`, but the allocation
        // holds NumEntries consecutive rows (standard Win32 idiom: index a
        // raw slice from the first element with the real length).
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
        for row in rows {
            if row.OperStatus != IfOperStatusUp || row.Type == IF_TYPE_SOFTWARE_LOOPBACK {
                continue;
            }
            let alias = decode_alias(&row.Alias);
            if alias.is_empty() {
                continue;
            }
            out.push((alias, row.InOctets, row.OutOctets));
        }
        FreeMibTable(table as *const core::ffi::c_void);
    }
    out
}

/// Alias is a fixed 257-wide NUL-terminated UTF-16 buffer.
fn decode_alias(alias: &[u16; 257]) -> String {
    let len = alias.iter().position(|&c| c == 0).unwrap_or(alias.len());
    String::from_utf16_lossy(&alias[..len])
}
