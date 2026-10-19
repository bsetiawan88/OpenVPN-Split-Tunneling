//! IPv4 route-table access through the IP Helper API (`GetIpForwardTable2`).
//!
//! Why not parse `route print -4`: the netstat-style table **omits routes
//! whose interface is currently down**. Leaked `redirect-gateway def1` routes
//! (0.0.0.0/1 + 128.0.0.0/1) sit on the VPN's DCO/TAP interface while OpenVPN
//! is not running — invisible to `route print`, yet they hijack all IPv4 the
//! instant OpenVPN brings the adapter up, killing openvpn's own link socket
//! (`write UDP ... code=1232`). `GetIpForwardTable2` returns the whole store
//! regardless of link state, so split-tunnel cleanup can actually see (and
//! remove) them.
//!
//! `DeleteIpForwardEntry2` is used for removal: it matches on the full row,
//! which is exactly what we hand back from a `list_v4` snapshot, and — unlike
//! `route.exe` — it reaches rows on a down interface.

use std::net::Ipv4Addr;

use anyhow::{bail, Result};
use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2,
};
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};

/// One IPv4 route row. The raw helper row is retained so [`delete`] can hand
/// the exact entry back to `DeleteIpForwardEntry2` (dest + prefix, next-hop,
/// interface and protocol all have to match).
#[derive(Clone, Copy)]
pub struct ForwardEntry {
    pub dest: Ipv4Addr,
    pub prefix_len: u8,
    pub next_hop: Ipv4Addr,
    pub if_index: u32,
    raw: MIB_IPFORWARD_ROW2,
}

/// A snapshot of every IPv4 route in the active store, including rows on
/// interfaces that are currently down.
pub fn list_v4() -> Result<Vec<ForwardEntry>> {
    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        let rc = GetIpForwardTable2(AF_INET, &mut table);
        if rc != NO_ERROR {
            bail!("GetIpForwardTable2 failed: 0x{:08x}", rc.0);
        }
        if table.is_null() {
            bail!("GetIpForwardTable2 returned a null table");
        }
        // Table is a header followed by `NumEntries` rows.
        let count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        let mut out = Vec::with_capacity(count);
        for row in rows {
            let (Some(dest), Some(next_hop)) = (
                sockaddr_v4(&row.DestinationPrefix.Prefix),
                sockaddr_v4(&row.NextHop),
            ) else {
                continue; // ignore IPv6-in-v4-table oddities
            };
            out.push(ForwardEntry {
                dest,
                prefix_len: row.DestinationPrefix.PrefixLength,
                next_hop,
                if_index: row.InterfaceIndex,
                raw: *row,
            });
        }
        FreeMibTable(table as *const core::ffi::c_void);
        Ok(out)
    }
}

/// Remove one row from the active store. Requires elevation — same privilege
/// the split-tunnel route management already needs for `route.exe` ADD.
pub fn delete(entry: &ForwardEntry) -> Result<()> {
    unsafe {
        let rc = DeleteIpForwardEntry2(&entry.raw);
        if rc != NO_ERROR {
            bail!(
                "DeleteIpForwardEntry2({}/{} via {} if{}) failed: 0x{:08x}",
                entry.dest,
                entry.prefix_len,
                entry.next_hop,
                entry.if_index,
                rc.0
            );
        }
    }
    Ok(())
}

fn sockaddr_v4(sa: &SOCKADDR_INET) -> Option<Ipv4Addr> {
    unsafe {
        if sa.si_family != AF_INET {
            return None;
        }
        // S_addr is network byte order; to_ne_bytes reproduces the bytes.
        let raw = sa.Ipv4.sin_addr.S_un.S_addr;
        Some(Ipv4Addr::from(raw.to_ne_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::list_v4;

    #[test]
    fn list_v4_enumerates_live_table() {
        // Exercises the real GetIpForwardTable2 path (no elevation needed to
        // read). Any Windows stack has at least the loopback routes, so a
        // non-empty result proves the snapshot works — the previous
        // `route print` parsing had no such direct check.
        let rows = list_v4().expect("GetIpForwardTable2 should succeed");
        assert!(!rows.is_empty(), "route snapshot was empty");
    }
}
