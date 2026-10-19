use std::net::Ipv4Addr;

use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::AF_INET;

/// Lingering TCP states. A row in one of these can share (local port, remote)
/// with the live connection that replaced it, and its owning PID is 0 or
/// System — matching it is what turned most of the traffic into "pid4".
const MIB_TCP_STATE_TIME_WAIT: u32 = 11;
const MIB_TCP_STATE_DELETE_TCB: u32 = 12;

/// Synchronous fallback when the observer-populated flow table hasn't caught
/// up with a fresh socket yet. Hits the Windows IP helper to find the PID
/// that owns (proto, local_addr, local_port[, remote]).
///
/// `remote` is the packet's destination. TCP rows carry the full 4-tuple, so
/// an exact match is possible; the previous port-only scan returned the first
/// row that shared a local port, which is frequently an unrelated System row.
///
/// Cost: ~hundreds of microseconds. We only call it on first-packet misses,
/// because the second the flow lands in the policy, every subsequent packet
/// from that PID takes the fast path.
pub fn pid_for_local_v4(
    local_addr: Ipv4Addr,
    local_port: u16,
    proto: u8,
    remote: Option<(Ipv4Addr, u16)>,
) -> Option<u32> {
    match proto {
        6 => pid_for_tcp_v4(local_addr, local_port, remote),
        17 => pid_for_udp_v4(local_addr, local_port),
        _ => None,
    }
}

fn pid_for_tcp_v4(
    local_addr: Ipv4Addr,
    local_port: u16,
    remote: Option<(Ipv4Addr, u16)>,
) -> Option<u32> {
    let buf = tcp_table()?;
    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;
    if count == 0 {
        return None;
    }
    let rows: &[MIB_TCPROW_OWNER_PID] =
        unsafe { std::slice::from_raw_parts(table.table.as_ptr(), count) };
    pick_tcp(rows, local_addr, local_port, remote)
}

/// Row-selection policy, split out of the table fetch so it can be tested
/// against synthetic rows instead of the live socket table.
fn pick_tcp(
    rows: &[MIB_TCPROW_OWNER_PID],
    local_addr: Ipv4Addr,
    local_port: u16,
    remote: Option<(Ipv4Addr, u16)>,
) -> Option<u32> {
    let want_local = u32::from(local_addr).to_be();

    // Pass 1 — exact 4-tuple, ignoring lingering states. Only this pass can
    // tell two sockets that share a local port apart.
    if let Some((remote_addr, remote_port)) = remote {
        let want_remote = u32::from(remote_addr).to_be();
        let found = rows.iter().find_map(|row| {
            if row.dwState == MIB_TCP_STATE_TIME_WAIT || row.dwState == MIB_TCP_STATE_DELETE_TCB {
                return None;
            }
            if port_from_dword(row.dwLocalPort) != local_port {
                return None;
            }
            if port_from_dword(row.dwRemotePort) != remote_port || row.dwRemoteAddr != want_remote {
                return None;
            }
            if row.dwLocalAddr != 0 && row.dwLocalAddr != want_local {
                return None;
            }
            pid_of(row.dwOwningPid)
        });
        if found.is_some() {
            return found;
        }
    }

    // Pass 2 — same local address, any remote: covers sockets whose remote the
    // table hasn't filled in yet (e.g. mid-handshake).
    let found = rows.iter().find_map(|row| {
        if port_from_dword(row.dwLocalPort) != local_port || row.dwLocalAddr != want_local {
            return None;
        }
        pid_of(row.dwOwningPid)
    });
    if found.is_some() {
        return found;
    }

    // Pass 3 — wildcard bind (0.0.0.0). Deliberately last: a wildcard row is
    // the least specific match and must never shadow a concrete one.
    rows.iter().find_map(|row| {
        if port_from_dword(row.dwLocalPort) != local_port || row.dwLocalAddr != 0 {
            return None;
        }
        pid_of(row.dwOwningPid)
    })
}

fn pid_for_udp_v4(local_addr: Ipv4Addr, local_port: u16) -> Option<u32> {
    let buf = udp_table()?;
    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;
    if count == 0 {
        return None;
    }
    let rows: &[MIB_UDPROW_OWNER_PID] =
        unsafe { std::slice::from_raw_parts(table.table.as_ptr(), count) };
    pick_udp(rows, local_addr, local_port)
}

/// Row-selection policy for UDP. UDP rows carry no remote, so the ordering is
/// concrete local address first, wildcard bind last.
fn pick_udp(rows: &[MIB_UDPROW_OWNER_PID], local_addr: Ipv4Addr, local_port: u16) -> Option<u32> {
    let want_local = u32::from(local_addr).to_be();

    // Exact local address first; UDP rows carry no remote, so a wildcard bind
    // is the only other possibility and must not shadow a concrete bind.
    let found = rows.iter().find_map(|row| {
        if port_from_dword(row.dwLocalPort) != local_port || row.dwLocalAddr != want_local {
            return None;
        }
        pid_of(row.dwOwningPid)
    });
    if found.is_some() {
        return found;
    }
    rows.iter().find_map(|row| {
        if port_from_dword(row.dwLocalPort) != local_port || row.dwLocalAddr != 0 {
            return None;
        }
        pid_of(row.dwOwningPid)
    })
}

/// PID 0 means "no owner recorded" (closed/lingering sockets), not a real
/// owner; returning it would let an unowned row shadow a live one.
fn pid_of(pid: u32) -> Option<u32> {
    if pid == 0 {
        None
    } else {
        Some(pid)
    }
}

fn tcp_table() -> Option<Vec<u8>> {
    let mut size: u32 = 0;
    unsafe {
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if rc != NO_ERROR.0 {
        return None;
    }
    Some(buf)
}

fn udp_table() -> Option<Vec<u8>> {
    let mut size: u32 = 0;
    unsafe {
        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if rc != NO_ERROR.0 {
        return None;
    }
    Some(buf)
}

/// dwLocalPort/dwRemotePort are DWORDs whose low 16 bits hold the port in
/// network byte order. Mask + byte-swap to get the host-order port.
fn port_from_dword(d: u32) -> u16 {
    u16::from_be((d & 0xFFFF) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ESTABLISHED: u32 = 5;
    const ME: Ipv4Addr = Ipv4Addr::new(192, 168, 68, 10);
    const PEER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 77);

    fn dword_port(port: u16) -> u32 {
        (port.to_be() as u32) & 0xFFFF
    }

    fn dword_addr(addr: Ipv4Addr) -> u32 {
        u32::from(addr).to_be()
    }

    fn tcp_row(
        state: u32,
        local_addr: Ipv4Addr,
        local_port: u16,
        remote_addr: Ipv4Addr,
        remote_port: u16,
        pid: u32,
    ) -> MIB_TCPROW_OWNER_PID {
        MIB_TCPROW_OWNER_PID {
            dwState: state,
            dwLocalAddr: dword_addr(local_addr),
            dwLocalPort: dword_port(local_port),
            dwRemoteAddr: dword_addr(remote_addr),
            dwRemotePort: dword_port(remote_port),
            dwOwningPid: pid,
        }
    }

    fn udp_row(local_addr: Ipv4Addr, local_port: u16, pid: u32) -> MIB_UDPROW_OWNER_PID {
        MIB_UDPROW_OWNER_PID {
            dwLocalAddr: dword_addr(local_addr),
            dwLocalPort: dword_port(local_port),
            dwOwningPid: pid,
        }
    }

    /// The misattribution this pins: a System row that merely shares the local
    /// port used to win, because the old scan returned the first port match.
    #[test]
    fn tcp_exact_four_tuple_beats_shared_port_row() {
        let rows = vec![
            tcp_row(ESTABLISHED, ME, 50000, Ipv4Addr::new(203, 0, 113, 9), 443, 4),
            tcp_row(ESTABLISHED, ME, 50000, PEER, 8080, 1234),
        ];
        assert_eq!(pick_tcp(&rows, ME, 50000, Some((PEER, 8080))), Some(1234));
    }

    #[test]
    fn tcp_time_wait_row_never_wins_the_exact_pass() {
        let rows = vec![
            tcp_row(MIB_TCP_STATE_TIME_WAIT, ME, 50000, PEER, 8080, 4),
            tcp_row(ESTABLISHED, ME, 50000, PEER, 8080, 4321),
        ];
        assert_eq!(pick_tcp(&rows, ME, 50000, Some((PEER, 8080))), Some(4321));
    }

    #[test]
    fn tcp_concrete_bind_beats_wildcard_bind() {
        let rows = vec![
            tcp_row(ESTABLISHED, Ipv4Addr::UNSPECIFIED, 50000, Ipv4Addr::UNSPECIFIED, 0, 4),
            tcp_row(ESTABLISHED, ME, 50000, PEER, 8080, 4321),
        ];
        assert_eq!(pick_tcp(&rows, ME, 50000, None), Some(4321));
    }

    #[test]
    fn tcp_pid_zero_is_not_an_owner() {
        let rows = vec![tcp_row(ESTABLISHED, ME, 50000, Ipv4Addr::UNSPECIFIED, 0, 0)];
        assert_eq!(pick_tcp(&rows, ME, 50000, None), None);
    }

    #[test]
    fn udp_concrete_bind_beats_wildcard_bind() {
        let rows = vec![udp_row(Ipv4Addr::UNSPECIFIED, 54321, 4), udp_row(ME, 54321, 7777)];
        assert_eq!(pick_udp(&rows, ME, 54321), Some(7777));
    }

    #[test]
    fn port_encoding_roundtrips() {
        for port in [53u16, 443, 50000, 65535] {
            assert_eq!(port_from_dword(dword_port(port)), port);
        }
    }
}
