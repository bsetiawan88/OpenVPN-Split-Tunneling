//! Driver presence + IOCTL channel to \\.\VpnWfpCallout.
//!
//! CTL_CODE layout mirrors `driver/ioctl.h` exactly:
//!   CTL = (DeviceType<<16)|(Access<<14)|(Function<<2)|Method
//! with DeviceType=0x8001, Method=BUFFERED(0), Access=ANY(0).
//! Rust structs are #[repr(C)] with matching field order so the wire
//! format cannot drift. Unit test asserts the computed codes.

use std::os::windows::ffi::OsStrExt;
use std::process::Command;

pub const SERVICE_NAME: &str = "VpnWfpCallout";
pub const DOS_DEVICE: &str = r"\\.\VpnWfpCallout";
pub const BFE_SERVICE: &str = "BFE";

const FILE_DEVICE_VPN_WFP: u32 = 0x8001;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;

pub const IOCTL_QUERY_ORIGINAL_DST: u32 = ctl_code(FILE_DEVICE_VPN_WFP, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_SET_PID_ALLOWLIST: u32 = ctl_code(FILE_DEVICE_VPN_WFP, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_FLUSH_FLOWS: u32 = ctl_code(FILE_DEVICE_VPN_WFP, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_SET_REDIRECT_TARGET: u32 = ctl_code(FILE_DEVICE_VPN_WFP, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);

const fn ctl_code(device: u32, function: u32, method: u32, access: u32) -> u32 {
    (device << 16) | (access << 14) | (function << 2) | method
}

pub const MAX_PIDS_PER_PUSH: usize = 512;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RedirectTarget {
    pub loopback_ip_be: u32, // 0x0100007F
    pub loopback_port_host: u16,
    pub reserved: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OriginalDstQuery {
    pub local_ip_be: u32,
    pub local_port_host: u16,
    /// Low byte = IPPROTO (6 TCP / 17 UDP), 0 = wildcard (legacy).
    pub proto_reserved: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OriginalDstReply {
    pub dst_ip_be: u32,
    pub dst_port_host: u16,
    pub _pad: u16,
    pub pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverStatus {
    pub installed: bool,
    pub running: bool,
    pub bfe_running: bool,
    pub device_openable: bool,
}

fn query_service(name: &str) -> (bool, bool) {
    let out = Command::new("sc.exe").args(["query", name]).output();
    let Ok(out) = out else {
        return (false, false);
    };
    if !out.status.success() {
        let text = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        let upper = text.to_uppercase();
        if upper.contains("FAILED 1060") || upper.contains("DOES NOT EXIST") {
            return (false, false);
        }
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string()
        + &String::from_utf8_lossy(&out.stderr);
    let upper = text.to_uppercase();
    let installed = upper.contains("SERVICE_NAME");
    // Match the STATE line specifically ("STATE              : 4  RUNNING"),
    // not any stray "4" elsewhere.
    let running = upper.lines().any(|l| l.contains("STATE") && l.contains("RUNNING"))
        || upper.contains(" 4  RUNNING");
    (installed, running)
}

fn wide_path(path: &str) -> Vec<u16> {
    std::ffi::OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn open_handle() -> anyhow::Result<windows::Win32::Foundation::HANDLE> {
    use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::core::PCWSTR;
    let w = wide_path(DOS_DEVICE);
    let h = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            (GENERIC_READ | GENERIC_WRITE).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
    };
    match h {
        Ok(h) if h != INVALID_HANDLE_VALUE => Ok(h),
        _ => anyhow::bail!("open {} failed: {}", DOS_DEVICE, std::io::Error::last_os_error()),
    }
}

fn ioctl_raw(in_code: u32, input: &[u8], output: &mut [u8]) -> anyhow::Result<u32> {
    use windows::Win32::System::IO::DeviceIoControl;
    let h = open_handle()?;
    let mut returned: u32 = 0;
    let in_ptr = if input.is_empty() { None } else { Some(input.as_ptr() as *const _) };
    let out_ptr = if output.is_empty() {
        None
    } else {
        Some(output.as_mut_ptr() as *mut _)
    };
    let ok = unsafe {
        DeviceIoControl(
            h,
            in_code,
            in_ptr,
            input.len() as u32,
            out_ptr,
            output.len() as u32,
            Some(&mut returned),
            None,
        )
    };
    let _ = unsafe { windows::Win32::Foundation::CloseHandle(h) };
    ok.map_err(|e| anyhow::anyhow!("DeviceIoControl(0x{:08x}) failed: {}", in_code, e))?;
    Ok(returned)
}

fn probe_device() -> bool {
    open_handle().map(|h| {
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(h) };
        true
    }).unwrap_or(false)
}

pub fn status() -> DriverStatus {
    let (installed, running) = query_service(SERVICE_NAME);
    let (_, bfe_running) = query_service(BFE_SERVICE);
    DriverStatus {
        installed,
        running,
        bfe_running,
        device_openable: probe_device(),
    }
}

#[allow(dead_code)]
pub fn is_available() -> bool {
    let st = status();
    st.running && st.bfe_running
}

pub fn set_redirect_target(loopback_ip_be: u32, port_host: u16) -> anyhow::Result<()> {
    let req = RedirectTarget {
        loopback_ip_be,
        loopback_port_host: port_host,
        reserved: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&req as *const _ as *const u8, std::mem::size_of::<RedirectTarget>())
    };
    ioctl_raw(IOCTL_SET_REDIRECT_TARGET, bytes, &mut [])?;
    Ok(())
}

pub fn push_allowlist(pids: &[u32]) -> anyhow::Result<()> {
    if pids.len() > MAX_PIDS_PER_PUSH {
        anyhow::bail!("allowlist chunk {} exceeds {}", pids.len(), MAX_PIDS_PER_PUSH);
    }
    let mut buf = Vec::with_capacity(4 + pids.len() * 4);
    buf.extend_from_slice(&(pids.len() as u32).to_le_bytes());
    for pid in pids {
        buf.extend_from_slice(&pid.to_le_bytes());
    }
    ioctl_raw(IOCTL_SET_PID_ALLOWLIST, &buf, &mut [])?;
    Ok(())
}

pub fn flush_flows() -> anyhow::Result<()> {
    ioctl_raw(IOCTL_FLUSH_FLOWS, &[], &mut [])?;
    Ok(())
}

pub fn query_original_dst(local_port_host: u16, proto: u8) -> anyhow::Result<OriginalDstReply> {
    let q = OriginalDstQuery {
        local_ip_be: 0x0100007F,
        local_port_host,
        proto_reserved: proto as u16,
    };
    let qbytes = unsafe {
        std::slice::from_raw_parts(&q as *const _ as *const u8, std::mem::size_of::<OriginalDstQuery>())
    };
    let mut reply = OriginalDstReply { dst_ip_be: 0, dst_port_host: 0, _pad: 0, pid: 0 };
    let rbytes = unsafe {
        std::slice::from_raw_parts_mut(&mut reply as *mut _ as *mut u8, std::mem::size_of::<OriginalDstReply>())
    };
    let n = ioctl_raw(IOCTL_QUERY_ORIGINAL_DST, qbytes, rbytes)?;
    if n as usize != std::mem::size_of::<OriginalDstReply>() {
        anyhow::bail!("QUERY_ORIGINAL_DST short reply: {} bytes", n);
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ctl_codes_match_ioctl_h() {
        assert_eq!(IOCTL_QUERY_ORIGINAL_DST, 0x80012000);
        assert_eq!(IOCTL_SET_PID_ALLOWLIST, 0x80012004);
        assert_eq!(IOCTL_FLUSH_FLOWS, 0x80012008);
        assert_eq!(IOCTL_SET_REDIRECT_TARGET, 0x8001200C);
        assert_eq!(std::mem::size_of::<RedirectTarget>(), 8);
        assert_eq!(std::mem::size_of::<OriginalDstQuery>(), 8);
        assert_eq!(std::mem::size_of::<OriginalDstReply>(), 12);
    }
}
