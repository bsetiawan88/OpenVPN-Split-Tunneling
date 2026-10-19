//! Passive HTTP request log for tunneled apps (non-MITM).
//!
//! Sniffs the first app→remote chunk of each tunneled TCP flow:
//!   - plaintext HTTP  → `METHOD host/path -> dst`
//!   - TLS ClientHello → `TLS SNI -> dst` (no decrypt, no cert games)
//!   - anything else   → ignored (keeps http.log clean)
//!
//! File-only, like activity.log: `%LocalAppData%\VpnClient\runtime\http.log`.
//! Gated by sentinel `%AppData%\VpnClient\http-log.flag` (mirrors the
//! `verbose.flag` pattern): checkbox ON creates it, OFF deletes it.
//! Called once per flow — one filesystem check per TCP connection is fine.

use std::net::SocketAddr;
use std::path::PathBuf;

const HTTP_LOG_MAX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SNIFF: usize = 8 * 1024;

/// Sentinel created/deleted by the UI checkbox.
pub fn is_enabled() -> bool {
    std::env::var("APPDATA")
        .ok()
        .map(|a| PathBuf::from(a).join("VpnClient").join("http-log.flag"))
        .map(|p| p.exists())
        .unwrap_or(false)
}

fn http_log_path() -> Option<PathBuf> {
    let local = std::env::var("LOCALAPPDATA").ok()?;
    Some(
        PathBuf::from(local)
            .join("VpnClient")
            .join("runtime")
            .join("http.log"),
    )
}

fn local_timestamp() -> String {
    let st = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds
    )
}

fn oneline(s: &str) -> String {
    const MAX: usize = 512;
    let mut o: String = s
        .replace("\r\n", " | ")
        .replace('\n', " | ")
        .replace('\r', " | ");
    if o.len() > MAX {
        o.truncate(MAX);
        o.push('…');
    }
    o
}

/// Entry point: call once with the FIRST app→remote bytes of a flow.
/// No-op when disabled, empty, or unrecognized. Never throws, never blocks
/// the hot path beyond one small file append.
pub fn maybe_log(pid: u32, exe: &str, dst: &SocketAddr, data: &[u8]) {
    if !is_enabled() {
        return;
    }
    if data.is_empty() {
        return;
    }
    let buf = if data.len() > MAX_SNIFF {
        &data[..MAX_SNIFF]
    } else {
        data
    };
    if let Some((method, host, target)) = try_parse_http(buf) {
        let dest = if host.is_empty() {
            target
        } else if target.starts_with("http://") || target.starts_with("https://") {
            target
        } else {
            format!("{}{}", host, target)
        };
        append_line(&format!(
            "HTTP {} \"{}\" (pid {}) -> {} via {}",
            method, dest, pid, dst, exe
        ));
    } else if let Some(sni) = try_parse_sni(buf) {
        append_line(&format!(
            "TLS {} (pid {}) -> {} SNI={} via {}",
            "ClientHello", pid, dst, sni, exe
        ));
    }
    // else: opaque binary — skip silently.
}

/// `METHOD SP target SP HTTP/x.y` on the first line + `Host:` header.
/// Returns (method, host, target). Host may be empty (HTTP/1.0 without it).
pub fn try_parse_http(buf: &[u8]) -> Option<(String, String, String)> {
    const METHODS: &[&str] = &[
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
    ];
    // Header block ends at \r\n\r\n (or \n\n); request-line at first \n.
    // Bound the scan so a 8KB binary blob can't burn cycles.
    let head_end = find_headers_end(buf)?;
    let head = std::str::from_utf8(&buf[..head_end]).ok()?;
    let mut lines = head.split('\n');
    let req_line = lines.next()?.trim_end_matches('\r').trim();
    let mut parts = req_line.split_whitespace();
    let method = parts.next()?;
    if !METHODS.contains(&method) {
        return None;
    }
    let target = parts.next()?.to_string();
    let proto = parts.next().unwrap_or("");
    if !proto.starts_with("HTTP/") {
        return None;
    }
    if target.len() > 2048 {
        return None;
    }
    let mut host = String::new();
    for line in lines {
        let l = line.trim_end_matches('\r');
        if l.len() > 6 && l.as_bytes()[4] == b':' {
            let (name, val) = l.split_at(5);
            if name.eq_ignore_ascii_case("Host:") {
                host = val.trim().to_string();
                break;
            }
        } else if l.len() > 5 && l.as_bytes()[4] == b':' {
            // "Host:" is 5 chars; guard the short-header path too.
            let (name, val) = l.split_at(5);
            if name.eq_ignore_ascii_case("Host:") {
                host = val.trim().to_string();
                break;
            }
        }
    }
    // Strip port from Host for readability? No — keep as-sent (debug value).
    Some((method.to_string(), host, target))
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    let limit = buf.len().min(MAX_SNIFF);
    // Look for \r\n\r\n first, then \n\n (lenient servers/clients).
    if let Some(i) = memchr2(&buf[..limit], b"\r\n\r\n") {
        return Some(i);
    }
    if let Some(i) = memchr2(&buf[..limit], b"\n\n") {
        return Some(i);
    }
    // No header terminator yet (first chunk only) — still try the first
    // line + available headers so short GETs log without waiting.
    // Require at least one newline to avoid matching random binary.
    let first_nl = buf[..limit].iter().position(|&b| b == b'\n')?;
    Some(first_nl + 1)
}

fn memchr2(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + needle.len())
}

/// Minimal TLS ClientHello SNI extractor. Validates just enough structure
/// (record 0x16, handshake 0x01, SNI extension 0x0000) to avoid false
/// positives on binary protocols.
pub fn try_parse_sni(buf: &[u8]) -> Option<String> {
    // TLS record: type(1) ver(2) len(2) — must be handshake.
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if rec_len == 0 || rec_len > 16384 {
        return None;
    }
    if buf.len() < 5 + 4 {
        return None;
    }
    // Handshake: type(1) len(3) — must be ClientHello (0x01).
    let hs_off = 5;
    if buf[hs_off] != 0x01 {
        return None;
    }
    let hs_len =
        ((buf[hs_off + 1] as usize) << 16) | ((buf[hs_off + 2] as usize) << 8) | buf[hs_off + 3] as usize;
    if hs_len == 0 || hs_len > 16384 {
        return None;
    }
    let mut p = hs_off + 4;
    // client_version(2) + random(32)
    if buf.len() < p + 34 {
        return None;
    }
    p += 34;
    // session_id
    if buf.len() < p + 1 {
        return None;
    }
    let sid_len = buf[p] as usize;
    p += 1 + sid_len;
    // cipher_suites
    if buf.len() < p + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2 + cs_len;
    // compression_methods
    if buf.len() < p + 1 {
        return None;
    }
    let cm_len = buf[p] as usize;
    p += 1 + cm_len;
    // extensions
    if buf.len() < p + 2 {
        return None;
    }
    let ext_total = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    let ext_end = p.saturating_add(ext_total);
    while p + 4 <= buf.len().min(ext_end) {
        let ext_type = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let ext_len = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
        p += 4;
        if p + ext_len > buf.len() {
            return None;
        }
        if ext_type == 0x0000 {
            // server_name_list: list_len(2) + name_type(1) + name_len(2) + name
            if ext_len < 5 {
                return None;
            }
            if buf[p + 2] != 0x00 {
                return None; // only host_name
            }
            let name_len = u16::from_be_bytes([buf[p + 3], buf[p + 4]]) as usize;
            if name_len == 0 || name_len > 253 || p + 5 + name_len > buf.len() {
                return None;
            }
            let name = std::str::from_utf8(&buf[p + 5..p + 5 + name_len]).ok()?;
            // Basic hostname sanity: no spaces/control, has a dot or localhost.
            if name.bytes().any(|b| b <= 0x20 || b == 0x7f) || name.len() > 253 {
                return None;
            }
            return Some(name.to_string());
        }
        p += ext_len;
    }
    None
}

/// Decrypted HTTPS request (MITM): full request line + header size. Bodies are
/// never logged by design. One line per connection (first header block).
pub fn log_mitm_request(
    pid: u32,
    exe: &str,
    dst: &std::net::SocketAddr,
    sni: &str,
    method: &str,
    host: &str,
    target: &str,
    header_bytes: usize,
) {
    let dest = if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("{}{}", host, target)
    };
    append_line(&format!(
        "HTTPS-decrypted {} \"{}\" (pid {}) -> {} SNI={} via {} [{}B headers]",
        method, dest, pid, dst, sni, exe, header_bytes
    ));
}

/// Decrypted TLS that is not HTTP (custom protocols, e.g. mtalk). Logs the
/// first printable line or a byte count so the user can tell decrypt worked
/// but there was no HTTP to show.
pub fn log_mitm_opaque(pid: u32, exe: &str, dst: &std::net::SocketAddr, sni: &str, data: &[u8]) {
    let preview: String = data
        .iter()
        .take(96)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else if b == b'\r' || b == b'\n' {
                ' '
            } else {
                '.'
            }
        })
        .collect();
    append_line(&format!(
        "HTTPS-decrypted (non-HTTP, {}B) \"{}\" (pid {}) -> {} SNI={} via {}",
        data.len(),
        preview.trim(),
        pid,
        dst,
        sni,
        exe
    ));
}

/// App handshook then sent nothing (racing/probe socket).
pub fn log_mitm_empty(pid: u32, exe: &str, dst: &std::net::SocketAddr, sni: &str) {
    append_line(&format!(
        "HTTPS-decrypted (empty) (pid {}) -> {} SNI={} via {}",
        pid, dst, sni, exe
    ));
}

fn append_line(line: &str) {    use std::io::Write;
    let Some(path) = http_log_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Bounded file: truncate with marker past the cap.
    if std::fs::metadata(&path)
        .map(|m| m.len() > HTTP_LOG_MAX_BYTES)
        .unwrap_or(false)
    {
        if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&path) {
            let mut f = f;
            let _ = f.set_len(0);
            use std::io::Seek;
            let _ = f.seek(std::io::SeekFrom::Start(0));
            let _ = writeln!(
                f,
                "[{}] http.log rotated (>8MB) — older lines discarded",
                local_timestamp()
            );
        }
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "[{}] {}", local_timestamp(), oneline(line));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get_with_host() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n";
        let (m, h, t) = try_parse_http(raw).unwrap();
        assert_eq!(m, "GET");
        assert_eq!(h, "example.com");
        assert_eq!(t, "/index.html");
    }

    #[test]
    fn rejects_binary() {
        assert!(try_parse_http(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x01]).is_none());
        assert!(try_parse_http(b"HELLO WORLD\r\n\r\n").is_none());
    }

    #[test]
    fn parses_connect() {
        let raw = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        assert!(try_parse_http(raw).is_some());
    }
}
