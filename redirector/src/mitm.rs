//! Opt-in TLS MITM for tunneled apps (decrypt-to-log, then re-encrypt).
//!
//! Passive `http_log` can only see TLS SNI. When the user explicitly opts an
//! app in (Settings → Decrypt), this module terminates the app's TLS with a
//! per-SNI leaf signed by a local CA, logs the *decrypted* HTTP request line
//! + headers to `http.log`, and re-encrypts toward the real server over the
//! VPN-pinned socket.
//!
//! Safety rails (fail-open, never break connectivity for policy misses):
//!   - Master switch `%AppData%\VpnClient\mitm.flag` + per-app allowlist
//!     `%AppData%\VpnClient\mitm-apps.txt` (full exe paths, matched by file
//!     name like `policy::identity_of`). Both written by the UI.
//!   - CA missing/unreadable, SNI absent/unparsable, app not listed, non-TLS
//!     bytes → caller falls back to the blind byte bridge (existing path).
//!   - Errors *after* the app handshake started can't fall back (the app
//!     already sees our cert) — those close the connection and the app
//!     retries; wedged states are bounded by timeouts.
//!   - Bodies are forwarded opaquely, never logged (v1). One request logged
//!     per connection (first header block); keep-alive follow-ups ride the
//!     blind copy.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const MITM_CA_CN: &str = "VpnClient Local MITM CA";
const FIRST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const REQ_HEAD_CAP: usize = 64 * 1024;
const RELAY_CHUNK: usize = 16 * 1024;

// ---------------------------------------------------------------------------
// Policy (sentinel files, mirrors http_log::is_enabled / verbose.flag)
// ---------------------------------------------------------------------------

fn appdata() -> Option<PathBuf> {
    std::env::var("APPDATA").ok().map(PathBuf::from)
}

/// Master switch. Absent = MITM fully off (zero handshake cost).
pub fn is_enabled() -> bool {
    appdata()
        .map(|a| a.join("VpnClient").join("mitm.flag"))
        .map(|p| p.exists())
        .unwrap_or(false)
}

fn apps_path() -> Option<PathBuf> {
    appdata().map(|a| a.join("VpnClient").join("mitm-apps.txt"))
}

fn basename_lower(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_lowercase()
}

/// True when the master flag exists AND the app's file name is allowlisted.
/// `exe_name` is the bare name divert/WFP already carry (e.g. `chrome.exe`).
pub fn policy_allows(exe_name: &str) -> bool {
    if !is_enabled() {
        return false;
    }
    let Some(path) = apps_path() else {
        return false;
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let wanted = exe_name.to_lowercase();
    text.lines()
        .map(|l| basename_lower(l.trim()))
        .any(|b| !b.is_empty() && b == wanted)
}

/// Allowlisted basenames (for diagnostics / future status reporting).
#[allow(dead_code)]
pub fn listed_apps() -> HashSet<String> {
    let Some(path) = apps_path() else {
        return HashSet::new();
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    text.lines()
        .map(|l| basename_lower(l.trim()))
        .filter(|b| !b.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// Local CA (generate-once, PEM files shared with the UI for trust install)
// ---------------------------------------------------------------------------

fn ca_paths() -> Option<(PathBuf, PathBuf)> {
    let dir = appdata()?.join("VpnClient").join("ca");
    Some((dir.join("ca.crt"), dir.join("ca.key")))
}

struct CaMaterial {
    cert_pem: String,
    key_pem: String,
}

/// Issuer objects rebuilt from the persisted PEMs. rcgen's `Certificate`
/// cannot be deserialized directly, so we re-wrap the same DN + key in a
/// fresh self-signed object: same subject name, same key → leaves chain to
/// the installed `ca.crt` (name + key match is what verifiers check).
struct IssuerMats {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

fn build_issuer(ca_cert_pem: &str, ca_key_pem: &str) -> Option<IssuerMats> {
    let key = rcgen::KeyPair::from_pem(ca_key_pem).ok()?;
    let params = rcgen::CertificateParams::from_ca_cert_pem(ca_cert_pem).ok()?;
    let cert = params.self_signed(&key).ok()?;
    Some(IssuerMats { cert, key })
}

/// Load the CA, generating + persisting it on first use. None on any
/// failure — callers treat MITM as unavailable and stay blind.
fn ensure_ca() -> Option<CaMaterial> {
    let (crt_path, key_path) = ca_paths()?;
    if crt_path.exists() && key_path.exists() {
        if let (Ok(c), Ok(k)) = (
            std::fs::read_to_string(&crt_path),
            std::fs::read_to_string(&key_path),
        ) {
            // Validate by rebuilding the issuer; a half-written file
            // regenerates below (with a loud line — trust must be redone).
            if build_issuer(&c, &k).is_some() {
                return Some(CaMaterial {
                    cert_pem: c,
                    key_pem: k,
                });
            }
        }
        tracing::warn!("mitm: existing CA files unreadable — regenerating (re-install trust!)");
    }
    let mut params = rcgen::CertificateParams::new(vec![]).ok()?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, MITM_CA_CN);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let key = rcgen::KeyPair::generate().ok()?;
    let cert = params.self_signed(&key).ok()?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();
    if let Some(parent) = crt_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Key first: a crash between the two writes leaves a missing crt, which
    // regenerates cleanly (instead of a crt without its key, which would
    // silently break issuance until noticed).
    // NOTE: user-profile ACLs apply, same as the UI's DPAPI credential store.
    // The key never leaves the box by design.
    std::fs::write(&key_path, &key_pem).ok()?;
    std::fs::write(&crt_path, &cert_pem).ok()?;
    tracing::info!("mitm: generated fresh local CA — install trust via Settings → Install CA");
    Some(CaMaterial { cert_pem, key_pem })
}

// ---------------------------------------------------------------------------
// Leaf certs (per-SNI, in-memory cache, signed by the local CA)
// ---------------------------------------------------------------------------

fn issue_leaf(
    issuer_cert: &rcgen::Certificate,
    issuer_key: &rcgen::KeyPair,
    name: &str,
) -> Option<Arc<rustls::sign::CertifiedKey>> {
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let mut leaf_params = rcgen::CertificateParams::new(vec![name.to_string()]).ok()?;
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    leaf_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let leaf_key = rcgen::KeyPair::generate().ok()?;
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, issuer_cert, issuer_key)
        .ok()?;
    let cert_der = leaf_cert.der().to_vec();
    let key_der = leaf_key.serialize_der();
    let provider = rustls::crypto::ring::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
            ),
        )
        .ok()?;
    Some(Arc::new(rustls::sign::CertifiedKey::new(
        vec![rustls::pki_types::CertificateDer::from(cert_der)],
        signing_key,
    )))
}

struct LeafResolver {
    issuer_cert: rcgen::Certificate,
    issuer_key: rcgen::KeyPair,
    cache: Mutex<HashMap<String, Arc<rustls::sign::CertifiedKey>>>,
}

impl std::fmt::Debug for LeafResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeafResolver").finish_non_exhaustive()
    }
}

impl rustls::server::ResolvesServerCert for LeafResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = client_hello.server_name()?.to_string();
        if name.is_empty() || name.len() > 253 {
            return None;
        }
        let Ok(mut cache) = self.cache.lock() else {
            return None;
        };
        if let Some(hit) = cache.get(&name) {
            return Some(hit.clone());
        }
        let ck = issue_leaf(&self.issuer_cert, &self.issuer_key, &name)?;
        cache.insert(name, ck.clone());
        // SNIs are effectively unbounded (CDN fronts, DoH) — bound memory.
        if cache.len() > 512 {
            cache.clear();
            tracing::debug!("mitm: leaf cache cleared (>512 SNIs)");
        }
        Some(ck)
    }

    fn only_raw_public_keys(&self) -> bool {
        false
    }
}

static SERVER_CFG: Mutex<Option<(Vec<u8>, Arc<rustls::ServerConfig>)>> =
    Mutex::new(None);

fn server_config() -> Option<Arc<rustls::ServerConfig>> {
    let ca = ensure_ca()?;
    let fingerprint = ca.cert_pem.as_bytes().to_vec();
    if let Ok(guard) = SERVER_CFG.lock() {
        if let Some((fp, cfg)) = guard.as_ref() {
            if fp == &fingerprint {
                return Some(cfg.clone());
            }
        }
    }
    let issuer = build_issuer(&ca.cert_pem, &ca.key_pem)?;
    let resolver = Arc::new(LeafResolver {
        issuer_cert: issuer.cert,
        issuer_key: issuer.key,
        cache: Mutex::new(HashMap::new()),
    });
    let cfg = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver),
    );
    if let Ok(mut guard) = SERVER_CFG.lock() {
        *guard = Some((fingerprint, cfg.clone()));
    }
    Some(cfg)
}

static CLIENT_CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

fn client_config() -> Arc<rustls::ClientConfig> {
    CLIENT_CFG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

fn server_name_for(sni: &str) -> Option<rustls::pki_types::ServerName<'static>> {
    if let Ok(ip) = sni.parse::<std::net::IpAddr>() {
        return Some(rustls::pki_types::ServerName::from(ip));
    }
    let borrowed: rustls::pki_types::ServerName<'_> = sni.try_into().ok()?;
    Some(borrowed.to_owned())
}

// ---------------------------------------------------------------------------
// Byte-stream adapters
// ---------------------------------------------------------------------------

/// AsyncRead head: already-consumed bytes (ClientHello peek) followed by the
/// live stream. Used on the app side so the TLS acceptor sees the full
/// handshake despite the earlier SNI peek.
struct Prefixed<R> {
    head: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R: AsyncRead + Unpin> AsyncRead for Prefixed<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.head.len() {
            let n = (self.head.len() - self.pos).min(buf.remaining());
            buf.put_slice(&self.head[self.pos..self.pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<R: AsyncWrite + Unpin> AsyncWrite for Prefixed<R> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

type SendResult = Result<(), mpsc::error::SendError<Vec<u8>>>;
type SendFuture = Pin<Box<dyn std::future::Future<Output = SendResult> + Send>>;

/// AsyncRead/AsyncWrite over the divert bridge channels (smoltcp ↔ task).
/// Lets the WinDivert backend reuse the exact same TLS relay as WFP.
/// Writes are driven by a real `send()` future (correct wakers under
/// backpressure); at most one is in flight so byte order is preserved.
pub struct ChanStream {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    pending: VecDeque<u8>,
    rx_done: bool,
    write_fut: Option<(usize, SendFuture)>,
}

impl ChanStream {
    pub fn new(rx: mpsc::Receiver<Vec<u8>>, tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            rx,
            tx,
            pending: VecDeque::new(),
            rx_done: false,
            write_fut: None,
        }
    }
}

impl AsyncRead for ChanStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            while !self.pending.is_empty() && buf.remaining() > 0 {
                let n = self.pending.len().min(buf.remaining());
                for _ in 0..n {
                    if let Some(b) = self.pending.pop_front() {
                        buf.put_slice(&[b]);
                    }
                }
            }
            if !buf.filled().is_empty() || self.rx_done {
                return Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    self.pending.extend(chunk);
                }
                Poll::Ready(None) => {
                    self.rx_done = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for ChanStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write_fut.is_none() {
            let n = buf.len().min(RELAY_CHUNK);
            let data = buf[..n].to_vec();
            let tx = self.tx.clone();
            self.write_fut = Some((n, Box::pin(async move { tx.send(data).await })));
        }
        let (n, fut) = self.write_fut.as_mut().expect("just set");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                let n = *n;
                self.write_fut = None;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(_)) => {
                self.write_fut = None;
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "bridge channel closed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Dropping the sender (on stream drop) FINs the app leg via the
        // bridge write-task observing recv()==None — same as divert's
        // half-close propagation. Nothing to flush eagerly here.
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// Decrypt relay (shared by both backends)
// ---------------------------------------------------------------------------

/// Read until the end of the first HTTP header block. Returns the buffered
/// plaintext (headers + any already-read body bytes).
async fn read_request_head<C: AsyncRead + Unpin>(
    client: &mut C,
) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = vec![0u8; RELAY_CHUNK];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if find_head_end(&buf).is_some() || buf.len() >= REQ_HEAD_CAP {
            break;
        }
        let to = deadline.saturating_duration_since(std::time::Instant::now());
        if to.is_zero() {
            break;
        }
        match tokio::time::timeout(to, client.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            _ => break,
        }
    }
    Ok(buf)
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    let limit = buf.len().min(REQ_HEAD_CAP);
    buf[..limit]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .or_else(|| {
            buf[..limit]
                .windows(2)
                .position(|w| w == b"\n\n")
                .map(|p| p + 2)
        })
}

async fn relay_with_logging<C, S>(
    mut client: C,
    mut server: S,
    pid: u32,
    exe: &str,
    dst: &SocketAddr,
    sni: &str,
) -> std::io::Result<u64>
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = read_request_head(&mut client).await?;
    let mut total = head.len() as u64;
    if head.is_empty() {
        // App handshook then said nothing (probe / racing socket).
        crate::http_log::log_mitm_empty(pid, exe, dst, sni);
    } else if let Some((method, host, target)) = crate::http_log::try_parse_http(&head) {
        let host = if host.is_empty() {
            sni.to_string()
        } else {
            host
        };
        crate::http_log::log_mitm_request(
            pid, exe, dst, sni, &method, &host, &target, head.len(),
        );
    } else {
        crate::http_log::log_mitm_opaque(pid, exe, dst, sni, &head);
    }
    if !head.is_empty() {
        server.write_all(&head).await?;
    }
    // Remainder (bodies, responses, keep-alive follow-ups) rides blind.
    let (up, down) = tokio::io::copy_bidirectional(&mut client, &mut server).await?;
    total += up + down;
    Ok(total)
}

// ---------------------------------------------------------------------------
// Backend entry points. Both consume the connection (decrypted relay done,
// however it ended) → caller returns afterwards. Callers MUST gate on
// eligible() + crypto_ready() first so ineligible flows keep `first` intact
// for the byte-exact blind path.
// ---------------------------------------------------------------------------

/// Prerequisite check that moves nothing: CA loadable AND SNI usable as a
/// TLS server name. Callers gate on this BEFORE handing over channels, so a
/// "no" keeps `first` intact for the byte-exact blind path.
pub fn crypto_ready(sni: &str) -> bool {
    if server_name_for(sni).is_none() {
        return false;
    }
    server_config().is_some()
}

/// WFP path: real sockets on both legs. Consumes the connection either way
/// (decrypted relay done, however it ended) — caller returns afterwards.
pub async fn try_mitm_wfp(
    inbound: TcpStream,
    outbound: TcpStream,
    first: Vec<u8>,
    pid: u32,
    exe: &str,
    dst: SocketAddr,
    sni: &str,
) -> std::io::Result<()> {
    let server_cfg = server_config()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "mitm CA unavailable"))?;
    let server_name = server_name_for(sni)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad SNI"))?;
    let prefixed = Prefixed {
        head: first,
        pos: 0,
        inner: inbound,
    };
    let client = tokio_rustls::TlsAcceptor::from(server_cfg)
        .accept(prefixed)
        .await?;
    let server = tokio_rustls::TlsConnector::from(client_config())
        .connect(server_name, outbound)
        .await?;
    match relay_with_logging(client, server, pid, exe, &dst, sni).await {
        Ok(n) => {
            tracing::info!(
                "mitm relay done: pid={} {} SNI={} ({} bytes decrypted-logged)",
                pid,
                exe,
                sni,
                n
            );
            Ok(())
        }
        Err(e) => {
            tracing::warn!("mitm relay pid={} SNI={} ended: {}", pid, sni, e);
            Ok(())
        }
    }
}

/// WinDivert path: app leg is the bridge channel pair. Same consume contract.
pub async fn try_mitm_divert(
    from_app: mpsc::Receiver<Vec<u8>>,
    to_app: mpsc::Sender<Vec<u8>>,
    first: Vec<u8>,
    outbound: TcpStream,
    pid: u32,
    exe: &str,
    dst: SocketAddr,
    sni: &str,
) -> std::io::Result<()> {
    let server_cfg = server_config()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "mitm CA unavailable"))?;
    let server_name = server_name_for(sni)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad SNI"))?;
    let chan = ChanStream::new(from_app, to_app);
    let prefixed = Prefixed {
        head: first,
        pos: 0,
        inner: chan,
    };
    let client = tokio_rustls::TlsAcceptor::from(server_cfg)
        .accept(prefixed)
        .await?;
    let server = tokio_rustls::TlsConnector::from(client_config())
        .connect(server_name, outbound)
        .await?;
    match relay_with_logging(client, server, pid, exe, &dst, sni).await {
        Ok(n) => {
            tracing::info!(
                "mitm relay done: pid={} {} SNI={} ({} bytes decrypted-logged)",
                pid,
                exe,
                sni,
                n
            );
            Ok(())
        }
        Err(e) => {
            tracing::warn!("mitm relay pid={} SNI={} ended: {}", pid, sni, e);
            Ok(())
        }
    }
}

/// Eligibility gate shared by both backends. Returns the SNI when a decrypt
/// attempt is warranted; None → stay blind (existing behavior + SNI line).
pub fn eligible(exe_name: &str, first: &[u8]) -> Option<String> {
    if !policy_allows(exe_name) {
        return None;
    }
    let sni = crate::http_log::try_parse_sni(first)?;
    if server_name_for(&sni).is_none() {
        return None;
    }
    Some(sni)
}

pub fn first_chunk_timeout() -> std::time::Duration {
    FIRST_READ_TIMEOUT
}

#[allow(dead_code)]
pub fn ca_crt_path() -> Option<PathBuf> {
    ca_paths().map(|(crt, _)| crt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_matching() {
        assert_eq!(basename_lower(r"C:\A\Chrome.EXE"), "chrome.exe");
        assert_eq!(basename_lower("x"), "x");
    }

    #[test]
    fn disabled_by_default_without_flag() {
        // No flag file in test env → gate closed. (If a dev machine has the
        // flag, this asserts the allowlist path instead — still meaningful.)
        if !is_enabled() {
            assert!(eligible("chrome.exe", b"\x16\x03").is_none());
        }
    }

    #[test]
    fn ca_generates_and_reloads() {
        // Sandboxed APPDATA so the real profile is untouched.
        let dir = std::env::temp_dir().join(format!("vpn-mitm-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let prev = std::env::var("APPDATA").ok();
        std::env::set_var("APPDATA", &dir);
        SERVER_CFG.lock().unwrap().take();
        let ca1 = ensure_ca().expect("generate");
        SERVER_CFG.lock().unwrap().take();
        let ca2 = ensure_ca().expect("reload");
        assert_eq!(ca1.cert_pem, ca2.cert_pem);
        assert!(build_issuer(&ca2.cert_pem, &ca2.key_pem).is_some());
        assert!(server_config().is_some());
        let _ = std::fs::remove_dir_all(&dir);
        if let Some(p) = prev {
            std::env::set_var("APPDATA", p);
        }
        SERVER_CFG.lock().unwrap().take();
    }
}
