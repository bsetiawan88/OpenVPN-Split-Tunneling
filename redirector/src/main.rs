mod adapter;
mod divert;
mod forward_table;
mod flows;
mod http_log;
mod nic_stats;
mod observer;
mod pidlookup;
mod policy;
mod policy_server;
mod proc_watcher;
mod process;
mod stack;
mod status_server;
mod tunneled;
mod vpn_state;
mod wfp;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Result;

fn main() -> Result<()> {
    // A silent redirector death (panic in a hidden window) leaves zero
    // evidence: the UI sees a dead pipe, the tunnel runs unmanaged. Leave a
    // last word in activity.log instead.
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!(" at {}:{}", l.file(), l.line()))
            .unwrap_or_default();
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("<non-string panic>");
        status_server::append_raw_line(&format!("PANIC: {}{}", payload, location));
    }));

    let log_path = redirector_log_path();
    tracing_subscriber::fmt()
        .with_env_filter(
            // The UI launches the redirector hidden with no RUST_LOG set, so
            // fall back to a filter that always keeps our own debug stream in
            // the file, and to full packet-level detail when the sentinel file
            // %AppData%\VpnClient\verbose.flag exists.
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter())),
        )
        // The service runs hidden with stderr attached to nothing, so the only
        // diagnostic we have (the "divert 5s" counters, inject warnings) was
        // being discarded. Tee every event to
        // %LocalAppData%\VpnClient\runtime\redirector.log so a slow-path
        // investigation has evidence after the fact.
        .with_writer(LogTee::new(log_path.clone()))
        .init();
    if let Some(p) = log_path.as_ref() {
        tracing::info!("redirector log -> {}", p.display());
    }

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        None | Some("adapters") => print_adapters(),
        Some("observe") => {
            // Accept --backend=wfp and --backend wfp; reject typos loudly
            // instead of silently falling back to WinDivert.
            let raw = args
                .iter()
                .find_map(|a| a.strip_prefix("--backend="))
                .map(|s| s.to_string())
                .or_else(|| {
                    args.windows(2).find_map(|w| {
                        if w[0] == "--backend" {
                            Some(w[1].clone())
                        } else {
                            None
                        }
                    })
                });
            let backend = match raw {
                None => wfp::Backend::default(),
                Some(s) => match wfp::Backend::parse(&s) {
                    Some(b) => b,
                    None => {
                        eprintln!(
                            "unknown --backend '{}' (expected windivert|wfp)",
                            s
                        );
                        print_help();
                        std::process::exit(2);
                    }
                },
            };
            run_observe(backend)
        }
        Some("wfp-status") => {
            let st = wfp::device::status();
            println!(
                "VpnWfpCallout installed={} running={} BFE running={} device_openable={} ({})",
                st.installed,
                st.running,
                st.bfe_running,
                st.device_openable,
                wfp::device::DOS_DEVICE
            );
            Ok(())
        }
        Some("help") | Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some(cmd) => {
            eprintln!("unknown command: {}", cmd);
            print_help();
            std::process::exit(2);
        }
    }
}

fn run_observe(backend: wfp::Backend) -> Result<()> {
    tracing::info!("redirector backend={:?}", backend);
    // Adapter byte counters are backend-agnostic observability: they tell the
    // 5s log what the NICs moved regardless of which capture path is active.
    nic_stats::spawn();
    match backend {
        wfp::Backend::Wfp => run_observe_wfp(),
        wfp::Backend::WindDivert => run_observe_windivert(),
    }
}

fn run_observe_windivert() -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let policy_state = policy::new();
        let flows = flows::new();
        let resolver = Arc::new(process::Resolver::new());
        let tunneled_paths = tunneled::new();

        let vpn_state = vpn_state::new();
        let bus = Arc::new(status_server::StatusBus::new());

        let policy_task = tokio::spawn(policy_server::run(policy_state.clone()));
        let vpn_task = tokio::spawn(vpn_state::watcher(vpn_state.clone(), bus.clone()));
        let status_task = tokio::spawn(status_server::run(bus.clone(), vpn_state.clone()));
        let watcher_task = tokio::spawn(proc_watcher::run(
            policy_state.clone(),
            bus.clone(),
            tunneled_paths.clone(),
            resolver.clone(),
        ));
        let observer_handle = {
            let resolver = resolver.clone();
            let policy_state = policy_state.clone();
            let flows = flows.clone();
            tokio::task::spawn_blocking(move || observer::run(resolver, policy_state, flows))
        };
        let divert_handle = {
            let policy_state = policy_state.clone();
            let flows = flows.clone();
            let vpn_state = vpn_state.clone();
            let bus = bus.clone();
            let resolver = resolver.clone();
            let tunneled_paths = tunneled_paths.clone();
            tokio::task::spawn_blocking(move || {
                divert::run(policy_state, flows, vpn_state, bus, resolver, tunneled_paths)
            })
        };

        tokio::select! {
            r = policy_task => r??,
            r = vpn_task => r??,
            r = status_task => r??,
            r = watcher_task => r??,
            r = observer_handle => r??,
            r = divert_handle => r??,
        }
        Ok(())
    })
}

fn run_observe_wfp() -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let policy_state = policy::new();
        let flows = flows::new();
        let resolver = Arc::new(process::Resolver::new());
        let tunneled_paths = tunneled::new();

        let vpn_state = vpn_state::new();
        let bus = Arc::new(status_server::StatusBus::new());

        let policy_task = tokio::spawn(policy_server::run(policy_state.clone()));
        let vpn_task = tokio::spawn(vpn_state::watcher(vpn_state.clone(), bus.clone()));
        let status_task = tokio::spawn(status_server::run(bus.clone(), vpn_state.clone()));
        let watcher_task = tokio::spawn(proc_watcher::run(
            policy_state.clone(),
            bus.clone(),
            tunneled_paths.clone(),
            resolver.clone(),
        ));
        // WFP replaces observer (SOCKET layer) + divert (NETWORK layer):
        // PID comes from FWPS_METADATA_FIELD_PROCESS_ID in the kernel,
        // so no GetExtendedTcpTable race and no smoltcp termination.
        // No spawn_blocking + nested runtime: run_async lives on this runtime.
        let wfp_task = tokio::spawn(wfp::run_async(
            policy_state.clone(),
            flows.clone(),
            vpn_state.clone(),
            bus.clone(),
            resolver.clone(),
            tunneled_paths.clone(),
        ));

        tokio::select! {
            r = policy_task => r??,
            r = vpn_task => r??,
            r = status_task => r??,
            r = watcher_task => r??,
            r = wfp_task => r??,
        }
        Ok(())
    })
}

/// Default log filter when RUST_LOG is unset (always, when the UI spawns us).
/// `redirector=debug` keeps the service's own diagnostics; creating
/// `%AppData%\VpnClient\verbose.flag` additionally turns on the `pkt` target,
/// which traces every captured packet. Sentinel instead of an env var because
/// the hidden UI-launched process never sees RUST_LOG.
fn default_filter() -> String {
    let verbose = std::env::var("APPDATA")
        .ok()
        .map(|a| PathBuf::from(a).join("VpnClient").join("verbose.flag"))
        .map(|p| p.exists())
        .unwrap_or(false);
    if verbose {
        "info,redirector=debug,pkt=debug".to_string()
    } else {
        "info,redirector=debug".to_string()
    }
}

/// %LocalAppData%\VpnClient\runtime\redirector.log — same runtime dir as
/// activity.log / openvpn.log. The redirector is the only one of those that
/// had no file of its own.
fn redirector_log_path() -> Option<PathBuf> {
    let local = std::env::var("LOCALAPPDATA").ok()?;
    Some(
        PathBuf::from(local)
            .join("VpnClient")
            .join("runtime")
            .join("redirector.log"),
    )
}

/// Keep the log bounded across restarts: append normally, but truncate a
/// file that has already grown past the cap so a long-lived service cannot
/// fill the disk.
const REDIRECTOR_LOG_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// `tracing` writer that mirrors to stderr (visible when run from a console)
/// and, when the runtime dir is writable, to a file. A failed open degrades
/// to stderr-only: logging must never break the packet path.
#[derive(Clone, Default)]
struct LogTee {
    file: Option<Arc<Mutex<std::fs::File>>>,
}

impl LogTee {
    fn new(path: Option<PathBuf>) -> Self {
        let file = path.and_then(|p| {
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let oversized = std::fs::metadata(&p)
                .map(|m| m.len() > REDIRECTOR_LOG_MAX_BYTES)
                .unwrap_or(false);
            let mut opts = std::fs::OpenOptions::new();
            opts.create(true).write(true);
            if oversized {
                opts.truncate(true);
            } else {
                opts.append(true);
            }
            opts.open(p).ok().map(|f| Arc::new(Mutex::new(f)))
        });
        Self { file }
    }
}

struct LogTeeWriter<'a> {
    file: Option<std::sync::MutexGuard<'a, std::fs::File>>,
}

impl std::io::Write for LogTeeWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = std::io::stderr().write_all(buf);
        if let Some(f) = self.file.as_mut() {
            let _ = f.write_all(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _ = std::io::stderr().flush();
        if let Some(f) = self.file.as_mut() {
            let _ = f.flush();
        }
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogTee {
    type Writer = LogTeeWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        LogTeeWriter {
            file: self
                .file
                .as_ref()
                .map(|f| f.lock().unwrap_or_else(|e| e.into_inner())),
        }
    }
}

fn print_help() {
    println!("redirector — VPN per-app routing service");
    println!();
    println!("USAGE:");
    println!("  redirector [adapters]              List network adapters, flag VPN candidates");
    println!("  redirector observe [--backend=windivert|wfp]  Run packet path (requires admin, default windivert)");
    println!("  redirector wfp-status              Show VpnWfpCallout + BFE service state");
    println!("  redirector help                    Show this message");
}

fn print_adapters() -> Result<()> {
    let adapters = adapter::enumerate()?;
    println!("Found {} adapters\n", adapters.len());

    for a in &adapters {
        let status = if a.is_up { "UP  " } else { "DOWN" };
        let marker = if a.is_vpn_candidate() { "  <-- VPN candidate" } else { "" };
        println!("[{}] {}{}", status, a.friendly_name, marker);
        println!("       description: {}", a.description);
        println!("       guid:        {}", a.adapter_name);
        if a.addresses.is_empty() {
            println!("       (no addresses)");
        } else {
            for ip in &a.addresses {
                println!("       address:     {}", ip);
            }
        }
        println!();
    }

    let vpn: Vec<_> = adapters
        .iter()
        .filter(|a| a.is_vpn_candidate() && a.is_up)
        .collect();
    match vpn.as_slice() {
        [] => println!("No active VPN adapter detected. Start OpenVPN before continuing."),
        [one] => println!(
            "VPN adapter ready: {} ({} addresses)",
            one.friendly_name,
            one.addresses.len()
        ),
        many => println!("Multiple VPN adapter candidates ({}) — narrow your config", many.len()),
    }
    Ok(())
}
