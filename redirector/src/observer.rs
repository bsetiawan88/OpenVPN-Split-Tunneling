use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use windivert::layer::SocketLayer;
use windivert::prelude::*;

use crate::flows::{self, FlowEntry, FlowTable, LocalEndpoint};
use crate::policy::{self, PolicyState};
use crate::process::Resolver;

pub fn run(resolver: Arc<Resolver>, policy_state: PolicyState, flows: FlowTable) -> Result<()> {
    let filter = "event = CONNECT or event = ACCEPT or event = BIND or event = CLOSE";
    let flags = WinDivertFlags::new().set_sniff().set_recv_only();
    let handle = WinDivert::socket(filter, 0, flags).context(
        "WinDivert::socket failed — start an elevated PowerShell, or check that WinDivert.dll + WinDivert64.sys are next to redirector.exe",
    )?;

    tracing::info!("SOCKET observer started, filter: {}", filter);
    println!(
        "\n{:<3} {:<8} {:<6} {:<5} {:<46} {:<46} {}",
        "TUN", "EVENT", "PID", "PROTO", "LOCAL", "REMOTE", "PROCESS"
    );
    println!("{}", "-".repeat(150));

    // Consecutive-NoData backoff: a single NoData may be transient, but a
    // real shutdown returns it immediately every time — without backoff the
    // continue below would spin at 100% CPU. 20ms × quiet box is harmless;
    // a debug line every 50th, one visible warn every 500th.
    let mut quiet_streak: u32 = 0;
    loop {
        match handle.recv() {
            Ok(packet) => {
                quiet_streak = 0;
                handle_event(&packet.address, &resolver, &policy_state, &flows);
            }
            Err(WinDivertError::Recv(WinDivertRecvError::NoData)) => {
                quiet_streak = quiet_streak.saturating_add(1);
                if quiet_streak % 50 == 1 {
                    tracing::debug!("socket observer: NoData x{} (transient or shut down?)", quiet_streak);
                }
                if quiet_streak % 500 == 0 {
                    tracing::warn!(
                        "socket observer: {} consecutive NoData — driver may be down, still retrying",
                        quiet_streak
                    );
                }
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            // Same backoff rationale as NoData: a fast-failing handle must
            // not warn-spin. (In practice the driver signals this state via
            // NoData; this arm is the backstop.)
            Err(e) => {
                tracing::warn!("recv error: {}", e);
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn handle_event(
    addr: &WinDivertAddress<SocketLayer>,
    resolver: &Resolver,
    policy_state: &PolicyState,
    flows: &FlowTable,
) {
    let pid = addr.process_id();
    let event = addr.event();
    let proto = addr.protocol();
    let local_addr = addr.local_address();
    let local_port = addr.local_port();

    match event {
        WinDivertEvent::SocketBind | WinDivertEvent::SocketConnect => {
            let key = LocalEndpoint { addr: local_addr, port: local_port, proto };
            flows::insert(flows, key, FlowEntry { pid });
        }
        WinDivertEvent::SocketClose => {
            let key = LocalEndpoint { addr: local_addr, port: local_port, proto };
            flows::remove(flows, &key);
        }
        _ => {}
    }

    log_event(addr, resolver, policy_state, pid, event, proto);
}

fn log_event(
    addr: &WinDivertAddress<SocketLayer>,
    resolver: &Resolver,
    policy_state: &PolicyState,
    pid: u32,
    event: WinDivertEvent,
    proto: u8,
) {
    let proto_s = proto_str(proto);
    let local = format!("{}:{}", addr.local_address(), addr.local_port());
    let remote = format!("{}:{}", addr.remote_address(), addr.remote_port());

    let event_str = match event {
        WinDivertEvent::SocketBind => "BIND",
        WinDivertEvent::SocketConnect => "CONNECT",
        WinDivertEvent::SocketAccept => "ACCEPT",
        WinDivertEvent::SocketListen => "LISTEN",
        WinDivertEvent::SocketClose => "CLOSE",
        _ => "OTHER",
    };

    let exe = resolver
        .resolve(pid)
        .map(|p| p.exe_name)
        .unwrap_or_else(|| "?".into());

    let marker = if policy::contains(policy_state, pid) { "VPN" } else { "" };

    println!(
        "{:<3} {:<8} {:<6} {:<5} {:<46} {:<46} {}",
        marker, event_str, pid, proto_s, local, remote, exe
    );
}

fn proto_str(p: u8) -> &'static str {
    match p {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        58 => "ICMP6",
        _ => "?",
    }
}
