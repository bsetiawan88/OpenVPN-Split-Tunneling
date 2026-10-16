use anyhow::{Context, Result};
use ipc::{AddPid, Body, RemovePid, Snapshot, MAX_FRAME_LEN, PIPE_NAME};
use prost::Message;
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::core::{w, BOOL};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

use crate::policy::{self, PolicyState};

struct SecurityDescriptor {
    psd: PSECURITY_DESCRIPTOR,
}

impl SecurityDescriptor {
    fn allow_authenticated_users() -> Result<Self> {
        let mut psd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w!("D:(A;;GA;;;AU)"),
                SDDL_REVISION_1 as u32,
                &mut psd,
                None,
            )
        }
        .context("ConvertStringSecurityDescriptorToSecurityDescriptorW failed")?;
        Ok(Self { psd })
    }

    fn attrs(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.psd.0,
            bInheritHandle: BOOL(0),
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.psd.0)));
        }
    }
}

unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

fn create_pipe(sd: &SecurityDescriptor, first: bool) -> Result<NamedPipeServer> {
    let attrs = sd.attrs();
    let mut opts = ServerOptions::new();
    if first {
        opts.first_pipe_instance(true);
    }
    unsafe {
        opts.create_with_security_attributes_raw(PIPE_NAME, &attrs as *const _ as *mut _)
    }
    .context("create_with_security_attributes_raw failed")
}

pub async fn run(state: PolicyState) -> Result<()> {
    let sd = SecurityDescriptor::allow_authenticated_users()?;
    // Parity with status_server: a first-instance failure (usually another
    // redirector holding the pipe) must leave a forensic line, not just
    // stderr in a hidden window.
    let mut server = match create_pipe(&sd, true) {
        Ok(s) => s,
        Err(e) => {
            crate::status_server::append_raw_line(&format!(
                "FATAL: policy pipe unavailable ({:#}) — another redirector running?",
                e
            ));
            return Err(e).context("policy pipe first instance failed");
        }
    };
    tracing::info!("policy pipe server listening on {}", PIPE_NAME);

    loop {
        if let Err(e) = server.connect().await {
            tracing::warn!("policy pipe accept failed ({:#}) — recreating", e);
            server = recreate_pipe(&sd).await;
            continue;
        }
        let connected = server;
        // Always succeeds eventually (see recreate_pipe): `server` is valid
        // at every loop top.
        server = recreate_pipe(&sd).await;

        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(connected, state).await {
                tracing::warn!("policy client disconnected: {}", e);
            }
        });
    }
}

/// Recreate a (non-first) pipe instance, retrying forever rather than
/// exiting the process (the old `?` killed bridge + watcher + status too).
/// Never returns Err.
async fn recreate_pipe(sd: &SecurityDescriptor) -> NamedPipeServer {
    loop {
        match create_pipe(sd, false) {
            Ok(s) => return s,
            Err(e) => {
                tracing::warn!("policy pipe recreate failed ({:#}) — retrying", e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}

async fn handle_client(mut pipe: NamedPipeServer, state: PolicyState) -> Result<()> {
    tracing::info!("policy client connected");
    let mut len_buf = [0u8; 4];
    loop {
        if let Err(e) = pipe.read_exact(&mut len_buf).await {
            if e.kind() == std::io::ErrorKind::UnexpectedEof
                || e.kind() == std::io::ErrorKind::BrokenPipe
            {
                tracing::info!("policy client closed cleanly");
                return Ok(());
            }
            return Err(e.into());
        }
        let len = u32::from_le_bytes(len_buf);
        if len > MAX_FRAME_LEN {
            anyhow::bail!("frame too large: {} bytes", len);
        }
        let mut body = vec![0u8; len as usize];
        pipe.read_exact(&mut body).await?;
        let msg = ipc::PolicyMessage::decode(body.as_slice())?;
        apply(&state, msg);
    }
}

fn apply(state: &PolicyState, msg: ipc::PolicyMessage) {
    match msg.body {
        Some(Body::AddPid(AddPid { pid })) => {
            tracing::info!("policy: add pid {}", pid);
            policy::add_unvalidated(state, pid);
        }
        Some(Body::RemovePid(RemovePid { pid })) => {
            tracing::info!("policy: remove pid {}", pid);
            policy::remove(state, pid);
        }
        Some(Body::Snapshot(Snapshot { pids })) => {
            tracing::info!("policy: snapshot ({} pids)", pids.len());
            policy::replace(state, pids);
        }
        None => tracing::warn!("policy: empty message body"),
    }
}
