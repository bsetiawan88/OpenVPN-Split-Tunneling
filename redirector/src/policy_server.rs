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
    let mut server = create_pipe(&sd, true)?;
    tracing::info!("policy pipe server listening on {}", PIPE_NAME);

    loop {
        server.connect().await.context("pipe connect failed")?;
        let connected = server;
        server = create_pipe(&sd, false)?;

        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(connected, state).await {
                tracing::warn!("policy client disconnected: {}", e);
            }
        });
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
