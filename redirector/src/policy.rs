use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

/// Tunnel membership: pid → admitted exe identity (lowercased file name,
/// "" when unknown, e.g. UI-pushed PIDs via the policy pipe).
///
/// The identity closes the PID-recycling hole: Windows reuses PIDs
/// aggressively under spawn storms (opencode's git/conhost churn), and a
/// bare PID set would instantly tunnel an unrelated new process that
/// inherits a dead PID inside the GC window. New bridge flows re-validate
/// the live exe against this identity (see divert policy_admit); file name
/// — not full path — is compared so QueryFullProcessImageName and sysinfo
/// path formats can never disagree and cause false evictions.
pub type PolicyState = Arc<RwLock<HashMap<u32, String>>>;

pub fn new() -> PolicyState {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Hot path (per packet): bare membership, no validation. New-flow
/// admission must go through divert's policy_admit instead.
pub fn contains(state: &PolicyState, pid: u32) -> bool {
    state.read().unwrap().contains_key(&pid)
}

/// Admit with known exe identity.
pub fn add(state: &PolicyState, pid: u32, exe_path: &str) {
    state
        .write()
        .unwrap()
        .insert(pid, identity_of(exe_path));
}

/// Admit without identity (policy-pipe pushes): skips exe validation.
pub fn add_unvalidated(state: &PolicyState, pid: u32) {
    state.write().unwrap().insert(pid, String::new());
}

pub fn remove(state: &PolicyState, pid: u32) {
    state.write().unwrap().remove(&pid);
}

pub fn replace(state: &PolicyState, pids: impl IntoIterator<Item = u32>) {
    let mut guard = state.write().unwrap();
    guard.clear();
    for pid in pids {
        guard.insert(pid, String::new());
    }
}

/// True when the stored identity matches the live exe (or no identity was
/// recorded — pipe-pushed and unknown-exe admissions skip validation).
pub fn exe_matches(state: &PolicyState, pid: u32, exe_path: &str) -> bool {
    match state.read().unwrap().get(&pid) {
        Some(stored) => stored.is_empty() || stored == &identity_of(exe_path),
        None => false,
    }
}

/// Drop PIDs that no longer exist. Bounds the set and the recycle window
/// (with identity validation, the residual window is ~one poll tick for
/// same-4-tuple reuse only).
pub fn retain_alive(state: &PolicyState, alive: &HashSet<u32>) {
    state.write().unwrap().retain(|p, _| alive.contains(p));
}

fn identity_of(exe_path: &str) -> String {
    exe_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(exe_path)
        .to_lowercase()
}
