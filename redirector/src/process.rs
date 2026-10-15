use std::collections::HashMap;
use std::sync::Mutex;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::core::PWSTR;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub exe_path: String,
    pub exe_name: String,
}

pub struct Resolver {
    cache: Mutex<HashMap<u32, Option<ProcessInfo>>>,
}

impl Resolver {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn resolve(&self, pid: u32) -> Option<ProcessInfo> {
        if pid == 0 || pid == 4 {
            return None;
        }
        {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(&pid) {
                return entry.clone();
            }
        }
        let info = lookup(pid);
        let mut cache = self.cache.lock().unwrap();
        // PIDs get reused and short-lived processes accumulate: cap the
        // cache so a long-running redirector can't grow it without bound.
        // A wrong (stale) entry only costs one extra lookup on next miss
        // because resolve() is always re-checked against the live process
        // table by callers via parent/exe matching.
        if cache.len() > 2000 {
            cache.clear();
        }
        cache.insert(pid, info.clone());
        info
    }

    /// Uncached resolve (skips the cache read, still populates it). For
    /// admission-time identity checks, where a stale entry is exactly the
    /// wrong answer (recycled PID still mapped to the previous owner).
    pub fn resolve_fresh(&self, pid: u32) -> Option<ProcessInfo> {
        if pid == 0 || pid == 4 {
            return None;
        }
        let info = lookup(pid);
        if let Ok(mut cache) = self.cache.lock() {
            if cache.len() > 2000 {
                cache.clear();
            }
            cache.insert(pid, info.clone());
        }
        info
    }

    /// Parent PID via Toolhelp32 snapshot. Uncached (cheap enough at
    /// first-packet rate, and parent relationships change over time).
    pub fn parent_of(&self, pid: u32) -> Option<u32> {
        parent_pid(pid)
    }

    /// Drop cache entries for dead PIDs. A stale entry maps a recycled PID
    /// to the previous owner's exe path, which mis-admits an unrelated new
    /// process on its first packet. Called by proc_watcher's GC sweep.
    pub fn retain_alive(&self, alive: &std::collections::HashSet<u32>) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.retain(|p, _| alive.contains(p));
        }
    }
}

pub fn parent_pid(pid: u32) -> Option<u32> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found: Option<u32> = None;
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    let ppid = entry.th32ParentProcessID;
                    if ppid != 0 && ppid != pid {
                        found = Some(ppid);
                    }
                    break;
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
        found
    }
}

fn lookup(pid: u32) -> Option<ProcessInfo> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let res = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(handle);
        res.ok()?;
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        let exe_name = path.rsplit('\\').next().unwrap_or(&path).to_string();
        Some(ProcessInfo {
            exe_path: path,
            exe_name,
        })
    }
}
