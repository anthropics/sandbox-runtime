//! `srt-win probe …` — self-checks that report what the calling
//! process's own token can do, so a check can run under exactly the
//! sandboxed child's token. Only [`connect`] is in a default build;
//! the rest are `test-hooks` CI smoke hooks.

use anyhow::{Context, Result};
#[cfg(feature = "test-hooks")]
use serde::Serialize;

/// Direct TCP connect to `target` (`ip:port`), classified as an exit
/// code: 0 = refused by the WFP fence (`WSAEACCES`), 3 = connected,
/// 2 = any other error.
pub fn connect(target: &str) -> Result<u32> {
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;
    // The raw code, not `ErrorKind::PermissionDenied`:
    // `ERROR_ACCESS_DENIED` (5) is not the WFP fence.
    const WSAEACCES: i32 = 10013;
    let addr: SocketAddr = target
        .parse()
        .with_context(|| format!("egress probe target '{target}'"))?;
    match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Err(e) if e.raw_os_error() == Some(WSAEACCES) => {
            eprintln!("srt-win: runner: egress probe {target}: BLOCKED ({e})");
            Ok(0)
        }
        Ok(_) => {
            eprintln!(
                "srt-win: runner: egress probe {target}: CONNECTED — WFP \
                 block-user filter is NOT in effect"
            );
            Ok(3)
        }
        Err(e) => {
            eprintln!(
                "srt-win: runner: egress probe {target}: UNREACHABLE: {e} \
                 (kind={:?}, os={:?})",
                e.kind(),
                e.raw_os_error(),
            );
            Ok(2)
        }
    }
}

#[cfg(feature = "test-hooks")]
#[derive(Debug, Serialize)]
pub struct ParentAccess {
    pub parent_pid: u32,
    pub threads: usize,
    /// Every `<object>:<right>` open that **succeeded** — e.g.
    /// `process:PROCESS_VM_WRITE`, `thread:1234:THREAD_SET_CONTEXT`.
    pub opened: Vec<String>,
    /// Opens that failed with something other than access-denied.
    pub errors: Vec<String>,
}

/// Rights that let the holder write to, run code in, or take the token of the target.
#[cfg(feature = "test-hooks")]
const PROCESS_RIGHTS: &[(&str, u32)] = &[
    ("PROCESS_TERMINATE", 0x0001),
    ("PROCESS_CREATE_THREAD", 0x0002),
    ("PROCESS_VM_OPERATION", 0x0008),
    ("PROCESS_VM_WRITE", 0x0020),
    ("PROCESS_DUP_HANDLE", 0x0040),
    ("PROCESS_CREATE_PROCESS", 0x0080),
    ("PROCESS_SET_INFORMATION", 0x0200),
    // Needed to open the process token (for impersonation).
    ("PROCESS_QUERY_INFORMATION", 0x0400),
    ("PROCESS_SUSPEND_RESUME", 0x0800),
    ("WRITE_DAC", 0x0004_0000),
    ("WRITE_OWNER", 0x0008_0000),
];

#[cfg(feature = "test-hooks")]
const THREAD_RIGHTS: &[(&str, u32)] = &[
    ("THREAD_TERMINATE", 0x0001),
    ("THREAD_SUSPEND_RESUME", 0x0002),
    ("THREAD_SET_CONTEXT", 0x0010),
    ("THREAD_SET_INFORMATION", 0x0020),
    ("THREAD_SET_THREAD_TOKEN", 0x0080),
    ("THREAD_IMPERSONATE", 0x0100),
    ("THREAD_DIRECT_IMPERSONATION", 0x0200),
    ("WRITE_DAC", 0x0004_0000),
    ("WRITE_OWNER", 0x0008_0000),
];

/// Try to open this process's parent and each of its threads with
/// every right in [`PROCESS_RIGHTS`] / [`THREAD_RIGHTS`] and report
/// which opens succeeded.
#[cfg(feature = "test-hooks")]
pub fn parent_access() -> Result<ParentAccess> {
    use crate::util::{OwnedHandle, parent_pid_of, thread_ids_of};
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
    use windows::Win32::System::Threading::{
        GetCurrentProcessId, OpenProcess, OpenThread, PROCESS_ACCESS_RIGHTS, THREAD_ACCESS_RIGHTS,
    };

    let me = unsafe { GetCurrentProcessId() };
    let parent_pid = parent_pid_of(me)?.context("own process not in the process snapshot")?;
    let tids = thread_ids_of(parent_pid)?;
    let mut opened = Vec::new();
    let mut errors = Vec::new();
    let mut record = |label: String, r: windows::core::Result<_>| match r {
        Ok(h) => {
            drop(OwnedHandle(h));
            opened.push(label);
        }
        Err(e) if e.code() == ERROR_ACCESS_DENIED.to_hresult() => {}
        Err(e) => errors.push(format!("{label}: {e}")),
    };
    for (name, mask) in PROCESS_RIGHTS {
        record(format!("process:{name}"), unsafe {
            OpenProcess(PROCESS_ACCESS_RIGHTS(*mask), false, parent_pid)
        });
    }
    for tid in &tids {
        for (name, mask) in THREAD_RIGHTS {
            record(format!("thread:{tid}:{name}"), unsafe {
                OpenThread(THREAD_ACCESS_RIGHTS(*mask), false, *tid)
            });
        }
    }
    Ok(ParentAccess {
        parent_pid,
        threads: tids.len(),
        opened,
        errors,
    })
}
