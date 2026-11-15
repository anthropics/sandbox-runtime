//! Broker / runner self-protection: rewrite this process's own DACL
//! so the sandbox child cannot `OpenProcess(our_pid,
//! PROCESS_VM_*|CREATE_THREAD|CREATE_PROCESS)`.
//!
//! The DACL is replaced with an explicit ALLOW list scoped to SIDs
//! the sandbox child does NOT have enabled in its token:
//!
//!   - SYSTEM (S-1-5-18) — child doesn't carry it
//!   - BUILTIN\Admins — child has it deny-only (LUA token)
//!   - OWNER RIGHTS = `READ_CONTROL` — suppresses the owner's
//!     implicit `WRITE_DAC`, which would otherwise let the child
//!     (same user as the runner = owner) `WRITE_DAC` it
//!
//! `PROTECTED_DACL_SECURITY_INFORMATION` is required: without it
//! the inherited "user has full access to their own process" ACE
//! survives and the rewrite is a no-op for same-user children.
//!
//! Called by both the **broker** (real user, before
//! `CreateProcessWithLogonW`) and the **runner** (`srt-sandbox`,
//! before [`crate::launch::run_lockdown`]) — with DIFFERENT
//! `extra_allow`:
//!
//!   - **broker** passes `Some(real-user-SID)`: the broker runs as
//!     the real user; adding `<real-user>:FA` lets non-elevated
//!     sibling tools (debuggers, task managers) open/query it. The
//!     child runs as `srt-sandbox`, so this ACE does not match the
//!     child.
//!   - **runner** passes `None`: the runner runs as `srt-sandbox`
//!     and so does the locked-down child. An `srt-sandbox:FA` ACE
//!     here would let the child `OpenProcess(PROCESS_CREATE_PROCESS,
//!     runner)` and parent-spawn under the runner's unrestricted
//!     token — exactly what self-protection exists to close. The
//!     runner DACL is therefore `[SY, BA, OW:RC]` only.
//!
//! The runner reaches itself via the `GetCurrentProcess()`
//! pseudo-handle (which bypasses the DACL).
//!
//! A process DACL does not cover the process's threads;
//! [`protect_own_threads`] gives them the same shape.

use anyhow::{Context, Result, anyhow};
use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT, SetSecurityInfo,
};
use windows::Win32::Security::{
    ACL, ACL_REVISION, AddAccessAllowedAce, DACL_SECURITY_INFORMATION, GetLengthSid, InitializeAcl,
    PROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::System::Threading::{GetCurrentProcess, PROCESS_ALL_ACCESS};
use windows::core::PWSTR;

use crate::sid::LocalPsid;

/// Open `current_exe()` with `share_mode = FILE_SHARE_READ` only (no
/// `FILE_SHARE_WRITE|FILE_SHARE_DELETE`) and return the handle. While
/// held, any attempt to open the file for write/delete — and
/// therefore rename-over / `MoveFileEx` /
/// `SetFileInformationByHandle(FileRenameInfo)` onto it — fails with
/// `ERROR_SHARING_VIOLATION`. Closes the "sandboxed command
/// overwrites the broker → next exec runs attacker binary" hole for
/// standalone `srt-win.exe` consumers under a `.`-granted cwd. Moot
/// when the consumer sets `srtWin.path = process.execPath` (a running
/// binary is already section-mapped), but standalone
/// `vendor/srt-win.exe` needs it.
///
/// Defense-in-depth only — call sites treat failure as
/// warn-and-continue so a third-party opener holding DELETE access
/// (AV/indexer/updater) can't DoS the exec path.
pub fn share_lock_current_exe() -> Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(std::env::current_exe().context("current_exe")?)
        .context("open current_exe with FILE_SHARE_READ-only")
}

/// Owner-Rights well-known SID (`S-1-3-4`). An ALLOW ACE on this SID
/// REPLACES the implicit `READ_CONTROL|WRITE_DAC` the object's owner
/// otherwise gets. Mask is `READ_CONTROL` for consistency with
/// [`crate::acl::Allow::OWNER_RIGHTS`]; mask-0 would also work here
/// (this path uses kernel `SetSecurityInfo`, which doesn't drop
/// mask-0 ACEs the way `SetNamedSecurityInfoW` does), but
/// `READ_CONTROL` is the project convention.
const SID_OWNER_RIGHTS: &str = "S-1-3-4";
const READ_CONTROL: u32 = 0x0002_0000;
const SID_SYSTEM: &str = "S-1-5-18";
const SID_BUILTIN_ADMINS: &str = "S-1-5-32-544";

/// Rewrite the current process's DACL to SYSTEM + Admins +
/// `OWNER_RIGHTS:READ_CONTROL`, plus an optional `extra_allow:FA`
/// ACE. The broker passes its real-user SID so non-elevated
/// real-user tools can still query/debug it; the runner passes
/// `None` (see module doc). Idempotent — safe to call once per
/// `srt-win exec` / `runner` invocation.
pub fn install_broker_dacl(extra_allow: Option<&str>) -> Result<()> {
    // RAII over `ConvertStringSidToSidW` → freed via `LocalFree` on
    // drop.
    let system = LocalPsid::from_string(SID_SYSTEM)?;
    let admins = LocalPsid::from_string(SID_BUILTIN_ADMINS)?;
    let owner_rights = LocalPsid::from_string(SID_OWNER_RIGHTS)?;
    let extra = extra_allow.map(LocalPsid::from_string).transpose()?;

    // (sid, mask) — SYSTEM/Admins (and the optional extra SID) get
    // full access; OWNER_RIGHTS gets READ_CONTROL only.
    let mut aces: Vec<(windows::Win32::Security::PSID, u32)> = Vec::with_capacity(4);
    aces.push((system.as_psid(), PROCESS_ALL_ACCESS.0));
    if let Some(ref e) = extra {
        aces.push((e.as_psid(), PROCESS_ALL_ACCESS.0));
    }
    aces.push((admins.as_psid(), PROCESS_ALL_ACCESS.0));
    aces.push((owner_rights.as_psid(), READ_CONTROL));

    let mut buf = build_allow_acl(&aces)?;
    let acl = buf.as_mut_ptr() as *mut ACL;
    unsafe {
        // PROTECTED strips inherited ACEs — without it the user
        // SID's default "full access to own process" inherited
        // grant fires and the rewrite is a no-op.
        let r = SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl),
            None,
        );
        if r.is_err() {
            return Err(anyhow!("SetSecurityInfo(broker process DACL): {r:?}"));
        }
    }
    // `buf` can drop here — `SetSecurityInfo` copies the ACL into
    // the kernel object's SECURITY_DESCRIPTOR.

    // Diagnostic: read back and dump the DACL as SDDL so CI can
    // confirm exactly what's on the broker process. Gated on
    // SANDBOX_RUNTIME_WIN_DEBUG — production callers (one exec per
    // user command) don't want a stderr line per command.
    if std::env::var_os("SANDBOX_RUNTIME_WIN_DEBUG").is_some() {
        match read_self_dacl_sddl() {
            Some(sddl) => eprintln!("srt-win: self-protect applied (DACL: {sddl})"),
            None => eprintln!("srt-win: self-protect applied"),
        }
    }
    Ok(())
}

/// Build an ACL of ACCESS_ALLOWED ACEs, one per `(sid, mask)`, in order.
fn build_allow_acl(aces: &[(windows::Win32::Security::PSID, u32)]) -> Result<Vec<u8>> {
    // Per ACE: 8-byte fixed prefix (Header 4 + Mask 4; `SidStart` is
    // the first DWORD of the SID) + `GetLengthSid`.
    const ACE_FIXED: usize = 8;
    let mut total = size_of::<ACL>();
    for (s, _) in aces {
        let len = unsafe { GetLengthSid(*s) } as usize;
        if len == 0 {
            return Err(anyhow!("GetLengthSid returned 0"));
        }
        total += ACE_FIXED + len;
    }
    total = (total + 3) & !3; // DWORD-align

    let mut buf = vec![0u8; total];
    let acl = buf.as_mut_ptr() as *mut ACL;
    unsafe {
        InitializeAcl(acl, total as u32, ACL_REVISION).context("InitializeAcl")?;
        for (s, mask) in aces {
            AddAccessAllowedAce(acl, ACL_REVISION, *mask, *s).context("AddAccessAllowedAce")?;
        }
    }
    Ok(buf)
}

/// Give every current thread of this process the DACL shape
/// [`install_broker_dacl`] gives the process (the process DACL does
/// not cover threads). Threads started later are not covered.
pub fn protect_own_threads() -> Result<usize> {
    use windows::Win32::Foundation::ERROR_INVALID_PARAMETER;
    use windows::Win32::System::Threading::{
        GetCurrentProcessId, OpenThread, THREAD_ACCESS_RIGHTS, THREAD_ALL_ACCESS,
    };
    /// `READ_CONTROL | WRITE_DAC` — what replacing a DACL needs.
    const DACL_RW: u32 = READ_CONTROL | 0x0004_0000;

    let system = LocalPsid::from_string(SID_SYSTEM)?;
    let admins = LocalPsid::from_string(SID_BUILTIN_ADMINS)?;
    let owner_rights = LocalPsid::from_string(SID_OWNER_RIGHTS)?;
    let mut buf = build_allow_acl(&[
        (system.as_psid(), THREAD_ALL_ACCESS.0),
        (admins.as_psid(), THREAD_ALL_ACCESS.0),
        (owner_rights.as_psid(), READ_CONTROL),
    ])?;
    let acl = buf.as_mut_ptr() as *mut ACL;

    let tids = crate::util::thread_ids_of(unsafe { GetCurrentProcessId() })?;
    if tids.is_empty() {
        return Err(anyhow!("thread snapshot lists no thread of this process"));
    }
    let mut protected = 0usize;
    for tid in &tids {
        unsafe {
            let h = match OpenThread(THREAD_ACCESS_RIGHTS(DACL_RW), false, *tid) {
                Ok(h) => crate::util::OwnedHandle(h),
                // The thread exited after the snapshot.
                Err(e) if e.code() == ERROR_INVALID_PARAMETER.to_hresult() => continue,
                Err(e) => return Err(anyhow!("OpenThread(WRITE_DAC, tid={tid}): {e}")),
            };
            let r = SetSecurityInfo(
                h.raw(),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(acl),
                None,
            );
            if r.is_err() {
                return Err(anyhow!("SetSecurityInfo(thread {tid} DACL): {r:?}"));
            }
            protected += 1;
        }
    }
    if protected == 0 {
        return Err(anyhow!("no thread of this process could be protected"));
    }
    Ok(protected)
}

/// Best-effort read of the current process's DACL as an SDDL
/// string. Returns `None` on any failure rather than erroring —
/// this is diagnostic only.
fn read_self_dacl_sddl() -> Option<String> {
    use crate::util::{from_pwstr, local_free};
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;
    unsafe {
        let mut psd = PSECURITY_DESCRIPTOR::default();
        let r = GetSecurityInfo(
            HANDLE(GetCurrentProcess().0),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut psd),
        );
        if r.is_err() || psd.0.is_null() {
            return None;
        }
        let mut s = PWSTR::null();
        let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut s,
            None,
        );
        local_free(psd.0);
        if ok.is_err() {
            return None;
        }
        let out = from_pwstr(s);
        local_free(s.0 as *mut c_void);
        Some(out)
    }
}
