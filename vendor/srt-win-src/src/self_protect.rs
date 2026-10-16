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
//! A process DACL does not cover the process's **threads** — each
//! thread object has its own descriptor, taken from the creating
//! token's default DACL, which grants the account full access. A
//! child running as the same account could open a runner thread for
//! `THREAD_SET_CONTEXT` or `THREAD_DIRECT_IMPERSONATION` and act with
//! the runner's token, which is not locked down. The runner closes
//! that on every launch with two pieces, both keyed on the same
//! trustees as the process DACL:
//!
//!   - [`protect_own_threads`] rewrites the DACL of every thread the
//!     runner has;
//!   - [`protect_future_threads`] rewrites the runner token's default
//!     DACL, so a thread created afterwards (by the runner, the
//!     runtime or the thread pool) starts out with the same shape.
//!
//! Neither depends on how the child's token is restricted: the DACLs
//! name neither the account's user SID nor a logon SID, and the
//! `OWNER RIGHTS` ACE takes away what ownership would otherwise give.

use anyhow::{Context, Result, anyhow};
use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT, SetSecurityInfo,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, AddAccessAllowedAce,
    DACL_SECURITY_INFORMATION, GetAce, GetLengthSid, InitializeAcl,
    PROTECTED_DACL_SECURITY_INFORMATION, PSID,
};
use windows::Win32::System::Threading::{GetCurrentProcess, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS};
use windows::core::PWSTR;

use crate::sid::LocalPsid;
use crate::util::OwnedHandle;

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

const SYNCHRONIZE: u32 = 0x0010_0000;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
/// Thread access that gives its holder nothing to act with: reading
/// the descriptor, waiting for exit, and the exit code and times.
const THREAD_RIGHTS_HARMLESS: u32 = READ_CONTROL | SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION;

/// Every single access right of a thread object outside
/// [`THREAD_RIGHTS_HARMLESS`] — the rights the sandbox account must
/// not be able to open a runner thread with. Includes the ones that
/// lend out the runner's identity or control (`THREAD_IMPERSONATE`,
/// `THREAD_DIRECT_IMPERSONATION`, `THREAD_SET_THREAD_TOKEN`,
/// `THREAD_SET_CONTEXT`, `THREAD_SET_INFORMATION`,
/// `THREAD_SUSPEND_RESUME`, `THREAD_TERMINATE`) and the ones that
/// would let the holder grant itself those (`WRITE_DAC`,
/// `WRITE_OWNER`).
fn withheld_thread_rights() -> impl Iterator<Item = u32> {
    (0..u32::BITS)
        .map(|bit| 1u32 << bit)
        .filter(|right| THREAD_ALL_ACCESS.0 & right != 0 && THREAD_RIGHTS_HARMLESS & right == 0)
}

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

/// Build an ACL of ACCESS_ALLOWED ACEs, one per `(sid, mask)`, in
/// order. The returned buffer is the ACL; cast `.as_mut_ptr()` to
/// `*mut ACL`.
fn build_allow_acl(aces: &[(windows::Win32::Security::PSID, u32)]) -> Result<Vec<u8>> {
    // ACL size = header + Σ(ACE fixed prefix + SID body). The fixed
    // prefix of an ACCESS_ALLOWED_ACE is 8 bytes (Header 4 + Mask 4);
    // `SidStart` is the first DWORD of the SID, so total per-ACE =
    // 8 + GetLengthSid.
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

/// Rewrite the DACL of every thread this process currently has to
/// SYSTEM + Admins + `OWNER_RIGHTS:READ_CONTROL` — the same shape
/// [`install_broker_dacl`] gives the process, for the same reason. A
/// thread object carries its own security descriptor, taken from the
/// creating token's default DACL, which grants the account full
/// access; the process DACL does not cover it. Without this a child
/// running as the same account can open a runner thread for
/// `THREAD_SET_CONTEXT` or `THREAD_DIRECT_IMPERSONATION` and act with
/// the runner's token, which is not locked down.
///
/// Repeatable. A thread this process can no longer open for a DACL
/// rewrite — one an earlier call already rewrote, one created after
/// [`protect_future_threads`], or one another principal created in
/// this process — is checked instead: it counts as protected only if
/// this process, whose token holds every SID the child's does, is
/// refused each right in [`withheld_thread_rights`].
///
/// Returns the number of threads rewritten or found protected; a
/// thread that is neither is an error.
pub fn protect_own_threads() -> Result<usize> {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};
    use windows::Win32::System::Threading::{
        GetCurrentProcessId, OpenThread, THREAD_ACCESS_RIGHTS,
    };
    /// `READ_CONTROL | WRITE_DAC` — what replacing a DACL needs.
    const DACL_RW: u32 = 0x0002_0000 | 0x0004_0000;

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
                // The thread exited after the snapshot: nothing left
                // to protect.
                Err(e) if e.code() == ERROR_INVALID_PARAMETER.to_hresult() => continue,
                // No DACL access for this process: accept the thread
                // only if it is already out of the account's reach.
                Err(e) if e.code() == ERROR_ACCESS_DENIED.to_hresult() => {
                    if let Some(right) = openable_withheld_right(*tid)? {
                        return Err(anyhow!(
                            "thread {tid}: its DACL cannot be rewritten and it grants \
                             this account access {right:#x}"
                        ));
                    }
                    protected += 1;
                    continue;
                }
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

/// The first right in [`withheld_thread_rights`] this process can
/// open thread `tid` with, or `None` when every one is refused (or
/// the thread has exited). Opens by ID, so the answer is what the
/// thread's descriptor grants this process's token — and the child's
/// token holds no SID this one lacks.
fn openable_withheld_right(tid: u32) -> Result<Option<u32>> {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};
    use windows::Win32::System::Threading::{OpenThread, THREAD_ACCESS_RIGHTS};
    for right in withheld_thread_rights() {
        match unsafe { OpenThread(THREAD_ACCESS_RIGHTS(right), false, tid) } {
            Ok(h) => {
                drop(OwnedHandle(h));
                return Ok(Some(right));
            }
            Err(e) if e.code() == ERROR_ACCESS_DENIED.to_hresult() => {}
            Err(e) if e.code() == ERROR_INVALID_PARAMETER.to_hresult() => return Ok(None),
            Err(e) => return Err(anyhow!("OpenThread({right:#x}, tid={tid}): {e}")),
        }
    }
    Ok(None)
}

/// Rewrite this process's token default DACL to SYSTEM + Admins +
/// `OWNER_RIGHTS:READ_CONTROL`, so that a thread created from now on
/// starts out with the DACL [`protect_own_threads`] gives the
/// existing ones. Thread objects get their descriptor from the
/// creating token's default DACL, and nothing announces a new thread
/// (the runtime and the thread pool start them on their own), so a
/// sweep alone cannot cover them.
///
/// The default DACL also lands on every other object this process
/// creates without an explicit descriptor — including a child
/// process, its first thread and its token, which the child must be
/// able to open. **Call it only once every such object exists**:
/// [`crate::launch::run_lockdown`] calls it after the child has been
/// created and before it is resumed, after which the runner creates
/// nothing else.
///
/// Verifies the effect before returning: a thread started here must
/// carry a DACL that passes [`dacl_shuts_out_account`], or the call
/// fails.
pub fn protect_future_threads() -> Result<()> {
    use windows::Win32::Security::{
        SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_DEFAULT_DACL, TOKEN_QUERY,
        TokenDefaultDacl,
    };
    use windows::Win32::System::Threading::OpenProcessToken;
    const GENERIC_ALL: u32 = 0x1000_0000;

    let system = LocalPsid::from_string(SID_SYSTEM)?;
    let admins = LocalPsid::from_string(SID_BUILTIN_ADMINS)?;
    let owner_rights = LocalPsid::from_string(SID_OWNER_RIGHTS)?;
    let mut buf = build_allow_acl(&[
        (system.as_psid(), GENERIC_ALL),
        (admins.as_psid(), GENERIC_ALL),
        (owner_rights.as_psid(), READ_CONTROL),
    ])?;
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_DEFAULT | TOKEN_QUERY,
            &mut tok,
        )
        .context("OpenProcessToken(TOKEN_ADJUST_DEFAULT)")?;
        let tok = OwnedHandle(tok);
        let tdd = TOKEN_DEFAULT_DACL {
            DefaultDacl: buf.as_mut_ptr() as *mut ACL,
        };
        SetTokenInformation(
            tok.raw(),
            TokenDefaultDacl,
            &tdd as *const _ as *const c_void,
            size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
        .context("SetTokenInformation(runner DefaultDacl)")?;
    }

    let aces = new_thread_ace_views()?;
    if !dacl_shuts_out_account(&aces) {
        return Err(anyhow!(
            "a thread created after the default-DACL change is still open to \
             the account (DACL: {aces:?})"
        ));
    }
    Ok(())
}

/// Start a thread, read the DACL it was created with, and let it end.
fn new_thread_ace_views() -> Result<Vec<AceView>> {
    use std::os::windows::io::AsRawHandle;
    let (release, wait) = std::sync::mpsc::channel::<()>();
    let probe = std::thread::Builder::new()
        .spawn(move || {
            // Ends when `release` is dropped.
            let _ = wait.recv();
        })
        .context("spawn default-DACL probe thread")?;
    // The creation handle carries full access, whatever the DACL says.
    let aces = thread_ace_views(HANDLE(probe.as_raw_handle()));
    drop(release);
    let _ = probe.join();
    aces
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AceKind {
    Allow,
    Deny,
    /// Any ACE type other than the two basic ones.
    Other,
}

/// One ACE of a DACL, reduced to what [`dacl_shuts_out_account`]
/// reads. `sid` is empty and `mask` is 0 for [`AceKind::Other`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct AceView {
    kind: AceKind,
    sid: String,
    mask: u32,
}

/// Whether a DACL with these ACEs leaves the sandbox account nothing
/// but `READ_CONTROL` on an object the account owns: every ALLOW ACE
/// names SYSTEM, Admins, or `OWNER RIGHTS` with at most
/// `READ_CONTROL`, and an `OWNER RIGHTS` ACE is present (without one
/// the owner may rewrite the DACL). An ACE of a type this does not
/// know fails the check.
fn dacl_shuts_out_account(aces: &[AceView]) -> bool {
    let mut owner_limited = false;
    for ace in aces {
        match (ace.kind, ace.sid.as_str()) {
            (AceKind::Deny, _) => {}
            (AceKind::Allow, SID_SYSTEM | SID_BUILTIN_ADMINS) => {}
            (AceKind::Allow, SID_OWNER_RIGHTS) if ace.mask & !READ_CONTROL == 0 => {
                owner_limited = true;
            }
            _ => return false,
        }
    }
    owner_limited
}

/// The ACEs of `acl`, in order.
fn ace_views(acl: *const ACL) -> Result<Vec<AceView>> {
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;
    let mut out = Vec::new();
    unsafe {
        for i in 0..u32::from((*acl).AceCount) {
            let mut p: *mut c_void = std::ptr::null_mut();
            GetAce(acl, i, &mut p).context("GetAce")?;
            let kind = match (*(p as *const ACE_HEADER)).AceType {
                ACCESS_ALLOWED_ACE_TYPE => AceKind::Allow,
                ACCESS_DENIED_ACE_TYPE => AceKind::Deny,
                _ => AceKind::Other,
            };
            out.push(if kind == AceKind::Other {
                AceView {
                    kind,
                    sid: String::new(),
                    mask: 0,
                }
            } else {
                // ALLOW and DENY ACEs share one layout: header, mask,
                // then the SID in place.
                let ace = p as *const ACCESS_ALLOWED_ACE;
                let sid = PSID(std::ptr::addr_of!((*ace).SidStart) as *mut c_void);
                AceView {
                    kind,
                    sid: crate::sid::psid_to_string(sid)?,
                    mask: (*ace).Mask,
                }
            });
        }
    }
    Ok(out)
}

/// The ACEs of the DACL on the thread behind `thread` (a handle with
/// `READ_CONTROL`). A thread with no DACL at all is an error.
fn thread_ace_views(thread: HANDLE) -> Result<Vec<AceView>> {
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;
    unsafe {
        let mut psd = PSECURITY_DESCRIPTOR::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let r = GetSecurityInfo(
            thread,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            Some(&mut psd),
        );
        if r.is_err() {
            return Err(anyhow!("GetSecurityInfo(thread DACL): {r:?}"));
        }
        let out = if dacl.is_null() {
            Err(anyhow!("thread has no DACL"))
        } else {
            ace_views(dacl)
        };
        crate::util::local_free(psd.0);
        out
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ace(kind: AceKind, sid: &str, mask: u32) -> AceView {
        AceView {
            kind,
            sid: sid.to_string(),
            mask,
        }
    }

    #[test]
    fn withheld_rights_cover_everything_but_the_harmless_ones() {
        let withheld: Vec<u32> = withheld_thread_rights().collect();
        // One bit each.
        assert!(withheld.iter().all(|r| r.count_ones() == 1));
        let union = withheld.iter().fold(0, |acc, r| acc | r);
        assert_eq!(union & THREAD_RIGHTS_HARMLESS, 0);
        assert_eq!(union | THREAD_RIGHTS_HARMLESS, THREAD_ALL_ACCESS.0);
        for (name, right) in [
            ("THREAD_TERMINATE", 0x0001),
            ("THREAD_SUSPEND_RESUME", 0x0002),
            ("THREAD_GET_CONTEXT", 0x0008),
            ("THREAD_SET_CONTEXT", 0x0010),
            ("THREAD_SET_INFORMATION", 0x0020),
            ("THREAD_QUERY_INFORMATION", 0x0040),
            ("THREAD_SET_THREAD_TOKEN", 0x0080),
            ("THREAD_IMPERSONATE", 0x0100),
            ("THREAD_DIRECT_IMPERSONATION", 0x0200),
            ("WRITE_DAC", 0x0004_0000),
            ("WRITE_OWNER", 0x0008_0000),
        ] {
            assert!(withheld.contains(&right), "{name} must be withheld");
        }
        assert!(!withheld.contains(&READ_CONTROL));
    }

    #[test]
    fn dacl_check_accepts_only_the_protected_shape() {
        const USER: &str = "S-1-5-21-1-2-3-1001";
        const LOGON: &str = "S-1-5-5-0-123456";
        let all = THREAD_ALL_ACCESS.0;
        let protected = [
            ace(AceKind::Allow, SID_SYSTEM, all),
            ace(AceKind::Allow, SID_BUILTIN_ADMINS, all),
            ace(AceKind::Allow, SID_OWNER_RIGHTS, READ_CONTROL),
        ];
        assert!(dacl_shuts_out_account(&protected));
        // A DENY ACE grants nothing, whoever it names.
        let mut with_deny = protected.to_vec();
        with_deny.insert(0, ace(AceKind::Deny, USER, all));
        assert!(dacl_shuts_out_account(&with_deny));

        // What a thread gets from an unchanged default DACL.
        assert!(!dacl_shuts_out_account(&[
            ace(AceKind::Allow, USER, all),
            ace(AceKind::Allow, SID_SYSTEM, all),
            ace(AceKind::Allow, LOGON, 0x0012_0000),
        ]));
        // Any ACE for the account or a logon SID, however narrow.
        for extra in [USER, LOGON, "S-1-1-0", "S-1-5-11", "S-1-5-32-545"] {
            let mut aces = protected.to_vec();
            aces.push(ace(AceKind::Allow, extra, 0x0010));
            assert!(!dacl_shuts_out_account(&aces), "{extra}");
        }
        // No OWNER RIGHTS ACE: the owner keeps WRITE_DAC.
        assert!(!dacl_shuts_out_account(&protected[..2]));
        // OWNER RIGHTS with more than READ_CONTROL.
        assert!(!dacl_shuts_out_account(&[
            ace(AceKind::Allow, SID_SYSTEM, all),
            ace(AceKind::Allow, SID_OWNER_RIGHTS, READ_CONTROL | 0x0004_0000),
        ]));
        // An ACE type the check does not understand.
        let mut with_other = protected.to_vec();
        with_other.push(ace(AceKind::Other, "", 0));
        assert!(!dacl_shuts_out_account(&with_other));
        // An empty DACL grants nothing, but leaves the owner WRITE_DAC.
        assert!(!dacl_shuts_out_account(&[]));
    }

    #[test]
    fn built_acl_reads_back_as_written() {
        let system = LocalPsid::from_string(SID_SYSTEM).unwrap();
        let owner_rights = LocalPsid::from_string(SID_OWNER_RIGHTS).unwrap();
        let buf = build_allow_acl(&[
            (system.as_psid(), THREAD_ALL_ACCESS.0),
            (owner_rights.as_psid(), READ_CONTROL),
        ])
        .unwrap();
        let aces = ace_views(buf.as_ptr() as *const ACL).unwrap();
        assert_eq!(
            aces,
            [
                ace(AceKind::Allow, SID_SYSTEM, THREAD_ALL_ACCESS.0),
                ace(AceKind::Allow, SID_OWNER_RIGHTS, READ_CONTROL),
            ]
        );
    }

    /// The sweep covers a thread it has already covered: the second
    /// call either rewrites it again or finds it out of reach.
    #[test]
    fn protect_own_threads_is_repeatable() {
        let first = protect_own_threads().expect("first sweep");
        assert!(first >= 1);
        let second = protect_own_threads().expect("second sweep");
        assert!(second >= 1);
        // The thread running this test now has the protected shape.
        let me = unsafe {
            windows::Win32::System::Threading::OpenThread(
                windows::Win32::System::Threading::THREAD_ACCESS_RIGHTS(READ_CONTROL),
                false,
                windows::Win32::System::Threading::GetCurrentThreadId(),
            )
        }
        .map(OwnedHandle)
        .expect("READ_CONTROL on own thread");
        let aces = thread_ace_views(me.raw()).unwrap();
        assert!(dacl_shuts_out_account(&aces), "{aces:?}");
    }
}
