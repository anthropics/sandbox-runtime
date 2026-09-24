//! Broker-side grants on the session's kernel objects so the two-hop
//! runner+child can attach them: the per-exec [`IsolatedDesk`] on
//! `WinSta0`, [`grant_sandbox_on_winsta`] on the station itself, and
//! [`grant_sandbox_on_session_bno`] on
//! `\Sessions\<TS>\BaseNamedObjects`.
//!
//! **Isolated desktop.** The broker creates a per-exec named desktop
//! on its current window station, passes the `<winsta>\<desk>` path
//! via `CreateProcessWithLogonW`'s `lpDesktop`, the runner lands
//! there, the lockdown child inherits it (`lpDesktop = NULL` in
//! `CreateProcessAsUserW`); neither can enumerate or message
//! top-level windows on the interactive `WinSta0\Default`, and a
//! co-located human's keystrokes are not capturable
//! (`WH_KEYBOARD_LL` is per-desktop; the Job's `UILIMIT_HANDLES` does
//! NOT gate low-level hooks, so desktop separation is the only
//! fence for that vector).
//!
//! Why the broker creates it (not the runner): the interactive user
//! has `WINSTA_CREATEDESKTOP` on `WinSta0` non-elevated (verified by
//! probe). When `lpDesktop != NULL`, seclogon **skips** its station
//! auto-grant for the new logon, so the runner cannot attach
//! `WinSta0` without an explicit ACE (verified by probe — child
//! `DLL_INIT_FAILED` without it) — hence
//! [`grant_sandbox_on_winsta`]: the broker adds attach-level rights
//! for the `srt-sandbox` **user** SID before resume. The grant is on
//! the user SID (not the per-logon SID) because seclogon stamps the
//! **broker's** interactive logon SID into the runner's
//! `TokenGroups` (`whoami /logonid` is identical for broker and
//! runner; the per-CPWLW logon session exists only at the
//! `AuthenticationId` LUID level, not as a distinct `S-1-5-5-*`
//! group), so there is no separate runner logon SID to grant. The
//! lockdown child inherits the runner's already-attached
//! station+desktop, so its deny-only logon SID never matters for
//! station attach.
//!
//! **Session BNO.** The lockdown child has every `SE_GROUP_LOGON_ID`
//! SID deny-only ([`crate::token::make_sandbox_token`]). The session
//! `BaseNamedObjects` directory grants `CREATE_OBJECT |
//! CREATE_SUBDIRECTORY` only to the broker's logon SID; Everyone gets
//! `QUERY | TRAVERSE`. So the child can open existing named objects
//! but cannot create the per-DLL **subdirectory** msys2/cygwin needs
//! for its shared heap (`NtCreateDirectoryObject … 0xC0000022`).
//! [`grant_sandbox_on_session_bno`] adds `(A;;DIRECTORY_QUERY|
//! TRAVERSE|CREATE_OBJECT|CREATE_SUBDIRECTORY;;;<srt-sandbox>)` so
//! the **user** SID carries the create rights independently of the
//! disabled logon SID. Unlike `WinSta0`, the BNO is an ordinary
//! object-manager directory whose access check honours user-SID ACEs;
//! and the broker's user SID has full control on it (verified by
//! probe), so the broker can write the DACL non-elevated.
//!
//! **Both grants persist for the session — no revoke-on-drop.**
//! Concurrent brokers (parallel `srt-win exec`, the normal case for a
//! parallel build) share one station and one BNO; the first to finish
//! revoking the only `srt-sandbox` ACE would kill the second's
//! still-running child. The ACE is on a per-logon-session object
//! (gone at logoff) and grants `srt-sandbox` no more than what
//! seclogon would have granted for `lpDesktop = NULL`, so leaving it
//! is harmless. The grant is idempotent (drop-then-readd), so the
//! first broker per session does one read+write and later brokers
//! converge to a no-op.
//!
//! Desktop-only — no `CreateWindowStationW`. Creating a new window
//! station requires create rights on the session's
//! `\Windows\WindowStations` object directory, which a non-elevated
//! token does not have on a standard interactive session
//! (`CreateWindowStationW → ACCESS_DENIED`, verified by probe). A
//! separate desktop already provides the isolation that matters: a
//! window's message queue is per-desktop, so processes on different
//! desktops cannot `SendMessage`/enumerate/`WH_*`-hook each other.
//! The clipboard- and atom-table separation a separate station would
//! add is already covered by the Job's UI limits
//! (`JOB_OBJECT_UILIMIT_READCLIPBOARD | WRITECLIPBOARD | GLOBALATOMS`).
//!
//! The kernel reference-counts a desktop by attached threads/handles.
//! The broker keeps the [`IsolatedDesk`] handle open from creation
//! until after the runner exits — dropping it then releases the
//! kernel object.

use anyhow::{Context, Result, anyhow};
use std::ffi::c_void;
use std::mem::size_of;
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    NtOpenDirectoryObject, NtQuerySecurityObject, NtSetSecurityObject,
};
use windows::Win32::Foundation::{
    HANDLE, OBJ_CASE_INSENSITIVE, STATUS_ACCESS_DENIED, UNICODE_STRING,
};
use windows::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetUserObjectSecurity,
    InitializeSecurityDescriptor, PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR,
    SetSecurityDescriptorDacl, SetUserObjectSecurity,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, CreateDesktopW, DESKTOP_CONTROL_FLAGS, GetProcessWindowStation, GetThreadDesktop,
    GetUserObjectInformationW, HDESK, UOI_NAME,
};
use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::core::PCWSTR;

use crate::acl::{
    Allow, Mask, NO_INHERIT, NewAce, SID_SYSTEM, ace_sid_is, build_allow_dacl, filter_aces,
    rebuild_acl,
};
use crate::sid::{current_user_sid, sid_bytes};
use crate::util::{OwnedHandle, wstr};

// winuser.h: DESKTOP_ALL_ACCESS = 0x1FF. OR with
// STANDARD_RIGHTS_REQUIRED so the creator holds full control on the
// object it just made.
const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F_0000;
const DESK_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | 0x0000_01FF;

/// `WINSTA_ALL_ACCESS | READ_CONTROL` (`0x2037F`). NOT `WRITE_DAC |
/// WRITE_OWNER | DELETE`: the sandbox-user SID is enabled in the
/// child token, so granting those would let the child rewrite the
/// station's DACL. `READ_CONTROL` is harmless and **load-bearing** —
/// without it the runner hangs during process init when the loader
/// opens the station for the `lpDesktop` attach (verified on the
/// Windows CI runner).
const WINSTA_GRANT_MASK: u32 = 0x0002_037F;

/// `DIRECTORY_QUERY | TRAVERSE | CREATE_OBJECT | CREATE_SUBDIRECTORY`
/// — the rights the broker's logon SID carries on the session BNO,
/// re-granted to the `srt-sandbox` user SID. NOT `WRITE_DAC`: the
/// sandbox child must not be able to widen the session BNO's DACL.
const BNO_GRANT_MASK: u32 = 0x0000_000F;

/// RAII holder for a per-exec desktop on the caller's current window
/// station, plus the wide `<winsta>\<desk>` buffer that backs
/// `STARTUPINFOW.lpDesktop`.
pub struct IsolatedDesk {
    desktop: HDESK,
    /// `STARTUPINFOW.lpDesktop` is `PWSTR` (mutable wide pointer per
    /// the API contract), so we keep the buffer here and hand out a
    /// raw pointer via [`desktop_name_ptr`]. Null-terminated.
    desk_path: Vec<u16>,
}

impl IsolatedDesk {
    /// Create a fresh per-exec desktop on the **current** window
    /// station — no `SetProcessWindowStation` dance. Explicit DACL
    /// `[broker-user, srt-sandbox, SYSTEM] : GENERIC_ALL` so the
    /// runner and lockdown child (both `srt-sandbox`) can attach.
    ///
    /// Name = `srt-sb-<pid>-<rand32>` (random suffix so concurrent
    /// execs in the same process — e.g. tests — don't collide; the
    /// kernel-assigned name is read back for the `lpDesktop` path).
    pub fn new(sb_sid: &str) -> Result<Self> {
        // Current station name (for the `<winsta>\<desk>` path). The
        // child's `lpDesktop` carries this name verbatim, so if the
        // read failed a guessed `WinSta0` would point the child at a
        // station the runner may not even be on — propagate.
        let ws_name = current_winsta_name().context("read caller's window-station name")?;

        // pid + 32 random bits (system CSPRNG). The random suffix
        // is what makes concurrent same-process callers (e.g. test
        // threads) collision-free, so don't quietly fall back to a
        // zero suffix on RNG failure — surface it. `BCryptGenRandom`
        // with `USE_SYSTEM_PREFERRED_RNG` essentially never fails.
        let mut r = [0u8; 4];
        unsafe { BCryptGenRandom(None, &mut r, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }
            .ok()
            .context("BCryptGenRandom (desktop name suffix)")?;
        let req = format!(
            "srt-sb-{}-{:08x}",
            std::process::id(),
            u32::from_le_bytes(r),
        );
        let req_w = wstr(&req);

        // Explicit DACL — the broker is a different user from the
        // runner/child, so the default DACL (broker's TokenDefaultDacl)
        // would deny `srt-sandbox`. `OwnedSa` heap-pins the SD; keep
        // it alive until `CreateDesktopW` returns.
        let me = current_user_sid()?;
        let sa = build_allow_dacl(&[
            Allow(&me, Mask::GENERIC_ALL, NO_INHERIT),
            Allow(sb_sid, Mask::GENERIC_ALL, NO_INHERIT),
            Allow(SID_SYSTEM, Mask::GENERIC_ALL, NO_INHERIT),
        ])?
        .into_security_attributes()?;

        let desktop = unsafe {
            CreateDesktopW(
                PCWSTR(req_w.as_ptr()),
                PCWSTR::null(),
                None,
                DESKTOP_CONTROL_FLAGS(0),
                DESK_ALL_ACCESS,
                Some(sa.as_ptr()),
            )
        }
        .with_context(|| format!("CreateDesktopW({req}) on {ws_name}"))?;
        // `sa` (OwnedSa: ACL + SD + SECURITY_ATTRIBUTES) drops here.

        // Read back the actual assigned name.
        let desk_name = match object_name(HANDLE(desktop.0)) {
            Ok(n) => n,
            Err(e) => {
                unsafe {
                    let _ = CloseDesktop(desktop);
                }
                return Err(e.context("UOI_NAME on new desktop"));
            }
        };

        let desk_path = wstr(&format!("{ws_name}\\{desk_name}"));
        Ok(Self { desktop, desk_path })
    }

    /// Pointer to the wide name buffer for `STARTUPINFOW.lpDesktop`.
    /// Caller must keep `self` alive until after the create-process
    /// call returns.
    pub fn desktop_name_ptr(&mut self) -> *mut u16 {
        self.desk_path.as_mut_ptr()
    }
}

impl Drop for IsolatedDesk {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseDesktop(self.desktop);
        }
    }
}

/// Add `(A;;WINSTA_ALL_ACCESS;;;<sb_sid>)` to the broker's window
/// station. Idempotent (any existing `<sb_sid>` ACE is dropped before
/// the fresh one is appended). Persists for the broker's logon
/// session — see module doc for why there is no revoke.
pub fn grant_sandbox_on_winsta(sb_sid: &str) -> Result<()> {
    let ws = unsafe { GetProcessWindowStation() }.context("GetProcessWindowStation")?;
    if ws.0.is_null() {
        return Err(anyhow!("GetProcessWindowStation returned null"));
    }
    let h = HANDLE(ws.0);
    // The windows-crate bindings type Get's `psirequested` as
    // `*const u32` and Set's as `*const OBJECT_SECURITY_INFORMATION`;
    // both are the same `DACL_SECURITY_INFORMATION` value.
    let si = DACL_SECURITY_INFORMATION;
    recompose_dacl(
        "WinSta0",
        &sid_bytes(sb_sid)?,
        WINSTA_GRANT_MASK,
        || {
            let mut needed = 0u32;
            unsafe {
                let _ = GetUserObjectSecurity(h, &si.0, None, 0, &mut needed);
            }
            if needed == 0 {
                return Err(anyhow!("GetUserObjectSecurity sizing returned 0"));
            }
            let mut sd = vec![0u8; needed as usize];
            unsafe {
                GetUserObjectSecurity(
                    h,
                    &si.0,
                    Some(PSECURITY_DESCRIPTOR(sd.as_mut_ptr() as *mut c_void)),
                    needed,
                    &mut needed,
                )
                .context("GetUserObjectSecurity(DACL)")?;
            }
            Ok(sd)
        },
        |psd| unsafe { SetUserObjectSecurity(h, &si, psd).context("SetUserObjectSecurity(DACL)") },
    )
    .context("grant srt-sandbox on WinSta0")
}

/// Add `(A;;0xF;;;<sb_sid>)` to `\Sessions\<broker-TS>\
/// BaseNamedObjects`. Idempotent. Persists for the broker's logon
/// session — see module doc for why there is no revoke. The broker's
/// **user** SID has full control on the session BNO (verified by
/// probe), so this works non-elevated.
pub fn grant_sandbox_on_session_bno(sb_sid: &str) -> Result<()> {
    let bno = open_session_bno()?;
    let si = DACL_SECURITY_INFORMATION.0;
    recompose_dacl(
        "session BNO",
        &sid_bytes(sb_sid)?,
        BNO_GRANT_MASK,
        || {
            // Two-call sizing — `NtQuerySecurityObject` returns
            // STATUS_BUFFER_TOO_SMALL and writes the needed length.
            let mut needed = 0u32;
            unsafe {
                let _ = NtQuerySecurityObject(bno.raw(), si, None, 0, &mut needed);
            }
            if needed == 0 {
                return Err(anyhow!("NtQuerySecurityObject sizing returned 0"));
            }
            let mut sd = vec![0u8; needed as usize];
            unsafe {
                NtQuerySecurityObject(
                    bno.raw(),
                    si,
                    Some(PSECURITY_DESCRIPTOR(sd.as_mut_ptr() as *mut c_void)),
                    needed,
                    &mut needed,
                )
            }
            .ok()
            .context("NtQuerySecurityObject(DACL)")?;
            Ok(sd)
        },
        |psd| unsafe {
            NtSetSecurityObject(bno.raw(), si, psd)
                .ok()
                .context("NtSetSecurityObject(DACL)")
        },
    )
    .context("grant srt-sandbox on session BaseNamedObjects")
}

/// `NtOpenDirectoryObject(\Sessions\<broker-TS>\BaseNamedObjects,
/// READ_CONTROL | WRITE_DAC)`. The direct path (not via the
/// `\Sessions\BNOLINKS\<TS>` symlink) so the open targets the
/// directory object itself.
fn open_session_bno() -> Result<OwnedHandle> {
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;

    let mut ts = 0u32;
    unsafe { ProcessIdToSessionId(std::process::id(), &mut ts) }
        .context("ProcessIdToSessionId(broker)")?;
    let path = format!("\\Sessions\\{ts}\\BaseNamedObjects");
    let (mut path_w, bytes) = crate::util::counted_utf16(&path);
    let name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: windows::core::PWSTR(path_w.as_mut_ptr()),
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        ..Default::default()
    };
    let mut h = HANDLE::default();
    let st = unsafe { NtOpenDirectoryObject(&mut h, READ_CONTROL | WRITE_DAC, &oa) };
    if st.is_err() {
        // STATUS_ACCESS_DENIED → the broker is not the interactive
        // user (e.g. service context with no full-control ACE on
        // this session's BNO). The grant is what makes msys2/cygwin
        // work under the lockdown token, so surface why.
        let why = if st == STATUS_ACCESS_DENIED {
            " — broker lacks WRITE_DAC on the session BNO (not the \
             interactive user?)"
        } else {
            ""
        };
        return Err(anyhow!(
            "NtOpenDirectoryObject({path}, READ_CONTROL|WRITE_DAC): \
             NTSTATUS 0x{:08X}{why}",
            st.0
        ));
    }
    Ok(OwnedHandle(h))
}

/// Walk-and-rebuild a kernel-object DACL: `read` returns the current
/// self-relative SD; drop any existing ACE for `target_sid`, append
/// one `(A;;mask;;;<target_sid>)`, then `write` the resulting
/// absolute SD. Shared by the WinSta0 grant (user-object SD APIs)
/// and the session-BNO grant (NT-native SD APIs). The broker is the
/// interactive user → it has `READ_CONTROL | WRITE_DAC` on both
/// objects non-elevated.
///
/// Walk-and-rebuild (not `SetEntriesInAclW`) so the round-trip is
/// byte-faithful for ACEs we don't touch. The walk is
/// [`crate::acl::filter_aces`] with a SID-match predicate; unlike
/// `apply_sandbox_aces` this **keeps** inherited ACEs (kernel
/// objects don't get the `UNPROTECTED`-re-derive treatment).
fn recompose_dacl(
    what: &str,
    target_sid: &[u8],
    mask: u32,
    read: impl FnOnce() -> Result<Vec<u8>>,
    write: impl FnOnce(PSECURITY_DESCRIPTOR) -> Result<()>,
) -> Result<()> {
    // 1) Read the current SD (self-relative).
    let sd_buf = read()?;
    let mut present = Default::default();
    let mut defaulted = Default::default();
    let mut old: *mut ACL = std::ptr::null_mut();
    unsafe {
        GetSecurityDescriptorDacl(
            PSECURITY_DESCRIPTOR(sd_buf.as_ptr() as *mut c_void),
            &mut present,
            &mut old,
            &mut defaulted,
        )
        .with_context(|| format!("GetSecurityDescriptorDacl({what})"))?;
    }
    // A present-but-NULL DACL is "grant everyone everything" —
    // `target_sid` already has access; rewriting it as a one-ACE
    // DACL would lock out every other principal. Shouldn't happen on
    // a csrss-created session object, but don't make it worse.
    if present.as_bool() && old.is_null() {
        return Ok(());
    }

    // 2) Walk `old`: keep ACEs whose SID isn't `target_sid`
    //    (INHERITED ACEs are kept too). `sd_buf` backs the kept ACE
    //    pointers until step 4's write.
    let kept = filter_aces(old, |_, body| !ace_sid_is(body, target_sid))
        .with_context(|| format!("filter_aces({what})"))?;

    // 3) New ACL = kept ACEs + one ALLOW for `target_sid`. Kept ACEs
    //    first (preserves the original ACE order — DENYs, if any,
    //    stay ahead of our appended ALLOW).
    let sid = PSID(target_sid.as_ptr() as *mut c_void);
    let new = rebuild_acl(kept.2, &[], &kept, &[NewAce::Allow(sid, mask, NO_INHERIT)])
        .with_context(|| format!("rebuild_acl({what})"))?;

    // 4) Write back via a fresh absolute SD.
    let mut sd: SECURITY_DESCRIPTOR = Default::default();
    let psd = PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut c_void);
    unsafe {
        InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION)
            .with_context(|| format!("InitializeSecurityDescriptor({what})"))?;
        SetSecurityDescriptorDacl(psd, true, Some(new.as_ptr()), false)
            .with_context(|| format!("SetSecurityDescriptorDacl({what})"))?;
    }
    write(psd)
}

/// Name of the window station this process is attached to (e.g.
/// `WinSta0`, `Service-0x0-<logonid>$`).
pub fn current_winsta_name() -> Result<String> {
    let ws = unsafe { GetProcessWindowStation() }.context("GetProcessWindowStation")?;
    if ws.0.is_null() {
        return Err(anyhow!("GetProcessWindowStation returned null"));
    }
    object_name(HANDLE(ws.0))
}

/// Name of this thread's current desktop (e.g. `Default`,
/// `srt-sb-…`). `None` on failure.
pub fn current_desktop_name() -> Option<String> {
    let d = unsafe { GetThreadDesktop(GetCurrentThreadId()) }.ok()?;
    if d.0.is_null() {
        return None;
    }
    object_name(HANDLE(d.0)).ok()
}

/// `true` when this thread is on the interactive `Default` desktop.
///
/// `run_lockdown` **fails closed** when this returns `true`: the
/// broker passes its `WinSta0\srt-sb-…` desktop via `lpDesktop` to
/// `CreateProcessWithLogonW`, so the runner is never on `Default`
/// in the two-hop path. A `Default` runner means the broker-side
/// creation failed and the child would share the interactive
/// desktop (`WH_KEYBOARD_LL` keylogging risk). Name-based — a
/// non-`Default` custom desktop is assumed isolated. Any read
/// failure → `true` (fail closed).
pub fn on_default_desktop() -> bool {
    current_desktop_name()
        .map(|n| n.eq_ignore_ascii_case("Default"))
        .unwrap_or(true)
}

/// Read a user-object's `UOI_NAME` (returned as a wide
/// NUL-terminated string).
fn object_name(h: HANDLE) -> Result<String> {
    let mut needed = 0u32;
    // Sizing call — expected to fail with ERROR_INSUFFICIENT_BUFFER
    // and write the required byte count.
    unsafe {
        let _ = GetUserObjectInformationW(h, UOI_NAME, None, 0, Some(&mut needed));
    }
    if needed == 0 {
        return Err(anyhow!("GetUserObjectInformationW sizing returned 0"));
    }
    let mut buf = vec![0u8; needed as usize];
    unsafe {
        GetUserObjectInformationW(
            h,
            UOI_NAME,
            Some(buf.as_mut_ptr() as *mut c_void),
            needed,
            Some(&mut needed),
        )
        .context("GetUserObjectInformationW(UOI_NAME)")?;
    }
    // SAFETY: `buf` is `needed` bytes, even-length (UTF-16);
    // reinterpret as u16.
    let wide =
        unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u16, (needed as usize) / 2) };
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    Ok(String::from_utf16_lossy(&wide[..end]))
}
