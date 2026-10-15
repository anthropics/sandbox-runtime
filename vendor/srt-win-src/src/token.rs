//! Restricted-token construction for the runner→child lockdown.
//!
//! Token shape:
//!   - `SidsToDisable = [BUILTIN\Administrators, <every
//!     SE_GROUP_LOGON_ID SID in the base token>]` — flips them to
//!     `SE_GROUP_USE_FOR_DENY_ONLY`. Admins is belt-and-braces (the
//!     runner runs as `srt-sandbox`, so it normally lacks Admins;
//!     covers elevated brokers / CI runners where the sandbox user
//!     was added to Admins out-of-band). The **logon SID(s) are the
//!     load-bearing strip**: seclogon stamps the broker's
//!     interactive logon SID into the runner's token (so the runner
//!     can attach to `WinSta0\Default`), and that SID matches the
//!     default per-process logon-session ACE
//!     (`VM_READ | QUERY | TERMINATE`) on every default-DACL process
//!     in the broker's session. Left enabled, the child can
//!     `OpenProcess(VM_READ)` + `ReadProcessMemory` any same-session
//!     real-user process — browser heap, shell, the host
//!     orchestrator. Nothing in the sandbox keys on the logon SID
//!     (FS/WFP key on user SID; the isolated desktop's DACL grants
//!     the sandbox user explicitly), so disabling it loses nothing.
//!   - `LUA_TOKEN` flag — token reads as a normal limited-user token
//!     to NT components.
//!   - All privileges deleted except `SeChangeNotifyPrivilege`.
//!   - Integrity Level = Medium (same as a normal user process).
//!   - No `RestrictingSids` array unless `write_restricted` (below) —
//!     Schannel credential acquisition fails under any token that
//!     carries one.
//!
//! ## Write-restricted token
//!
//! The token a sandboxed command gets from the library unless its
//! `windows.writeRestrictedToken` option is `false`; `srt-win exec`
//! builds it when given `--write-restricted-token`, and the token
//! above (the ordinary one) otherwise.
//!
//! With `write_restricted` set, [`make_sandbox_token`] adds the
//! `WRITE_RESTRICTED` flag and the restricting-SID list
//! [`restricting_sid_list`] = `[<capability SIDs of this session's
//! write roots>, <sandbox user SID>, Everyone, RESTRICTED]`;
//! everything above is unchanged. A restricted token is
//! access-checked twice — once against its ordinary groups, once
//! against the restricting list — and both must grant. With
//! `WRITE_RESTRICTED` the second check applies to write-class access
//! only, so reads behave as before, while a write must be granted to
//! a SID in the list. The sandbox account is a member of
//! `BUILTIN\Users` and `Authenticated Users`; neither is in the
//! list, so write access those groups hold anywhere on the machine
//! stops reaching the child.
//!
//! Why each SID is in the list:
//!   - **The capability SIDs** — one per write root the session was
//!     given (`crate::persist`). A root whose grant is kept between
//!     sessions allows writing to its capability SID, not to the
//!     sandbox user SID, so only a token that lists that SID passes
//!     the second check there: a session of one project cannot write
//!     another's root. The list may be empty.
//!   - **The sandbox user SID** — every per-session ACE the broker
//!     writes for the sandbox (read grants, deny stamps, the
//!     window-station / desktop / `BaseNamedObjects` grants, the
//!     default DACL below, the account's own profile) is keyed on
//!     it, so those keep satisfying both checks with no change to
//!     the ACL code. It is also what keeps the WFP egress BLOCK
//!     matching — see [`crate::wfp::sddl_sandbox_user`]. **Removing
//!     it from the list would silently disable the network fence.**
//!   - **Everyone** and **RESTRICTED** — system objects a process
//!     needs write-class access to in order to start and run
//!     (named-object directories, ALPC ports, devices) grant one of
//!     these; without them the CLR and most non-trivial programs do
//!     not start.
//!
//! What stays writable under the option: anything that grants write
//! to the sandbox user SID, to Everyone or to RESTRICTED, and
//! objects the sandbox account owns (an owner is implicitly allowed
//! to rewrite the DACL, and the owner is in the list).
//!
//! Cost: Schannel refuses to acquire credentials for a restricted
//! token, so TLS clients built on it (System32 `curl.exe`, git's
//! schannel backend, .NET / PowerShell web requests) fail inside the
//! sandbox. OpenSSL-based clients are unaffected.

use anyhow::{Context, Result, anyhow};
use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::Foundation::{HANDLE, LUID};
use windows::Win32::Security::{
    ACL, ACL_REVISION, AddAccessAllowedAce, AllocateAndInitializeSid,
    CREATE_RESTRICTED_TOKEN_FLAGS, CreateRestrictedToken, DuplicateTokenEx, FreeSid, GetLengthSid,
    GetTokenInformation, InitializeAcl, LUA_TOKEN, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    PSID, SID_AND_ATTRIBUTES, SID_IDENTIFIER_AUTHORITY, SecurityImpersonation, SetTokenInformation,
    TOKEN_ACCESS_INFORMATION, TOKEN_ALL_ACCESS, TOKEN_DEFAULT_DACL, TOKEN_GROUPS,
    TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_USER,
    TokenAccessInformation, TokenDefaultDacl, TokenGroups, TokenIntegrityLevel, TokenPrimary,
    TokenPrivileges, TokenRestrictedSids, TokenUser, WRITE_RESTRICTED,
};
use windows::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::sid::{LocalPsid, psid_to_string};
use crate::util::{pcwstr, wstr};

/// Medium IL (`SECURITY_MANDATORY_MEDIUM_RID`). The sandbox child
/// runs at Medium — same as normal user processes — so Schannel /
/// LSA / registry edge cases that fire at Low IL don't apply.
pub const IL_MEDIUM: u32 = 0x2000;

/// `BUILTIN\Administrators`. Always added to `SidsToDisable` so an
/// elevated broker still produces a non-admin child.
const SID_BUILTIN_ADMINS: &str = "S-1-5-32-544";

/// `Everyone` (World). In the write-restricted list — see the module
/// doc.
pub const SID_EVERYONE: &str = "S-1-1-0";

/// `NT AUTHORITY\RESTRICTED`. In the write-restricted list — see the
/// module doc.
pub const SID_RESTRICTED: &str = "S-1-5-12";

/// `TOKEN_WRITE_RESTRICTED` (winnt.h) — the bit in
/// `TOKEN_ACCESS_INFORMATION.Flags` that says the restricting SIDs
/// gate write-class access only.
const TOKEN_FLAG_WRITE_RESTRICTED: u32 = 0x0008;

/// `CreateRestrictedToken` flags for the child token: `LUA_TOKEN`
/// always, plus `WRITE_RESTRICTED` when the option is on.
pub fn restricted_token_flags(write_restricted: bool) -> CREATE_RESTRICTED_TOKEN_FLAGS {
    if write_restricted {
        LUA_TOKEN | WRITE_RESTRICTED
    } else {
        LUA_TOKEN
    }
}

/// The restricting-SID list of the write-restricted token, in the
/// order it is passed to `CreateRestrictedToken`: the session's
/// capability SIDs (duplicates dropped), then the three fixed SIDs.
/// `user_sid` is the sandbox account's own SID and **must** stay in
/// the list: the WFP egress BLOCK and every per-session sandbox ACE
/// key on it (module doc).
pub fn restricting_sid_list(user_sid: &str, capability_sids: &[String]) -> Vec<String> {
    let mut v: Vec<String> = Vec::with_capacity(capability_sids.len() + 3);
    for c in capability_sids {
        if !v.contains(c) {
            v.push(c.clone());
        }
    }
    v.extend([
        user_sid.to_owned(),
        SID_EVERYONE.to_owned(),
        SID_RESTRICTED.to_owned(),
    ]);
    v
}

/// What a token's restricting-SID state is, as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "test-hooks", derive(serde::Serialize))]
pub struct TokenRestriction {
    /// `TOKEN_WRITE_RESTRICTED` is set in the token's flags.
    pub write_restricted: bool,
    /// The token's restricting SIDs (`TokenRestrictedSids`), as
    /// strings, in token order. Empty for an unrestricted token.
    pub restricted_sids: Vec<String>,
}

/// Read `tok`'s restricting SIDs and write-restricted flag. Needs
/// `TOKEN_QUERY` on the handle.
pub fn token_restriction(tok: HANDLE) -> Result<TokenRestriction> {
    let groups = get_token_info(tok, TokenRestrictedSids)?;
    let access = get_token_info(tok, TokenAccessInformation)?;
    if groups.len() < size_of::<u32>() || access.len() < size_of::<TOKEN_ACCESS_INFORMATION>() {
        return Err(anyhow!("GetTokenInformation returned a short buffer"));
    }
    unsafe {
        let tg = &*(groups.as_ptr() as *const TOKEN_GROUPS);
        let restricted_sids =
            std::slice::from_raw_parts(tg.Groups.as_ptr(), tg.GroupCount as usize)
                .iter()
                .map(|g| psid_to_string(g.Sid))
                .collect::<Result<Vec<_>>>()?;
        let flags = (*(access.as_ptr() as *const TOKEN_ACCESS_INFORMATION)).Flags;
        Ok(TokenRestriction {
            write_restricted: flags & TOKEN_FLAG_WRITE_RESTRICTED != 0,
            restricted_sids,
        })
    }
}

/// [`token_restriction`] of this process's own primary token. Used
/// only by the `test-hooks` `probe token` subcommand.
#[cfg(feature = "test-hooks")]
pub fn own_token_restriction() -> Result<TokenRestriction> {
    use windows::Win32::Security::TOKEN_QUERY;
    let mut h = HANDLE::default();
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h)
            .context("OpenProcessToken(TOKEN_QUERY)")?;
    }
    let h = crate::util::OwnedHandle(h);
    token_restriction(h.raw())
}

/// `tok`'s user SID as a string.
fn token_user_sid(tok: HANDLE) -> Result<String> {
    let buf = get_token_info(tok, TokenUser)?;
    psid_to_string(unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid })
}

/// `SE_GROUP_INTEGRITY` attribute (winnt.h). Required on the
/// `TOKEN_MANDATORY_LABEL.Label.Attributes` field.
const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;

/// Every `SE_GROUP_LOGON_ID` SID in `token`'s `TokenGroups`, copied
/// into owned byte buffers (each is a self-relative SID; cast
/// `.as_ptr()` to `PSID` for Win32 calls). `SE_GROUP_LOGON_ID` is a
/// 2-bit value (`0xC000_0000`); both bits are required, not `!= 0`.
fn logon_sids_of(token: HANDLE) -> Result<Vec<Vec<u8>>> {
    let buf = get_token_info(token, TokenGroups)?;
    unsafe {
        let tg = &*(buf.as_ptr() as *const TOKEN_GROUPS);
        Ok(
            std::slice::from_raw_parts(tg.Groups.as_ptr(), tg.GroupCount as usize)
                .iter()
                .filter(|g| g.Attributes & (SE_GROUP_LOGON_ID as u32) == SE_GROUP_LOGON_ID as u32)
                .map(|g| {
                    let len = GetLengthSid(g.Sid) as usize;
                    std::slice::from_raw_parts(g.Sid.0 as *const u8, len).to_vec()
                })
                .collect(),
        )
    }
}

/// Open this process's primary token with full access.
pub fn open_self_token() -> Result<HANDLE> {
    unsafe {
        let mut h = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut h)
            .context("OpenProcessToken")?;
        Ok(h)
    }
}

/// Build the restricted child token from `base`. The caller
/// duplicates the result to a primary token via [`to_primary`].
///
/// `write_restricted` adds the `WRITE_RESTRICTED` flag and the
/// [`restricting_sid_list`] (module doc) built from
/// `capability_sids`. It fails closed: if the token cannot be created
/// with the list, or the created token does not report exactly that
/// list and flag, this returns an error — there is no fallback to the
/// ordinary token, nor to a shorter list.
///
/// `capability_sids` must be empty without `write_restricted`, and
/// each must be a capability SID (`crate::persist`): the list arrives
/// in the launch spec, and nothing else is accepted from it as a
/// restricting SID.
pub fn make_sandbox_token(
    base: HANDLE,
    write_restricted: bool,
    capability_sids: &[String],
) -> Result<HANDLE> {
    if !write_restricted && !capability_sids.is_empty() {
        return Err(anyhow!(
            "capability SIDs were given without the write-restricted token"
        ));
    }
    if let Some(bad) = capability_sids
        .iter()
        .find(|s| !crate::persist::is_capability_sid(s))
    {
        return Err(anyhow!("'{bad}' is not a capability SID"));
    }
    // SIDs to disable: `BUILTIN\Administrators` + every
    // `SE_GROUP_LOGON_ID` group in `base` (see module doc — the
    // logon-SID strip is what stops the child reading same-session
    // real-user process memory). `logon_sids` owns the logon-SID
    // bytes and must outlive `CreateRestrictedToken`; `admins` is
    // RAII over `ConvertStringSidToSidW` (`LocalFree` on drop).
    let admins = LocalPsid::from_string(SID_BUILTIN_ADMINS)?;
    let logon_sids = logon_sids_of(base)?;
    let disable: Vec<SID_AND_ATTRIBUTES> = std::iter::once(admins.as_psid())
        .chain(logon_sids.iter().map(|s| PSID(s.as_ptr() as *mut c_void)))
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: 0,
        })
        .collect();

    // Privileges to delete: everything in `base` except
    // SeChangeNotifyPrivilege.
    let to_delete = privileges_except(base, &["SeChangeNotifyPrivilege"])?;

    // Restricting SIDs: none by default; the capability SIDs plus
    // the fixed three when `write_restricted`. `restrict_sids` owns
    // the SID memory and must outlive `CreateRestrictedToken`.
    let restrict_want: Vec<String> = if write_restricted {
        restricting_sid_list(&token_user_sid(base)?, capability_sids)
    } else {
        Vec::new()
    };
    let restrict_sids: Vec<LocalPsid> = restrict_want
        .iter()
        .map(|s| LocalPsid::from_string(s))
        .collect::<Result<_>>()?;
    let restrict: Vec<SID_AND_ATTRIBUTES> = restrict_sids
        .iter()
        .map(|s| SID_AND_ATTRIBUTES {
            Sid: s.as_psid(),
            Attributes: 0,
        })
        .collect();

    let mut out = HANDLE::default();
    unsafe {
        CreateRestrictedToken(
            base,
            restricted_token_flags(write_restricted),
            Some(&disable),
            if to_delete.is_empty() {
                None
            } else {
                Some(&to_delete)
            },
            if restrict.is_empty() {
                None
            } else {
                Some(&restrict)
            },
            &mut out,
        )
        .with_context(|| {
            format!(
                "CreateRestrictedToken(disable=[Admins, logon-SIDs], \
                 write_restricted={write_restricted})"
            )
        })?;
    }
    // `admins` + `logon_sids` (which back the disable-array PSIDs)
    // and `restrict_sids` drop at the end of this function.

    // RAII-own `out` so a `?` below closes it.
    let guard = crate::util::OwnedHandle(out);
    if write_restricted {
        // Fail closed on a token that is not the shape that was asked
        // for: the caller is about to run a process whose write
        // confinement depends on it.
        let got = token_restriction(guard.raw()).context("read back restricting SIDs")?;
        let same_sids = {
            let (mut a, mut b) = (got.restricted_sids.clone(), restrict_want.clone());
            a.sort();
            b.sort();
            a == b
        };
        if !got.write_restricted || !same_sids {
            return Err(anyhow!(
                "write-restricted token was not created as requested: \
                 write_restricted={} restricted_sids={:?} (wanted {:?})",
                got.write_restricted,
                got.restricted_sids,
                restrict_want,
            ));
        }
    }
    set_il(guard.raw(), IL_MEDIUM)?;
    set_default_dacl(guard.raw(), base)?;
    Ok(guard.into_raw())
}

/// Duplicate to a primary token (`CreateProcessAsUserW` requires a
/// primary).
pub fn to_primary(token: HANDLE) -> Result<HANDLE> {
    unsafe {
        let mut out = HANDLE::default();
        DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut out,
        )
        .context("DuplicateTokenEx(primary)")?;
        Ok(out)
    }
}

/// Set the token's integrity level via a mandatory-label SID built
/// with `AllocateAndInitializeSid` (so [`FreeSid`] is the correct
/// release fn — the one place in this crate where it is).
fn set_il(tok: HANDLE, rid: u32) -> Result<()> {
    unsafe {
        let ml_auth = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 16],
        };
        let mut sid = PSID::default();
        AllocateAndInitializeSid(&ml_auth, 1, rid, 0, 0, 0, 0, 0, 0, 0, &mut sid)
            .context("AllocateAndInitializeSid(mandatory label)")?;
        let tml = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: SE_GROUP_INTEGRITY,
            },
        };
        let r = SetTokenInformation(
            tok,
            TokenIntegrityLevel,
            &tml as *const _ as *const c_void,
            size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(sid),
        );
        // Free regardless of outcome.
        FreeSid(sid);
        r.context("SetTokenInformation(IntegrityLevel)")?;
        Ok(())
    }
}

/// Rewrite the token's default DACL so objects the child *creates*
/// (process, thread, mutex, …) are accessible to SYSTEM and to the
/// **sandbox user** (`base`'s `TokenUser`). The donor leaked the
/// SYSTEM SID here; this version uses [`LocalPsid`] so it's freed on
/// return.
///
/// Keyed on the user SID, not the logon SID: every logon SID in the
/// child token is deny-only (see [`make_sandbox_token`]), so a
/// logon-SID ALLOW ACE here would be ignored at access-check. The
/// user SID is also in the write-restricted token's restricting list,
/// so this DACL keeps granting the child write access to the objects
/// it creates when that option is on.
/// Siblings inside the sandbox (e.g. a parallel build's worker
/// processes) share the `srt-sandbox` user SID, so the user-SID grant
/// covers them — and the broker (different user, two hops away) never
/// opens child-created objects directly.
fn set_default_dacl(tok: HANDLE, base: HANDLE) -> Result<()> {
    let system = LocalPsid::from_string("S-1-5-18")?;
    let user_buf = get_token_info(base, TokenUser)?;
    let user = unsafe { (*(user_buf.as_ptr() as *const TOKEN_USER)).User.Sid };
    let sids = [system.as_psid(), user];

    // Sized ACL: header + per-ACE (8-byte fixed prefix + SID body).
    const ACE_FIXED: usize = 8;
    let mut total = size_of::<ACL>();
    for s in &sids {
        total += ACE_FIXED + unsafe { GetLengthSid(*s) } as usize;
    }
    total = (total + 3) & !3;
    let mut buf = vec![0u8; total];
    let acl = buf.as_mut_ptr() as *mut ACL;
    unsafe {
        InitializeAcl(acl, total as u32, ACL_REVISION).context("InitializeAcl(default DACL)")?;
        // GENERIC_ALL.
        const GENERIC_ALL: u32 = 0x1000_0000;
        for s in &sids {
            AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, *s)
                .context("AddAccessAllowedAce(default DACL)")?;
        }
        let tdd = TOKEN_DEFAULT_DACL { DefaultDacl: acl };
        SetTokenInformation(
            tok,
            TokenDefaultDacl,
            &tdd as *const _ as *const c_void,
            size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
        .context("SetTokenInformation(DefaultDacl)")?;
    }
    // `user_buf` (which backs `user`) and `system` both drop here.
    Ok(())
}

fn get_token_info(tok: HANDLE, cls: TOKEN_INFORMATION_CLASS) -> Result<Vec<u8>> {
    unsafe {
        let mut len = 0u32;
        let _ = GetTokenInformation(tok, cls, None, 0, &mut len);
        if len == 0 {
            return Err(anyhow!("GetTokenInformation({cls:?}) sizing returned 0"));
        }
        let mut buf = vec![0u8; len as usize];
        GetTokenInformation(
            tok,
            cls,
            Some(buf.as_mut_ptr() as *mut c_void),
            len,
            &mut len,
        )
        .with_context(|| format!("GetTokenInformation({cls:?})"))?;
        Ok(buf)
    }
}

/// Every privilege LUID in `base` except those named in `keep`.
fn privileges_except(base: HANDLE, keep: &[&str]) -> Result<Vec<LUID_AND_ATTRIBUTES>> {
    let keep_luids: Vec<LUID> = keep
        .iter()
        .filter_map(|n| {
            let mut l = LUID::default();
            let w = wstr(n);
            unsafe { LookupPrivilegeValueW(None, pcwstr(&w), &mut l).ok()? };
            Some(l)
        })
        .collect();
    let buf = get_token_info(base, TokenPrivileges)?;
    unsafe {
        let tp = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
        let arr = std::slice::from_raw_parts(tp.Privileges.as_ptr(), tp.PrivilegeCount as usize);
        Ok(arr
            .iter()
            .filter(|p| {
                !keep_luids
                    .iter()
                    .any(|k| k.LowPart == p.Luid.LowPart && k.HighPart == p.Luid.HighPart)
            })
            .map(|p| LUID_AND_ATTRIBUTES {
                Luid: p.Luid,
                Attributes: Default::default(),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::CloseHandle;

    #[test]
    fn restricted_token_builds() {
        let base = open_self_token().expect("open_self_token");
        let r = make_sandbox_token(base, false, &[]);
        // Capability SIDs are refused without the flag, and so is
        // anything that is not one with it.
        let cap = crate::persist::new_capability_sid().unwrap();
        assert!(make_sandbox_token(base, false, std::slice::from_ref(&cap)).is_err());
        assert!(make_sandbox_token(base, true, &[SID_BUILTIN_ADMINS.to_owned()]).is_err());
        unsafe {
            let _ = CloseHandle(base);
        }
        let tok = r.expect("make_sandbox_token");
        // The ordinary token carries no restricting SIDs.
        let shape = token_restriction(tok).expect("token_restriction");
        assert!(!shape.write_restricted);
        assert_eq!(shape.restricted_sids, Vec::<String>::new());
        let prim = to_primary(tok).expect("to_primary");
        unsafe {
            let _ = CloseHandle(tok);
            let _ = CloseHandle(prim);
        }
    }

    /// The exact flag and restricting list of the write-restricted token. The
    /// user SID is first and must stay: the WFP egress BLOCK matches
    /// through it (see `wfp::sddl_sandbox_user`), so a list without
    /// it would leave the child's network egress unfenced.
    #[test]
    fn write_restricted_shape_is_pinned() {
        assert_eq!(restricted_token_flags(false), LUA_TOKEN);
        assert_eq!(restricted_token_flags(false).0, 0x4);
        assert_eq!(restricted_token_flags(true).0, 0x4 | 0x8);
        assert_eq!(WRITE_RESTRICTED.0, 0x8);
        assert_eq!(
            restricting_sid_list("S-1-5-21-1-2-3-1005", &[]),
            ["S-1-5-21-1-2-3-1005", "S-1-1-0", "S-1-5-12"]
        );
        // Capability SIDs lead, once each, in the order given; the
        // three fixed SIDs always follow.
        let (a, b) = (
            "S-1-0-1936880739-1-2-3-4".to_owned(),
            "S-1-0-1936880739-5-6-7-8".to_owned(),
        );
        assert_eq!(
            restricting_sid_list("S-1-5-21-1-2-3-1005", &[b.clone(), a.clone(), b.clone()]),
            [
                b.as_str(),
                a.as_str(),
                "S-1-5-21-1-2-3-1005",
                "S-1-1-0",
                "S-1-5-12"
            ]
        );
    }

    /// The kernel reports the token that was asked for: the
    /// capability SIDs and the three fixed SIDs, the write-restricted
    /// flag, and it survives the duplicate to a primary token that
    /// `CreateProcessAsUserW` is given.
    #[test]
    fn write_restricted_token_reports_exact_list() {
        let caps = [
            crate::persist::new_capability_sid().unwrap(),
            crate::persist::new_capability_sid().unwrap(),
        ];
        for caps in [&caps[..0], &caps[..]] {
            let base = open_self_token().expect("open_self_token");
            let user = token_user_sid(base).expect("token_user_sid");
            let r = make_sandbox_token(base, true, caps);
            unsafe {
                let _ = CloseHandle(base);
            }
            let tok = r.expect("make_sandbox_token(write_restricted)");
            let prim = to_primary(tok).expect("to_primary");
            for h in [tok, prim] {
                let shape = token_restriction(h).expect("token_restriction");
                assert!(shape.write_restricted, "TOKEN_WRITE_RESTRICTED not set");
                assert_eq!(shape.restricted_sids, restricting_sid_list(&user, caps));
            }
            unsafe {
                let _ = CloseHandle(tok);
                let _ = CloseHandle(prim);
            }
        }
    }

    #[test]
    fn privileges_except_keeps_change_notify() {
        let base = open_self_token().expect("open_self_token");
        let to_delete = privileges_except(base, &["SeChangeNotifyPrivilege"]).unwrap();
        // Resolve SeChangeNotifyPrivilege's LUID and assert it's NOT
        // in the deletion set.
        let mut keep = LUID::default();
        let w = wstr("SeChangeNotifyPrivilege");
        unsafe {
            LookupPrivilegeValueW(None, pcwstr(&w), &mut keep).unwrap();
            let _ = CloseHandle(base);
        }
        assert!(
            !to_delete
                .iter()
                .any(|p| p.Luid.LowPart == keep.LowPart && p.Luid.HighPart == keep.HighPart),
            "SeChangeNotifyPrivilege must not be in the deletion set"
        );
    }
}
