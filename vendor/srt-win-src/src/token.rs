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
//! What the library always uses; `srt-win exec` builds it only with
//! `--write-restricted-token`.
//!
//! `write_restricted` adds the `WRITE_RESTRICTED` flag and the
//! restricting SIDs [`restricting_sid_list`]: a write must then also
//! be granted to a SID in that list, which `BUILTIN\Users` and
//! `Authenticated Users` are not in. The sandbox user SID must stay
//! in the list — the WFP egress BLOCK matches through it
//! ([`crate::wfp::sddl_sandbox_user`]) — and Everyone and RESTRICTED
//! are what a process needs write-class access through to start.
//! The capability SIDs of the session's write roots (`crate::persist`)
//! lead the list: a kept root passes this check only through its own.

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

/// `Everyone` (World).
pub const SID_EVERYONE: &str = "S-1-1-0";

/// `NT AUTHORITY\RESTRICTED`.
pub const SID_RESTRICTED: &str = "S-1-5-12";

/// `TOKEN_WRITE_RESTRICTED` (winnt.h), a bit of `TOKEN_ACCESS_INFORMATION.Flags`.
const TOKEN_FLAG_WRITE_RESTRICTED: u32 = 0x0008;

pub fn restricted_token_flags(write_restricted: bool) -> CREATE_RESTRICTED_TOKEN_FLAGS {
    if write_restricted {
        LUA_TOKEN | WRITE_RESTRICTED
    } else {
        LUA_TOKEN
    }
}

/// The restricting-SID list of the write-restricted token, in order:
/// the capability SIDs (duplicates dropped), then the three fixed
/// SIDs. `user_sid` must stay in it: the WFP egress BLOCK keys on it.
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
    pub write_restricted: bool,
    /// `TokenRestrictedSids` as strings, in token order.
    pub restricted_sids: Vec<String>,
}

/// Read `tok`'s restricting SIDs and write-restricted flag (needs `TOKEN_QUERY`).
pub fn token_restriction(tok: HANDLE) -> Result<TokenRestriction> {
    let groups = get_token_info(tok, TokenRestrictedSids)?;
    let access = get_token_info(tok, TokenAccessInformation)?;
    if groups.len() < size_of::<u32>() || access.len() < size_of::<TOKEN_ACCESS_INFORMATION>() {
        return Err(anyhow!("GetTokenInformation returned a short buffer"));
    }
    let restricted_sids = token_group_sids(&groups)?
        .into_iter()
        .map(psid_to_string)
        .collect::<Result<Vec<_>>>()?;
    unsafe {
        let info = access.as_ptr() as *const TOKEN_ACCESS_INFORMATION;
        let flags = std::ptr::read_unaligned(std::ptr::addr_of!((*info).Flags));
        Ok(TokenRestriction {
            write_restricted: flags & TOKEN_FLAG_WRITE_RESTRICTED != 0,
            restricted_sids,
        })
    }
}

/// The SIDs of a `TOKEN_GROUPS` buffer. A buffer with no groups may be
/// shorter than the struct, so it is read by offset, never by reference.
fn token_group_sids(buf: &[u8]) -> Result<Vec<PSID>> {
    let short = || anyhow!("TOKEN_GROUPS buffer is shorter than its group count needs");
    let count = buf.get(..size_of::<u32>()).ok_or_else(short)?;
    let count = u32::from_ne_bytes(count.try_into().expect("four bytes")) as usize;
    let first = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    let each = size_of::<SID_AND_ATTRIBUTES>();
    if count > 0 && buf.len() < first + count * each {
        return Err(short());
    }
    Ok((0..count)
        .map(|i| unsafe {
            std::ptr::read_unaligned(
                    buf.as_ptr().add(first + i * each) as *const SID_AND_ATTRIBUTES
                )
                .Sid
        })
        .collect())
}

/// [`token_restriction`] of this process's own primary token (`test-hooks` only).
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

/// Build the restricted child token from `base` (non-primary; see
/// [`to_primary`]). `write_restricted` fails closed: an error unless
/// the created token reports exactly the requested list and flag.
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

    // `restrict_sids` owns the SID memory and must outlive
    // `CreateRestrictedToken`.
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
pub(crate) fn set_il(tok: HANDLE, rid: u32) -> Result<()> {
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
/// logon-SID ALLOW ACE here would be ignored at access-check.
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
        // Capability SIDs are refused without the flag; other SIDs with it.
        let cap = crate::persist::new_capability_sid().unwrap();
        assert!(make_sandbox_token(base, false, std::slice::from_ref(&cap)).is_err());
        assert!(make_sandbox_token(base, true, &[SID_BUILTIN_ADMINS.to_owned()]).is_err());
        unsafe {
            let _ = CloseHandle(base);
        }
        let tok = r.expect("make_sandbox_token");
        let shape = token_restriction(tok).expect("token_restriction");
        assert!(!shape.write_restricted);
        assert_eq!(shape.restricted_sids, Vec::<String>::new());
        let prim = to_primary(tok).expect("to_primary");
        unsafe {
            let _ = CloseHandle(tok);
            let _ = CloseHandle(prim);
        }
    }

    #[test]
    fn token_group_sids_reads_a_buffer_shorter_than_the_struct() {
        // What the kernel returns for no groups can be the count alone.
        assert!(token_group_sids(&0u32.to_ne_bytes()).unwrap().is_empty());
        assert!(token_group_sids(&[0u8; 2]).is_err());
        // A count the buffer does not hold is refused, not read.
        let mut one = 1u32.to_ne_bytes().to_vec();
        assert!(token_group_sids(&one).is_err());
        one.resize(
            std::mem::offset_of!(TOKEN_GROUPS, Groups) + size_of::<SID_AND_ATTRIBUTES>(),
            0,
        );
        assert_eq!(token_group_sids(&one).unwrap().len(), 1);
    }

    /// The user SID must stay in the list: the WFP egress BLOCK matches through it.
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

    /// The kernel reports the requested list and flag, also after `to_primary`.
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
