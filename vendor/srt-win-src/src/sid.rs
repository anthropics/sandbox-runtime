//! PSID ↔ string-SID helpers and token-membership queries.
//!
//! All `PSID` values returned by `ConvertStringSidToSidW` are
//! heap-allocated by the OS via `LocalAlloc` and **must** be freed
//! with `LocalFree` — never `FreeSid`, which is only valid for SIDs
//! built by `AllocateAndInitializeSid`. The `LocalPsid` RAII wrapper
//! enforces that.

use anyhow::{Context, Result, anyhow};
use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows::Win32::Security::{
    GetLengthSid, GetTokenInformation, LookupAccountNameW, LookupAccountSidW, PSID, SID_NAME_USE,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PWSTR;

use crate::util::{from_pwstr, local_free, pcwstr, wstr};

/// RAII wrapper for a `PSID` returned by `ConvertStringSidToSidW`.
/// Freed via `LocalFree` on drop.
pub struct LocalPsid(PSID);

impl LocalPsid {
    /// Parse a string SID like `"S-1-5-32-544"`.
    pub fn from_string(sid_str: &str) -> Result<Self> {
        let mut sid = PSID::default();
        let w = wstr(sid_str);
        unsafe {
            ConvertStringSidToSidW(pcwstr(&w), &mut sid)
                .map_err(|e| anyhow!("ConvertStringSidToSidW({sid_str}): {e}"))?;
        }
        Ok(Self(sid))
    }

    pub fn as_psid(&self) -> PSID {
        self.0
    }

    /// The SID's binary form (`GetLengthSid` bytes at the PSID).
    /// Borrow lives as long as `self`.
    pub fn as_bytes(&self) -> &[u8] {
        let len = unsafe { GetLengthSid(self.0) } as usize;
        unsafe { std::slice::from_raw_parts(self.0.0 as *const u8, len) }
    }
}

impl Drop for LocalPsid {
    fn drop(&mut self) {
        if !self.0.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.0)));
            }
        }
    }
}

/// String SID → owned self-relative SID bytes. Cast `.as_ptr()` to
/// `PSID` for Win32 calls; the buffer is the canonical wire form so
/// byte-equality is SID-equality.
pub fn sid_bytes(sid_str: &str) -> Result<Vec<u8>> {
    Ok(LocalPsid::from_string(sid_str)?.as_bytes().to_vec())
}

/// Stringify a `PSID`. Used for serialisation and logging.
pub fn psid_to_string(sid: PSID) -> Result<String> {
    let mut p = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut p).map_err(|e| anyhow!("ConvertSidToStringSidW: {e}"))?;
    }
    let s = from_pwstr(p);
    local_free(p.0 as *mut c_void);
    Ok(s)
}

/// Resolve an account name (local or domain) to a string SID via
/// `LookupAccountNameW` with a NULL system name (local SAM first,
/// then domain). Errors if the name is not found.
pub fn lookup_account_sid(name: &str) -> Result<String> {
    unsafe {
        let mut cb_sid: u32 = 0;
        let mut cch_dom: u32 = 0;
        let mut use_: SID_NAME_USE = SID_NAME_USE::default();
        let name_w = wstr(name);
        // Sizing call. Expected to fail with ERROR_INSUFFICIENT_BUFFER.
        let _ = LookupAccountNameW(
            windows::core::PCWSTR::null(),
            pcwstr(&name_w),
            None,
            &mut cb_sid,
            None,
            &mut cch_dom,
            &mut use_,
        );
        if cb_sid == 0 {
            return Err(anyhow!("LookupAccountNameW({name}): account not found"));
        }
        let mut sid_buf = vec![0u8; cb_sid as usize];
        let mut dom_buf = vec![0u16; cch_dom.max(1) as usize];
        LookupAccountNameW(
            windows::core::PCWSTR::null(),
            pcwstr(&name_w),
            Some(PSID(sid_buf.as_mut_ptr() as *mut c_void)),
            &mut cb_sid,
            Some(PWSTR(dom_buf.as_mut_ptr())),
            &mut cch_dom,
            &mut use_,
        )
        .map_err(|e| anyhow!("LookupAccountNameW({name}): {e}"))?;
        psid_to_string(PSID(sid_buf.as_mut_ptr() as *mut c_void))
    }
}

/// Outcome of a SID → account reverse lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidExistence {
    /// `LookupAccountSidW` resolved the SID to an account.
    Mapped,
    /// `LookupAccountSidW` returned `ERROR_NONE_MAPPED` — well-formed
    /// SID with no corresponding account. Treat as "absent".
    Unmapped,
    /// Lookup failed for a transient reason (e.g. domain controller
    /// unreachable). Caller should fall through to other checks
    /// rather than report absent.
    Unknown,
}

/// Reverse-lookup: does any account correspond to `sid_str`?
/// SAM/LSA liveness probe when resolving the sandbox group for the
/// state-dir DENY ACE.
pub fn sid_account_exists(sid_str: &str) -> Result<SidExistence> {
    use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NONE_MAPPED, GetLastError};
    let psid = LocalPsid::from_string(sid_str)?;
    unsafe {
        let mut cch_name: u32 = 0;
        let mut cch_dom: u32 = 0;
        let mut use_: SID_NAME_USE = SID_NAME_USE::default();
        // Sizing call — we only care about the error code.
        let r = LookupAccountSidW(
            windows::core::PCWSTR::null(),
            psid.as_psid(),
            None,
            &mut cch_name,
            None,
            &mut cch_dom,
            &mut use_,
        );
        if r.is_ok() {
            // Shouldn't happen with zero-length buffers, but treat as
            // mapped if it does.
            return Ok(SidExistence::Mapped);
        }
        match GetLastError() {
            ERROR_INSUFFICIENT_BUFFER => Ok(SidExistence::Mapped),
            ERROR_NONE_MAPPED => Ok(SidExistence::Unmapped),
            // RPC_S_SERVER_UNAVAILABLE, ERROR_TRUSTED_RELATIONSHIP_FAILURE,
            // etc. — don't claim absence on a transient lookup failure.
            _ => Ok(SidExistence::Unknown),
        }
    }
}

/// Reverse of [`lookup_account_sid`]: SID string → account name
/// (without domain). Used to find the localised name of well-known
/// groups (`BUILTIN\Users` is "Benutzer" on de-DE) so SAM calls
/// that take a group *name* work on non-English Windows.
pub fn lookup_account_name(sid_str: &str) -> Result<String> {
    let psid = LocalPsid::from_string(sid_str)?;
    let mut cch_name: u32 = 0;
    let mut cch_dom: u32 = 0;
    let mut use_: SID_NAME_USE = SID_NAME_USE::default();
    unsafe {
        let _ = LookupAccountSidW(
            windows::core::PCWSTR::null(),
            psid.as_psid(),
            None,
            &mut cch_name,
            None,
            &mut cch_dom,
            &mut use_,
        );
    }
    if cch_name == 0 {
        return Err(anyhow!("LookupAccountSidW({sid_str}): sizing returned 0"));
    }
    let mut name = vec![0u16; cch_name as usize];
    let mut dom = vec![0u16; cch_dom.max(1) as usize];
    unsafe {
        LookupAccountSidW(
            windows::core::PCWSTR::null(),
            psid.as_psid(),
            Some(PWSTR(name.as_mut_ptr())),
            &mut cch_name,
            Some(PWSTR(dom.as_mut_ptr())),
            &mut cch_dom,
            &mut use_,
        )
        .map_err(|e| anyhow!("LookupAccountSidW({sid_str}): {e}"))?;
    }
    Ok(String::from_utf16_lossy(&name[..cch_name as usize]))
}

/// String SID of the current process token's user.
pub fn current_user_sid() -> Result<String> {
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok).context("OpenProcessToken")?;
        let mut len = 0u32;
        let _ = GetTokenInformation(tok, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let r = GetTokenInformation(
            tok,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            len,
            &mut len,
        );
        let _ = CloseHandle(tok);
        r.context("GetTokenInformation(TokenUser)")?;
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        psid_to_string(tu.User.Sid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psid_string_round_trip() {
        // Well-known Everyone SID.
        let p = LocalPsid::from_string("S-1-1-0").expect("from_string");
        let s = psid_to_string(p.as_psid()).expect("to_string");
        assert_eq!(s, "S-1-1-0");
    }

    #[test]
    fn lookup_builtin_users() {
        // BUILTIN\Users exists on every Windows install.
        let s = lookup_account_sid("BUILTIN\\Users").expect("lookup");
        assert_eq!(s, "S-1-5-32-545");
    }

    #[test]
    fn lookup_missing_account_errors() {
        let r = lookup_account_sid("no-such-group-srt-win-test");
        assert!(r.is_err());
    }

    #[test]
    fn current_user_sid_is_nonempty() {
        let s = current_user_sid().expect("current_user_sid");
        assert!(s.starts_with("S-1-"), "got {s}");
    }
}
