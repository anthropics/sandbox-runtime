//! Small Win32 helpers shared across the crate.

use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::core::{PCWSTR, PWSTR};

/// Owns a kernel `HANDLE`; `CloseHandle` on drop. For tokens, file
/// handles, process handles — anything whose only cleanup is
/// `CloseHandle`. `into_raw()` disarms the guard and returns the
/// handle for callers that need to pass ownership upward.
#[derive(Debug)]
pub struct OwnedHandle(pub HANDLE);

impl OwnedHandle {
    pub fn raw(&self) -> HANDLE {
        self.0
    }
    /// Disarm the guard and return the raw handle (caller takes
    /// ownership and is responsible for closing it).
    pub fn into_raw(self) -> HANDLE {
        let h = self.0;
        std::mem::forget(self);
        h
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// UTF-8 → NUL-terminated UTF-16 buffer. Keep the returned `Vec`
/// alive for as long as the resulting `PCWSTR` / `PWSTR` is in use.
pub fn wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Overwrite `buf` with zeros using volatile writes so LLVM
/// dead-store elimination can't remove the scrub in release. For
/// clearing UTF-16 password buffers after `LogonUserW` /
/// `CreateProcessWithLogonW` has consumed them.
pub fn scrub_wstr(buf: &mut [u16]) {
    for c in buf.iter_mut() {
        // SAFETY: `c` is a valid, aligned, exclusive `&mut u16`.
        unsafe { core::ptr::write_volatile(c, 0) };
    }
}

/// Borrow a `Vec<u16>` from `wstr` as a `PCWSTR`.
pub fn pcwstr(buf: &[u16]) -> PCWSTR {
    PCWSTR(buf.as_ptr())
}

/// Read a NUL-terminated `PWSTR` (typically returned by a Win32 API
/// that allocates) into an owned `String`. Caller still owns the
/// underlying allocation.
pub fn from_pwstr(p: PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    unsafe {
        while *p.0.add(len) != 0 {
            len += 1;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(p.0, len) };
    String::from_utf16_lossy(slice)
}

/// `LocalFree` a pointer returned by a Win32 API documented to require
/// it (e.g. `ConvertSidToStringSidW`,
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW`).
pub fn local_free(p: *mut c_void) {
    unsafe {
        let _ = LocalFree(Some(HLOCAL(p)));
    }
}

use anyhow::{Result, anyhow, bail};
use windows::Win32::Foundation::WIN32_ERROR;

/// `Ok(())` if `r` is `ERROR_SUCCESS`, else `bail!("{label}:
/// WIN32_ERROR=0x…")`. For Win32 APIs that return a bare
/// `WIN32_ERROR` rather than a `windows::core::Result` (e.g.
/// `Get`/`SetNamedSecurityInfoW`).
pub(crate) fn win32_ok(r: WIN32_ERROR, label: &str) -> Result<()> {
    if r.is_err() {
        bail!("{label}: WIN32_ERROR=0x{:08x}", r.0)
    }
    Ok(())
}

use windows::Win32::System::Registry::{
    HKEY, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW,
    RegSetValueExW,
};

/// `RegCreateKeyExW(root, subkey, KEY_SET_VALUE)` →
/// `RegSetValueExW(value_name, ty, data)` → `RegCloseKey`. Creates
/// intermediate subkeys. The single registry-write helper for
/// `cert_store::install_root_ca` (`HKEY_USERS`, `REG_BINARY`) and
/// `user::set_logon_ui_hidden` (`HKEY_LOCAL_MACHINE`, `REG_DWORD`).
pub fn reg_set_value(
    root: HKEY,
    subkey: &str,
    value_name: &str,
    ty: REG_VALUE_TYPE,
    data: &[u8],
) -> Result<()> {
    let sub_w = wstr(subkey);
    let val_w = wstr(value_name);
    let mut hkey = HKEY::default();
    let r = unsafe {
        RegCreateKeyExW(
            root,
            pcwstr(&sub_w),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut hkey,
            None,
        )
    };
    if r.is_err() {
        return Err(anyhow!("RegCreateKeyExW({subkey}): {r:?}"));
    }
    let r = unsafe { RegSetValueExW(hkey, pcwstr(&val_w), None, ty, Some(data)) };
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    if r.is_err() {
        return Err(anyhow!("RegSetValueExW({subkey}\\{value_name}): {r:?}"));
    }
    Ok(())
}

use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{GetSecurityDescriptorLength, PSECURITY_DESCRIPTOR};

const SDDL_REVISION_1: u32 = 1;

/// Heap-allocated security descriptor owned by us; `LocalFree` on
/// drop. Built from an SDDL string via [`OwnedSd::from_sddl`].
/// Fields are `pub(crate)` so callers that need the byte view
/// (e.g. `wfp.rs`'s `FWP_BYTE_BLOB` provider data) can read them
/// without pulling subsystem-specific types into util.
pub struct OwnedSd {
    pub(crate) ptr: PSECURITY_DESCRIPTOR,
    pub(crate) len: u32,
}

impl OwnedSd {
    pub fn from_sddl(sddl: &str) -> Result<Self> {
        let w = wstr(sddl);
        let mut psd = PSECURITY_DESCRIPTOR::default();
        let mut sz: u32 = 0;
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                pcwstr(&w),
                SDDL_REVISION_1,
                &mut psd,
                Some(&mut sz),
            )
            .map_err(|e| {
                anyhow!("ConvertStringSecurityDescriptorToSecurityDescriptorW({sddl}): {e}")
            })?;
            if sz == 0 {
                sz = GetSecurityDescriptorLength(psd);
            }
        }
        Ok(Self { ptr: psd, len: sz })
    }

    /// Take ownership of a `PSECURITY_DESCRIPTOR` returned by a Win32
    /// API documented to require `LocalFree` (e.g.
    /// `GetNamedSecurityInfoW`). `len` is queried for completeness;
    /// callers that only need the free-on-drop guard can ignore it.
    pub fn from_raw(psd: PSECURITY_DESCRIPTOR) -> Self {
        let len = if psd.0.is_null() {
            0
        } else {
            unsafe { GetSecurityDescriptorLength(psd) }
        };
        Self { ptr: psd, len }
    }
}

impl Drop for OwnedSd {
    fn drop(&mut self) {
        if !self.ptr.0.is_null() {
            local_free(self.ptr.0);
        }
    }
}
