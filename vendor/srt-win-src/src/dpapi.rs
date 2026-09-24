//! Thin DPAPI wrappers (`CryptProtectData` / `CryptUnprotectData`).
//!
//! Used to encrypt the sandbox user's password at rest in
//! `HKLM\SOFTWARE\sandbox-runtime\Cred\Blob`.
//!
//! ## SECURITY: machine-scope DPAPI is NOT a boundary
//!
//! [`protect_machine`] uses `CRYPTPROTECT_LOCAL_MACHINE`, which lets a
//! **non-elevated** broker decrypt a blob the **elevated** install
//! wrote — but it also lets **any local account** (including the
//! sandbox user) decrypt the same blob if it can read it. The
//! credential file's **DACL** is the only gate: the state-DB
//! directory carries an explicit `(D;OICI;FA;;;<sandbox-runtime-users>)`
//! DENY plus the broker-only `PROTECTED` allow set. With that DENY in
//! place the sandbox user's `CreateFileW` fails before DPAPI is ever
//! reached.
//!
//! User-scope DPAPI (no `CRYPTPROTECT_LOCAL_MACHINE`) is NOT an
//! option here: the elevated install and the non-elevated broker
//! run under the same user but different logon sessions, and a
//! self-elevated `runas` child may not have the user's master key
//! loaded — machine scope is the only shape that round-trips
//! reliably across that split.

use anyhow::{Result, anyhow};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    CryptUnprotectData,
};
use windows::core::PCWSTR;

/// `CryptProtectData` with `CRYPTPROTECT_LOCAL_MACHINE |
/// CRYPTPROTECT_UI_FORBIDDEN`. See the module-level note: this is
/// **not** a security boundary against other local accounts; the
/// caller must DACL the ciphertext.
pub fn protect_machine(plaintext: &[u8]) -> Result<Vec<u8>> {
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut out = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(
            &in_blob,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
        .map_err(|e| anyhow!("CryptProtectData: {e}"))?;
    }
    Ok(take_blob(out))
}

/// `CryptUnprotectData` with `CRYPTPROTECT_UI_FORBIDDEN`. Decrypts
/// either machine- or user-scope blobs (DPAPI infers the scope from
/// the blob header).
pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut out = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(
            &in_blob,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
        .map_err(|e| anyhow!("CryptUnprotectData: {e}"))?;
    }
    Ok(take_blob(out))
}

/// Copy `out.pbData[..out.cbData]` into an owned `Vec<u8>` and
/// `LocalFree` the DPAPI-allocated buffer. `pbData` is freed
/// whenever it is non-null — including when `cbData == 0`, which
/// the API can in principle return for an empty plaintext.
fn take_blob(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    if out.pbData.is_null() {
        return Vec::new();
    }
    let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(out.pbData as *mut core::ffi::c_void)));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let pt = b"the only gate is the file DACL";
        let ct = protect_machine(pt).expect("protect");
        assert_ne!(ct.as_slice(), pt);
        assert!(ct.len() > pt.len()); // header + MAC overhead
        let back = unprotect(&ct).expect("unprotect");
        assert_eq!(back.as_slice(), pt);
    }

    #[test]
    fn unprotect_rejects_garbage() {
        assert!(unprotect(b"not a dpapi blob").is_err());
    }
}
