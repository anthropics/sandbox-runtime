//! Machine-wide install state in `HKLM\SOFTWARE\sandbox-runtime`.
//!
//! The registry is the natural home for small machine-wide
//! key/value state written by an elevated installer and read
//! unprivileged, and its DEFAULT security model is exactly the one
//! the install state needs — properties a `%ProgramData%` file
//! store had to hand-build (and defend in review, repeatedly):
//!
//! - Standard users cannot create keys under `HKLM\SOFTWARE`, so
//!   there is nothing to squat: no take-ownership, no no-follow
//!   open, no reparse rejection for the store itself.
//! - Admin-write / Users-read is the inherited default, so the
//!   identity, marker, and ambient-deny values are trustworthy on
//!   read — no SAM cross-validation, no corrupt-file degrade
//!   paths, no schema-version machinery.
//!
//! Layout (all opens `KEY_WOW64_64KEY` so a 32-bit build would not
//! land in WOW6432Node):
//!
//! - `HKLM\SOFTWARE\sandbox-runtime`: `MarkerVersion` (DWORD,
//!   written LAST — registry writes are not transactional across
//!   values, so the marker is the commit point), `SandboxUser`,
//!   `SandboxUserSid`, `SandboxGroupSid` (SZ), `CreatedAt`
//!   (QWORD), `AmbientDenies` (MULTI_SZ).
//! - `…\Cred`: one `Blob` (BINARY, machine-scope DPAPI). Created
//!   with an explicit SA — DACL atomic with creation — SYSTEM/
//!   Administrators full, Users READ (machine DPAPI means readable
//!   ⇒ decryptable: the shared-credential trade-off), sandbox
//!   group DENY (the child must never learn its own password: with
//!   it, it could CreateProcessWithLogonW itself a fresh logon
//!   session outside the job/desktop confinement).
//! - `…\Ca`: one `Der` (BINARY). Users KEY_READ|KEY_SET_VALUE so
//!   the unelevated `trust-ca` can record the CA; sandbox group
//!   DENY so the CHILD cannot touch the record (the accepted
//!   replace-the-CA trade-off is scoped to REAL local users).

use anyhow::{Context, Result, anyhow};
use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::Win32::Security::Authorization::{SE_REGISTRY_KEY, SetNamedSecurityInfoW};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, KEY_WRITE, REG_BINARY, REG_DWORD,
    REG_MULTI_SZ, REG_OPENED_EXISTING_KEY, REG_OPTION_NON_VOLATILE, REG_QWORD, REG_SZ, RegCloseKey,
    RegCreateKeyExW, RegDeleteTreeW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};

use crate::util::{OwnedSd, pcwstr, wstr};

pub const BASE: &str = r"SOFTWARE\sandbox-runtime";
pub const CRED_SUBKEY: &str = r"SOFTWARE\sandbox-runtime\Cred";
pub const CA_SUBKEY: &str = r"SOFTWARE\sandbox-runtime\Ca";

/// RAII HKEY.
pub struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

impl Key {
    /// Open an existing key. `Ok(None)` when absent.
    pub fn open(path: &str, write: bool) -> Result<Option<Key>> {
        let mut h = HKEY::default();
        let w = wstr(path);
        let access =
            KEY_READ | KEY_WOW64_64KEY | if write { KEY_WRITE } else { Default::default() };
        let r = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, pcwstr(&w), None, access, &mut h) };
        if r == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if r.is_err() {
            return Err(anyhow!("RegOpenKeyExW(HKLM\\{path}): {r:?}"));
        }
        Ok(Some(Key(h)))
    }

    /// Open an existing key for VALUE WRITES ONLY: `KEY_READ |
    /// KEY_SET_VALUE`, never `KEY_WRITE` — `KEY_WRITE` (0x20006)
    /// includes `KEY_CREATE_SUB_KEY` (0x4), which the `Ca` subkey's
    /// `BUILTIN\Users` allow mask (0x2001b) deliberately does not
    /// grant, so an unelevated `trust-ca` open requesting KEY_WRITE
    /// would be ACCESS_DENIED despite having exactly the rights it
    /// needs. `Ok(None)` when absent.
    pub fn open_for_set_value(path: &str) -> Result<Option<Key>> {
        use windows::Win32::System::Registry::KEY_SET_VALUE;
        let mut h = HKEY::default();
        let w = wstr(path);
        let access = KEY_READ | KEY_SET_VALUE | KEY_WOW64_64KEY;
        let r = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, pcwstr(&w), None, access, &mut h) };
        if r == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if r.is_err() {
            return Err(anyhow!("RegOpenKeyExW(HKLM\\{path}, set-value): {r:?}"));
        }
        Ok(Some(Key(h)))
    }

    /// Create (or open) a key, optionally with an explicit security
    /// descriptor (SDDL). Returns `(key, created)`. When the key
    /// already existed the SA is IGNORED by the API — callers that
    /// need a guaranteed DACL must follow up with
    /// [`set_key_dacl_from_sddl`] (only admins can have created it,
    /// so this is drift-healing, not squat defense).
    pub fn create(path: &str, sddl: Option<&str>) -> Result<(Key, bool)> {
        let mut h = HKEY::default();
        let mut disp = Default::default();
        let w = wstr(path);
        let sd;
        let mut sa = None;
        if let Some(sddl) = sddl {
            sd = OwnedSd::from_sddl(sddl).with_context(|| format!("SD for HKLM\\{path}"))?;
            sa = Some(windows::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>()
                    as u32,
                lpSecurityDescriptor: sd.ptr.0,
                bInheritHandle: false.into(),
            });
        }
        let r = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                pcwstr(&w),
                None,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE | KEY_WOW64_64KEY,
                sa.as_ref().map(|s| s as *const _),
                &mut h,
                Some(&mut disp),
            )
        };
        if r.is_err() {
            return Err(anyhow!("RegCreateKeyExW(HKLM\\{path}): {r:?}"));
        }
        Ok((Key(h), disp != REG_OPENED_EXISTING_KEY))
    }

    fn set_raw(
        &self,
        name: &str,
        ty: windows::Win32::System::Registry::REG_VALUE_TYPE,
        data: &[u8],
    ) -> Result<()> {
        let w = wstr(name);
        let r = unsafe { RegSetValueExW(self.0, pcwstr(&w), None, ty, Some(data)) };
        if r.is_err() {
            return Err(anyhow!("RegSetValueExW({name}): {r:?}"));
        }
        Ok(())
    }

    pub fn set_sz(&self, name: &str, val: &str) -> Result<()> {
        let mut v: Vec<u16> = val.encode_utf16().collect();
        v.push(0);
        self.set_raw(name, REG_SZ, unsafe {
            std::slice::from_raw_parts(v.as_ptr() as *const u8, v.len() * 2)
        })
    }

    pub fn set_dword(&self, name: &str, val: u32) -> Result<()> {
        self.set_raw(name, REG_DWORD, &val.to_le_bytes())
    }

    pub fn set_qword(&self, name: &str, val: u64) -> Result<()> {
        self.set_raw(name, REG_QWORD, &val.to_le_bytes())
    }

    pub fn set_binary(&self, name: &str, val: &[u8]) -> Result<()> {
        self.set_raw(name, REG_BINARY, val)
    }

    pub fn set_multi_sz(&self, name: &str, vals: &[String]) -> Result<()> {
        let mut v: Vec<u16> = Vec::new();
        for s in vals {
            v.extend(s.encode_utf16());
            v.push(0);
        }
        v.push(0); // double-NUL terminator (also for the empty list)
        self.set_raw(name, REG_MULTI_SZ, unsafe {
            std::slice::from_raw_parts(v.as_ptr() as *const u8, v.len() * 2)
        })
    }

    fn get_raw(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let w = wstr(name);
        let mut len: u32 = 0;
        let r = unsafe { RegQueryValueExW(self.0, pcwstr(&w), None, None, None, Some(&mut len)) };
        if r == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if r.is_err() {
            return Err(anyhow!("RegQueryValueExW({name}) sizing: {r:?}"));
        }
        let mut buf = vec![0u8; len as usize];
        let mut len2 = len;
        let r = unsafe {
            RegQueryValueExW(
                self.0,
                pcwstr(&w),
                None,
                None,
                Some(buf.as_mut_ptr()),
                Some(&mut len2),
            )
        };
        if r.is_err() {
            return Err(anyhow!("RegQueryValueExW({name}): {r:?}"));
        }
        buf.truncate(len2 as usize);
        Ok(Some(buf))
    }

    pub fn get_sz(&self, name: &str) -> Result<Option<String>> {
        let Some(b) = self.get_raw(name)? else {
            return Ok(None);
        };
        let u16s: Vec<u16> = b
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .take_while(|&c| c != 0)
            .collect();
        Ok(Some(String::from_utf16_lossy(&u16s)))
    }

    pub fn get_dword(&self, name: &str) -> Result<Option<u32>> {
        Ok(self
            .get_raw(name)?
            .filter(|b| b.len() >= 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    }

    pub fn get_qword(&self, name: &str) -> Result<Option<u64>> {
        Ok(self
            .get_raw(name)?
            .filter(|b| b.len() >= 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])))
    }

    pub fn get_binary(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.get_raw(name)
    }

    pub fn get_multi_sz(&self, name: &str) -> Result<Option<Vec<String>>> {
        let Some(b) = self.get_raw(name)? else {
            return Ok(None);
        };
        let u16s: Vec<u16> = b
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        let mut out = Vec::new();
        for part in u16s.split(|&c| c == 0) {
            if !part.is_empty() {
                out.push(String::from_utf16_lossy(part));
            }
        }
        Ok(Some(out))
    }
}

/// Rewrite a key's DACL from SDDL (PROTECTED). Drift-healing for
/// open-existing paths — see [`Key::create`].
pub fn set_key_dacl_from_sddl(path: &str, sddl: &str) -> Result<()> {
    let sd = OwnedSd::from_sddl(sddl).with_context(|| format!("SD for HKLM\\{path}"))?;
    let mut present = windows::core::BOOL::from(false);
    let mut dacl = std::ptr::null_mut();
    let mut defaulted = windows::core::BOOL::from(false);
    unsafe {
        GetSecurityDescriptorDacl(sd.ptr, &mut present, &mut dacl, &mut defaulted)
            .with_context(|| format!("GetSecurityDescriptorDacl for HKLM\\{path}"))?;
    }
    if !present.as_bool() || dacl.is_null() {
        anyhow::bail!("SDDL '{sddl}' yielded no DACL");
    }
    let full = format!(r"MACHINE\{path}");
    let w = wstr(&full);
    let r = unsafe {
        SetNamedSecurityInfoW(
            pcwstr(&w),
            SE_REGISTRY_KEY,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    crate::util::win32_ok(r, &format!("SetNamedSecurityInfoW(HKLM\\{path})"))
}

/// Delete the whole `HKLM\SOFTWARE\sandbox-runtime` tree
/// (uninstall). No-op when absent.
pub fn delete_tree() -> Result<()> {
    let w = wstr(BASE);
    let r = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, pcwstr(&w)) };
    if r == ERROR_FILE_NOT_FOUND || r.is_ok() {
        return Ok(());
    }
    Err(anyhow!("RegDeleteTreeW(HKLM\\{BASE}): {r:?}"))
}

/// Create the key with `sddl` atomically, or — when it already
/// exists (RegCreateKeyExW IGNORES the SA then; the rotation path)
/// — rewrite its DACL to `sddl`. One primitive so no call site can
/// take the create half without the heal half. Only admins can have
/// created a key under HKLM\SOFTWARE, so the heal is drift repair,
/// not squat defense.
pub fn ensure_key_with_dacl(path: &str, sddl: &str) -> Result<Key> {
    let (key, created) = Key::create(path, Some(sddl))?;
    if !created {
        set_key_dacl_from_sddl(path, sddl)?;
    }
    Ok(key)
}

/// Delete one subkey tree under HKLM. No-op when absent.
pub fn delete_subtree(path: &str) -> Result<()> {
    let w = wstr(path);
    let r = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, pcwstr(&w)) };
    if r == ERROR_FILE_NOT_FOUND || r.is_ok() {
        return Ok(());
    }
    Err(anyhow!("RegDeleteTreeW(HKLM\\{path}): {r:?}"))
}

/// Delete one value from an open key. No-op when absent.
pub fn delete_value(key: &Key, name: &str) -> Result<()> {
    use windows::Win32::System::Registry::RegDeleteValueW;
    let w = wstr(name);
    let r = unsafe { RegDeleteValueW(key.0, pcwstr(&w)) };
    if r == ERROR_FILE_NOT_FOUND || r.is_ok() {
        return Ok(());
    }
    Err(anyhow!("RegDeleteValueW({name}): {r:?}"))
}
