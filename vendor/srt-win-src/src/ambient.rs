//! Install-time ambient write-deny targets.
//!
//! The sandbox-user FS model's confinement premise — "a fresh local
//! account has no inherent rights on real-user files" — holds under
//! inheritance-protected profiles but NOT in Windows' stock
//! world-writable corners: directories whose DACLs grant
//! Users/Authenticated Users write access to every local account,
//! the sandbox user included. `srt-win install` stamps each of these
//! with `(D;OICI;WriteDeny;;;<sb-SID>)` (scoped to the sandbox user
//! only; reads unaffected), records them in the state DB
//! (`ambient_denies`), and `uninstall` removes them. Recording them
//! makes [`crate::state_db`]'s recompose chokepoint fold the deny
//! into every converge, so a session grant/stamp/release or crash
//! recovery on the same path can never strip an install-time deny.
//!
//! Deliberately NOT in this list:
//! - Drive roots (`C:\`, `D:\`): semantically fine — inherited denies
//!   compose correctly with grants (nearer-ancestor allow wins) — but
//!   `SetNamedSecurityInfoW` materializes inheritable ACEs onto every
//!   unprotected descendant, so stamping a volume root rewrites DACLs
//!   volume-wide at stamp and unstamp time. Tracked separately.
//! - Third-party subtrees that sever inheritance and grant Users
//!   (`C:\ProgramData\<app>` with its own permissive protected DACL):
//!   unreachable by any ancestor stamp; the WRITE_RESTRICTED-token
//!   mechanism that would close them wholesale breaks Schannel by
//!   LSASS policy (see RESTRICTINGSIDS-RESULTS.md).

use std::path::Path;

/// The fixed world-writable system list, resolved against this
/// machine's environment. Entries that do not exist on this SKU are
/// omitted (e.g. `FxsTmp` is absent on some arm64 builds; `SysWOW64`
/// twins exist only where WOW64 is installed).
///
/// Sources: stock Windows 11 DACLs, verified by probing sandboxed
/// writes (each of these accepted a write from the sandbox account
/// with zero grants): `%ProgramData%` (`Users:(WD,AD)` + CREATOR
/// OWNER), `%PUBLIC%`, and the classic `Users`-writable spool/temp
/// dirs under `%SystemRoot%`.
pub fn ambient_deny_targets() -> Vec<String> {
    let program_data = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    let public = std::env::var("PUBLIC").unwrap_or_else(|_| r"C:\Users\Public".into());
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let sr = |tail: &str| -> String { format!("{system_root}\\{tail}") };

    let candidates: Vec<String> = vec![
        program_data,
        public,
        sr("Temp"),
        sr("Tasks"),
        sr("tracing"),
        sr(r"Registration\CRMLog"),
        sr(r"System32\FxsTmp"),
        sr(r"System32\com\dmp"),
        sr(r"System32\spool\PRINTERS"),
        sr(r"System32\spool\drivers\color"),
        sr(r"SysWOW64\FxsTmp"),
        sr(r"SysWOW64\com\dmp"),
        sr(r"SysWOW64\Tasks"),
    ];
    candidates
        .into_iter()
        .filter(|p| Path::new(p).is_dir())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_exist_and_are_absolute() {
        for t in ambient_deny_targets() {
            assert!(Path::new(&t).is_dir(), "{t} should exist");
            assert!(t.chars().nth(1) == Some(':'), "{t} should be absolute");
        }
    }

    /// On any Windows box the big three resolve and exist.
    #[test]
    fn core_targets_present() {
        let ts = ambient_deny_targets();
        let has = |frag: &str| ts.iter().any(|t| t.to_ascii_lowercase().contains(frag));
        assert!(has("programdata"), "ProgramData missing from {ts:?}");
        assert!(has("public"), "Public missing from {ts:?}");
        assert!(has(r"\temp"), "Windows\\Temp missing from {ts:?}");
    }
}
