//! Path canonicalization and file-identity (`FILE_ID_INFO`)
//! helpers — the "which file is this, exactly" layer that
//! `state_db.rs` keys on and `main.rs` validates with. Nothing here
//! touches ACL/ACE/SD types; the ACL machinery lives in
//! [`crate::acl`].

use anyhow::{Context, Result, bail};
use std::mem::size_of;
use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_FLAG_BACKUP_SEMANTICS, FILE_NAME_NORMALIZED,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GETFINALPATHNAMEBYHANDLE_FLAGS,
    GetFinalPathNameByHandleW, OPEN_EXISTING, VOLUME_NAME_DOS, VOLUME_NAME_GUID,
};

use crate::util::{OwnedHandle, pcwstr, wstr};

/// True iff `decoded` round-trips back to `original` via
/// `encode_utf16` — i.e., `from_utf16_lossy(original)` was
/// lossless (no unpaired-surrogate substitution).
#[inline]
fn utf16_roundtrips(original: &[u16], decoded: &str) -> bool {
    decoded.encode_utf16().eq(original.iter().copied())
}

/// Typed [`canonicalize_path`] error. The hard-error vs
/// soft-skip decision in `main.rs` matches on the variant rather
/// than a substring of the formatted message, so a wording change
/// here cannot silently downgrade a glob to a skip.
#[derive(Debug)]
pub enum CanonError {
    /// Input contains `*` or `?` (outside the `\\?\` prefix).
    /// Always a config bug — never transient.
    Glob,
    /// `ERROR_FILE_NOT_FOUND` / `ERROR_PATH_NOT_FOUND` from
    /// `CreateFileW`. Distinguished so a deny target that does not
    /// exist yet can be materialized as a placeholder chain
    /// ([`create_placeholder_chain`]) instead of soft-skipped.
    NotFound(anyhow::Error),
    /// Open / final-path / attribute read failed for any other
    /// reason (unpaired-surrogate canonical paths, permission
    /// denied, transient IO error).
    Other(anyhow::Error),
}

impl std::fmt::Display for CanonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Glob => write!(
                f,
                "Windows fs deny requires explicit file or directory \
                 paths; got glob"
            ),
            Self::NotFound(e) | Self::Other(e) => write!(f, "{e:#}"),
        }
    }
}
impl std::error::Error for CanonError {}

/// True iff the [`windows::core::Error`] at `e`'s root is
/// `ERROR_FILE_NOT_FOUND` (2) or `ERROR_PATH_NOT_FOUND` (3).
pub fn is_not_found(e: &anyhow::Error) -> bool {
    // By the one table of open errors.
    open_failure(e) == OpenFailure::NotFound
}

/// Why a path could not be opened, as far as it decides what to do
/// with a record that names the path ([`classify_open_failure`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFailure {
    /// Nothing has that name: the object is gone from there, or its
    /// drive letter names nothing. Where the object is, if anywhere,
    /// is a question for its file id.
    NotFound,
    /// The volume cannot be reached right now — no media in the drive,
    /// a locked encrypted volume, a device that is not connected, a
    /// share whose server does not answer.
    VolumeUnavailable,
    /// Anything else (access denied, a sharing violation, an I/O
    /// error): a failure, not an absence.
    Other,
}

/// The one table of open errors, by `HRESULT`.
pub fn classify_open_failure(hresult: u32) -> OpenFailure {
    // BitLocker: the volume is locked (`FVE_E_LOCKED_VOLUME`).
    const FVE_E_LOCKED_VOLUME: u32 = 0x8031_0000;
    if hresult == FVE_E_LOCKED_VOLUME {
        return OpenFailure::VolumeUnavailable;
    }
    // Everything else of interest is a Win32 error code.
    if hresult & 0xFFFF_0000 != 0x8007_0000 {
        return OpenFailure::Other;
    }
    match hresult & 0xFFFF {
        // ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND
        2 | 3 => OpenFailure::NotFound,
        // The Win32 codes for "the drive, device, share or host is not there".
        15 | 20 | 21 | 51 | 53 | 55 | 59 | 64 | 67 | 433 | 1005 | 1110 | 1112 | 1167 | 1203
        | 1231 | 1232 | 1617 => OpenFailure::VolumeUnavailable,
        _ => OpenFailure::Other,
    }
}

/// [`classify_open_failure`] of the system error at the root of `e`;
/// [`OpenFailure::Other`] when there is none.
pub fn open_failure(e: &anyhow::Error) -> OpenFailure {
    e.root_cause()
        .downcast_ref::<windows::core::Error>()
        .map_or(OpenFailure::Other, |we| {
            classify_open_failure(we.code().0 as u32)
        })
}

/// True iff `p` names a UNC network path (`\\server\share\…`,
/// `//server/share/…`, `\\?\UNC\server\…`) — NOT a local extended
/// path (`\\?\C:\…`) or device namespace (`\\.\…`). Checked before
/// materializing a placeholder chain: never `mkdir` on the user's
/// SMB share; the local ACL model does not apply there.
pub fn is_unc_path(p: &str) -> bool {
    // Normalize `/` → `\` so Git-Bash-style `//server/…` and
    // mixed-separator inputs are recognized.
    let n = p.replace('/', "\\");
    if n.get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case(r"\\?\UNC\"))
    {
        return true;
    }
    n.starts_with(r"\\") && !n.starts_with(r"\\?\") && !n.starts_with(r"\\.\")
}

/// Strip a `\\?\` or `\\?\UNC\` extended-path prefix from a
/// pre-canonicalized input (either separator style). Used for
/// comparable component-count sort keys so `\\?\C:\y` and `C:\y`
/// depth-compare correctly.
pub fn strip_extended_prefix(p: &str) -> &str {
    for pfx in [r"\\?\UNC\", "//?/UNC/", r"\\?\", "//?/"] {
        if p.get(..pfx.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(pfx))
        {
            return &p[pfx.len()..];
        }
    }
    p
}

/// Resolve `path` to its kernel-canonical form via
/// `GetFinalPathNameByHandleW` (handles symlinks, junctions, 8.3
/// short names, drive-letter case). Returns the `\\?\`-prefixed
/// path and whether it's a directory.
///
/// `state_db.rs` uses the canonical path as the DB key so a stamp
/// via two equivalent paths (e.g. `C:\PROGRA~1\…` and
/// `C:\Program Files\…`) refcounts correctly.
///
/// Returns [`CanonError::Other`] for any open/resolve failure,
/// including a canonical path that is not UTF-8-representable
/// (unpaired surrogates) — fail closed rather than round-trip a
/// U+FFFD-substituted string into the wrong filesystem object.
pub fn canonicalize_path(path: &str) -> Result<(String, bool), CanonError> {
    // Glob check on the INPUT, ignoring the `\\?\` extended-path
    // prefix (its `?` is not a wildcard). Without the strip,
    // canonicalize_path would reject its OWN output (which always
    // carries the prefix).
    let glob_in = path.strip_prefix(r"\\?\").unwrap_or(path);
    if glob_in.contains('*') || glob_in.contains('?') {
        return Err(CanonError::Glob);
    }
    (|| -> Result<(String, bool)> {
        // Open without requesting any data access so we don't
        // need read permission on the target.
        // `BACKUP_SEMANTICS` lets directories open too.
        let h = open_for_metadata(path)
            .with_context(|| format!("open '{path}' for canonicalization"))?;

        let buf = final_path_from_handle(h.raw())
            .with_context(|| format!("GetFinalPathNameByHandleW('{path}')"))?;
        let canonical = String::from_utf16_lossy(&buf);
        if !utf16_roundtrips(&buf, &canonical) {
            bail!(
                "canonical path for '{path}' is not representable as \
                 UTF-8 (contains unpaired surrogates); not supported"
            );
        }

        // Directory check on the OPEN HANDLE (not a path
        // re-resolve): the handle was opened without
        // `FILE_FLAG_OPEN_REPARSE_POINT`, so a symlink-to-dir was
        // already followed and `h` is the directory itself.
        use windows::Win32::Storage::FileSystem::{
            FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandleEx,
        };
        let mut info = FILE_BASIC_INFO::default();
        unsafe {
            GetFileInformationByHandleEx(
                h.raw(),
                FileBasicInfo,
                (&mut info as *mut FILE_BASIC_INFO).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        }
        .with_context(|| format!("GetFileInformationByHandleEx(FileBasicInfo) '{path}'"))?;
        let is_dir = info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
        Ok((canonical, is_dir))
    })()
    .map_err(|e| {
        if is_not_found(&e) {
            CanonError::NotFound(e)
        } else {
            CanonError::Other(e)
        }
    })
}

/// A filesystem object created by [`create_placeholder_chain`].
/// `canon` is the CANONICAL path so it keys the same as
/// `working_aces` rows.
#[derive(Debug, Clone)]
pub struct Placeholder {
    pub canon: String,
    pub is_dir: bool,
}

/// Materialize `path` (a deny target that does not exist yet):
/// `mkdir` each missing intermediate directory then create an
/// empty leaf. Returns `(leaf_canonical, components_we_created)`.
/// The caller stamps the leaf with the full [`SbAce::Deny`] mask —
/// the deny lands on the exact path, not an over-broad ancestor —
/// and the intermediates with object-only `DenyDelete`.
///
/// **Leaf is a FILE** unless `leaf_is_dir` (target ended with a
/// path separator) or a deeper deny target already created it as a
/// directory (overlapping denies are processed deepest-first). If
/// the user later needs a directory where a placeholder file
/// landed, they (non-sandboxed) delete + `mkdir`; the sandbox
/// cannot.
///
/// Placeholders are PERMANENT (leave-in-place): `acl restore`
/// strips the ACEs but never deletes the file/dir — a user who
/// wrote into a placeholder cannot lose data.
///
/// `record_intent` is called with each component's canonical path
/// BEFORE the on-disk create — intent-first, so a crash between
/// record and create leaves a harmless orphan row rather than an
/// unrecorded on-disk component a later holder cannot discover.
///
/// Idempotent: an `AlreadyExists` on any component is accepted and
/// not added to the return list (we didn't create it); the
/// caller's ancestor-discovery picks it up if it's a recorded
/// placeholder. An intermediate that already exists as a FILE is a
/// hard error (cannot mkdir through it); a leaf that already
/// exists as either kind is accepted.
///
/// [`SbAce::Deny`]: crate::acl::SbAce::Deny
pub fn create_placeholder_chain(
    path: &str,
    leaf_is_dir: bool,
    mut record_intent: impl FnMut(&str) -> Result<()>,
) -> Result<(String, Vec<Placeholder>)> {
    use std::io::ErrorKind::AlreadyExists;
    use std::path::Path;
    // Strip a trailing separator so `Path::components` doesn't
    // yield an empty leaf.
    let target = Path::new(path.trim_end_matches(['\\', '/']));
    // 1. Walk parents to the first that exists — capture its
    //    CANONICAL path. A component we CREATE takes exactly the
    //    case we give it, so `<base-canon>\<component>…` is
    //    canonical without a post-create re-resolve — which lets
    //    intent be recorded BEFORE the create.
    let mut base: Option<(&Path, String)> = None;
    for anc in target.ancestors().skip(1) {
        if anc.as_os_str().is_empty() {
            break;
        }
        match canonicalize_path(&anc.display().to_string()) {
            Ok((c, true)) => {
                base = Some((anc, c));
                break;
            }
            Ok((_, false)) => bail!(
                "deny target '{path}': ancestor '{}' exists as a \
                 FILE — cannot create placeholder chain through it",
                anc.display()
            ),
            Err(CanonError::NotFound(_)) => {}
            Err(e) => bail!(
                "deny target '{path}': canonicalize ancestor '{}': {e}",
                anc.display()
            ),
        }
    }
    let (base_raw, mut cur_canon) = base.ok_or_else(|| {
        anyhow::anyhow!(
            "deny target '{path}' has no existing ancestor \
             directory"
        )
    })?;
    let tail: Vec<_> = target
        .strip_prefix(base_raw)
        .expect("ancestors() yields prefixes of self")
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    // 2. Per component: record intent, then create. On hard
    //    failure, best-effort unwind (with leave-in-place a leaked
    //    empty component is only cosmetic, but a half-built chain
    //    from a hard error is still worth cleaning up).
    let mut created: Vec<Placeholder> = Vec::new();
    let unwind = |created: &[Placeholder]| {
        for p in created.iter().rev() {
            let _ = if p.is_dir {
                std::fs::remove_dir(&p.canon)
            } else {
                std::fs::remove_file(&p.canon)
            };
        }
    };
    let mut cur_raw = base_raw.to_path_buf();
    for (i, comp) in tail.iter().enumerate() {
        let is_leaf = i + 1 == tail.len();
        let is_dir = !is_leaf || leaf_is_dir;
        // `\\?\C:\` already has a trailing `\` — don't double it.
        if !cur_canon.ends_with('\\') {
            cur_canon.push('\\');
        }
        cur_canon.push_str(comp);
        cur_raw.push(comp);
        if let Err(e) = record_intent(&cur_canon) {
            unwind(&created);
            return Err(e);
        }
        let r = if is_dir {
            std::fs::create_dir(&cur_raw)
        } else {
            // `create_new` so a raced-in leaf is never truncated.
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&cur_raw)
                .map(drop)
        };
        match r {
            Ok(()) => created.push(Placeholder {
                canon: cur_canon.clone(),
                is_dir,
            }),
            Err(e) if e.kind() == AlreadyExists => {
                if !is_leaf && !cur_raw.is_dir() {
                    unwind(&created);
                    bail!(
                        "deny target '{path}': intermediate '{}' \
                         exists as a FILE — cannot create placeholder \
                         chain through it",
                        cur_raw.display()
                    );
                }
                // Not ours to record; a Deny'd dir/file at this
                // name is at least as strong. `cur_canon` may
                // differ from the on-disk canonical (case) if we
                // didn't create it — re-canonicalize so the caller
                // and ancestor-discovery key correctly.
                cur_canon = canonicalize_path(&cur_raw.display().to_string())
                    .map(|(c, _)| c)
                    .unwrap_or(cur_canon);
            }
            Err(e) => {
                unwind(&created);
                return Err(e).with_context(|| {
                    format!(
                        "create placeholder {} '{}'",
                        if is_dir { "dir" } else { "leaf" },
                        cur_raw.display()
                    )
                });
            }
        }
    }
    Ok((cur_canon, created))
}

/// Open `path` with no data access (`dwDesiredAccess = 0`), full
/// sharing, `BACKUP_SEMANTICS` (so directories open), `OPEN_EXISTING`.
/// Shared by every metadata-query helper so a future change to the
/// open flags (e.g. `FILE_FLAG_OPEN_REPARSE_POINT`) lands once.
fn open_for_metadata(path: &str) -> Result<OwnedHandle> {
    let w = wstr(path);
    let h = unsafe {
        CreateFileW(
            pcwstr(&w),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }?;
    if h == INVALID_HANDLE_VALUE {
        bail!("CreateFileW('{path}'): INVALID_HANDLE_VALUE");
    }
    Ok(OwnedHandle(h))
}

/// `GetFinalPathNameByHandleW` two-call sizing pattern. Returns the
/// raw UTF-16 buffer (no NUL); caller decodes and round-trip-checks.
fn final_path_from_handle(h: HANDLE) -> Result<Vec<u16>> {
    final_path_with(h, VOLUME_NAME_DOS.0)
}

/// [`final_path_from_handle`] with the volume named as `volume_name`
/// says (`VOLUME_NAME_DOS`, `VOLUME_NAME_GUID`).
fn final_path_with(h: HANDLE, volume_name: u32) -> Result<Vec<u16>> {
    let flags = GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | volume_name);
    let need = unsafe { GetFinalPathNameByHandleW(h, &mut [], flags) };
    if need == 0 {
        bail!("sizing: {}", std::io::Error::last_os_error());
    }
    let mut buf = vec![0u16; need as usize + 1];
    let n = unsafe { GetFinalPathNameByHandleW(h, &mut buf, flags) };
    if n == 0 || n as usize >= buf.len() {
        // n >= buf.len() means "buffer too small" (a concurrent
        // rename grew the path between the size probe and the
        // data call). We bail rather than retry — narrow window,
        // and the caller can re-stamp.
        bail!("{}", std::io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

/// The `\\?\`-prefixed path of the object `h` is open on, as
/// [`canonicalize_path`] would give it.
pub(crate) fn final_path_of(h: HANDLE) -> Result<String> {
    let buf = final_path_from_handle(h)?;
    let s = String::from_utf16_lossy(&buf);
    if !utf16_roundtrips(&buf, &s) {
        bail!("the path is not representable as UTF-8");
    }
    Ok(s)
}

/// Immediate parent of a `\\?\…` canonical path, as a string.
/// Returns `None` when there is no targetable parent (the path is
/// a root, or its immediate parent is a root — touching the
/// volume root's DACL is out of scope for the parent
/// `DenyFdc` ACE).
pub fn canonical_parent_of(canonical_path: &str) -> Option<String> {
    std::path::Path::new(canonical_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty() && p.parent().is_some())
        .map(|p| p.display().to_string())
}

// ─── File identity (FILE_ID_INFO) ───────────────────────────────────

/// A file's stable identity on a volume — the
/// `(VolumeSerialNumber, FileId128)` pair from `FILE_ID_INFO`. On
/// NTFS this is the MFT record identity, so it survives rename
/// and lets us both VALIDATE at restore time (the path still
/// resolves to the same file we stamped) and LOCATE a relocated
/// file for reporting. Stored as a 24-byte blob (8 + 16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    pub volume_serial: u64,
    pub id128: [u8; 16],
}

impl FileId {
    pub fn as_bytes(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[..8].copy_from_slice(&self.volume_serial.to_le_bytes());
        out[8..].copy_from_slice(&self.id128);
        out
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 24 {
            bail!("FileId::from_bytes: expected 24 bytes, got {}", b.len());
        }
        let mut vs = [0u8; 8];
        vs.copy_from_slice(&b[..8]);
        let mut id = [0u8; 16];
        id.copy_from_slice(&b[8..]);
        Ok(Self {
            volume_serial: u64::from_le_bytes(vs),
            id128: id,
        })
    }
}

/// `FILE_ID_INFO` of an already-open handle.
pub(crate) fn file_id_from_handle(h: HANDLE) -> Result<FileId> {
    use windows::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };
    let mut info = FILE_ID_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            h,
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .context("GetFileInformationByHandleEx(FileIdInfo)")?;
    Ok(FileId {
        volume_serial: info.VolumeSerialNumber,
        id128: info.FileId.Identifier,
    })
}

/// `FILE_ID_INFO` of `canonical_path`. Opens with no data access
/// (identity query only), so a DENY-ACE on the file does not
/// interfere — the broker is the real user, not the deny trustee.
pub fn capture_file_id(canonical_path: &str) -> Result<FileId> {
    let h = open_for_metadata(canonical_path)
        .with_context(|| format!("open '{canonical_path}' for file_id"))?;
    file_id_from_handle(h.raw()).with_context(|| format!("file_id '{canonical_path}'"))
}

/// `(file_id, NumberOfLinks, is_dir)` from ONE metadata open.
/// `links > 1` on a non-directory means an alternate hardlink
/// name exists; the additive-ACE refcount in `state_db` is
/// PATH-keyed, so releasing one alias would strip the SHARED
/// DACL while another alias's holder still expects it denied.
/// Directory `NumberOfLinks` counts subdirs (NTFS has no dir
/// hardlinks), so callers gate the check on `!is_dir`.
pub fn capture_id_and_links(canonical_path: &str) -> Result<(FileId, u32, bool)> {
    use windows::Win32::Storage::FileSystem::{
        FILE_STANDARD_INFO, FileStandardInfo, GetFileInformationByHandleEx,
    };
    let h = open_for_metadata(canonical_path)
        .with_context(|| format!("open '{canonical_path}' for file_id+links"))?;
    let id = file_id_from_handle(h.raw()).with_context(|| format!("file_id '{canonical_path}'"))?;
    let mut std_info = FILE_STANDARD_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            h.raw(),
            FileStandardInfo,
            (&mut std_info as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    }
    .with_context(|| {
        format!(
            "GetFileInformationByHandleEx(FileStandardInfo) \
             '{canonical_path}'"
        )
    })?;
    Ok((id, std_info.NumberOfLinks, std_info.Directory))
}

/// Where a recorded `(volume_serial, file_id)` is now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Located {
    /// The object exists; this is its current path.
    At(String),
    /// Positively gone: its volume was found and the volume reported
    /// that no file has this id.
    Gone,
    /// No volume present on this machine has the recorded serial (detached,
    /// locked or reformatted). The object may still exist on it.
    VolumeAbsent,
    /// Could not be established either way — the volume is there and
    /// the open-by-id or path query failed for a reason other than
    /// "no such file". The object may still exist.
    Unknown,
}

/// Whether `canon` (canonical form) is a path on a drive letter:
/// `\\?\X:\…`, as opposed to a share (`\\?\UNC\…`) or anything else in
/// the device namespace.
pub fn is_drive_path(canon: &str) -> bool {
    let b = canon.as_bytes();
    canon.starts_with(r"\\?\")
        && b.len() >= 7
        && b[4].is_ascii_alphabetic()
        && b[5] == b':'
        && b[6] == b'\\'
}

/// Whether the drive letter `canon` (a drive path) is on names a
/// network share right now.
pub fn on_network_drive(canon: &str) -> bool {
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;
    const DRIVE_REMOTE: u32 = 4;
    if !is_drive_path(canon) {
        return false;
    }
    let wide = wstr(&canon[4..7]);
    // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives
    // the call.
    unsafe { GetDriveTypeW(windows::core::PCWSTR(wide.as_ptr())) == DRIVE_REMOTE }
}

/// The root (`\\\\?\\Volume{…}\\`) of every volume on this machine, whether
/// it has a drive letter, is mounted only at a folder, or neither.
/// Network shares are not volumes and are not among them.
fn local_volume_roots() -> Vec<String> {
    use windows::Win32::Storage::FileSystem::{FindFirstVolumeW, FindNextVolumeW, FindVolumeClose};
    let mut out = Vec::new();
    // A volume GUID path is 49 characters and a NUL.
    let mut buf = [0u16; 64];
    // SAFETY: `buf` is writable for its length for both calls, and the
    // search handle is closed once.
    let Ok(find) = (unsafe { FindFirstVolumeW(&mut buf) }) else {
        return out;
    };
    loop {
        let len = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
        out.push(String::from_utf16_lossy(&buf[..len]));
        buf.fill(0);
        if unsafe { FindNextVolumeW(find, &mut buf) }.is_err() {
            break;
        }
    }
    let _ = unsafe { FindVolumeClose(find) };
    out
}

/// A handle on the root of the volume with this serial, if present:
/// among this machine's volumes and, unless `local_only`, drive letters
/// mapped to shares (opening one of those contacts its server).
fn open_volume(volume_serial: u64, local_only: bool) -> Option<OwnedHandle> {
    let remote = (b'A'..=b'Z')
        .map(|drive| format!(r"{}:\", drive as char))
        .filter(|root| !local_only && on_network_drive(&format!(r"\\?\{root}")))
        .map(|root| format!(r"\\?\{root}"));
    local_volume_roots()
        .into_iter()
        .chain(remote)
        .find_map(|root| {
            let vh = open_for_metadata(&root).ok()?;
            (file_id_from_handle(vh.raw()).ok()?.volume_serial == volume_serial).then_some(vh)
        })
}

/// Whether the volume with this serial is present on this machine and
/// can be opened, mounted or not. A drive whose media is out, a locked
/// encrypted volume and a network share are not.
pub fn volume_mounted(volume_serial: u64) -> bool {
    open_volume(volume_serial, true).is_some()
}

/// Locate the current path of a file by `(volume_serial, file_id)`.
/// [`Located::Gone`] only when the volume answered that the id names
/// no file; every other failure is [`Located::Unknown`].
pub fn locate_by_file_id(file_id: &FileId) -> Located {
    locate_on(file_id, false)
}

/// [`locate_by_file_id`] looking only at volumes attached to this
/// machine: a drive letter mapped to a network share is not opened.
pub fn locate_by_file_id_local(file_id: &FileId) -> Located {
    locate_on(file_id, true)
}

fn locate_on(file_id: &FileId, local_only: bool) -> Located {
    // A handle ON the volume the file lived on, to anchor
    // OpenFileById.
    let Some(vh) = open_volume(file_id.volume_serial, local_only) else {
        // No volume that is present carries this serial.
        return Located::VolumeAbsent;
    };
    // `ERROR_INVALID_PARAMETER` is how NTFS rejects a stale file
    // reference.
    locate_from(vh.raw(), file_id, true)
}

/// The root of the share `canon` is on: `\\?\UNC\server\share\`, or
/// the root of a drive letter (one mapped to a share). `None` for any
/// other shape.
pub fn share_root(canon: &str) -> Option<String> {
    let rest = canon.strip_prefix(r"\\?\")?;
    if let Some(unc) = rest
        .strip_prefix(r"UNC\")
        .or_else(|| rest.strip_prefix(r"unc\"))
    {
        let mut parts = unc.split('\\').filter(|p| !p.is_empty());
        let (server, share) = (parts.next()?, parts.next()?);
        return Some(format!(r"\\?\UNC\{server}\{share}\"));
    }
    let b = rest.as_bytes();
    (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
        .then(|| format!(r"\\?\{}\", &rest[..2]))
}

/// [`locate_by_file_id`] on the share `canon` is on (contacts the server).
/// Only the share's plain "no such file" is `Gone`; unsupported or refused
/// is `Unknown`; a share that does not answer is `VolumeAbsent`.
pub fn locate_on_share(canon: &str, file_id: &FileId) -> Located {
    let Some(root) = share_root(canon) else {
        return Located::Unknown;
    };
    let root_handle = match open_for_metadata(&root) {
        Ok(h) => h,
        Err(e) => {
            return match open_failure(&e) {
                OpenFailure::Other => Located::Unknown,
                _ => Located::VolumeAbsent,
            };
        }
    };
    // The same name may lead to another volume now: an id means
    // nothing there.
    match file_id_from_handle(root_handle.raw()) {
        Ok(now) if now.volume_serial == file_id.volume_serial => {}
        _ => return Located::Unknown,
    }
    locate_from(root_handle.raw(), file_id, false)
}

/// Open the object `file_id` names on the volume `anchor` is open on, and
/// say where it is. `stale_is_gone`: `ERROR_INVALID_PARAMETER` means the id
/// names nothing (true of local NTFS, not of a share).
fn locate_from(anchor: HANDLE, file_id: &FileId, stale_is_gone: bool) -> Located {
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER};
    use windows::Win32::Storage::FileSystem::{
        ExtendedFileIdType, FILE_ID_128, FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, OpenFileById,
    };
    let desc = FILE_ID_DESCRIPTOR {
        dwSize: std::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
        Type: ExtendedFileIdType,
        Anonymous: FILE_ID_DESCRIPTOR_0 {
            ExtendedFileId: FILE_ID_128 {
                Identifier: file_id.id128,
            },
        },
    };
    // No access is asked for: the final path needs only a valid handle.
    let fh = match unsafe {
        OpenFileById(
            anchor,
            &desc,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    } {
        Ok(h) => OwnedHandle(h),
        Err(e) if e.code() == ERROR_FILE_NOT_FOUND.into() => return Located::Gone,
        Err(e) if stale_is_gone && e.code() == ERROR_INVALID_PARAMETER.into() => {
            return Located::Gone;
        }
        Err(_) => return Located::Unknown,
    };
    // By drive letter or mount folder where the volume has one,
    // by volume GUID path where it has none.
    let Ok(buf) =
        final_path_from_handle(fh.raw()).or_else(|_| final_path_with(fh.raw(), VOLUME_NAME_GUID.0))
    else {
        return Located::Unknown;
    };
    let s = String::from_utf16_lossy(&buf);
    if utf16_roundtrips(&buf, &s) {
        Located::At(s)
    } else {
        Located::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The share a path is on, for a lookup by file id there.
    #[test]
    fn the_root_of_a_share_is_its_server_and_share_or_its_drive() {
        assert_eq!(
            share_root(r"\\?\UNC\srv\data\a\b").as_deref(),
            Some(r"\\?\UNC\srv\data\")
        );
        assert_eq!(
            share_root(r"\\?\UNC\srv\data").as_deref(),
            Some(r"\\?\UNC\srv\data\")
        );
        assert_eq!(share_root(r"\\?\Z:\a\b").as_deref(), Some(r"\\?\Z:\"));
        assert_eq!(share_root(r"\\?\UNC\srv"), None);
        assert_eq!(share_root(r"\\srv\data\a"), None);
        assert_eq!(share_root(r"\\?\Volume{x}\a"), None);
    }

    /// The table of open errors.
    #[test]
    fn open_errors_are_absence_unavailability_or_failure() {
        let win32 = |code: u32| classify_open_failure(0x8007_0000 | code);
        for code in [2, 3] {
            assert_eq!(win32(code), OpenFailure::NotFound, "{code}");
        }
        for code in [
            15, 20, 21, 51, 53, 55, 59, 64, 67, 433, 1005, 1110, 1112, 1167, 1203, 1231, 1232, 1617,
        ] {
            assert_eq!(win32(code), OpenFailure::VolumeUnavailable, "{code}");
        }
        assert_eq!(
            classify_open_failure(0x8031_0000),
            OpenFailure::VolumeUnavailable
        );
        for code in [0, 1, 5, 32, 87, 123, 1117, 1920] {
            assert_eq!(win32(code), OpenFailure::Other, "{code}");
        }
        for hr in [0, 5, 0x8031_0001, 0x8000_4005, 0xC000_0022] {
            assert_eq!(classify_open_failure(hr), OpenFailure::Other, "{hr:#x}");
        }
        let e = anyhow::Error::from(windows::core::Error::from(
            windows::Win32::Foundation::ERROR_NOT_READY,
        ))
        .context("open 'E:\\work'");
        assert_eq!(open_failure(&e), OpenFailure::VolumeUnavailable);
        assert_eq!(
            open_failure(&anyhow::anyhow!("no system error")),
            OpenFailure::Other
        );
    }

    /// Volumes are found by enumeration, not by drive letter.
    #[test]
    fn the_system_volume_is_found_among_the_volumes() {
        let roots = local_volume_roots();
        assert!(
            roots
                .iter()
                .all(|r| r.starts_with(r"\\?\Volume{") && r.ends_with('\\')),
            "{roots:?}"
        );
        let here = capture_file_id(std::env::temp_dir().to_str().unwrap()).unwrap();
        assert!(volume_mounted(here.volume_serial));
        assert!(!volume_mounted(here.volume_serial ^ 0x5a5a_5a5a_5a5a_5a5a));
        match locate_by_file_id_local(&here) {
            Located::At(p) => assert_eq!(capture_file_id(&p).unwrap(), here),
            other => panic!("{other:?}"),
        }
        let mut elsewhere = here;
        elsewhere.volume_serial ^= 0x5a5a_5a5a_5a5a_5a5a;
        assert_eq!(locate_by_file_id_local(&elsewhere), Located::VolumeAbsent);
    }

    #[test]
    fn canonicalize_rejects_globs() {
        for p in ["C:\\foo\\*.txt", "C:\\foo\\bar?.txt"] {
            assert!(matches!(canonicalize_path(p), Err(CanonError::Glob)), "{p}");
        }
        assert!(matches!(
            canonicalize_path(r"C:\srt-win-no-such-path"),
            Err(CanonError::NotFound(_))
        ));
    }

    /// `create_placeholder_chain` records intent before creating,
    /// builds the missing dirs + leaf, and returns exactly what it
    /// created; a second call is idempotent (`AlreadyExists`
    /// accepted, nothing new returned).
    #[test]
    fn placeholder_chain_round_trip() {
        let base = std::env::temp_dir().join(format!("srt-ph-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let leaf = base.join("a").join("b").join("secret.txt");
        let mut recorded = Vec::new();
        let mut rec = |c: &str| {
            // Intent-first: not on disk yet when recorded.
            assert!(!std::path::Path::new(c).exists(), "{c}");
            recorded.push(c.to_owned());
            Ok(())
        };
        let (leaf_canon, chain) =
            create_placeholder_chain(&leaf.display().to_string(), false, &mut rec).unwrap();
        // Two dirs + one leaf file, root-first; leaf canonical.
        assert_eq!(chain.len(), 3);
        assert!(chain[0].is_dir && chain[1].is_dir && !chain[2].is_dir);
        assert!(leaf_canon.starts_with(r"\\?\"), "{leaf_canon}");
        assert_eq!(leaf_canon, chain[2].canon);
        assert_eq!(recorded.len(), 3);
        assert!(leaf.is_file());
        // Idempotent: second call finds everything already present
        // → returns nothing new; leaf canon unchanged.
        let (again_canon, again) =
            create_placeholder_chain(&leaf.display().to_string(), false, |_| Ok(())).unwrap();
        assert!(again.is_empty(), "got {again:?}");
        assert_eq!(again_canon, leaf_canon);
        // Trailing separator ⇒ directory leaf.
        let dir_leaf = format!("{}\\", base.join("d").display());
        let (dc, _) = create_placeholder_chain(&dir_leaf, true, |_| Ok(())).unwrap();
        assert!(base.join("d").is_dir());
        assert!(dc.starts_with(r"\\?\"), "{dc}");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn canonicalize_round_trip_self() {
        // The test binary's own path is a real file we definitely
        // can open.
        let exe = std::env::current_exe().unwrap();
        let (canon, is_dir) = canonicalize_path(&exe.display().to_string()).unwrap();
        assert!(canon.starts_with(r"\\?\"), "got {canon}");
        assert!(!is_dir);
        // Round-trip: canonicalizing the canonical path is a no-op.
        let (again, _) = canonicalize_path(&canon).unwrap();
        assert_eq!(canon, again);
    }

    /// The parent of a file directly under a drive root IS the
    /// volume root. Touching the volume root's DACL (even with an
    /// additive `DenyFdc` ACE) is out of scope — so
    /// `canonical_parent_of` must return `None` for a top-level
    /// child. Rust's `Path::parent()` returns the root (not
    /// `None`) in this case, so the helper has to recognize and
    /// reject it.
    #[test]
    fn parent_at_volume_root_is_not_stampable() {
        for p in [r"\\?\C:\foo.txt", r"\\?\C:\ProgramData", r"\\?\D:\x"] {
            assert_eq!(
                canonical_parent_of(p),
                None,
                "would stamp the volume root for top-level child {p:?}: \
                 got {:?}",
                canonical_parent_of(p),
            );
        }
        // Anchors (already pass today, must keep passing):
        // the root itself has no parent; a nested path's parent
        // is the immediate directory.
        assert_eq!(canonical_parent_of(r"\\?\C:\"), None);
        assert_eq!(
            canonical_parent_of(r"\\?\C:\a\b").as_deref(),
            Some(r"\\?\C:\a"),
        );
    }

    #[test]
    fn lossy_canonical_path_detected() {
        // Lone high surrogate → from_utf16_lossy substitutes
        // U+FFFD, so the round-trip check must reject it.
        let bad = [0x0041, 0xD800, 0x0042];
        assert!(!utf16_roundtrips(&bad, &String::from_utf16_lossy(&bad)));
        // A valid surrogate PAIR (U+1F600 = D83D DE00) and plain
        // ASCII both round-trip.
        let pair = [0x0041, 0xD83D, 0xDE00, 0x0042];
        assert!(utf16_roundtrips(&pair, &String::from_utf16_lossy(&pair)));
        let ok = [0x0041, 0x0042];
        assert!(utf16_roundtrips(&ok, &String::from_utf16_lossy(&ok)));
    }

    #[test]
    fn unc_and_extended_prefix() {
        for p in [
            r"\\server\share\x",
            "//server/share/x",
            r"\\?\UNC\server\share",
            r"\\?\unc\server\share",
            "//?/UNC/server/share",
        ] {
            assert!(is_unc_path(p), "should be UNC: {p}");
        }
        for p in [r"\\?\C:\x", "//?/C:/x", r"\\.\PIPE\x", r"C:\x", "/tmp/x"] {
            assert!(!is_unc_path(p), "should NOT be UNC: {p}");
        }
        assert_eq!(strip_extended_prefix(r"\\?\C:\y"), r"C:\y");
        assert_eq!(strip_extended_prefix("//?/C:/y"), "C:/y");
        assert_eq!(strip_extended_prefix(r"\\?\UNC\srv\s"), r"srv\s");
        assert_eq!(strip_extended_prefix(r"C:\y"), r"C:\y");
    }
}
