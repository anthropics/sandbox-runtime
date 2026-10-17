//! Write grants that are kept between sessions, for the
//! write-restricted token (`srt-win exec --write-restricted-token`).
//!
//! An inheriting ACE on a directory is copied by Windows to every
//! file and directory below it, so granting a project root costs time
//! linear in the tree, and so does taking the grant back. The
//! per-session model (`acl grant` / `acl revoke`) pays that twice per
//! session. Here it is paid once per root: the grant stays on disk
//! and a later session start only reads the root's own DACL.
//!
//! A grant that stays must not let a session of one project write
//! another. So it is not given to the sandbox user SID (every
//! session has that). Each write root gets its own **capability
//! SID**, and the root's ACEs ([`crate::acl::persistent_aces`]) allow
//! writing only to a token that carries that SID among its
//! restricting SIDs — which the broker puts there only for the roots
//! of the session it launches ([`crate::token`]).
//!
//! ## Capability SIDs
//!
//! `S-1-0-1936880739-<a>-<b>-<c>-<d>`: 128 random bits from the
//! system CSPRNG in four sub-authorities, under the Null identifier
//! authority (0) and a fixed first sub-authority (`"srtc"` as a
//! number). Windows issues account, group, domain, service, package
//! and logon SIDs under authorities 5, 11, 12 and 15, and the only
//! well-known SID under authority 0 is `S-1-0-0`, with a single
//! sub-authority. A five-sub-authority SID under authority 0 is
//! therefore one no account or well-known principal can have, no
//! lookup resolves, and — unlike a made-up `S-1-5-21-…` domain SID —
//! none is tried against a domain controller. The fixed
//! sub-authority lets an ACE for a capability SID be recognised on
//! disk without the state database ([`is_capability_sid`]).
//!
//! The SID is not a secret. A process cannot add a restricting SID to
//! its token: restricting an already restricted token again yields
//! the intersection of the two lists.
//!
//! ## State, and what is trusted for what
//!
//! - The session database (`state_db`, in a directory whose DACL
//!   admits only the real user, SYSTEM and administrators and denies
//!   the sandbox group) maps a root's canonical path and file id to
//!   its capability SID, records the deny ACEs kept with a root, and
//!   holds one write record per path: written before a DACL write
//!   with `done = 0`, set to `done = 1` after the call returned.
//!   Crash recovery replays a record left at 0.
//! - A marker in the real user's registry hive
//!   (`HKCU\Software\sandbox-runtime\PersistentGrants`) lists every
//!   root that may carry a persistent grant, with its file id. A root
//!   is added before its first ACE is written and removed only after
//!   its ACEs were removed. The hive is writable by the real user and
//!   administrators only, so not by the sandbox account, and it does
//!   not live in the database directory: deleting or resetting the
//!   database loses neither the list nor the means to find each
//!   root's object again.
//!
//! ## Running without the write-restricted token
//!
//! A persistent root allows the sandbox GROUP to write. Under the
//! write-restricted token that is half of what is needed; under the
//! ordinary token it is all of it. So nothing may run the sandbox
//! account under the ordinary token while a persistent grant exists:
//! [`unrestricted_block_reason`] refuses when the marker cannot be
//! read, when it or the database lists a root, or when persistent
//! grants were ever made and the database is missing or unreadable;
//! and `acl grant` without `--persistent` also reads the DACL of each
//! path it is about to grant ([`clear_for_unrestricted_grant`]).
//! `acl forget` is what removes the grants.
//!
//! ## A root whose volume is gone
//!
//! A root on a removable disk, a virtual disk, a locked encrypted
//! volume or a share that does not answer cannot be reached to take
//! its ACEs off, and waiting for it must not keep `acl forget` failing
//! forever. Such a root — and each deny target kept with it — is moved
//! from the records to a list of **pending strips** in the marker
//! ([`PendingStrip`]: the object's file id, the group its ACEs name,
//! its last path). `forget` then succeeds and reports it as pending.
//!
//! Whether a volume is there is asked of the volumes of the machine,
//! not of drive letters: a volume mounted only at a folder is present,
//! and an object on a present volume is looked for by its file id
//! wherever it has been renamed or moved to, and stripped there. Only
//! when its volume reports that no such object exists is a record
//! dropped. What becomes of a record is one table ([`disposition`]),
//! fed by one classification of open errors
//! (`path_id::classify_open_failure`).
//!
//! Every later session start, `forget` and uninstall looks at the
//! list again ([`retry_pending`]): once the volume is back the ACEs
//! are removed, and only then the entry. A pending strip does not
//! refuse the ordinary token while its volume is absent — nothing can
//! be written there. From the moment the volume is present again
//! until the strip has succeeded it refuses exactly as a live kept
//! grant does. Nothing drops an entry for a volume that never
//! returns except `acl forget --drop-pending` ([`drop_pending`]), which
//! says what it leaves behind.
//!
//! An entry on a network share is tried at its recorded path and
//! then looked for by its file id on that share, which contacts the
//! server: by an explicit `forget` or uninstall only. Where the share
//! cannot say where the object is, or that it is gone, the entry
//! stays until `--drop-pending`. It does not refuse the
//! ordinary token meanwhile (a local group's entries on a share's
//! files match no token there).
//!
//! ## The profile read grant
//!
//! `crate::profile` keeps a second kind of grant for the sandbox
//! group — read access to the real user's profile — and writes it
//! through the converge of this module: its record of a path
//! (`profile_paths`) is one more input to the ACE list a path is to
//! carry, so a path that is both a write root and part of that grant
//! is written once, with one list. It is refused under the ordinary
//! token by the same rule, and has its own removal (`profile forget`).

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use windows::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};

use crate::acl::{self, AceView, DaclTarget, PersistentTrustees, PersistentWant, SbAce};
use crate::path_id::{self, FileId, Located};
use crate::reg;
use crate::state_db::Locked;

// ─── Capability SIDs ────────────────────────────────────────────────

/// First sub-authority of every capability SID: ASCII `"srtc"`.
const CAPABILITY_TAG: u32 = 0x7372_7463;

/// What every capability SID starts with — see the module doc.
pub const CAPABILITY_SID_PREFIX: &str = "S-1-0-1936880739-";

/// The capability SID made of `random` (four little-endian `u32`s).
pub fn capability_sid_from(random: [u8; 16]) -> String {
    let mut s = format!("S-1-0-{CAPABILITY_TAG}");
    for c in random.as_chunks::<4>().0 {
        s.push_str(&format!("-{}", u32::from_le_bytes(*c)));
    }
    s
}

/// A fresh capability SID from the system CSPRNG. An RNG failure is
/// an error, never a predictable SID.
pub fn new_capability_sid() -> Result<String> {
    let mut r = [0u8; 16];
    unsafe { BCryptGenRandom(None, &mut r, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }
        .ok()
        .context("BCryptGenRandom (capability SID)")?;
    Ok(capability_sid_from(r))
}

/// Whether `sid` is a capability SID in its canonical spelling: the
/// prefix and exactly four decimal `u32` sub-authorities.
pub fn is_capability_sid(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix(CAPABILITY_SID_PREFIX) else {
        return false;
    };
    let mut n = 0;
    rest.split('-').all(|p| {
        n += 1;
        p.parse::<u32>().is_ok_and(|v| v.to_string() == p)
    }) && n == 4
}

// ─── Marker ─────────────────────────────────────────────────────────

pub(crate) const MARKER_KEY: &str = r"Software\sandbox-runtime\PersistentGrants";
const MARKER_ROOTS: &str = "Roots";
const MARKER_EVER: &str = "EverEnabled";
const MARKER_PENDING: &str = "Pending";
const MARKER_GROUP: &str = "GroupSid";
const MARKER_PREVIOUS_GROUPS: &str = "PreviousGroupSids";

/// Remember the sandbox group's SID beside the grants that name it,
/// so they can still be recognised — and removed — after the install
/// record that held it is gone (an uninstall whose removal of the
/// grants did not finish).
///
/// A group SID that was recorded before and differs — the sandbox was
/// reinstalled while grants of the old install were still recorded —
/// is kept in a list beside it: entries naming it are still ours to
/// remove (`PersistentTrustees::previous_group_sids`).
pub(crate) fn marker_set_group_sid(group_sid: &str) -> Result<()> {
    let key = reg::Key::create_hkcu(MARKER_KEY)?;
    if let Some(old) = key.get_sz(MARKER_GROUP)?.filter(|s| !s.is_empty())
        && old != group_sid
    {
        let mut previous = key
            .get_multi_sz(MARKER_PREVIOUS_GROUPS)?
            .unwrap_or_default();
        if !previous.contains(&old) {
            previous.push(old);
            key.set_multi_sz(MARKER_PREVIOUS_GROUPS, &previous)?;
        }
    }
    key.set_sz(MARKER_GROUP, group_sid)
}

/// Set the marker's `EverEnabled`: from now on "nothing is recorded"
/// is believed only from a state database that can be read.
pub(crate) fn marker_set_ever() -> Result<()> {
    reg::Key::create_hkcu(MARKER_KEY)?.set_dword(MARKER_EVER, 1)
}

/// Clear `EverEnabled` once nothing is recorded any more: no root in
/// the marker or the database, and no profile read grant.
pub(crate) fn marker_clear_ever_if_unused(conn: &Connection) -> Result<()> {
    let m = read_marker()?;
    if m.roots.is_empty()
        && m.pending.is_empty()
        && all_root_paths(conn)?.is_empty()
        && !crate::profile::recorded(conn)?
        && let Some(key) = reg::Key::open_hkcu(MARKER_KEY, true)?
    {
        reg::delete_value(&key, MARKER_EVER)?;
        // With nothing recorded, no entry of an earlier group is left
        // to recognise either.
        if key.get_multi_sz(MARKER_PREVIOUS_GROUPS)?.is_some() {
            reg::delete_value(&key, MARKER_PREVIOUS_GROUPS)?;
        }
    }
    Ok(())
}

/// One root in the marker: where it was granted and which object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerRoot {
    pub file_id: FileId,
    pub path: String,
}

impl MarkerRoot {
    /// `<48 hex digits of the file id>|<canonical path>`.
    pub fn encode(&self) -> String {
        let hex: String = self
            .file_id
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{hex}|{}", self.path)
    }

    pub fn decode(s: &str) -> Result<Self> {
        let (hex, path) = s
            .split_once('|')
            .filter(|(h, p)| h.len() == 48 && h.is_ascii() && !p.is_empty())
            .ok_or_else(|| anyhow!("malformed persistent-grant marker entry '{s}'"))?;
        let bytes = (0..24)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .with_context(|| format!("malformed persistent-grant marker entry '{s}'"))?;
        Ok(Self {
            file_id: FileId::from_bytes(&bytes)?,
            path: path.to_owned(),
        })
    }
}

/// A kept grant whose removal is waiting for its volume: the object,
/// the sandbox group its ACEs name, and the path it was last known
/// at (for messages; the file id is what finds it again).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingStrip {
    pub file_id: FileId,
    pub group_sid: String,
    pub path: String,
}

impl PendingStrip {
    /// `<48 hex digits of the file id>|<group SID>|<path>`.
    pub fn encode(&self) -> String {
        let hex: String = self
            .file_id
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{hex}|{}|{}", self.group_sid, self.path)
    }

    pub fn decode(s: &str) -> Result<Self> {
        let bad = || anyhow!("malformed pending-strip marker entry '{s}'");
        let mut it = s.splitn(3, '|');
        let (hex, group, path) = (
            it.next().ok_or_else(bad)?,
            it.next().ok_or_else(bad)?,
            it.next().ok_or_else(bad)?,
        );
        let root = MarkerRoot::decode(&format!("{hex}|{path}")).map_err(|_| bad())?;
        Ok(Self {
            file_id: root.file_id,
            group_sid: group.to_owned(),
            path: root.path,
        })
    }
}

/// The marker as read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Marker {
    /// A persistent grant was made at some point and `acl forget
    /// --all` has not completed since.
    pub ever_enabled: bool,
    pub roots: Vec<MarkerRoot>,
    /// Kept grants waiting for their volume to be removed.
    pub pending: Vec<PendingStrip>,
    /// The sandbox group the recorded grants name.
    pub group_sid: Option<String>,
    /// Groups of earlier installs that recorded grants may still name.
    pub previous_group_sids: Vec<String>,
}

impl Marker {
    /// No root, no pending strip, and no grant was ever made.
    fn nothing_recorded(&self) -> bool {
        !self.ever_enabled && self.roots.is_empty() && self.pending.is_empty()
    }
}

/// Read the marker. An absent key is the empty marker; anything that
/// cannot be read or parsed is an error, which callers treat as
/// "grants may exist".
pub fn read_marker() -> Result<Marker> {
    let Some(key) = reg::Key::open_hkcu(MARKER_KEY, false)? else {
        return Ok(Marker::default());
    };
    let roots = key
        .get_multi_sz(MARKER_ROOTS)?
        .unwrap_or_default()
        .iter()
        .map(|s| MarkerRoot::decode(s))
        .collect::<Result<_>>()?;
    let pending = key
        .get_multi_sz(MARKER_PENDING)?
        .unwrap_or_default()
        .iter()
        .map(|s| PendingStrip::decode(s))
        .collect::<Result<_>>()?;
    Ok(Marker {
        ever_enabled: key.get_dword(MARKER_EVER)?.unwrap_or(0) != 0,
        roots,
        pending,
        group_sid: key.get_sz(MARKER_GROUP)?.filter(|s| !s.is_empty()),
        previous_group_sids: key
            .get_multi_sz(MARKER_PREVIOUS_GROUPS)?
            .unwrap_or_default(),
    })
}

fn write_marker_roots(roots: &[MarkerRoot]) -> Result<()> {
    let key = reg::Key::create_hkcu(MARKER_KEY)?;
    let encoded: Vec<String> = roots.iter().map(MarkerRoot::encode).collect();
    key.set_multi_sz(MARKER_ROOTS, &encoded)
}

/// List `path` (object `file_id`) in the marker, replacing an entry
/// for the same path. `EverEnabled` is set first.
fn marker_add(path: &str, file_id: FileId) -> Result<()> {
    let mut m = read_marker()?;
    marker_set_ever()?;
    let entry = MarkerRoot {
        file_id,
        path: path.to_owned(),
    };
    if m.roots.contains(&entry) {
        return Ok(());
    }
    m.roots.retain(|r| r.path != path);
    m.roots.push(entry);
    write_marker_roots(&m.roots)
}

fn write_pending(pending: &[PendingStrip]) -> Result<()> {
    let key = reg::Key::create_hkcu(MARKER_KEY)?;
    let encoded: Vec<String> = pending.iter().map(PendingStrip::encode).collect();
    key.set_multi_sz(MARKER_PENDING, &encoded)
}

/// Add pending strips to the marker (an object already listed is not
/// listed twice).
pub(crate) fn marker_add_pending(new: &[PendingStrip]) -> Result<()> {
    if new.is_empty() {
        return Ok(());
    }
    let mut pending = read_marker()?.pending;
    for p in new {
        if !pending.iter().any(|q| q.file_id == p.file_id) {
            pending.push(p.clone());
        }
    }
    write_pending(&pending)
}

fn marker_remove(path: &str) -> Result<()> {
    let mut m = read_marker()?;
    if m.roots.iter().any(|r| r.path == path) {
        m.roots.retain(|r| r.path != path);
        write_marker_roots(&m.roots)?;
    }
    Ok(())
}

// ─── Running without the write-restricted token ─────────────────────

/// Root paths the session database records, or `None` if it is
/// missing, unreadable, or has no such table.
fn db_roots_ro() -> Option<Vec<String>> {
    let conn = crate::state_db::open_db_ro().ok()??;
    all_root_paths(&conn).ok()
}

/// Why a command that runs the sandbox account WITHOUT the
/// write-restricted token must not run now; `None` when it may.
///
/// The marker is read first and is enough on its own to refuse. The
/// database is consulted only once persistent grants were ever made,
/// and then both a root it records and its absence refuse: "nothing
/// recorded" is accepted only from a store that is there to be read.
pub fn unrestricted_block_reason() -> Option<String> {
    write_grant_block_reason().or_else(crate::profile::block_reason)
}

/// [`unrestricted_block_reason`] for the write grants alone. A
/// profile read grant refuses the ordinary token under the same rule
/// ([`crate::profile::block_reason`]) and has its own removal.
pub fn write_grant_block_reason() -> Option<String> {
    block_reason_from(read_marker(), db_roots_ro, path_id::volume_mounted)
}

/// [`unrestricted_block_reason`] on what was read: `marker` as
/// [`read_marker`] returned it, `db_roots` as [`db_roots_ro`] does.
/// Every "could not read" refuses.
///
/// A pending strip refuses only while the volume it waits for is
/// mounted (`mounted`): then its ACEs are reachable again and still on
/// disk. On an absent volume nothing can be written.
fn block_reason_from(
    marker: Result<Marker>,
    db_roots: impl FnOnce() -> Option<Vec<String>>,
    mounted: impl Fn(u64) -> bool,
) -> Option<String> {
    let m = match marker {
        Ok(m) => m,
        Err(e) => {
            return Some(format!(
                "the persistent-grant marker cannot be read ({e:#})"
            ));
        }
    };
    if let Some(r) = m.roots.first() {
        return Some(format!(
            "{} persistent write grant(s) exist (e.g. '{}')",
            m.roots.len(),
            r.path
        ));
    }
    if let Some(p) = m.pending.iter().find(|p| mounted(p.file_id.volume_serial)) {
        return Some(format!(
            "the persistent write grant on '{}' is still on disk: its volume was absent \
             when it was forgotten and is mounted again",
            p.path
        ));
    }
    if !m.ever_enabled {
        return None;
    }
    match db_roots() {
        Some(v) if v.is_empty() => None,
        Some(v) => Some(format!(
            "the state database records {} persistent write grant(s) (e.g. '{}')",
            v.len(),
            v[0]
        )),
        None => Some(
            "persistent write grants were made and the state database is missing or \
             unreadable, so where they are cannot be established"
                .to_owned(),
        ),
    }
}

/// `{state, roots, reason?}` for `srt-win user status`: `none` when
/// the ordinary token may be used, `present` when the marker lists
/// roots, `unknown` otherwise.
pub fn status_json() -> serde_json::Value {
    let m = read_marker().unwrap_or_default();
    let roots: Vec<String> = m.roots.into_iter().map(|r| r.path).collect();
    // Grants waiting for an absent volume: listed, and no reason to
    // refuse the ordinary token until the volume is back.
    let pending: Vec<String> = m.pending.into_iter().map(|p| p.path).collect();
    match write_grant_block_reason() {
        None => serde_json::json!({ "state": "none", "roots": roots, "pending": pending }),
        Some(reason) => serde_json::json!({
            "state": if roots.is_empty() { "unknown" } else { "present" },
            "roots": roots,
            "pending": pending,
            "reason": reason,
        }),
    }
}

// ─── Identities ─────────────────────────────────────────────────────

/// The SIDs persistent ACEs are written for.
#[derive(Debug, Clone)]
pub struct Ids {
    /// From the install record (administrator-written). `None` when
    /// nothing is installed: grants cannot be made, and `forget` can
    /// no longer tell the group's ACEs apart.
    pub group_sid: Option<String>,
    pub sandbox_user_sid: Option<String>,
    pub real_user_sid: String,
    /// Sandbox groups other than `group_sid` that grants recorded for
    /// this user were made for: the marker's, when the install record
    /// names another group now or none.
    pub previous_group_sids: Vec<String>,
}

impl Ids {
    pub fn load() -> Result<Self> {
        let setup = crate::install::read_setup()?;
        // With the install record gone (an uninstall that removed the
        // account before the grants were all taken off), the group the
        // recorded grants name is still known from the marker.
        let marker = read_marker().unwrap_or_default();
        let group_sid = setup
            .as_ref()
            .map(|s| s.sandbox_group_sid.clone())
            .or_else(|| marker.group_sid.clone());
        // Every other group the marker knows of: the one recorded
        // with the grants, if the sandbox has been reinstalled since,
        // and those before it.
        let mut previous_group_sids: Vec<String> = marker
            .group_sid
            .into_iter()
            .chain(marker.previous_group_sids)
            .filter(|g| Some(g) != group_sid.as_ref())
            .collect();
        previous_group_sids.dedup();
        Ok(Self {
            group_sid,
            sandbox_user_sid: setup.map(|s| s.sandbox_user_sid),
            real_user_sid: crate::sid::current_user_sid()?,
            previous_group_sids,
        })
    }

    pub(crate) fn trustees(&self) -> PersistentTrustees<'_> {
        PersistentTrustees {
            group_sid: self.group_sid.as_deref(),
            real_user_sid: &self.real_user_sid,
            previous_group_sids: &self.previous_group_sids,
            sandbox_user_sid: self.sandbox_user_sid.as_deref(),
        }
    }
}

// ─── Rows ───────────────────────────────────────────────────────────

fn all_root_paths(conn: &Connection) -> Result<Vec<String>> {
    let mut s = conn.prepare("SELECT canonical_path FROM persistent_roots")?;
    let rows = s.query_map([], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

fn root_row(conn: &Connection, canon: &str) -> Result<Option<(FileId, String)>> {
    let row: Option<(Vec<u8>, String)> = conn
        .query_row(
            "SELECT file_id, capability_sid FROM persistent_roots \
             WHERE canonical_path = ?1",
            params![canon],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .context("SELECT persistent_roots")?;
    row.map(|(id, sid)| Ok((FileId::from_bytes(&id)?, sid)))
        .transpose()
}

/// The longest of `roots` that is `canon` or a directory above it.
pub fn covering_root<'a>(roots: &'a [String], canon: &str) -> Option<&'a str> {
    roots
        .iter()
        .map(String::as_str)
        .filter(|r| {
            canon == *r
                || (canon.starts_with(r)
                    && (r.ends_with('\\') || canon.as_bytes().get(r.len()) == Some(&b'\\')))
        })
        .max_by_key(|r| r.len())
}

/// The ACEs `canon` (now the object `cur`) is to carry, from the
/// rows. A row recorded for a different object at this path is not
/// applied to the one that is there now.
fn wanted(conn: &Connection, ids: &Ids, canon: &str, cur: FileId) -> Result<Vec<AceView>> {
    let cap = root_row(conn, canon)?
        .filter(|(id, _)| *id == cur)
        .map(|(_, sid)| sid);
    let mut s = conn.prepare_cached(
        "SELECT kind, mask, file_id FROM persistent_denies WHERE canonical_path = ?1",
    )?;
    let rows = s.query_map(params![canon], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let (mut deny, mut deny_fdc, mut deny_delete) = (None, false, false);
    for row in rows {
        let (kind, mask, id) = row?;
        if FileId::from_bytes(&id)? != cur {
            continue;
        }
        match SbAce::parse(&kind, &mask)? {
            SbAce::Deny(d) => deny = Some(d),
            SbAce::DenyFdc => deny_fdc = true,
            SbAce::DenyDelete => deny_delete = true,
            SbAce::Grant(_) => bail!("persistent_denies holds a grant row for '{canon}'"),
        }
    }
    // What the profile read grant recorded for this object: an
    // excluded path is a read deny, any other kind one allow.
    let mut profile = None;
    match crate::profile::recorded_kind(conn, canon, cur)? {
        Some(crate::profile_plan::Kind::Denied) => deny = Some(acl::DenyMask::ReadDeny),
        Some(crate::profile_plan::Kind::Container) => profile = Some(acl::ProfileAce::Container),
        Some(crate::profile_plan::Kind::Granted) => profile = Some(acl::ProfileAce::Granted),
        Some(crate::profile_plan::Kind::File) => profile = Some(acl::ProfileAce::File),
        Some(crate::profile_plan::Kind::Skipped | crate::profile_plan::Kind::Ungranted) | None => {}
    }
    if cap.is_none() && deny.is_none() && !deny_fdc && !deny_delete && profile.is_none() {
        return Ok(Vec::new());
    }
    let group_sid = ids.group_sid.as_deref().ok_or_else(|| {
        anyhow!("no install record: the sandbox group SID is unknown — run `srt-win install`")
    })?;
    Ok(acl::persistent_aces(&PersistentWant {
        group_sid,
        real_user_sid: &ids.real_user_sid,
        capability_sid: cap.as_deref(),
        deny,
        deny_fdc,
        deny_delete,
        profile,
    }))
}

/// The wanted ACE list as the text a write record stores.
fn spec_of(want: &[AceView]) -> String {
    want.iter().map(AceView::sddl).collect()
}

// ─── Converge ───────────────────────────────────────────────────────

/// Bring `canon`'s persistent ACEs to what the rows say, writing only
/// if needed. Returns whether it wrote.
///
/// It reads `canon`'s own DACL and nothing below it. The write is
/// skipped when the persistent ACEs on disk are exactly the wanted
/// ones (trustee, mask, inheritance flags, order) AND the write
/// record says a write of exactly that list completed on this file
/// id. The record is what makes the first test sufficient: a write
/// interrupted part-way has already put the ACEs on the root while
/// some descendants still lack them.
///
/// Otherwise: write record with `done = 0`, the DACL write, then
/// `done = 1`. Any failure is returned; nothing is assumed written.
fn converge(conn: &Connection, ids: &Ids, canon: &str) -> Result<bool> {
    converge_on(conn, ids, canon, None)
}

/// An object that is already open, for [`converge_on`]: the handle
/// (with `READ_CONTROL | WRITE_DAC`), and the identity read from it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OpenObject {
    pub handle: windows::Win32::Foundation::HANDLE,
    pub id: FileId,
    pub is_dir: bool,
}

/// [`converge`], reading and writing through `on` when given instead
/// of opening `canon` by name. The profile read grant passes a handle
/// it opened without following a link, so what is written is the
/// object it looked at and never the target of a link put in its
/// place. `canon` is still the key of the records.
pub(crate) fn converge_on(
    conn: &Connection,
    ids: &Ids,
    canon: &str,
    on: Option<&OpenObject>,
) -> Result<bool> {
    let (cur, is_dir) = match on {
        Some(o) => (o.id, o.is_dir),
        None => {
            let (cur, _links, is_dir) = path_id::capture_id_and_links(canon)?;
            (cur, is_dir)
        }
    };
    let target = match on {
        Some(o) => DaclTarget::Handle(o.handle, canon),
        None => DaclTarget::Path(canon),
    };
    let want = wanted(conn, ids, canon, cur)?;
    let aces = acl::read_aces_at(target).with_context(|| format!("read the DACL of '{canon}'"))?;
    let is_root = want.iter().any(|a| is_capability_sid(&a.sid));
    if is_root {
        // An ALLOW for the sandbox user SID (a non-persistent grant
        // of a running session, here or on a directory above) would
        // pass both access checks of every session's token.
        if let Some(sb) = &ids.sandbox_user_sid
            && acl::allows_more_than_read(&aces, sb)
        {
            bail!(
                "'{canon}' grants write access to the sandbox user SID (a session without \
                 the write-restricted token holds it); refusing to keep a persistent grant \
                 beside it"
            );
        }
        for ace in acl::owner_write_paths(&aces) {
            eprintln!(
                "srt-win: WARNING: '{canon}' carries {ace}: files the sandbox creates under \
                 it stay writable to sessions of other projects"
            );
        }
    }
    let t = ids.trustees();
    let spec = spec_of(&want);
    let record: Option<(Vec<u8>, String, i64)> = conn
        .query_row(
            "SELECT file_id, spec, done FROM persistent_writes WHERE canonical_path = ?1",
            params![canon],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .context("SELECT persistent_writes")?;
    // The same entries, and laid out so that no explicit deny on the
    // object sits behind one of our allows (a DACL an earlier build
    // wrote with its allows at the head is rewritten).
    let same = acl::persistent_on_disk(&aces, &t, is_dir) == acl::comparable(&want, is_dir)
        && acl::persistent_layout_ok(&aces, &t);
    // Settled: no write is outstanding for this path. With ACEs
    // wanted, that takes a completed write of exactly this list on
    // this object; with none wanted, only that no write was left
    // unfinished.
    let settled = match &record {
        None => want.is_empty(),
        Some((id, s, done)) => {
            *done == 1 && (want.is_empty() || (*s == spec && id.as_slice() == cur.as_bytes()))
        }
    };
    if same && settled {
        if want.is_empty() {
            conn.execute(
                "DELETE FROM persistent_writes WHERE canonical_path = ?1",
                params![canon],
            )?;
        }
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO persistent_writes (canonical_path, file_id, spec, done) \
         VALUES (?1, ?2, ?3, 0) \
         ON CONFLICT(canonical_path) DO UPDATE SET \
           file_id = excluded.file_id, spec = excluded.spec, done = 0",
        params![canon, cur.as_bytes().as_slice(), spec],
    )
    .context("record persistent write intent")?;
    acl::write_persistent_aces_at(target, &t, &want)?;
    if want.is_empty() {
        conn.execute(
            "DELETE FROM persistent_writes WHERE canonical_path = ?1",
            params![canon],
        )
    } else {
        conn.execute(
            "UPDATE persistent_writes SET done = 1 WHERE canonical_path = ?1",
            params![canon],
        )
    }
    .context("record persistent write completion")?;
    if std::env::var_os("SANDBOX_RUNTIME_WIN_DEBUG").is_some() {
        eprintln!(
            "srt-win: persistent DACL write '{canon}' ({} ACE(s))",
            want.len()
        );
    }
    Ok(true)
}

/// After a [`converge_on`] that failed: whether the object itself
/// carries exactly the wanted ACEs all the same. The system writes an
/// object's own DACL first and then updates what is below it, so a
/// failure further down (a descendant whose access list the caller
/// may not change) leaves the object as wanted. The write record is
/// then closed, so recovery does not repeat a write that cannot get
/// further; `false` leaves it open.
pub(crate) fn settled_on_object(
    conn: &Connection,
    ids: &Ids,
    canon: &str,
    on: &OpenObject,
) -> Result<bool> {
    let want = wanted(conn, ids, canon, on.id)?;
    let aces = acl::read_aces_at(DaclTarget::Handle(on.handle, canon))?;
    if acl::persistent_on_disk(&aces, &ids.trustees(), on.is_dir)
        != acl::comparable(&want, on.is_dir)
        || !acl::persistent_layout_ok(&aces, &ids.trustees())
    {
        return Ok(false);
    }
    if want.is_empty() {
        conn.execute(
            "DELETE FROM persistent_writes WHERE canonical_path = ?1",
            params![canon],
        )?;
    } else {
        conn.execute(
            "UPDATE persistent_writes SET done = 1 WHERE canonical_path = ?1",
            params![canon],
        )?;
    }
    Ok(true)
}

/// Crash recovery: finish every DACL write whose record was left at
/// `done = 0`. A record whose path is gone, or now names another
/// object, is dropped (the object it was for is found again through
/// the marker by `acl forget`). A failure is logged and the record
/// kept; the session start that needs the path fails on it then.
pub(crate) fn replay_pending(conn: &Connection) {
    let read = || -> Result<Vec<(String, Vec<u8>)>> {
        let mut s =
            conn.prepare("SELECT canonical_path, file_id FROM persistent_writes WHERE done = 0")?;
        let rows = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    };
    let pending = match read() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("srt-win: WARNING: reading pending persistent writes: {e:#}");
            return;
        }
    };
    if pending.is_empty() {
        return;
    }
    let ids = match Ids::load() {
        Ok(ids) => ids,
        Err(e) => {
            eprintln!("srt-win: WARNING: pending persistent writes not replayed: {e:#}");
            return;
        }
    };
    for (canon, id) in pending {
        let stale = match path_id::capture_file_id(&canon) {
            Ok(cur) => cur.as_bytes().as_slice() != id.as_slice(),
            Err(e) => path_id::is_not_found(&e),
        };
        let r = if stale {
            conn.execute(
                "DELETE FROM persistent_writes WHERE canonical_path = ?1",
                params![canon],
            )
            .map(|_| ())
            .map_err(anyhow::Error::from)
        } else {
            converge(conn, &ids, &canon).map(|_| ())
        };
        if let Err(e) = r {
            eprintln!("srt-win: WARNING: replay persistent write '{canon}': {e:#}");
        }
    }
}

// ─── Grant ──────────────────────────────────────────────────────────

/// Outcome of [`apply`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    pub roots: usize,
    /// Paths whose DACL was written.
    pub writes: usize,
    /// Paths found as wanted and left alone.
    pub unchanged: usize,
}

/// Make sure `canon` has a capability SID recorded for the object
/// that is there now, and that the marker lists it.
fn record_root(conn: &Connection, ids: &Ids, canon: &str) -> Result<()> {
    let cur = path_id::capture_file_id(canon)?;
    match root_row(conn, canon)? {
        Some((id, sid)) if id == cur => {
            if !is_capability_sid(&sid) {
                bail!("the state database holds '{sid}' as the capability SID of '{canon}'");
            }
        }
        prior => {
            if prior.is_some() {
                // The path names another object than the one granted
                // before. Take the grant off that one, wherever it is
                // now, before this one gets a SID of its own.
                forget_one(conn, ids, canon)?;
            }
            let sid = new_capability_sid()?;
            conn.execute(
                "INSERT INTO persistent_roots (canonical_path, file_id, capability_sid) \
                 VALUES (?1, ?2, ?3)",
                params![canon, cur.as_bytes().as_slice(), sid],
            )
            .with_context(|| format!("store the capability SID of '{canon}'"))?;
        }
    }
    // Before any ACE is written — see the module doc.
    if let Some(g) = &ids.group_sid {
        marker_set_group_sid(g)?;
    }
    marker_add(canon, cur).with_context(|| format!("list '{canon}' in the persistent-grant marker"))
}

fn record_deny(conn: &Connection, canon: &str, ace: SbAce, root: &str) -> Result<()> {
    let id = path_id::capture_file_id(canon)?;
    let prior: Option<(String, Vec<u8>)> = conn
        .query_row(
            "SELECT mask, file_id FROM persistent_denies \
             WHERE canonical_path = ?1 AND kind = ?2",
            params![canon, ace.kind()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .context("SELECT persistent_denies")?;
    // Never narrowed while the object is the same: a deny stays as
    // wide as any session asked for until the root is forgotten.
    let eff = match prior {
        Some((mask, old)) if old.as_slice() == id.as_bytes() => {
            SbAce::parse(ace.kind(), &mask)?.max(ace)
        }
        _ => ace,
    };
    conn.execute(
        "INSERT INTO persistent_denies (canonical_path, kind, file_id, mask, root) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(canonical_path, kind) DO UPDATE SET \
           file_id = excluded.file_id, mask = excluded.mask, root = excluded.root",
        params![
            canon,
            ace.kind(),
            id.as_bytes().as_slice(),
            eff.as_str(),
            root
        ],
    )
    .context("UPSERT persistent_denies")?;
    Ok(())
}

/// Session start with the write-restricted token: record `roots`
/// (canonical write roots) and the deny targets under any persistent
/// root, then converge every path involved — roots first — reading
/// one DACL per path and writing only where needed.
///
/// Deny targets under a persistent root are stamped for the sandbox
/// group and kept with the root: this adds and widens, and never
/// removes; `acl forget` removes them with the grant. A deny target
/// (not a placeholder directory on the way to one) also gets the
/// delete-child deny on its parent. Targets under no persistent root
/// are returned for the caller to stamp per session as before.
///
/// Every failure is returned: no capability SID, no marker entry, an
/// unreadable DACL, a failed write. Nothing falls back to a
/// per-session grant.
pub fn apply(
    db: &Locked,
    ids: &Ids,
    roots: &[String],
    denies: &[(String, SbAce)],
) -> Result<(Applied, Vec<(String, SbAce)>)> {
    let conn = db.conn();
    if ids.group_sid.is_none() {
        bail!("no install record: run `srt-win install`");
    }
    // A kept grant whose volume was absent when it was forgotten: if
    // the volume is back, its ACEs come off now.
    retry_pending(conn, ids, false)?;
    let mut touched: Vec<String> = Vec::new();
    let mut touch = |p: &str| {
        if !touched.iter().any(|t| t == p) {
            touched.push(p.to_owned());
        }
    };
    for root in roots {
        record_root(conn, ids, root)?;
        touch(root);
    }
    let all_roots = all_root_paths(conn)?;
    let mut per_session = Vec::new();
    for (canon, ace) in denies {
        let Some(root) = covering_root(&all_roots, canon) else {
            per_session.push((canon.clone(), *ace));
            continue;
        };
        record_deny(conn, canon, *ace, root)?;
        touch(canon);
        if matches!(ace, SbAce::Deny(_) | SbAce::DenyDelete)
            && let Some(parent) = path_id::canonical_parent_of(canon)
        {
            record_deny(conn, &parent, SbAce::DenyFdc, root)?;
            touch(&parent);
        }
    }
    let mut out = Applied {
        roots: roots.len(),
        ..Default::default()
    };
    for p in &touched {
        if converge(conn, ids, p).with_context(|| format!("persistent grant '{p}'"))? {
            out.writes += 1;
        } else {
            out.unchanged += 1;
        }
    }
    Ok((out, per_session))
}

/// The capability SIDs of `roots` (as given on `exec --write-root`),
/// for the child token. Reads the database only. A root with no
/// capability SID recorded for the object now at its path is an
/// error: the command must not run with a shorter list than asked.
pub fn capability_sids_for(roots: &[String]) -> Result<Vec<String>> {
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    let conn = crate::state_db::open_db_ro()?
        .ok_or_else(|| anyhow!("the state database is missing or unreadable"))?;
    let mut out = Vec::with_capacity(roots.len());
    for raw in roots {
        let (canon, _) =
            path_id::canonicalize_path(raw).map_err(|e| anyhow!("write root '{raw}': {e}"))?;
        let cur = path_id::capture_file_id(&canon)?;
        match root_row(&conn, &canon)? {
            Some((id, sid)) if id == cur && is_capability_sid(&sid) => {
                if !out.contains(&sid) {
                    out.push(sid);
                }
            }
            _ => bail!(
                "write root '{canon}' has no persistent grant recorded for it — \
                 `srt-win acl grant --persistent` it first"
            ),
        }
    }
    Ok(out)
}

// ─── Forget ─────────────────────────────────────────────────────────

/// Per-root outcome of [`forget`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Forgot {
    /// Persistent ACEs were on disk and were removed.
    Removed,
    /// Nothing was on disk; the records are gone.
    Absent,
    /// The object is on a volume that is not mounted. Its records are
    /// gone and it is listed as a pending strip, to be removed when
    /// the volume is back.
    Pending,
    /// Could not be completed; the root stays recorded.
    Failed(String),
}

impl Forgot {
    pub fn as_str(&self) -> &'static str {
        match self {
            Forgot::Removed => "removed",
            Forgot::Absent => "absent",
            Forgot::Pending => "pending",
            Forgot::Failed(_) => "failed",
        }
    }
}

/// What opening a recorded path found, as far as it decides what
/// becomes of the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AtPath {
    /// The recorded object.
    Recorded,
    /// Something, but not the recorded object.
    Another,
    /// Nothing has that name ([`path_id::OpenFailure::NotFound`]).
    Nothing,
    /// The volume cannot be reached right now
    /// ([`path_id::OpenFailure::VolumeUnavailable`]).
    Unavailable,
}

/// What removing a record's ACEs takes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Disposition {
    /// Remove them at the recorded path.
    StripHere,
    /// The object is at another path now — renamed, moved, or the
    /// volume is mounted elsewhere: remove them there.
    StripAt(String),
    /// The object no longer exists: there is nothing to remove.
    Drop,
    /// The object is on a volume that cannot be reached now: a
    /// pending strip.
    Pending,
    /// It could not be established where the object is while its
    /// volume is there: an error; the record stays.
    Fail,
}

/// The one table: where the recorded path leads now (`at_path`), where
/// the object was found by its file id (`located`, asked only when the
/// path does not lead to it), and whether the path is on a network
/// share (`network`), where a volume cannot be looked for and an
/// object not be found by its id.
///
/// | path \\ by file id | at P     | gone | volume absent        | unknown |
/// |--------------------|----------|------|----------------------|---------|
/// | the object         | here     | here | here                 | here    |
/// | another / nothing  | strip P  | drop | pending (local only) | fail    |
/// | volume unavailable | strip P  | drop | pending              | pending |
///
/// On a share, "another / nothing" with the object not found is a
/// failure, as it always was: the share answered, and the object is
/// not where it was recorded.
fn disposition(at_path: AtPath, located: impl FnOnce() -> Located, network: bool) -> Disposition {
    if at_path == AtPath::Recorded {
        return Disposition::StripHere;
    }
    match (located(), at_path) {
        (Located::At(p), _) => Disposition::StripAt(p),
        (Located::Gone, _) => Disposition::Drop,
        (Located::VolumeAbsent | Located::Unknown, AtPath::Unavailable) => Disposition::Pending,
        (Located::VolumeAbsent, _) if !network => Disposition::Pending,
        _ => Disposition::Fail,
    }
}

/// Whether `canon` is somewhere volumes cannot be enumerated: a share,
/// or a drive letter mapped to one.
fn on_network(canon: &str) -> bool {
    !path_id::is_drive_path(canon) || path_id::on_network_drive(canon)
}

/// What is at `path` now, against the recorded object `id`: the open
/// error classified ([`path_id::open_failure`]). An error that is
/// neither "nothing there" nor "volume unavailable" is returned.
fn at_path(path: &str, id: &FileId) -> Result<AtPath> {
    match path_id::capture_file_id(path) {
        Ok(now) if now == *id => Ok(AtPath::Recorded),
        Ok(_) => Ok(AtPath::Another),
        Err(e) => match path_id::open_failure(&e) {
            path_id::OpenFailure::NotFound => Ok(AtPath::Nothing),
            path_id::OpenFailure::VolumeUnavailable => Ok(AtPath::Unavailable),
            path_id::OpenFailure::Other => Err(e.context(format!("open '{path}'"))),
        },
    }
}

/// Remove `canon`'s persistent grant: its ACEs from the object at the
/// path and from the object it was granted on wherever that is now,
/// the deny ACEs kept with it, its capability SID, and its marker
/// entry.
///
/// Rows and ACEs go together: the row deletions commit only after
/// every DACL write succeeded, and the marker entry is removed after
/// that. What becomes of each recorded object — the root and every
/// deny target — is decided by [`disposition`]: one that cannot be
/// found while its volume is there fails the call, so the root stays
/// listed ("could not look" is not "nothing there"); one whose VOLUME
/// cannot be reached becomes a pending strip (see the module doc),
/// written to the marker before the rows go.
fn forget_one(conn: &Connection, ids: &Ids, canon: &str) -> Result<Forgot> {
    forget_one_with(conn, ids, canon, path_id::locate_by_file_id)
}

fn forget_one_with(
    conn: &Connection,
    ids: &Ids,
    canon: &str,
    locate: impl Fn(&FileId) -> Located,
) -> Result<Forgot> {
    // Every object the grant may have been written on.
    let mut granted: Vec<FileId> = Vec::new();
    granted.extend(root_row(conn, canon)?.map(|(id, _)| id));
    for r in read_marker()?.roots {
        if r.path == canon && !granted.contains(&r.file_id) {
            granted.push(r.file_id);
        }
    }
    let tx = conn.unchecked_transaction().context("begin forget tx")?;
    let denies: Vec<(String, Vec<u8>)> = {
        let mut s = tx.prepare(
            "SELECT DISTINCT canonical_path, file_id FROM persistent_denies WHERE root = ?1",
        )?;
        let rows = s.query_map(params![canon], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    tx.execute(
        "DELETE FROM persistent_denies WHERE root = ?1",
        params![canon],
    )?;
    tx.execute(
        "DELETE FROM persistent_roots WHERE canonical_path = ?1",
        params![canon],
    )?;
    // With the rows gone, converging a path strips it (or leaves
    // what another root still records for it).
    let mut removed = false;
    let mut pending: Vec<PendingStrip> = Vec::new();
    let mut recorded: Vec<(String, FileId)> =
        granted.iter().map(|id| (canon.to_owned(), *id)).collect();
    recorded.extend(
        denies
            .iter()
            .filter_map(|(d, id)| Some((d.clone(), FileId::from_bytes(id).ok()?))),
    );
    // Whatever is at a recorded path now carries nothing of ours any
    // more, whichever object it is.
    let mut stripped_here: Vec<&str> = Vec::new();
    for (path, id) in &recorded {
        let at = at_path(path, id)?;
        if matches!(at, AtPath::Recorded | AtPath::Another)
            && !stripped_here.contains(&path.as_str())
        {
            removed |= converge(&tx, ids, path)?;
            stripped_here.push(path);
        }
        match disposition(at, || locate(id), on_network(path)) {
            Disposition::StripHere | Disposition::Drop => {}
            Disposition::StripAt(now) => removed |= converge(&tx, ids, &now)?,
            Disposition::Pending => pending.push(PendingStrip {
                file_id: *id,
                group_sid: ids.group_sid.clone().unwrap_or_default(),
                path: path.clone(),
            }),
            Disposition::Fail => bail!(
                "the object recorded for '{path}' is no longer at that path and could not \
                 be located by file id; its ACEs may still be on disk"
            ),
        }
    }
    // A root with no record of the object it was granted on (nothing
    // in the database or the marker): the path is all there is.
    if granted.is_empty() && path_id::capture_file_id(canon).is_ok() {
        removed |= converge(&tx, ids, canon)?;
    }
    // Before the rows go: a crash in between leaves the object listed
    // twice, never not at all.
    marker_add_pending(&pending)?;
    tx.commit().context("commit forget")?;
    marker_remove(canon)?;
    Ok(if !pending.is_empty() {
        Forgot::Pending
    } else if removed {
        Forgot::Removed
    } else {
        Forgot::Absent
    })
}

/// Look at every pending strip again.
///
/// One on a volume of this machine is looked for by its file id among
/// the volumes that are present: found, the ACEs come off the object
/// wherever it is now, and only then the entry goes; the volume
/// reporting that no such object exists, the entry goes; the volume
/// still away, or the object not reachable, it stays. Nothing else
/// removes an entry — a volume that will never return is given up
/// only by [`drop_pending`], on request.
///
/// One on a network share is tried at its recorded path and, when
/// that does not lead to it, looked for by its id on that share —
/// only when `probe_network` is set (an explicit `forget` or
/// uninstall), because either contacts the server: never at a session
/// start.
///
/// Returns what is still pending.
pub(crate) fn retry_pending(
    conn: &Connection,
    ids: &Ids,
    probe_network: bool,
) -> Result<Vec<PendingStrip>> {
    retry_pending_with(
        read_marker()?.pending,
        |p| {
            if !on_network(&p.path) {
                return path_id::locate_by_file_id_local(&p.file_id);
            }
            if !probe_network {
                return Located::VolumeAbsent;
            }
            // On a share the recorded path is tried first. If it does
            // not lead to the recorded object — nothing there, or
            // another object — the object may have been renamed and
            // still carry the grant: it is looked for by its id on
            // that share. Found, it is stripped where it is. The
            // share saying the id names nothing, the entry goes. The
            // share not saying (it does not open files by id, or
            // refused), the entry STAYS: only `--drop-pending` gives
            // it up. A path that does not answer waits.
            let elsewhere = || match path_id::locate_on_share(&p.path, &p.file_id) {
                Located::Gone => {
                    eprintln!(
                        "srt-win: the object the kept grant on '{}' was made on no longer \
                         exists on its share; its record is dropped",
                        p.path
                    );
                    Located::Gone
                }
                Located::At(at) => Located::At(at),
                other => {
                    eprintln!(
                        "srt-win: the object the kept grant on '{}' was made on is not at \
                         that path, and the share could not say where it is or that it is \
                         gone; if it was renamed it still carries the grant. The record \
                         stays (`srt-win acl forget --drop-pending` gives it up).",
                        p.path
                    );
                    other
                }
            };
            match path_id::capture_file_id(&p.path) {
                Ok(now) if now == p.file_id => Located::At(p.path.clone()),
                Ok(_) => elsewhere(),
                Err(e) if path_id::is_not_found(&e) => elsewhere(),
                Err(_) => Located::VolumeAbsent,
            }
        },
        |p, at| {
            // The ACEs name the group that was installed when the grant
            // was made, which may not be the one installed now.
            let then = Ids {
                group_sid: Some(p.group_sid.clone()).filter(|g| !g.is_empty()),
                ..ids.clone()
            };
            converge(conn, &then, at).map(|_| ())
        },
    )
    .and_then(|(left, changed)| {
        if changed {
            write_pending(&left)?;
        }
        Ok(left)
    })
}

/// [`retry_pending`] on what was read, with the lookups passed in:
/// what stays pending, and whether the list changed.
fn retry_pending_with(
    pending: Vec<PendingStrip>,
    locate: impl Fn(&PendingStrip) -> Located,
    strip: impl Fn(&PendingStrip, &str) -> Result<()>,
) -> Result<(Vec<PendingStrip>, bool)> {
    let before = pending.len();
    let mut left = Vec::new();
    for p in pending {
        match locate(&p) {
            Located::At(at) => {
                if let Err(e) = strip(&p, &at) {
                    eprintln!(
                        "srt-win: WARNING: the kept grant on '{at}' (forgotten while its \
                         volume was absent) could not be removed: {e:#}"
                    );
                    left.push(p);
                }
            }
            Located::Gone => {}
            Located::VolumeAbsent | Located::Unknown => left.push(p),
        }
    }
    let changed = left.len() != before;
    Ok((left, changed))
}

/// Give up the pending strips recorded for `paths`: the deliberate way
/// to stop waiting for a volume that will not return (reformatted,
/// discarded). Nothing is written anywhere but the list. The entries
/// dropped are returned, so the caller can say what is being
/// abandoned.
///
/// Only an entry whose volume really is absent can be given up. First
/// everything that can be removed is ([`retry_pending`]); an entry
/// that is then still pending while its volume is present, by the
/// same enumeration of volumes everything else uses, is live on a
/// reachable object: it is not dropped, and the call fails saying so.
/// One on a share that is still pending is one whose path does not
/// answer or whose object could not be found by its id there: it may
/// be given up, and what that leaves behind is said. A path with no pending
/// entry is an error too. Either way nothing is dropped.
pub fn drop_pending(conn: &Connection, ids: &Ids, paths: &[String]) -> Result<Vec<PendingStrip>> {
    let pending = retry_pending(conn, ids, true)?;
    let names = |p: &PendingStrip, want: &str| {
        let want = want.trim_end_matches('\\');
        let have = p.path.trim_end_matches('\\');
        have.eq_ignore_ascii_case(want)
            || have
                .strip_prefix(r"\\?\")
                .is_some_and(|h| h.eq_ignore_ascii_case(want))
    };
    let named = |p: &PendingStrip| paths.iter().any(|want| names(p, want));
    for want in paths {
        if !pending.iter().any(|p| names(p, want)) {
            bail!(
                "no kept grant is waiting for a volume at '{want}' (what could be removed \
                 has been)"
            );
        }
    }
    for p in pending.iter().filter(|p| named(p)) {
        // What is left on a share after the retry above is a path
        // that does not answer, or an object the share could not
        // find by its id.
        let reachable = !on_network(&p.path) && path_id::volume_mounted(p.file_id.volume_serial);
        if reachable {
            bail!(
                "the volume of '{}' is present, and its entries could not be removed just \
                 now; they are live and are not given up. Run `srt-win acl forget --all` \
                 for the reason",
                p.path
            );
        }
    }
    let (dropped, left): (Vec<_>, Vec<_>) = pending.into_iter().partition(named);
    for p in dropped.iter().filter(|p| on_network(&p.path)) {
        // What is given up on a share, exactly: the object was not at
        // its path and could not be found by its id — which is not
        // the share saying it is gone.
        eprintln!(
            "srt-win: giving up the kept grant recorded at '{}': the object is not at that \
             path and its share could not be asked where it is. If it still exists under \
             another name it keeps the entries of {}; `icacls <its path> /remove:g \"*{}\" \
             /T` removes them.",
            p.path,
            if p.group_sid.is_empty() {
                "the sandbox group"
            } else {
                "group"
            },
            if p.group_sid.is_empty() {
                "<sandbox group SID>"
            } else {
                &p.group_sid
            },
        );
    }
    write_pending(&left)?;
    Ok(dropped)
}

/// `acl forget`: remove the persistent grants of `roots` (canonical
/// paths, or paths as recorded when they no longer resolve), or with
/// `all` of every root the marker or the database lists. One DACL
/// write — one walk of the tree — per root that carries a grant.
///
/// With `all`, once no root is left listed, the marker's
/// `EverEnabled` is cleared too.
pub fn forget(
    db: &Locked,
    ids: &Ids,
    roots: &[String],
    all: bool,
) -> Result<Vec<(String, Forgot)>> {
    let conn = db.conn();
    // First the grants forgotten earlier whose volume was absent.
    // An explicit request: one on a share is tried at its path too.
    let still_pending = retry_pending(conn, ids, true)?;
    let mut targets: Vec<String> = roots.to_vec();
    if all {
        targets.extend(read_marker()?.roots.into_iter().map(|r| r.path));
        targets.extend(all_root_paths(conn)?);
    }
    let mut seen = std::collections::HashSet::new();
    targets.retain(|t| seen.insert(t.clone()));
    let mut out = Vec::with_capacity(targets.len());
    for t in targets {
        let r = match forget_one(conn, ids, &t) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("srt-win: forget '{t}': {e:#}");
                Forgot::Failed(format!("{e:#}"))
            }
        };
        out.push((t, r));
    }
    // … which are part of the answer for as long as they wait.
    for p in still_pending {
        if !out.iter().any(|(t, _)| *t == p.path) {
            out.push((p.path, Forgot::Pending));
        }
    }
    if all {
        marker_clear_ever_if_unused(conn)?;
    }
    Ok(out)
}

/// `srt-win uninstall`: forget every persistent grant of the calling
/// user. Does nothing — and creates no state — when none was ever
/// made. Returns how many roots were processed and how many failed.
pub fn forget_everything() -> Result<Forgotten> {
    forget_everything_as(None)
}

/// What the half of `srt-win uninstall` that runs as the calling user
/// does once the elevated half has returned.
///
/// The calling user's grants name the sandbox group, and their records
/// are the calling user's own (their registry hive, their session
/// database), which an elevated process running as another account
/// cannot reach. So ONLY this half forgets them — the elevated step
/// removes the machine-wide install and nothing else — and it does so
/// by what is true afterwards, not by the elevated step's exit code
/// alone:
///
/// - the install record is still there: the account and group were
///   not removed (the prompt was declined, or the step failed before
///   it got that far). The grants are still what a session runs on;
///   nothing of the caller's is touched.
/// - the install record is gone: the account and group are removed,
///   whether or not the step then reported a failure of something
///   else. The grants are forgotten, always — otherwise they would
///   name a group that no longer exists, and after a reinstall would
///   no longer be recognised by the new group's SID.
///
/// The group's SID is read before the hop, so its ACEs can still be
/// recognised once the group is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterElevation {
    /// The install is gone: forget the caller's grants. `step_failed`
    /// is the elevated step's exit code if it was not 0 — it removed
    /// the account and then failed at something else.
    ForgetGrants { step_failed: Option<i32> },
    /// The install is still there: change nothing of the caller's,
    /// exit with this code.
    LeaveEverything(i32),
}

pub fn after_elevation(elevated_exit: i32, install_record_present: bool) -> AfterElevation {
    if install_record_present {
        // Not removed. An exit of 0 with the record still there is not
        // a clean removal either.
        AfterElevation::LeaveEverything(if elevated_exit == 0 { 1 } else { elevated_exit })
    } else {
        AfterElevation::ForgetGrants {
            step_failed: (elevated_exit != 0).then_some(elevated_exit),
        }
    }
}

/// What [`forget_everything`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Forgotten {
    /// Roots processed.
    pub roots: usize,
    /// Roots that could not be completed; they stay recorded.
    pub failed: usize,
    /// Paths on volumes that are not mounted, still to be stripped.
    pub pending: Vec<String>,
}

/// [`forget_everything`] with the identities read earlier: after the
/// install record is gone, `ids` taken before it went still name the
/// group the grants were written for.
pub fn forget_everything_as(ids: Option<&Ids>) -> Result<Forgotten> {
    if read_marker().is_ok_and(|m| m.nothing_recorded()) {
        return Ok(Forgotten::default());
    }
    let loaded;
    let ids = match ids {
        Some(ids) => ids,
        None => {
            loaded = Ids::load()?;
            &loaded
        }
    };
    let holder = crate::state_db::HolderPid(std::process::id());
    let (out, _) = crate::state_db::with_init_lock(holder, false, |db| forget(db, ids, &[], true))?;
    Ok(Forgotten {
        roots: out.len(),
        failed: out
            .iter()
            .filter(|(_, r)| matches!(r, Forgot::Failed(_)))
            .count(),
        pending: out
            .into_iter()
            .filter(|(_, r)| *r == Forgot::Pending)
            .map(|(p, _)| p)
            .collect(),
    })
}

/// `acl grant` without `--persistent` is about to give the sandbox
/// USER SID access to `targets` (canonical), for sessions that run
/// under the ordinary token. Refuse while a persistent grant is
/// recorded anywhere ([`unrestricted_block_reason`]) — and, because
/// the records may be gone while ACEs remain, look at each target's
/// own DACL too: a persistent ALLOW written on the target itself is
/// removed (one walk), one inherited from a directory above cannot be
/// removed from here and refuses. So does a target whose DACL cannot
/// be read: "could not look" is not "no grant there".
pub fn clear_for_unrestricted_grant(db: &Locked, targets: &[String]) -> Result<()> {
    // A grant forgotten while its volume was absent, and back now.
    retry_pending(db.conn(), &Ids::load()?, false)?;
    if let Some(why) = write_grant_block_reason() {
        bail!(
            "{why}; grants for the ordinary token are refused until `srt-win acl forget \
             --all` has removed them"
        );
    }
    if let Some(why) = crate::profile::block_reason() {
        bail!(
            "{why}; grants for the ordinary token are refused until `srt-win profile \
             forget` has removed it"
        );
    }
    let ids = Ids::load()?;
    for canon in targets {
        match unrecorded_grant_on(acl::read_aces(canon), ids.group_sid.as_deref()) {
            Ok(UnrecordedGrant::None) => {}
            Ok(UnrecordedGrant::Own) => {
                eprintln!("srt-win: '{canon}' carries an unrecorded persistent grant; removing it");
                forget_one(db.conn(), &ids, canon)
                    .with_context(|| format!("remove the persistent grant on '{canon}'"))?;
            }
            Ok(UnrecordedGrant::Inherited) => bail!(
                "'{canon}' inherits a persistent write grant from a directory above it that \
                 is no longer recorded; run `srt-win acl forget <that directory>`"
            ),
            Err(e) => bail!(
                "the access list of '{canon}' cannot be read ({e:#}), so a persistent write \
                 grant on it cannot be ruled out; grants for the ordinary token are refused"
            ),
        }
    }
    Ok(())
}

/// A persistent ALLOW found on a path that no record lists.
#[derive(Debug, PartialEq, Eq)]
enum UnrecordedGrant {
    None,
    /// Written on the path itself: `forget_one` can remove it.
    Own,
    /// Inherited from a directory above: not removable from here.
    Inherited,
}

/// What `aces` (a path's own DACL, as [`acl::read_aces`] returned it)
/// says about a persistent ALLOW — one for the sandbox group or for a
/// capability SID. A DACL that could not be read is an error, never
/// [`UnrecordedGrant::None`].
fn unrecorded_grant_on(
    aces: Result<Vec<AceView>>,
    group_sid: Option<&str>,
) -> Result<UnrecordedGrant> {
    let aces = aces?;
    let mut grants = aces
        .iter()
        .filter(|a| !a.deny && (group_sid == Some(a.sid.as_str()) || is_capability_sid(&a.sid)))
        .peekable();
    if grants.peek().is_none() {
        return Ok(UnrecordedGrant::None);
    }
    Ok(if grants.any(|a| a.inherited) {
        UnrecordedGrant::Inherited
    } else {
        UnrecordedGrant::Own
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_sid_format() {
        let sid = capability_sid_from([
            1, 0, 0, 0, // 1
            0, 1, 0, 0, // 256
            0xff, 0xff, 0xff, 0xff, // u32::MAX
            0, 0, 0, 0, // 0
        ]);
        assert_eq!(sid, "S-1-0-1936880739-1-256-4294967295-0");
        assert!(sid.starts_with(CAPABILITY_SID_PREFIX));
        assert_eq!(CAPABILITY_TAG.to_be_bytes(), *b"srtc");
        assert!(is_capability_sid(&sid));
        // The system parses it as a SID with five sub-authorities
        // under authority 0, and renders it back unchanged.
        let p = crate::sid::LocalPsid::from_string(&sid).unwrap();
        let b = p.as_bytes();
        assert_eq!((b[0], b[1]), (1, 5));
        assert_eq!(b[2..8], [0u8; 6]);
        assert_eq!(crate::sid::psid_to_string(p.as_psid()).unwrap(), sid);
        assert_eq!(acl::sid_string_from_bytes(b).as_deref(), Some(sid.as_str()));
    }

    #[test]
    fn generated_capability_sids_are_valid_and_distinct() {
        let a = new_capability_sid().unwrap();
        let b = new_capability_sid().unwrap();
        assert!(is_capability_sid(&a), "{a}");
        assert!(is_capability_sid(&b), "{b}");
        assert_ne!(a, b);
    }

    #[test]
    fn only_the_exact_layout_is_a_capability_sid() {
        for not in [
            "S-1-0-0",                           // Nobody
            "S-1-1-0",                           // Everyone
            "S-1-5-12",                          // RESTRICTED
            "S-1-3-4",                           // OWNER RIGHTS
            "S-1-5-32-545",                      // BUILTIN\Users
            "S-1-5-21-1-2-3-1001",               // an account
            "S-1-15-3-1024-1-2-3-4-5-6-7-8",     // a package capability
            "S-1-0-1936880739-1-2-3",            // three random parts
            "S-1-0-1936880739-1-2-3-4-5",        // five
            "S-1-0-1936880739-1-2-3-4294967296", // not a u32
            "S-1-0-1936880739-01-2-3-4",         // not canonical
            "S-1-0-1936880739-1-2-3-",           // empty part
            "S-1-0-1936880738-1-2-3-4",          // another tag
            "S-1-5-1936880739-1-2-3-4",          // another authority
            "s-1-0-1936880739-1-2-3-4",          // not canonical
            "",
        ] {
            assert!(!is_capability_sid(not), "{not}");
        }
        assert!(is_capability_sid("S-1-0-1936880739-1-2-3-4"));
    }

    #[test]
    fn uninstall_forgets_grants_only_after_the_elevated_removal_succeeded() {
        // The install is gone: the grants are forgotten, whatever the
        // elevated step's exit code — it removed the account, and may
        // have failed at something after that.
        assert_eq!(
            after_elevation(0, false),
            AfterElevation::ForgetGrants { step_failed: None }
        );
        for code in [1, 2, 23, -1, 259] {
            assert_eq!(
                after_elevation(code, false),
                AfterElevation::ForgetGrants {
                    step_failed: Some(code)
                }
            );
        }
        // The install is still there — a declined prompt (10), a step
        // that failed before removing the account: nothing of the
        // caller's is touched, and the code is passed on.
        for code in [10, 1, 2, -1, 259] {
            assert_eq!(
                after_elevation(code, true),
                AfterElevation::LeaveEverything(code)
            );
        }
        // "Succeeded" with the account still there is not a removal.
        assert_eq!(after_elevation(0, true), AfterElevation::LeaveEverything(1));
    }

    #[test]
    fn a_pending_strip_round_trips_and_blocks_only_while_its_volume_is_mounted() {
        let id = |serial: u64| {
            let mut b = [0u8; 24];
            b[..8].copy_from_slice(&serial.to_le_bytes());
            b[8] = 7;
            FileId::from_bytes(&b).unwrap()
        };
        let p = PendingStrip {
            file_id: id(0xAB),
            group_sid: "S-1-5-21-1-2-3-1001".to_owned(),
            path: r"\\?\E:\work|odd".to_owned(),
        };
        assert_eq!(PendingStrip::decode(&p.encode()).unwrap(), p);
        assert!(PendingStrip::decode("nonsense").is_err());
        assert!(PendingStrip::decode("zz|S-1-1-0|x").is_err());

        let marker = || {
            Ok(Marker {
                pending: vec![p.clone()],
                ..Default::default()
            })
        };
        let no_db = || -> Option<Vec<String>> { panic!("the database is not consulted") };
        // Its volume is absent: no reason to refuse the ordinary token.
        assert_eq!(block_reason_from(marker(), no_db, |_| false), None);
        // Another volume being mounted changes nothing.
        let serial = p.file_id.volume_serial;
        assert_eq!(
            block_reason_from(marker(), no_db, |s| s == serial + 1),
            None
        );
        // Its volume is back: refused, exactly as a live kept grant.
        let why = block_reason_from(marker(), no_db, |s| s == serial).unwrap();
        assert!(why.contains(r"E:\work"), "{why}");
        // A marker with only a pending strip is not "nothing recorded".
        assert!(!marker().unwrap().nothing_recorded());
        assert!(Marker::default().nothing_recorded());
    }

    /// The re-check of pending strips: what stays listed.
    #[test]
    fn pending_strips_are_retried_until_the_strip_succeeds() {
        use std::cell::RefCell;
        let id = |n: u8| FileId::from_bytes(&[n; 24]).unwrap();
        let entry = |n: u8| PendingStrip {
            file_id: id(n),
            group_sid: "S-1-5-21-1-2-3-1001".to_owned(),
            path: format!(r"\\?\E:\root{n}"),
        };
        let all = || vec![entry(1), entry(2), entry(3), entry(4)];
        let stripped = RefCell::new(Vec::<String>::new());
        // 1: volume still absent. 2: back, at a new path. 3: the
        // volume is back and reports the object gone. 4: cannot be
        // established.
        let locate = |p: &PendingStrip| match p.file_id.as_bytes()[0] {
            1 => Located::VolumeAbsent,
            2 => Located::At(r"\\?\F:\moved".to_owned()),
            3 => Located::Gone,
            _ => Located::Unknown,
        };
        let (left, changed) = retry_pending_with(all(), locate, |p, at| {
            stripped.borrow_mut().push(format!("{}@{at}", p.path));
            Ok(())
        })
        .unwrap();
        assert!(changed);
        assert_eq!(left, vec![entry(1), entry(4)]);
        // Stripped where the object is now, not where it was.
        assert_eq!(*stripped.borrow(), [r"\\?\E:\root2@\\?\F:\moved"]);

        // A strip that fails keeps its entry: it goes on blocking.
        let (left, changed) =
            retry_pending_with(all(), locate, |_, _| Err(anyhow!("access denied"))).unwrap();
        assert_eq!(left, vec![entry(1), entry(2), entry(4)]);
        assert!(changed, "the gone one was dropped");

        // Nothing to do: nothing rewritten.
        let (left, changed) =
            retry_pending_with(vec![entry(1)], locate, |_, _| unreachable!()).unwrap();
        assert_eq!((left, changed), (vec![entry(1)], false));

        // The table: what removing a record's ACEs takes.
        use AtPath::{Another, Nothing, Recorded, Unavailable};
        let at = || Located::At("p".into());
        let cases: [(AtPath, Located, bool, Disposition); 16] = [
            // The path leads to the object: nothing else is asked.
            (Recorded, Located::Unknown, false, Disposition::StripHere),
            (
                Recorded,
                Located::VolumeAbsent,
                true,
                Disposition::StripHere,
            ),
            // Not at its path, on a volume that is there: by file id.
            (Nothing, at(), false, Disposition::StripAt("p".into())),
            (Another, at(), false, Disposition::StripAt("p".into())),
            (Nothing, Located::Gone, false, Disposition::Drop),
            (Another, Located::Gone, true, Disposition::Drop),
            (Nothing, Located::Unknown, false, Disposition::Fail),
            (Another, Located::Unknown, false, Disposition::Fail),
            // Its volume is not among those present: the drive letter
            // names nothing, or another volume.
            (Nothing, Located::VolumeAbsent, false, Disposition::Pending),
            (Another, Located::VolumeAbsent, false, Disposition::Pending),
            // The volume is there by name and cannot be reached: no
            // media, locked, not connected, the server away.
            (
                Unavailable,
                Located::VolumeAbsent,
                false,
                Disposition::Pending,
            ),
            (Unavailable, Located::Unknown, false, Disposition::Pending),
            (
                Unavailable,
                Located::VolumeAbsent,
                true,
                Disposition::Pending,
            ),
            (Unavailable, at(), false, Disposition::StripAt("p".into())),
            // A share that answers, with the object not where it was:
            // it cannot be looked for by id there.
            (Nothing, Located::VolumeAbsent, true, Disposition::Fail),
            (Another, Located::VolumeAbsent, true, Disposition::Fail),
        ];
        for (at_path, located, network, want) in cases {
            let asked = std::cell::Cell::new(false);
            let got = disposition(
                at_path,
                || {
                    asked.set(true);
                    located.clone()
                },
                network,
            );
            assert_eq!(got, want, "{at_path:?} / {located:?} / network={network}");
            assert_eq!(
                asked.get(),
                at_path != Recorded,
                "{at_path:?}: looked up by id"
            );
        }
    }

    #[test]
    fn marker_entry_round_trips() {
        let r = MarkerRoot {
            file_id: FileId {
                volume_serial: 0x0123_4567_89ab_cdef,
                id128: *b"0123456789abcdef",
            },
            path: r"\\?\C:\work\a|b".to_owned(),
        };
        let s = r.encode();
        assert_eq!(s.find('|'), Some(48));
        assert_eq!(MarkerRoot::decode(&s).unwrap(), r);
        for bad in ["", "|x", "zz|x", &s[1..], &s[..49]] {
            assert!(MarkerRoot::decode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn covering_root_is_the_longest_ancestor() {
        let roots = vec![
            r"\\?\C:\a".to_owned(),
            r"\\?\C:\a\b".to_owned(),
            r"\\?\D:\".to_owned(),
        ];
        let c = |p: &str| covering_root(&roots, p);
        assert_eq!(c(r"\\?\C:\a"), Some(r"\\?\C:\a"));
        assert_eq!(c(r"\\?\C:\a\x"), Some(r"\\?\C:\a"));
        assert_eq!(c(r"\\?\C:\a\b\x\y"), Some(r"\\?\C:\a\b"));
        assert_eq!(c(r"\\?\D:\x"), Some(r"\\?\D:\"));
        // A sibling whose name merely starts with a root's name.
        assert_eq!(c(r"\\?\C:\ab"), None);
        assert_eq!(c(r"\\?\C:\"), None);
    }

    fn marker_with(ever_enabled: bool, roots: &[&str]) -> Marker {
        Marker {
            ever_enabled,
            roots: roots
                .iter()
                .map(|p| MarkerRoot {
                    file_id: FileId::from_bytes(&[0u8; 24]).unwrap(),
                    path: (*p).to_owned(),
                })
                .collect(),
            ..Default::default()
        }
    }

    /// The ordinary token is allowed only on a positive "nothing
    /// kept": every store that could not be read refuses.
    #[test]
    fn ordinary_token_is_refused_on_any_read_failure() {
        let no_db = || -> Option<Vec<String>> { panic!("database consulted") };
        // Nothing was ever kept: allowed, without the database.
        assert_eq!(
            block_reason_from(Ok(Marker::default()), no_db, |_| false),
            None
        );
        // The marker cannot be read.
        let r = block_reason_from(Err(anyhow!("access denied")), no_db, |_| false).unwrap();
        assert!(r.contains("cannot be read"), "{r}");
        // The marker lists a root.
        let r = block_reason_from(Ok(marker_with(true, &[r"\\?\C:\a"])), no_db, |_| false).unwrap();
        assert!(r.contains("1 persistent write grant"), "{r}");
        // Grants were made, no root is listed now: the database decides.
        let ever = || Ok(marker_with(true, &[]));
        assert_eq!(
            block_reason_from(ever(), || Some(Vec::new()), |_| false),
            None
        );
        let r =
            block_reason_from(ever(), || Some(vec![r"\\?\C:\b".to_owned()]), |_| false).unwrap();
        assert!(r.contains("state database records 1"), "{r}");
        // … and a database that is missing or unreadable refuses.
        let r = block_reason_from(ever(), || None, |_| false).unwrap();
        assert!(r.contains("missing or unreadable"), "{r}");
    }

    #[test]
    fn unreadable_dacl_is_not_an_absent_grant() {
        const GROUP: &str = "S-1-5-21-1-2-3-1001";
        let cap = capability_sid_from([7; 16]);
        let ace = |sid: &str, deny: bool, inherited: bool| AceView {
            deny,
            inherited,
            flags: 0x3,
            mask: 0x0013_01bf,
            sid: sid.to_owned(),
        };
        let on = |aces: Vec<AceView>| unrecorded_grant_on(Ok(aces), Some(GROUP)).unwrap();
        assert!(unrecorded_grant_on(Err(anyhow!("access denied")), Some(GROUP)).is_err());
        assert_eq!(on(vec![]), UnrecordedGrant::None);
        // Other trustees, and the group's DENY, are not grants.
        assert_eq!(
            on(vec![
                ace("S-1-5-32-545", false, true),
                ace(GROUP, true, false)
            ]),
            UnrecordedGrant::None
        );
        assert_eq!(on(vec![ace(GROUP, false, false)]), UnrecordedGrant::Own);
        assert_eq!(on(vec![ace(&cap, false, false)]), UnrecordedGrant::Own);
        assert_eq!(
            on(vec![ace(GROUP, false, false), ace(&cap, false, true)]),
            UnrecordedGrant::Inherited
        );
        // Without an install record the group cannot be told apart;
        // a capability SID still can.
        assert_eq!(
            unrecorded_grant_on(Ok(vec![ace(GROUP, false, false)]), None).unwrap(),
            UnrecordedGrant::None
        );
        assert_eq!(
            unrecorded_grant_on(Ok(vec![ace(&cap, false, true)]), None).unwrap(),
            UnrecordedGrant::Inherited
        );
    }
}
