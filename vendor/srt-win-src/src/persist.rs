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

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use windows::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};

use crate::acl::{self, AceView, PersistentTrustees, PersistentWant, SbAce};
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

const MARKER_KEY: &str = r"Software\sandbox-runtime\PersistentGrants";
const MARKER_ROOTS: &str = "Roots";
const MARKER_EVER: &str = "EverEnabled";

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

/// The marker as read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Marker {
    /// A persistent grant was made at some point and `acl forget
    /// --all` has not completed since.
    pub ever_enabled: bool,
    pub roots: Vec<MarkerRoot>,
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
    Ok(Marker {
        ever_enabled: key.get_dword(MARKER_EVER)?.unwrap_or(0) != 0,
        roots,
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
    reg::Key::create_hkcu(MARKER_KEY)?.set_dword(MARKER_EVER, 1)?;
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
    block_reason_from(read_marker(), db_roots_ro)
}

/// [`unrestricted_block_reason`] on what was read: `marker` as
/// [`read_marker`] returned it, `db_roots` as [`db_roots_ro`] does.
/// Every "could not read" refuses.
fn block_reason_from(
    marker: Result<Marker>,
    db_roots: impl FnOnce() -> Option<Vec<String>>,
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
    let roots: Vec<String> = read_marker()
        .map(|m| m.roots.into_iter().map(|r| r.path).collect())
        .unwrap_or_default();
    match unrestricted_block_reason() {
        None => serde_json::json!({ "state": "none", "roots": roots }),
        Some(reason) => serde_json::json!({
            "state": if roots.is_empty() { "unknown" } else { "present" },
            "roots": roots,
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
}

impl Ids {
    pub fn load() -> Result<Self> {
        let setup = crate::install::read_setup()?;
        Ok(Self {
            group_sid: setup.as_ref().map(|s| s.sandbox_group_sid.clone()),
            sandbox_user_sid: setup.map(|s| s.sandbox_user_sid),
            real_user_sid: crate::sid::current_user_sid()?,
        })
    }

    fn trustees(&self) -> PersistentTrustees<'_> {
        PersistentTrustees {
            group_sid: self.group_sid.as_deref(),
            real_user_sid: &self.real_user_sid,
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
    if cap.is_none() && deny.is_none() && !deny_fdc && !deny_delete {
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
    let (cur, _links, is_dir) = path_id::capture_id_and_links(canon)?;
    let want = wanted(conn, ids, canon, cur)?;
    let aces = acl::read_aces(canon).with_context(|| format!("read the DACL of '{canon}'"))?;
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
    let same = acl::persistent_on_disk(&aces, &t, is_dir) == acl::comparable(&want, is_dir);
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
    acl::write_persistent_aces(canon, &t, &want)?;
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
    /// Could not be completed; the root stays recorded.
    Failed(String),
}

impl Forgot {
    pub fn as_str(&self) -> &'static str {
        match self {
            Forgot::Removed => "removed",
            Forgot::Absent => "absent",
            Forgot::Failed(_) => "failed",
        }
    }
}

/// Remove `canon`'s persistent grant: its ACEs from the object at the
/// path and from the object it was granted on if that has moved, the
/// deny ACEs kept with it, its capability SID, and its marker entry.
/// Returns whether any ACE was on disk.
///
/// Rows and ACEs go together: the row deletions commit only after
/// every DACL write succeeded, and the marker entry is removed after
/// that. An object that can be neither found at its path nor located
/// by file id fails the call, so the root stays listed — "could not
/// look" is not "nothing there".
fn forget_one(conn: &Connection, ids: &Ids, canon: &str) -> Result<bool> {
    let here = match path_id::capture_file_id(canon) {
        Ok(id) => Some(id),
        Err(e) if path_id::is_not_found(&e) => None,
        Err(e) => return Err(e.context(format!("open '{canon}'"))),
    };
    // Every object the grant may have been written on.
    let mut granted: Vec<FileId> = Vec::new();
    granted.extend(root_row(conn, canon)?.map(|(id, _)| id));
    for r in read_marker()?.roots {
        if r.path == canon && !granted.contains(&r.file_id) {
            granted.push(r.file_id);
        }
    }
    let tx = conn.unchecked_transaction().context("begin forget tx")?;
    let denies: Vec<String> = {
        let mut s =
            tx.prepare("SELECT DISTINCT canonical_path FROM persistent_denies WHERE root = ?1")?;
        let rows = s.query_map(params![canon], |r| r.get(0))?;
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
    if here.is_some() {
        removed |= converge(&tx, ids, canon)?;
    }
    for id in granted.iter().filter(|id| Some(**id) != here) {
        match path_id::locate_by_file_id(id) {
            Located::At(moved) => removed |= converge(&tx, ids, &moved)?,
            Located::Gone => {}
            Located::Unknown => bail!(
                "the object '{canon}' was granted on is no longer at that path and could \
                 not be located by file id; its ACEs may still be on disk"
            ),
        }
    }
    for d in &denies {
        match path_id::capture_file_id(d) {
            Ok(_) => removed |= converge(&tx, ids, d)?,
            Err(e) if path_id::is_not_found(&e) => {}
            Err(e) => return Err(e.context(format!("open '{d}'"))),
        }
    }
    tx.commit().context("commit forget")?;
    marker_remove(canon)?;
    Ok(removed)
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
            Ok(true) => Forgot::Removed,
            Ok(false) => Forgot::Absent,
            Err(e) => {
                eprintln!("srt-win: forget '{t}': {e:#}");
                Forgot::Failed(format!("{e:#}"))
            }
        };
        out.push((t, r));
    }
    if all
        && read_marker()?.roots.is_empty()
        && all_root_paths(conn)?.is_empty()
        && let Some(key) = reg::Key::open_hkcu(MARKER_KEY, true)?
    {
        reg::delete_value(&key, MARKER_EVER)?;
    }
    Ok(out)
}

/// `srt-win uninstall`: forget every persistent grant of the calling
/// user. Does nothing — and creates no state — when none was ever
/// made. Returns how many roots were processed and how many failed.
pub fn forget_everything() -> Result<(usize, usize)> {
    if read_marker().is_ok_and(|m| m == Marker::default()) {
        return Ok((0, 0));
    }
    let ids = Ids::load()?;
    let holder = crate::state_db::HolderPid(std::process::id());
    let (out, _) =
        crate::state_db::with_init_lock(holder, false, |db| forget(db, &ids, &[], true))?;
    let failed = out
        .iter()
        .filter(|(_, r)| matches!(r, Forgot::Failed(_)))
        .count();
    Ok((out.len(), failed))
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
    if let Some(why) = unrestricted_block_reason() {
        bail!(
            "{why}; grants for the ordinary token are refused until `srt-win acl forget \
             --all` has removed them"
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
        }
    }

    /// The ordinary token is allowed only on a positive "nothing
    /// kept": every store that could not be read refuses.
    #[test]
    fn ordinary_token_is_refused_on_any_read_failure() {
        let no_db = || -> Option<Vec<String>> { panic!("database consulted") };
        // Nothing was ever kept: allowed, without the database.
        assert_eq!(block_reason_from(Ok(Marker::default()), no_db), None);
        // The marker cannot be read.
        let r = block_reason_from(Err(anyhow!("access denied")), no_db).unwrap();
        assert!(r.contains("cannot be read"), "{r}");
        // The marker lists a root.
        let r = block_reason_from(Ok(marker_with(true, &[r"\\?\C:\a"])), no_db).unwrap();
        assert!(r.contains("1 persistent write grant"), "{r}");
        // Grants were made, no root is listed now: the database decides.
        let ever = || Ok(marker_with(true, &[]));
        assert_eq!(block_reason_from(ever(), || Some(Vec::new())), None);
        let r = block_reason_from(ever(), || Some(vec![r"\\?\C:\b".to_owned()])).unwrap();
        assert!(r.contains("state database records 1"), "{r}");
        // … and a database that is missing or unreadable refuses.
        let r = block_reason_from(ever(), || None).unwrap();
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
