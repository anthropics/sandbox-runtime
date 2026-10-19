//! The pure half of the profile read grant ([`crate::profile`]): what is
//! never readable, and which directory gets which entry. No Windows call
//! is made here.
//! The walk goes down from the profile root. A directory is a container
//! (a non-inheriting list entry; children looked at one by one) exactly
//! when some exclusion could lie beneath it, existing or not; otherwise it
//! is granted whole. So no excluded path ever has an ancestor that carries
//! an inheriting allow. A protected exclusion is read-denied; an
//! ungranted-only one (the temporary directory) gets nothing at all. A
//! link at or above a rule's path is resolved, and the rule is applied
//! beneath its target as well ([`plan_resolved`]).

/// Version of the exclusion list and of the walk rule. A recorded
/// grant made with another version is reported as outdated.
pub const LIST_VERSION: u32 = 3;

/// What a built-in exclusion's path is relative to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    /// The profile directory.
    Profile,
    /// The roaming application-data known folder.
    Roaming,
    /// The local application-data known folder.
    Local,
}

/// One built-in exclusion. `path` uses `\`; a component that is `*`
/// matches any one name, and a component ending in `*` any name with
/// that prefix.
#[derive(Debug, Clone, Copy)]
pub struct Excl {
    pub base: Base,
    pub path: &'static str,
    /// A directory (denied with an inheriting entry, and created empty
    /// when missing) or a file.
    pub dir: bool,
    /// False for a directory whose deny is written by its owner in
    /// this crate; it is then only kept out of the grant.
    pub stamp: bool,
    /// Ungranted-only (see the module doc): kept out of the grant,
    /// not denied. Every other entry is protected.
    pub ungranted_only: bool,
    /// Create the directory, empty, when it is missing, so the deny
    /// has an object to sit on.
    pub create: bool,
}

/// A protected directory.
const fn dir(base: Base, path: &'static str) -> Excl {
    Excl {
        base,
        path,
        dir: true,
        stamp: true,
        ungranted_only: false,
        create: true,
    }
}

/// A protected directory that is not created when missing.
const fn store(base: Base, path: &'static str) -> Excl {
    Excl {
        base,
        path,
        dir: true,
        stamp: true,
        ungranted_only: false,
        create: false,
    }
}

/// A protected file.
const fn file(base: Base, path: &'static str) -> Excl {
    Excl {
        base,
        path,
        dir: false,
        stamp: true,
        ungranted_only: false,
        create: false,
    }
}

/// An ungranted-only directory.
const fn ungranted(base: Base, path: &'static str) -> Excl {
    Excl {
        base,
        path,
        dir: true,
        stamp: false,
        ungranted_only: true,
        create: false,
    }
}

use Base::{Local, Profile, Roaming};

/// Every path that is never granted and carries a read deny for the
/// sandbox group. Configuration can add to this list
/// ([`Rules::new`]'s `extra`); nothing removes an entry.
pub const BUILT_IN: &[Excl] = &[
    // Keys and sign-ins kept in dot-directories of the profile.
    dir(Profile, ".ssh"),
    dir(Profile, ".gnupg"),
    dir(Profile, ".aws"),
    dir(Profile, ".azure"),
    dir(Profile, ".kube"),
    dir(Profile, ".docker"),
    dir(Profile, ".terraform.d"),
    dir(Profile, ".wrangler"),
    dir(Profile, ".vercel"),
    dir(Profile, ".netlify"),
    dir(Profile, ".claude"),
    // The same kind of store under the XDG-style `.config`, which
    // tools ported from other systems use on Windows too.
    dir(Profile, r".config\gcloud"),
    dir(Profile, r".config\gh"),
    dir(Profile, r".config\configstore"),
    file(Profile, r".config\git\credentials"),
    // Where those tools keep the same sign-ins when they follow the
    // Windows convention instead.
    dir(Roaming, "gcloud"),
    dir(Roaming, "GitHub CLI"),
    dir(Roaming, "gnupg"),
    dir(Roaming, "com.vercel.cli"),
    dir(Roaming, "netlify"),
    dir(Roaming, "xdg.config"),
    dir(Roaming, "terraform.d"),
    file(Roaming, "terraform.rc"),
    dir(Local, "heroku"),
    // Plaintext token files of further command-line tools, at their
    // Windows locations and under `.config` where the tool follows XDG.
    store(Local, "github-copilot"),
    store(Profile, r".config\github-copilot"),
    store(Profile, r".config\doctl"),
    store(Roaming, "doctl"),
    store(Profile, r".config\op"),
    file(Profile, r".config\hub"),
    file(Profile, r".gem\credentials"),
    file(Profile, r".pulumi\credentials.json"),
    file(Roaming, r"postgresql\pgpass.conf"),
    file(Profile, ".pgpass"),
    file(Roaming, r"Composer\auth.json"),
    file(Profile, r".composer\auth.json"),
    file(Profile, r".fly\config.yml"),
    file(Profile, ".databrickscfg"),
    file(Profile, ".boto"),
    file(Profile, ".s3cfg"),
    file(Roaming, "s3cmd.ini"),
    store(Profile, ".kaggle"),
    store(Profile, ".snowsql"),
    store(Profile, ".oci"),
    store(Profile, ".bluemix"),
    store(Profile, ".ibmcloud"),
    store(Profile, ".railway"),
    store(Profile, ".supabase"),
    // Package-feed sign-in caches (the token stores, not the
    // configuration files that name a feed, which are readable).
    dir(Local, ".IdentityService"),
    dir(Local, "MicrosoftCredentialProvider"),
    // Credential files.
    file(Profile, ".git-credentials"),
    file(Profile, ".netrc"),
    file(Profile, "_netrc"),
    file(Profile, ".pypirc"),
    file(Profile, ".vault-token"),
    file(Profile, ".terraformrc"),
    file(Profile, r".cargo\credentials"),
    file(Profile, r".cargo\credentials.toml"),
    file(Profile, r".gradle\enterprise\keys.properties"),
    file(Profile, r".gradle\develocity\keys.properties"),
    // The user's registry hives and their logs.
    file(Profile, "NTUSER.DAT*"),
    file(Profile, "ntuser.ini"),
    file(Profile, "ntuser.pol"),
    file(Local, r"Microsoft\Windows\UsrClass.dat*"),
    // Browser profiles: cookies, saved passwords, session storage.
    dir(Local, r"Google\Chrome\User Data"),
    dir(Local, r"Microsoft\Edge\User Data"),
    dir(Local, r"BraveSoftware\Brave-Browser\User Data"),
    dir(Roaming, r"Mozilla\Firefox"),
    dir(Local, r"Mozilla\Firefox"),
    // Other channels of those browsers, others on the same engines,
    // and the mail client that shares Firefox's profile layout.
    store(Local, r"Google\Chrome Beta\User Data"),
    store(Local, r"Google\Chrome Dev\User Data"),
    store(Local, r"Google\Chrome SxS\User Data"),
    store(Local, r"Chromium\User Data"),
    store(Local, r"Microsoft\Edge Beta\User Data"),
    store(Local, r"Microsoft\Edge Dev\User Data"),
    store(Local, r"Microsoft\Edge SxS\User Data"),
    store(Local, r"BraveSoftware\Brave-Browser-Beta\User Data"),
    store(Local, r"BraveSoftware\Brave-Browser-Nightly\User Data"),
    store(Local, r"Vivaldi\User Data"),
    store(Local, r"Yandex\YandexBrowser\User Data"),
    store(Roaming, "Opera Software"),
    store(Local, "Opera Software"),
    store(Roaming, r"Mozilla\SeaMonkey"),
    store(Roaming, "Thunderbird"),
    store(Local, "Thunderbird"),
    // Embedded browser profiles of desktop applications.
    dir(Local, r"*\EBWebView"),
    dir(Local, r"Microsoft\*\EBWebView"),
    // Password managers.
    dir(Roaming, "1Password"),
    dir(Local, "1Password"),
    dir(Roaming, "Bitwarden"),
    dir(Roaming, "Bitwarden CLI"),
    dir(Roaming, "KeePass"),
    dir(Roaming, "KeePassXC"),
    // Windows' own per-user secret stores.
    dir(Roaming, r"Microsoft\Credentials"),
    dir(Roaming, r"Microsoft\Protect"),
    dir(Roaming, r"Microsoft\Vault"),
    dir(Roaming, r"Microsoft\Crypto"),
    dir(Roaming, r"Microsoft\SystemCertificates"),
    dir(Local, r"Microsoft\Credentials"),
    dir(Local, r"Microsoft\Protect"),
    dir(Local, r"Microsoft\Vault"),
    dir(Local, r"Microsoft\Crypto"),
    dir(Local, r"Microsoft\SystemCertificates"),
    // Account token caches and web sessions of the signed-in user.
    dir(Local, r"Microsoft\IdentityCache"),
    dir(Local, r"Microsoft\TokenBroker"),
    dir(Local, r"Microsoft\OneAuth"),
    dir(Local, r"Microsoft\Windows\INetCookies"),
    dir(Local, r"Microsoft\Windows\INetCache"),
    dir(Local, r"Microsoft\Windows\WebCache"),
    // Private data of packaged applications.
    dir(Local, "Packages"),
    // This library's state directory. Its owner (`state_db`) writes its
    // access list, deny included, on every open.
    Excl {
        base: Local,
        path: "sandbox-runtime",
        dir: true,
        stamp: false,
        ungranted_only: false,
        create: false,
    },
    // Ungranted-only: every program writes there, and sessions stage
    // directories of their own in it.
    ungranted(Local, "Temp"),
];

/// Files in the profile ROOT that are granted by name. Every other
/// file of the root is left unreadable. These can hold the sign-in
/// of a private package feed or a git host.
pub const READABLE_ROOT_FILES: &[&str] = &[".npmrc", ".gitconfig"];

/// The configuration files that are readable by design although they
/// can hold a feed sign-in, with what reads them.
pub const READABLE_CONFIG: &[(Base, &str, &str)] = &[
    (Profile, ".npmrc", "npm"),
    (Profile, ".gitconfig", "git"),
    (Profile, r".config\git\config", "git"),
    (Roaming, r"pip\pip.ini", "pip"),
    (Profile, r"pip\pip.ini", "pip"),
    (Profile, r".config\pip\pip.conf", "pip"),
    (Roaming, r"NuGet\NuGet.Config", "NuGet"),
    (Profile, r".m2\settings.xml", "Maven"),
    (Profile, r".m2\settings-security.xml", "Maven"),
    (Profile, r".gradle\gradle.properties", "Gradle"),
];

// ─── Names ──────────────────────────────────────────────────────────

/// A file name in the form names are compared in: without an
/// alternate-data-stream suffix (`name:stream`), without the trailing
/// dots and spaces Win32 drops when it opens a name, lower-cased.
pub fn norm_component(name: &str) -> String {
    let base = name.split(':').next().unwrap_or("");
    base.trim_end_matches(['.', ' ']).to_lowercase()
}

/// One component of an exclusion.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pat {
    Lit(String),
    Prefix(String),
    Any,
}

impl Pat {
    fn parse(component: &str) -> Pat {
        if component == "*" {
            Pat::Any
        } else if let Some(prefix) = component.strip_suffix('*') {
            Pat::Prefix(norm_component(prefix))
        } else {
            Pat::Lit(norm_component(component))
        }
    }

    /// Whether a normalized name matches. The empty name (`.`, `..`,
    /// or a name of dots and spaces only) matches nothing.
    fn matches(&self, norm: &str) -> bool {
        if norm.is_empty() {
            return false;
        }
        match self {
            Pat::Lit(l) => l == norm,
            Pat::Prefix(p) => norm.starts_with(p.as_str()),
            Pat::Any => true,
        }
    }
}

/// A directory entry's names: the long one and, where the volume
/// keeps them, the 8.3 one. An exclusion matches if either does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    pub long: String,
    pub short: Option<String>,
}

impl Name {
    pub fn long(name: &str) -> Name {
        Name {
            long: name.to_owned(),
            short: None,
        }
    }

    fn matched_by(&self, pat: &Pat) -> bool {
        pat.matches(&norm_component(&self.long))
            || self
                .short
                .as_deref()
                .is_some_and(|s| pat.matches(&norm_component(s)))
    }
}

/// `path` split into components, either separator, with a `\\?\`
/// prefix and empty components dropped.
pub fn split_path(path: &str) -> Vec<String> {
    let p = path
        .strip_prefix(r"\\?\")
        .or_else(|| path.strip_prefix("//?/"))
        .unwrap_or(path);
    p.split(['\\', '/'])
        .filter(|c| !c.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The components of `path` beneath `profile`, or why it cannot be an
/// exclusion: it is not inside the profile, or it holds `.`, `..` or
/// a wildcard.
pub fn rel_components(profile: &str, path: &str) -> Result<Vec<String>, String> {
    let comps = split_path(path);
    let absolute = path.starts_with(['\\', '/']) || comps.first().is_some_and(|c| c.ends_with(':'));
    let rel = if absolute {
        let root = split_path(profile);
        let inside = comps.len() >= root.len()
            && root
                .iter()
                .zip(&comps)
                .all(|(a, b)| a.to_lowercase() == b.to_lowercase());
        if !inside {
            return Err(format!("'{path}' is not inside the profile '{profile}'"));
        }
        comps[root.len()..].to_vec()
    } else {
        comps
    };
    for c in &rel {
        if c == "." || c == ".." || c.contains(['*', '?']) || norm_component(c).is_empty() {
            return Err(format!(
                "'{path}': component '{c}' cannot be part of an exclusion"
            ));
        }
    }
    Ok(rel)
}

// ─── Rules ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Rule {
    pats: Vec<Pat>,
    /// The components as spelled, for creating a missing directory.
    spelled: Vec<String>,
    stamp: bool,
    /// Ungranted-only; otherwise protected.
    ungranted: bool,
    /// A protected built-in directory with no wildcard: created when
    /// missing.
    placeholder: bool,
}

/// The exclusions in force for one profile: the built-in list placed
/// at the profile's known-folder locations, plus what configuration
/// added.
#[derive(Debug, Clone)]
pub struct Rules {
    rules: Vec<Rule>,
}

/// Where the application-data folders are when nothing redirects
/// them.
const CONVENTIONAL_ROAMING: [&str; 2] = ["AppData", "Roaming"];
const CONVENTIONAL_LOCAL: [&str; 2] = ["AppData", "Local"];

impl Rules {
    /// `roaming` and `local` are the known-folder locations as
    /// components beneath the profile, `None` when a folder is not
    /// inside the profile.
    pub fn new(
        roaming: Option<&[String]>,
        local: Option<&[String]>,
        extra: &[Vec<String>],
    ) -> Rules {
        let mut rules = Vec::new();
        let conventional = |c: &[&str]| c.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        for e in BUILT_IN {
            let mut bases: Vec<Vec<String>> = Vec::new();
            match e.base {
                Base::Profile => bases.push(Vec::new()),
                Base::Roaming => {
                    bases.push(conventional(&CONVENTIONAL_ROAMING));
                    bases.extend(roaming.map(<[String]>::to_vec));
                }
                Base::Local => {
                    bases.push(conventional(&CONVENTIONAL_LOCAL));
                    bases.extend(local.map(<[String]>::to_vec));
                }
            }
            bases.dedup_by(|a, b| {
                a.len() == b.len()
                    && a.iter()
                        .zip(b.iter())
                        .all(|(x, y)| norm_component(x) == norm_component(y))
            });
            for base in bases {
                let mut spelled = base;
                spelled.extend(e.path.split('\\').map(str::to_owned));
                let pats: Vec<Pat> = spelled.iter().map(|c| Pat::parse(c)).collect();
                let wild = pats.iter().any(|p| !matches!(p, Pat::Lit(_)));
                rules.push(Rule {
                    pats,
                    spelled,
                    stamp: e.stamp,
                    ungranted: e.ungranted_only,
                    placeholder: e.dir && e.stamp && e.create && !wild && !e.ungranted_only,
                });
            }
        }
        for x in extra.iter().filter(|x| !x.is_empty()) {
            rules.push(Rule {
                pats: x.iter().map(|c| Pat::Lit(norm_component(c))).collect(),
                spelled: x.clone(),
                stamp: true,
                ungranted: false,
                placeholder: false,
            });
        }
        Rules { rules }
    }

    /// The exclusions of one kind, as written: components beneath the
    /// profile joined by `\\`, wildcards included.
    fn spelled_where(&self, ungranted: bool) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for r in self.rules.iter().filter(|r| r.ungranted == ungranted) {
            let s = r.spelled.join("\\");
            if !out.contains(&s) {
                out.push(s);
            }
        }
        out
    }

    /// The protected exclusions, built-in and added.
    pub fn spelled(&self) -> Vec<String> {
        self.spelled_where(false)
    }

    /// The ungranted-only exclusions.
    pub fn spelled_ungranted(&self) -> Vec<String> {
        self.spelled_where(true)
    }

    fn at_or_beneath(&self, rel: &[Name], ungranted: bool) -> bool {
        self.rules.iter().any(|r| {
            r.ungranted == ungranted
                && r.pats.len() <= rel.len()
                && r.pats.iter().zip(rel).all(|(p, n)| n.matched_by(p))
        })
    }

    /// Whether `rel` (components beneath the profile) is a protected
    /// exclusion or lies beneath one.
    pub fn excludes(&self, rel: &[Name]) -> bool {
        self.at_or_beneath(rel, false)
    }

    /// Whether `rel` is an ungranted-only exclusion or lies beneath
    /// one.
    pub fn ungranted(&self, rel: &[Name]) -> bool {
        self.at_or_beneath(rel, true)
    }

    /// Whether an exclusion of either kind could lie strictly beneath
    /// the directory `rel`, whatever is on disk.
    pub fn could_exclude_beneath(&self, rel: &[Name]) -> bool {
        self.rules.iter().any(|r| {
            r.pats.len() > rel.len() && r.pats.iter().zip(rel).all(|(p, n)| n.matched_by(p))
        })
    }

    fn all(&self) -> Vec<usize> {
        (0..self.rules.len()).collect()
    }
}

// ─── Session grants against a recorded grant ────────────────────────

/// How a path stands to an exclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// The path is the excluded one.
    Equal,
    /// It lies beneath the excluded directory.
    Inside,
    /// The excluded path lies beneath it.
    Above,
}

/// How `path` stands to the recorded exclusion `rule`, both absolute;
/// `rule` may hold the wildcards of the built-in list. `None` when
/// neither contains the other.
pub fn relation(path: &str, rule: &str) -> Option<Relation> {
    let p: Vec<String> = split_path(path).iter().map(|c| norm_component(c)).collect();
    let r: Vec<Pat> = split_path(rule).iter().map(|c| Pat::parse(c)).collect();
    let shared = p.len().min(r.len());
    if !(0..shared).all(|i| r[i].matches(&p[i])) {
        return None;
    }
    Some(match p.len().cmp(&r.len()) {
        std::cmp::Ordering::Equal => Relation::Equal,
        std::cmp::Ordering::Greater => Relation::Inside,
        std::cmp::Ordering::Less => Relation::Above,
    })
}

/// What listing a directory gave ([`session_grant_refusal`]'s `list`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listing {
    /// Its entry names.
    Entries(Vec<String>),
    /// Nothing to list: the path is not there, or is a file.
    Nothing,
    /// A link: not followed.
    Link,
    /// It is there and could not be listed — access denied, an I/O
    /// error, a path that is not looked at at all — with the reason.
    Failed(String),
}

/// What lies beneath a path that is above a wildcard rule.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Beneath {
    /// Every level that could lead to a match was listed; none does.
    NoMatch,
    /// Something that exists matches the rule.
    Match,
    /// A level could not be listed. Treated as a possible match: a
    /// path is admitted because it was looked at and found empty of
    /// matches, never because looking failed.
    Unexamined(String),
}

/// Whether something that exists beneath the directory `path` matches the
/// rest of `rule`, which `path` lies above. A directory that cannot be
/// listed counts as a match.
fn matched_beneath(path: &str, rule: &str, list: &dyn Fn(&str) -> Listing) -> Beneath {
    fn go(dir: &str, rest: &[Pat], top: bool, list: &dyn Fn(&str) -> Listing) -> Beneath {
        let Some((first, rest)) = rest.split_first() else {
            return Beneath::Match;
        };
        let names = match list(dir) {
            Listing::Entries(names) => names,
            Listing::Nothing => return Beneath::NoMatch,
            Listing::Link if top => return Beneath::Unexamined(format!("'{dir}' is a link")),
            Listing::Link => return Beneath::NoMatch,
            Listing::Failed(why) => {
                return Beneath::Unexamined(format!("'{dir}' could not be listed: {why}"));
            }
        };
        let mut unexamined = None;
        for name in names.iter().filter(|n| first.matches(&norm_component(n))) {
            let child = format!("{}\\{name}", dir.trim_end_matches('\\'));
            match go(&child, rest, false, list) {
                Beneath::Match => return Beneath::Match,
                Beneath::NoMatch => {}
                u @ Beneath::Unexamined(_) => unexamined = unexamined.or(Some(u)),
            }
        }
        unexamined.unwrap_or(Beneath::NoMatch)
    }
    let depth = split_path(path).len();
    let pats: Vec<Pat> = split_path(rule).iter().map(|c| Pat::parse(c)).collect();
    if pats.len() <= depth {
        return Beneath::NoMatch;
    }
    go(path, &pats[depth..], true, list)
}

/// Why a session must not be granted `path` while a profile read grant
/// with these exclusions exists (`None`: it may): it is a protected path,
/// lies inside one, or lies above one. Only a read path can be `admitted`.
pub fn session_grant_refusal(
    path: &str,
    write: bool,
    protected: &[String],
    ungranted: &[String],
    admitted: &[String],
    list: &dyn Fn(&str) -> Listing,
) -> Option<String> {
    let what = if write { "write" } else { "read" };
    for u in ungranted {
        if relation(path, u) == Some(Relation::Equal) {
            return Some(format!(
                "a {what} grant on '{path}' would cover everything in it, and it is not \
                 granted as a whole; grant a directory inside it"
            ));
        }
    }
    let is_admitted = !write
        && admitted
            .iter()
            .any(|a| relation(path, a) == Some(Relation::Equal) && !a.contains('*'));
    for r in protected {
        match relation(path, r) {
            None => {}
            Some(Relation::Above) if r.contains('*') => match matched_beneath(path, r, list) {
                Beneath::NoMatch => {}
                Beneath::Match => {
                    return Some(format!(
                        "a {what} grant on '{path}' would be inherited by what the excluded \
                         '{r}' covers beneath it; choose a narrower directory"
                    ));
                }
                Beneath::Unexamined(why) => {
                    return Some(format!(
                        "'{path}' may lie above something '{r}' excludes from the profile \
                         read grant, and could not be examined ({why}); a {what} grant is \
                         made only on a path that was looked at"
                    ));
                }
            },
            Some(Relation::Above) => {
                return Some(format!(
                    "a {what} grant on '{path}' would be inherited by the excluded '{r}' \
                     beneath it if that is ever created again; choose a narrower directory"
                ));
            }
            Some(Relation::Equal | Relation::Inside) if is_admitted => {}
            Some(Relation::Equal) => {
                return Some(format!("'{path}' is excluded from reads of the profile"));
            }
            Some(Relation::Inside) => {
                return Some(format!(
                    "'{path}' lies inside '{r}', which is excluded from reads of the profile"
                ));
            }
        }
    }
    for u in ungranted {
        if relation(path, u) == Some(Relation::Above) {
            return Some(format!(
                "a {what} grant on '{path}' would cover everything in '{u}', which is not \
                 granted as a whole; choose a narrower directory"
            ));
        }
    }
    None
}

// ─── Plan ───────────────────────────────────────────────────────────

/// One directory entry as the walk sees it.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: Name,
    pub is_dir: bool,
    /// Set for an entry nothing may be written on or through: a
    /// reparse point or a cloud placeholder.
    pub skip: Option<String>,
    /// The entry is a reparse point: something that may redirect to
    /// another place ([`Tree::resolve_link`]).
    pub link: bool,
}

/// Where a link leads, with every link on the way resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkTarget {
    /// Inside the profile: the target's components beneath it (empty
    /// for the profile directory itself).
    Inside(Vec<String>),
    /// Outside the profile, not a redirection at all, or a link whose
    /// own data cannot be decoded, with a word about it.
    Elsewhere(String),
}

/// Why a link has no destination to follow ([`link_destination`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoDestination {
    /// It leads off this machine's drive letters, or is not a
    /// redirection: known not to be inside the profile.
    Elsewhere(String),
    /// Its data cannot be made sense of.
    Malformed(String),
}

/// What a reparse point says about where it leads, as read from the
/// link itself ([`parse_reparse`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkData {
    /// A junction, with its target in the object namespace
    /// (`\??\C:\dir`).
    Junction(String),
    /// A symbolic link, with its target as stored and whether that is
    /// relative to the link's directory.
    Symlink { target: String, relative: bool },
    /// Some other kind of reparse point (a cloud placeholder, an
    /// application link), by tag. Not a redirection to follow.
    Other(u32),
}

/// Read a reparse data buffer (`FSCTL_GET_REPARSE_POINT`).
pub fn parse_reparse(buf: &[u8]) -> Result<LinkData, String> {
    const TAG_MOUNT_POINT: u32 = 0xA000_0003;
    const TAG_SYMLINK: u32 = 0xA000_000C;
    let u16_at = |at: usize| -> Result<usize, String> {
        buf.get(at..at + 2)
            .map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])))
            .ok_or_else(|| "truncated reparse data".to_owned())
    };
    let tag = buf
        .get(0..4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or("truncated reparse data")?;
    // Header: tag, data length, reserved.
    let names_at = match tag {
        TAG_MOUNT_POINT => 16,
        TAG_SYMLINK => 20,
        other => return Ok(LinkData::Other(other)),
    };
    let (off, len) = (u16_at(8)?, u16_at(10)?);
    let bytes = buf
        .get(names_at + off..names_at + off + len)
        .ok_or("truncated reparse data")?;
    let wide: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let target = String::from_utf16(&wide).map_err(|_| "a link target that is not valid UTF-16")?;
    Ok(if tag == TAG_MOUNT_POINT {
        LinkData::Junction(target)
    } else {
        let flags = buf
            .get(16..20)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or("truncated reparse data")?;
        LinkData::Symlink {
            target,
            relative: flags & 1 != 0,
        }
    })
}

/// Where the link at `link` (`\\?\X:\…`) leads, with `rest` — the
/// components that followed it — appended: a path on a drive letter,
/// in the same form.
pub fn link_destination(
    link: &str,
    data: &LinkData,
    rest: &[String],
) -> Result<String, NoDestination> {
    use NoDestination::{Elsewhere, Malformed};
    let drive_of = |p: &str| -> Option<(char, String)> {
        let b = p.as_bytes();
        (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\')
            .then(|| (b[0] as char, p[3..].to_owned()))
    };
    let not_drive = || Elsewhere(format!("'{link}' is not a drive path"));
    let link_plain = link.strip_prefix(r"\\?\").ok_or_else(not_drive)?;
    let (link_drive, link_tail) = drive_of(link_plain).ok_or_else(not_drive)?;
    let absolute = |target: &str| -> Result<(char, String), NoDestination> {
        let plain = target
            .strip_prefix(r"\??\")
            .or_else(|| target.strip_prefix(r"\\?\"))
            .unwrap_or(target);
        drive_of(plain).ok_or_else(|| {
            Elsewhere(format!(
                "leads to '{target}', which is not on a drive of this machine; not followed"
            ))
        })
    };
    let (drive, tail) = match data {
        LinkData::Other(tag) => {
            return Err(Elsewhere(format!(
                "a reparse point of another kind ({tag:#x}); not followed"
            )));
        }
        LinkData::Junction(target) => absolute(target)?,
        LinkData::Symlink {
            target,
            relative: false,
        } => absolute(target)?,
        LinkData::Symlink {
            target,
            relative: true,
        } => {
            if let Some(rooted) = target.strip_prefix('\\') {
                // Relative to the root of the link's drive.
                if rooted.starts_with('\\') {
                    return Err(Elsewhere(format!("leads to '{target}'; not followed")));
                }
                (link_drive, rooted.to_owned())
            } else {
                let parent = link_tail.rsplit_once('\\').map_or("", |(p, _)| p);
                (link_drive, format!("{parent}\\{target}"))
            }
        }
    };
    // Lexical `.` and `..`, as the system resolves a link's target.
    let mut comps: Vec<&str> = Vec::new();
    for c in tail
        .split(['\\', '/'])
        .chain(rest.iter().map(String::as_str))
    {
        match c {
            "" | "." => {}
            ".." => {
                comps.pop().ok_or_else(|| {
                    Malformed(format!("'{link}' leads above the root of its drive"))
                })?;
            }
            c => comps.push(c),
        }
    }
    Ok(format!(
        r"\\?\{}:\{}",
        drive.to_ascii_uppercase(),
        comps.join("\\")
    ))
}

/// What the walk reads the tree through. `list` is called for the
/// root and for every directory about to be treated as a container;
/// an `Err` makes that directory skipped, with the error as reason.
pub trait Tree {
    fn list(&mut self, rel: &[String]) -> Result<Vec<Entry>, String>;
    fn resolve_link(&mut self, rel: &[String]) -> LinkTarget;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Directory: non-inheriting traverse + list + read attributes.
    Container,
    /// Directory: inheriting read + execute; not descended.
    Granted,
    /// File: read + execute on the file itself.
    File,
    /// Protected exclusion: read deny (inheriting on a directory).
    Denied,
    /// An ungranted-only exclusion, or a directory inside one on the
    /// way to a protected path: nothing written, nothing granted.
    Ungranted,
    /// Nothing written.
    Skipped,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Container => "container",
            Kind::Granted => "granted",
            Kind::File => "file",
            Kind::Denied => "denied",
            Kind::Ungranted => "ungranted",
            Kind::Skipped => "skipped",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Some(match s {
            "container" => Kind::Container,
            "granted" => Kind::Granted,
            "file" => Kind::File,
            "denied" => Kind::Denied,
            "ungranted" => Kind::Ungranted,
            "skipped" => Kind::Skipped,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Components beneath the profile; empty for the root.
    pub rel: Vec<String>,
    pub is_dir: bool,
    pub kind: Kind,
    /// Not on disk: an excluded directory, or a directory on the way
    /// to one, that is to be created empty.
    pub missing: bool,
    /// A denied directory whose deny another part of this crate
    /// writes: recorded as excluded, not written.
    pub stamp: bool,
    /// Why a skipped node was skipped.
    pub note: Option<String>,
}

/// A link the walk met where a rule points: its path, and the rules
/// that matched down to and including its name.
struct LinkHit {
    rel: Vec<String>,
    rules: Vec<usize>,
}

/// What a walk produces.
struct Found {
    nodes: Vec<Node>,
    hits: Vec<LinkHit>,
}

/// How many times the rules may grow by resolving links: the length of a
/// chain of links that each sit beneath the previous one's target.
const MAX_LINK_ROUNDS: usize = 8;

/// The plan for a profile: every node the grant touches or reports,
/// parents before children, in the order the tree listed them.
pub fn plan(tree: &mut dyn Tree, rules: &Rules) -> Result<Vec<Node>, String> {
    plan_resolved(tree, rules).map(|(nodes, _)| nodes)
}

/// [`plan`], with the rules it ended up with: those carried over to the
/// targets of links included, which are what is recorded.
pub fn plan_resolved(tree: &mut dyn Tree, rules: &Rules) -> Result<(Vec<Node>, Rules), String> {
    let mut rules = rules.clone();
    for _ in 0..=MAX_LINK_ROUNDS {
        let entries = tree.list(&[])?;
        let mut found = Found {
            nodes: vec![Node {
                rel: Vec::new(),
                is_dir: true,
                kind: Kind::Container,
                missing: false,
                stamp: true,
                note: None,
            }],
            hits: Vec::new(),
        };
        let all = rules.all();
        walk(tree, &rules, &[], entries, &all, false, &mut found);
        let Found { nodes: out, hits } = found;
        let mut grew = false;
        for hit in hits {
            let LinkTarget::Inside(target) = tree.resolve_link(&hit.rel) else {
                continue;
            };
            if target.is_empty() {
                return Err(format!(
                    "'{}' is a link to the profile directory itself and stands where an \
                     exclusion applies; the profile cannot be granted around it",
                    hit.rel.join("\\")
                ));
            }
            let depth = hit.rel.len();
            for i in hit.rules {
                let from = rules.rules[i].clone();
                let mut pats: Vec<Pat> =
                    target.iter().map(|c| Pat::Lit(norm_component(c))).collect();
                pats.extend(from.pats[depth..].iter().cloned());
                let mut spelled = target.clone();
                spelled.extend(from.spelled[depth..].iter().cloned());
                let same = |r: &Rule| r.pats == pats && r.ungranted == from.ungranted;
                if !rules.rules.iter().any(same) {
                    // The carried-over rule is the source rule at another place,
                    // with its `stamp` and `placeholder` as the source has them.
                    rules.rules.push(Rule {
                        pats,
                        spelled,
                        stamp: from.stamp,
                        ungranted: from.ungranted,
                        placeholder: from.placeholder,
                    });
                    grew = true;
                }
            }
        }
        if !grew {
            return Ok((out, rules));
        }
    }
    Err(format!(
        "links beneath the profile lead on to further links more than {MAX_LINK_ROUNDS} times"
    ))
}

/// Walk one container. `alive` are the rules whose first `rel.len()`
/// components matched the path so far.
fn walk(
    tree: &mut dyn Tree,
    rules: &Rules,
    rel: &[String],
    entries: Vec<Entry>,
    alive: &[usize],
    bare: bool,
    found: &mut Found,
) {
    let depth = rel.len();
    let node = |name: &str, is_dir: bool, kind: Kind| Node {
        rel: rel.iter().cloned().chain([name.to_owned()]).collect(),
        is_dir,
        kind,
        missing: false,
        stamp: true,
        note: None,
    };
    for e in &entries {
        let name = e.name.long.as_str();
        let next: Vec<usize> = alive
            .iter()
            .copied()
            .filter(|&i| e.name.matched_by(&rules.rules[i].pats[depth]))
            .collect();
        if let Some(why) = &e.skip {
            found.nodes.push(Node {
                note: Some(why.clone()),
                ..node(name, e.is_dir, Kind::Skipped)
            });
            // Nothing is written on it. If rules point at or through
            // it and it leads somewhere, they follow it there.
            if e.link && !next.is_empty() {
                found.hits.push(LinkHit {
                    rel: rel.iter().cloned().chain([name.to_owned()]).collect(),
                    rules: next,
                });
            }
            continue;
        }
        let ending: Vec<&Rule> = next
            .iter()
            .map(|&i| &rules.rules[i])
            .filter(|r| r.pats.len() == depth + 1)
            .collect();
        // A protected rule ending here wins over an ungranted-only one.
        let protected: Vec<&&Rule> = ending.iter().filter(|r| !r.ungranted).collect();
        if !protected.is_empty() {
            found.nodes.push(Node {
                stamp: protected.iter().all(|r| r.stamp),
                ..node(name, e.is_dir, Kind::Denied)
            });
            continue;
        }
        if bare || !ending.is_empty() {
            // An ungranted-only exclusion, or something inside one:
            // no entry of any kind.
            if !e.is_dir {
                continue;
            }
            let deeper: Vec<usize> = next
                .iter()
                .copied()
                .filter(|&i| rules.rules[i].pats.len() > depth + 1)
                .collect();
            if !deeper.is_empty() {
                let child: Vec<String> = rel.iter().cloned().chain([name.to_owned()]).collect();
                match tree.list(&child) {
                    Ok(children) => {
                        found.nodes.push(node(name, true, Kind::Ungranted));
                        walk(tree, rules, &child, children, &deeper, true, found);
                    }
                    Err(why) => found.nodes.push(Node {
                        note: Some(why),
                        ..node(name, true, Kind::Skipped)
                    }),
                }
            } else if !ending.is_empty() {
                found.nodes.push(node(name, true, Kind::Ungranted));
            }
            continue;
        }
        if !e.is_dir {
            let readable = if depth == 0 {
                let n = norm_component(name);
                READABLE_ROOT_FILES.iter().any(|f| norm_component(f) == n)
            } else {
                true
            };
            if readable {
                found.nodes.push(node(name, false, Kind::File));
            }
            continue;
        }
        if next.is_empty() {
            found.nodes.push(node(name, true, Kind::Granted));
            continue;
        }
        let child: Vec<String> = rel.iter().cloned().chain([name.to_owned()]).collect();
        match tree.list(&child) {
            Ok(children) => {
                found.nodes.push(node(name, true, Kind::Container));
                walk(tree, rules, &child, children, &next, false, found);
            }
            Err(why) => found.nodes.push(Node {
                note: Some(why),
                ..node(name, true, Kind::Skipped)
            }),
        }
    }
    // Missing excluded directories are created empty so the deny has an
    // object to sit on; never inside or through an ungranted-only exclusion.
    if bare {
        return;
    }
    let mut made: Vec<String> = Vec::new();
    for &i in alive {
        let r = &rules.rules[i];
        if !r.placeholder {
            continue;
        }
        if entries.iter().any(|e| e.name.matched_by(&r.pats[depth])) {
            continue;
        }
        // The other rules that start with the same missing name share
        // the directories they have in common.
        for end in depth + 1..=r.pats.len() {
            let chain: Vec<String> = rel
                .iter()
                .cloned()
                .chain(r.spelled[depth..end].iter().cloned())
                .collect();
            let key = chain[depth..]
                .iter()
                .map(|c| norm_component(c))
                .collect::<Vec<_>>()
                .join("\\");
            if made.contains(&key) {
                continue;
            }
            made.push(key);
            let last = end == r.pats.len();
            // A shorter rule may end at this directory: then it is the
            // excluded one, and nothing is created beneath it.
            let names: Vec<Name> = chain.iter().map(|c| Name::long(c)).collect();
            if rules.ungranted(&names) {
                break;
            }
            let excluded_here = rules.excludes(&names);
            found.nodes.push(Node {
                rel: chain,
                is_dir: true,
                kind: if last || excluded_here {
                    Kind::Denied
                } else {
                    Kind::Container
                },
                missing: true,
                stamp: true,
                note: None,
            });
            if excluded_here && !last {
                break;
            }
        }
    }
}

// ─── A session's read deny on top of the grant ─────────────────────────

/// The recorded paths of a profile read grant that carry an allow of
/// their own — containers, granted directories, granted files — held
/// in the form they are compared in.
#[derive(Debug, Clone, Default)]
pub struct RecordedAllows {
    /// `(as recorded, normalized components)`.
    paths: Vec<(String, Vec<String>)>,
}

fn norm_path(p: &str) -> Vec<String> {
    split_path(p).iter().map(|c| norm_component(c)).collect()
}

impl RecordedAllows {
    pub fn new<'a>(recorded: impl IntoIterator<Item = (&'a str, Kind)>) -> Self {
        Self {
            paths: recorded
                .into_iter()
                .filter(|(_, kind)| matches!(kind, Kind::Container | Kind::Granted | Kind::File))
                .map(|(path, _)| (path.to_owned(), norm_path(path)))
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// The recorded path that `path` itself is, if it is one.
    pub fn at(&self, path: &str) -> Option<&str> {
        let path = norm_path(path);
        self.paths
            .iter()
            .find(|(_, p)| *p == path)
            .map(|(recorded, _)| recorded.as_str())
    }

    /// The recorded paths a read deny on `deny` has to be written on
    /// as well, for it to hold against the grant.
    pub fn covered(&self, deny: &str, allows: &[String]) -> Vec<&str> {
        let deny = norm_path(deny);
        let beneath = |path: &[String], dir: &[String]| {
            path.len() >= dir.len() && path[..dir.len()] == dir[..]
        };
        let spared: Vec<Vec<String>> = allows
            .iter()
            .map(|a| norm_path(a))
            .filter(|a| a.len() > deny.len() && beneath(a, &deny))
            .collect();
        self.paths
            .iter()
            .filter(|(_, path)| path.len() > deny.len() && beneath(path, &deny))
            .filter(|(_, path)| !spared.iter().any(|a| beneath(path, a)))
            .map(|(recorded, _)| recorded.as_str())
            .collect()
    }
}

/// [`RecordedAllows::covered`] for one deny and no session allows.
#[cfg(test)]
fn covered_by_read_deny<'a>(
    deny: &str,
    recorded: impl IntoIterator<Item = (&'a str, Kind)>,
) -> Vec<&'a str> {
    let all: Vec<(&'a str, Kind)> = recorded.into_iter().collect();
    let index = RecordedAllows::new(all.iter().copied());
    let covered: Vec<String> = index
        .covered(deny, &[])
        .into_iter()
        .map(str::to_owned)
        .collect();
    all.into_iter()
        .map(|(p, _)| p)
        .filter(|p| covered.iter().any(|c| c == p))
        .collect()
}

// ─── An exclusion whose deny cannot be written ─────────────────────────

/// One entry of an object's access list, as far as it decides reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AceFact<'a> {
    pub deny: bool,
    pub sid: &'a str,
    pub mask: u32,
    /// The entry is a template for objects beneath and does not apply
    /// to this object.
    pub inherit_only: bool,
    /// Objects beneath inherit the entry (to files, to directories,
    /// or both).
    pub inherited_beneath: bool,
    /// The entry is itself a copy inherited from a directory above.
    pub inherited: bool,
}

/// Groups every token of the sandbox account carries, besides its own
/// SID and the sandbox group's: `Everyone`, `Authenticated Users`,
/// `BUILTIN\Users` (the account is made a member).
pub const SANDBOX_ALWAYS: [&str; 3] = ["S-1-1-0", "S-1-5-11", "S-1-5-32-545"];

/// Groups its token carries depending on how it was logged on.
pub const SANDBOX_MAYBE: [&str; 9] = [
    "S-1-5-4",
    "S-1-5-3",
    "S-1-5-6",
    "S-1-5-2",
    "S-1-2-0",
    "S-1-2-1",
    "S-1-5-15",
    "S-1-5-113",
    "S-1-5-64-10",
];

/// Read data / list directory, and the generic rights that include it.
const READS: u32 = 0x1 | 0x8000_0000 | 0x1000_0000;

/// Whether an object's own access list may let the sandbox account read
/// it. No access list at all admits everyone; a group the account only may
/// be in counts for an allow, never for a deny.
pub fn may_read(dacl: Option<&[AceFact<'_>]>, certain: &[&str], maybe: &[&str]) -> bool {
    let Some(dacl) = dacl else {
        return true;
    };
    reading_entry(dacl, certain, maybe).is_some()
}

/// The entry of `dacl` that lets the sandbox account read — on the
/// object, or failing that in what it hands down ([`may_read`]).
/// `None` if nothing does.
pub fn reading_entry<'a>(
    dacl: &'a [AceFact<'a>],
    certain: &[&str],
    maybe: &[&str],
) -> Option<&'a AceFact<'a>> {
    let here = dacl.iter().filter(|a| !a.inherit_only);
    let beneath = dacl.iter().filter(|a| a.inherited_beneath);
    first_word_on_reading(here, certain, maybe)
        .or_else(|| first_word_on_reading(beneath, certain, maybe))
}

/// The first entry among `aces` that speaks of reading and names the
/// account decides, as an access check does.
fn first_word_on_reading<'a>(
    aces: impl Iterator<Item = &'a AceFact<'a>>,
    certain: &[&str],
    maybe: &[&str],
) -> Option<&'a AceFact<'a>> {
    for ace in aces.filter(|a| a.mask & READS != 0) {
        let is_certain = certain.contains(&ace.sid);
        if ace.deny && is_certain {
            return None;
        }
        if !ace.deny && (is_certain || maybe.contains(&ace.sid)) {
            return Some(ace);
        }
    }
    None
}

/// What an excluded path is when its deny could not be written. The first
/// layer holds regardless: nothing above it carries an inheriting allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unstamped {
    /// Its own access list gives the sandbox account no read — neither
    /// on the object nor, for a directory, in what it hands down to
    /// the objects beneath: closed without the deny.
    SelfClosed,
    /// Its own access list lets the sandbox account read it, and that
    /// cannot be changed from here. Reported, loudly; the grant is not
    /// what opened it and cannot close it.
    Unprotected,
    /// The access list cannot even be read by the calling user: not
    /// its owner, and given no right to. Nobody established that the
    /// sandbox account is kept out.
    Unverifiable,
}

/// `dacl`: `Err` if the access list could not be read.
pub fn unstamped_exclusion(
    dacl: Result<Option<&[AceFact<'_>]>, ()>,
    certain: &[&str],
    maybe: &[&str],
) -> Unstamped {
    match dacl {
        Err(()) => Unstamped::Unverifiable,
        Ok(dacl) if may_read(dacl, certain, maybe) => Unstamped::Unprotected,
        Ok(_) => Unstamped::SelfClosed,
    }
}

// ─── Stores an environment variable moves ───────────────────────────

/// What a variable that relocates a protected store names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Moved {
    /// A directory; these paths in it are the protected ones.
    Beneath(&'static [&'static str]),
    /// The protected file or directory itself.
    Itself,
    /// A `;`-separated list of protected files.
    List,
}

/// Variables that move a protected store. What one names, when inside the
/// profile, is protected as well as the store's default place.
pub const ENV_STORES: &[(&str, Moved)] = &[
    (
        "CARGO_HOME",
        Moved::Beneath(&["credentials", "credentials.toml"]),
    ),
    (
        "GRADLE_USER_HOME",
        Moved::Beneath(&[r"enterprise\keys.properties", r"develocity\keys.properties"]),
    ),
    ("GNUPGHOME", Moved::Itself),
    ("DOCKER_CONFIG", Moved::Itself),
    ("AZURE_CONFIG_DIR", Moved::Itself),
    ("GH_CONFIG_DIR", Moved::Itself),
    ("AWS_SHARED_CREDENTIALS_FILE", Moved::Itself),
    ("AWS_CONFIG_FILE", Moved::Itself),
    ("NETRC", Moved::Itself),
    ("KUBECONFIG", Moved::List),
];

/// A path as a variable gives it: separators one way, none at the end.
fn env_path(v: &str) -> Option<String> {
    let v = v.trim().replace('/', "\\");
    let v = v.trim_end_matches('\\');
    (!v.is_empty()).then(|| v.to_owned())
}

/// Whether `p` names a place whatever the current directory is: a
/// drive path (`X:\…`) or a UNC or device path (`\\…`).
fn is_absolute(p: &str) -> bool {
    let b = p.as_bytes();
    p.starts_with(r"\\") || (b.len() >= 3 && b[0].is_ascii_alphabetic() && &b[1..3] == b":\\")
}

/// The absolute paths the calling user's environment (`own_env`) says
/// hold a protected store ([`ENV_STORES`]), and the relative values it
/// ignored as `VAR=value`: a relative path names nothing fixed.
pub fn env_exclusions(own_env: &dyn Fn(&str) -> Option<String>) -> (Vec<String>, Vec<String>) {
    let (mut out, mut ignored) = (Vec::new(), Vec::new());
    for (var, moved) in ENV_STORES {
        let Some(value) = own_env(var) else {
            continue;
        };
        let values: Vec<String> = match moved {
            Moved::List => value.split(';').filter_map(env_path).collect(),
            _ => env_path(&value).into_iter().collect(),
        };
        for v in values {
            if !is_absolute(&v) {
                ignored.push(format!("{var}={v}"));
            } else if let Moved::Beneath(rel) = moved {
                out.extend(rel.iter().map(|r| format!("{v}\\{r}")));
            } else {
                out.push(v);
            }
        }
    }
    (out, ignored)
}

/// Whether both credential files of the cargo home `dir` are among the
/// recorded protected exclusions. Only then is `dir` offered as
/// `CARGO_HOME`.
pub fn cargo_home_protected(exclusions: &[String], dir: &str) -> bool {
    let key = |p: &str| {
        p.strip_prefix(r"\\?\")
            .unwrap_or(p)
            .trim_end_matches('\\')
            .to_lowercase()
    };
    ["credentials", "credentials.toml"].iter().all(|f| {
        let want = format!("{}\\{f}", key(dir));
        exclusions.iter().any(|e| key(e) == want)
    })
}

// ─── Configuration pointers ─────────────────────────────────────────

/// Variables an embedder may set so a tool reads the real user's files in
/// place, each only when its file or directory is there and covered by the
/// grant. `RUSTUP_HOME` and `CARGO_HOME` name directories.
pub fn env_pointers(
    profile: &str,
    roaming: Option<&str>,
    readable: &dyn Fn(&str) -> bool,
    dir_readable: &dyn Fn(&str) -> bool,
    own_env: &dyn Fn(&str) -> Option<String>,
) -> Vec<(&'static str, String)> {
    let at = |base: &str, rel: &str| format!("{}\\{rel}", base.trim_end_matches('\\'));
    let first = |candidates: &[String]| candidates.iter().find(|p| readable(p)).cloned();
    let mut out = Vec::new();
    if let Some(p) = first(&[at(profile, ".npmrc")]) {
        out.push(("NPM_CONFIG_USERCONFIG", p));
    }
    if let Some(p) = first(&[
        at(profile, ".gitconfig"),
        at(profile, r".config\git\config"),
    ]) {
        out.push(("GIT_CONFIG_GLOBAL", p));
    }
    let mut pip = Vec::new();
    pip.extend(roaming.map(|r| at(r, r"pip\pip.ini")));
    pip.push(at(profile, r"pip\pip.ini"));
    pip.push(at(profile, r".config\pip\pip.conf"));
    if let Some(p) = first(&pip) {
        out.push(("PIP_CONFIG_FILE", p));
    }
    if let Some(settings) = first(&[at(profile, r".m2\settings.xml")]) {
        let mut v = format!("-s \"{settings}\"");
        if let Some(sec) = first(&[at(profile, r".m2\settings-security.xml")]) {
            v.push_str(&format!(" \"-Dsettings.security={sec}\""));
        }
        out.push(("MAVEN_ARGS", v));
    }
    for (var, rel) in [("RUSTUP_HOME", ".rustup"), ("CARGO_HOME", ".cargo")] {
        let dir = own_env(var)
            .map(|v| v.trim_end_matches('\\').to_owned())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| at(profile, rel));
        if dir_readable(&dir) {
            out.push((var, dir));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// An in-memory tree: path (components joined by `\`, `""` for
    /// the root) → entries.
    #[derive(Default, Clone)]
    struct Mem {
        dirs: BTreeMap<String, Vec<Entry>>,
        unreadable: Vec<String>,
        /// Link path → where it points: a path beneath the profile
        /// (`""` for the profile itself), or `None` for outside it.
        links: BTreeMap<String, Option<String>>,
        /// Links whose own data cannot be decoded.
        broken: Vec<String>,
    }

    fn entry(name: &str, is_dir: bool) -> Entry {
        Entry {
            name: Name::long(name),
            is_dir,
            skip: None,
            link: false,
        }
    }

    impl Mem {
        /// Add `path`; a trailing `\` makes it a directory. Parents
        /// are added as directories.
        fn add(&mut self, path: &str) -> &mut Self {
            let is_dir = path.ends_with('\\');
            let comps = split_path(path);
            for i in 0..comps.len() {
                let parent = comps[..i].join("\\");
                let dir = i + 1 < comps.len() || is_dir;
                let list = self.dirs.entry(parent).or_default();
                if !list.iter().any(|e| e.name.long == comps[i]) {
                    list.push(entry(&comps[i], dir));
                }
                if dir {
                    self.dirs.entry(comps[..=i].join("\\")).or_default();
                }
            }
            self
        }

        fn entry_mut(&mut self, path: &str) -> &mut Entry {
            let comps = split_path(path);
            let parent = comps[..comps.len() - 1].join("\\");
            self.dirs
                .get_mut(&parent)
                .unwrap()
                .iter_mut()
                .find(|e| e.name.long == comps[comps.len() - 1])
                .unwrap()
        }
    }

    impl Mem {
        /// Make the directory `path` a link to `target`.
        fn link(&mut self, path: &str, target: Option<&str>) -> &mut Self {
            if !self.dirs.contains_key(path) {
                self.add(&format!("{path}\\"));
            }
            let e = self.entry_mut(path);
            e.skip = Some("reparse point".into());
            e.link = true;
            self.links
                .insert(path.to_owned(), target.map(str::to_owned));
            self
        }

        /// `path` with every link on the way resolved, as the final
        /// path of a real open is; `None` for outside the profile or
        /// a cycle.
        fn real(&self, path: &str) -> Option<String> {
            let mut cur = path.to_owned();
            for _ in 0..32 {
                let comps = split_path(&cur);
                let hit = (1..=comps.len())
                    .map(|n| comps[..n].join("\\"))
                    .find(|prefix| self.links.contains_key(prefix));
                let Some(prefix) = hit else {
                    return Some(cur);
                };
                let target = self.links[&prefix].clone()?;
                let rest = &cur[prefix.len()..];
                cur = format!("{target}{rest}")
                    .trim_start_matches('\\')
                    .to_owned();
            }
            None
        }
    }

    impl Tree for Mem {
        fn resolve_link(&mut self, rel: &[String]) -> LinkTarget {
            if self.broken.contains(&rel.join("\\")) {
                return LinkTarget::Elsewhere("its data cannot be decoded".to_owned());
            }
            match self.real(&rel.join("\\")) {
                Some(real) => LinkTarget::Inside(split_path(&real)),
                None => LinkTarget::Elsewhere("outside the profile".to_owned()),
            }
        }

        fn list(&mut self, rel: &[String]) -> Result<Vec<Entry>, String> {
            let key = rel.join("\\");
            if self.unreadable.contains(&key) {
                return Err("access denied".to_owned());
            }
            self.dirs
                .get(&key)
                .cloned()
                .ok_or_else(|| format!("no directory '{key}'"))
        }
    }

    fn rules() -> Rules {
        Rules::new(None, None, &[])
    }

    fn kinds(nodes: &[Node]) -> BTreeMap<String, (Kind, bool)> {
        nodes
            .iter()
            .map(|n| (n.rel.join("\\"), (n.kind, n.missing)))
            .collect()
    }

    /// The node planned for `path`.
    fn by<'a>(nodes: &'a [Node], path: &str) -> &'a Node {
        nodes
            .iter()
            .find(|n| n.rel.join("\\") == path)
            .unwrap_or_else(|| panic!("no node for '{path}'"))
    }

    fn names(rel: &[String]) -> Vec<Name> {
        rel.iter().map(|c| Name::long(c)).collect()
    }

    #[test]
    fn a_profile_is_planned_by_the_walk_rule() {
        let mut t = Mem::default();
        t.add(r"Documents\notes.txt")
            .add(r"source\repo\a.rs")
            .add(".npmrc")
            .add(".gitconfig")
            .add(".netrc")
            .add("NTUSER.DAT")
            .add("ntuser.dat.LOG1")
            .add("stray.txt")
            .add(r".ssh\id_ed25519")
            .add(r".cargo\credentials.toml")
            .add(r".cargo\config.toml")
            .add(r".cargo\bin\rg.exe")
            .add(r".config\git\config")
            .add(r".config\git\credentials")
            .add(r".config\gh\hosts.yml")
            .add(r".config\pip\pip.conf")
            .add(r".m2\settings.xml")
            .add(r"AppData\Roaming\npm\tool.cmd")
            .add(r"AppData\Roaming\Microsoft\Credentials\x")
            .add(r"AppData\Roaming\Microsoft\Windows\Start Menu\a.lnk")
            .add(r"AppData\Local\Temp\t.tmp")
            .add(r"AppData\Local\Programs\Python\python.exe")
            .add(r"AppData\Local\SomeApp\EBWebView\Cookies")
            .add(r"AppData\Local\SomeApp\data.bin")
            .add(r"AppData\LocalLow\x");
        let nodes = plan(&mut t, &rules()).unwrap();
        let k = kinds(&nodes);
        let is = |p: &str, kind: Kind| {
            assert_eq!(k.get(p).map(|v| v.0), Some(kind), "{p}");
        };
        let absent = |p: &str| assert!(!k.contains_key(p), "{p} is in the plan");
        is("", Kind::Container);
        is("Documents", Kind::Granted);
        is("source", Kind::Granted);
        is(".m2", Kind::Granted);
        absent(r"Documents\notes.txt");
        is(".npmrc", Kind::File);
        is(".gitconfig", Kind::File);
        absent("stray.txt");
        is(".netrc", Kind::Denied);
        is("NTUSER.DAT", Kind::Denied);
        is("ntuser.dat.LOG1", Kind::Denied);
        is(".ssh", Kind::Denied);
        absent(r".ssh\id_ed25519");
        is(".cargo", Kind::Container);
        is(r".cargo\credentials.toml", Kind::Denied);
        is(r".cargo\config.toml", Kind::File);
        is(r".cargo\bin", Kind::Granted);
        is(".config", Kind::Container);
        is(r".config\git", Kind::Container);
        is(r".config\git\config", Kind::File);
        is(r".config\git\credentials", Kind::Denied);
        is(r".config\gh", Kind::Denied);
        is(r".config\pip", Kind::Granted);
        is("AppData", Kind::Container);
        is(r"AppData\Roaming", Kind::Container);
        is(r"AppData\Roaming\npm", Kind::Granted);
        is(r"AppData\Roaming\Microsoft", Kind::Container);
        is(r"AppData\Roaming\Microsoft\Credentials", Kind::Denied);
        is(r"AppData\Roaming\Microsoft\Windows", Kind::Granted);
        is(r"AppData\Local", Kind::Container);
        is(r"AppData\Local\Temp", Kind::Ungranted);
        absent(r"AppData\Local\Temp\t.tmp");
        is(r"AppData\Local\Programs", Kind::Container);
        is(r"AppData\Local\Programs\Python", Kind::Granted);
        is(r"AppData\Local\SomeApp", Kind::Container);
        is(r"AppData\Local\SomeApp\EBWebView", Kind::Denied);
        is(r"AppData\Local\SomeApp\data.bin", Kind::File);
        is(r"AppData\LocalLow", Kind::Granted);
        assert_eq!(k.get(".aws"), Some(&(Kind::Denied, true)));
        assert_eq!(k.get(".config\\gcloud"), Some(&(Kind::Denied, true)));
        assert_eq!(
            k.get(r"AppData\Local\Google"),
            Some(&(Kind::Container, true))
        );
        assert_eq!(
            k.get(r"AppData\Local\Google\Chrome\User Data"),
            Some(&(Kind::Denied, true))
        );
        absent(".kaggle");
        absent(r"AppData\Local\Vivaldi");
        absent(r"AppData\Roaming\Thunderbird");
        absent(".git-credentials");
        absent(r".gradle");
        assert!(!k.keys().any(|p| p.contains('*')));
        absent(r"AppData\Local\sandbox-runtime");
        for (i, n) in nodes.iter().enumerate() {
            if let Some((_, parent)) = n.rel.split_last() {
                let at = nodes.iter().position(|m| m.rel == parent).unwrap();
                assert!(at < i, "{:?} precedes its parent", n.rel);
            }
        }
    }

    #[test]
    fn the_state_directory_is_excluded_and_left_to_its_owner() {
        let mut t = Mem::default();
        t.add(r"AppData\Local\sandbox-runtime\state.db");
        let nodes = plan(&mut t, &rules()).unwrap();
        let n = nodes
            .iter()
            .find(|n| n.rel.join("\\") == r"AppData\Local\sandbox-runtime")
            .unwrap();
        assert_eq!((n.kind, n.stamp), (Kind::Denied, false));
    }

    /// An ungranted-only directory gets nothing and gives its
    /// children nothing; a protected path inside it is still denied,
    /// and the directories on the way to it get nothing either.
    #[test]
    fn an_ungranted_only_directory_is_left_bare_but_for_protected_paths_inside() {
        let extra = vec![split_path(r"AppData\Local\Temp\app\keys")];
        let rules = Rules::new(None, None, &extra);
        let mut t = Mem::default();
        t.add(r"AppData\Local\Temp\loose.txt")
            .add(r"AppData\Local\Temp\session-1\work\f.txt")
            .add(r"AppData\Local\Temp\app\keys\ca.key")
            .add(r"AppData\Local\Temp\app\other\o.txt")
            .add(r"AppData\Local\Temp\app\a.txt")
            .add(r"AppData\Local\Other\x");
        let nodes = plan(&mut t, &rules).unwrap();
        let k = kinds(&nodes);
        let got: Vec<(&str, Kind)> = k
            .iter()
            .filter(|(p, _)| p.starts_with(r"AppData\Local\Temp"))
            .map(|(p, v)| (p.as_str(), v.0))
            .collect();
        assert_eq!(
            got,
            [
                (r"AppData\Local\Temp", Kind::Ungranted),
                (r"AppData\Local\Temp\app", Kind::Ungranted),
                (r"AppData\Local\Temp\app\keys", Kind::Denied),
            ]
        );
        assert!(!k.contains_key(r"AppData\Local\Temp\session-1"));
        let mut t = Mem::default();
        t.add(r"AppData\Local\x");
        let k = kinds(&plan(&mut t, &rules).unwrap());
        assert!(!k.keys().any(|p| p.starts_with(r"AppData\Local\Temp")));
    }

    /// A link where a rule points: the rule follows it to its target.
    #[test]
    fn a_rule_follows_a_link_to_its_target_inside_the_profile() {
        let mut t = Mem::default();
        t.add(r"dotfiles\.ssh\id_ed25519")
            .add(r"dotfiles\.config\gh\hosts.yml")
            .add(r"dotfiles\.config\git\config")
            .add(r"dotfiles\.config\git\credentials")
            .add(r"dotfiles\.config\nvim\init.lua")
            .add(r"dotfiles\README")
            .add(r"Documents\a.txt");
        t.link(".ssh", Some(r"dotfiles\.ssh"))
            .link(".config", Some(r"dotfiles\.config"));
        let (nodes, rules) = plan_resolved(&mut t, &rules()).unwrap();
        let k = kinds(&nodes);
        let is = |p: &str, kind: Kind| assert_eq!(k.get(p).map(|v| v.0), Some(kind), "{p}");
        is(".ssh", Kind::Skipped);
        is(".config", Kind::Skipped);
        is("dotfiles", Kind::Container);
        is(r"dotfiles\.ssh", Kind::Denied);
        is(r"dotfiles\.config", Kind::Container);
        is(r"dotfiles\.config\gh", Kind::Denied);
        is(r"dotfiles\.config\git", Kind::Container);
        is(r"dotfiles\.config\git\credentials", Kind::Denied);
        is(r"dotfiles\.config\git\config", Kind::File);
        is(r"dotfiles\.config\nvim", Kind::Granted);
        is(r"dotfiles\README", Kind::File);
        is("Documents", Kind::Granted);
        assert!(!k.contains_key(r"dotfiles\.ssh\id_ed25519"));
        let spelled = rules.spelled();
        for want in [
            r"dotfiles\.ssh",
            r"dotfiles\.config\gh",
            r"dotfiles\.config\gcloud",
        ] {
            assert!(
                spelled.iter().any(|s| s == want),
                "{want} not in {spelled:?}"
            );
        }
        assert!(rules.excludes(&names(&split_path(r"dotfiles\.ssh\new-key"))));
        assert!(rules.could_exclude_beneath(&names(&split_path("dotfiles"))));
        let mut plain = Mem::default();
        plain
            .add(r"dotfiles\.ssh\id_ed25519")
            .add(r"dotfiles\README");
        let k = kinds(&plan(&mut plain, &super::tests::rules()).unwrap());
        assert_eq!(k.get("dotfiles").map(|v| v.0), Some(Kind::Granted));
    }

    /// A link's destination is worked out from the link's own data,
    /// and is a destination only on a drive letter.
    #[test]
    fn a_link_is_followed_only_to_a_drive_of_this_machine() {
        let link = r"\\?\C:\Users\me\.ssh";
        let rest = ["keys".to_owned(), "id".to_owned()];
        let j = |t: &str| LinkData::Junction(t.to_owned());
        let sym = |t: &str, relative: bool| LinkData::Symlink {
            target: t.to_owned(),
            relative,
        };
        let to = |d: &LinkData| link_destination(link, d, &rest);
        assert_eq!(
            to(&j(r"\??\C:\Users\me\dotfiles\.ssh")).unwrap(),
            r"\\?\C:\Users\me\dotfiles\.ssh\keys\id"
        );
        assert_eq!(
            to(&j(r"\??\d:\elsewhere\")).unwrap(),
            r"\\?\D:\elsewhere\keys\id"
        );
        assert_eq!(to(&sym(r"\??\C:\x", false)).unwrap(), r"\\?\C:\x\keys\id");
        assert_eq!(
            to(&sym(r"dotfiles\.ssh", true)).unwrap(),
            r"\\?\C:\Users\me\dotfiles\.ssh\keys\id"
        );
        assert_eq!(
            to(&sym(r"..\shared\.\ssh", true)).unwrap(),
            r"\\?\C:\Users\shared\ssh\keys\id"
        );
        assert_eq!(
            to(&sym(r"\data\ssh", true)).unwrap(),
            r"\\?\C:\data\ssh\keys\id"
        );
        assert_eq!(
            link_destination(link, &sym("..", true), &[]).unwrap(),
            r"\\?\C:\Users"
        );
        for d in [
            j(r"\??\UNC\server\share\x"),
            sym(r"\??\UNC\server\share\x", false),
            sym(r"\\server\share\x", false),
            sym(r"\\server\share\x", true),
            sym(r"\\?\UNC\server\share", false),
            j(r"\??\Volume{01234567-89ab-cdef-0123-456789abcdef}\x"),
            sym(r"\Device\Mup\server\share", false),
            sym(r"..\..\..\..\x", true),
            LinkData::Other(0x9000_001A),
        ] {
            assert!(to(&d).is_err(), "{d:?} was followed to {:?}", to(&d));
        }
        assert!(link_destination(r"\\?\UNC\s\h\l", &sym("x", true), &[]).is_err());

        let wide = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let buffer = |tag: u32, flags: Option<u32>, subst: &str, print: &str| {
            let (s, p) = (wide(subst), wide(print));
            let mut b = Vec::new();
            b.extend(tag.to_le_bytes());
            b.extend(0u16.to_le_bytes());
            b.extend(0u16.to_le_bytes());
            b.extend(0u16.to_le_bytes());
            b.extend((s.len() as u16).to_le_bytes());
            b.extend((s.len() as u16).to_le_bytes());
            b.extend((p.len() as u16).to_le_bytes());
            if let Some(f) = flags {
                b.extend(f.to_le_bytes());
            }
            b.extend(&s);
            b.extend(&p);
            b
        };
        assert_eq!(
            parse_reparse(&buffer(0xA000_0003, None, r"\??\C:\t", r"C:\t")),
            Ok(j(r"\??\C:\t"))
        );
        assert_eq!(
            parse_reparse(&buffer(0xA000_000C, Some(1), r"..\t", r"..\t")),
            Ok(sym(r"..\t", true))
        );
        assert_eq!(
            parse_reparse(&buffer(0xA000_000C, Some(0), r"\??\UNC\s\h", "")),
            Ok(sym(r"\??\UNC\s\h", false))
        );
        assert_eq!(
            parse_reparse(&buffer(0x9000_001A, None, "", "")),
            Ok(LinkData::Other(0x9000_001A))
        );
        assert!(parse_reparse(&[0x03, 0, 0, 0xA0, 0, 0]).is_err());
        let mut cut = buffer(0xA000_0003, None, r"\??\C:\t", "");
        cut.truncate(cut.len() - 4);
        assert!(parse_reparse(&cut).is_err());
    }

    /// A link whose target is not there yet, and one that cannot be
    /// read.
    #[test]
    fn a_missing_link_target_is_still_protected_and_an_undecodable_link_is_skipped() {
        let mut t = Mem::default();
        t.add(r"dotfiles\README").add(r"Documents\a.txt");
        t.link(".ssh", Some(r"dotfiles\.ssh"));
        let (nodes, rules) = plan_resolved(&mut t, &rules()).unwrap();
        let k = kinds(&nodes);
        assert_eq!(k.get("dotfiles").map(|v| v.0), Some(Kind::Container));
        assert_eq!(k.get(r"dotfiles\.ssh"), Some(&(Kind::Denied, true)));
        assert_eq!(k.get(r"dotfiles\README").map(|v| v.0), Some(Kind::File));
        assert!(rules.excludes(&names(&split_path(r"dotfiles\.ssh\id_new"))));
        let mut t = Mem::default();
        t.add(r"Documents\a.txt");
        t.link(".ssh", Some(r"dotfiles\.ssh"));
        let nodes = plan(&mut t, &super::tests::rules()).unwrap();
        let k = kinds(&nodes);
        assert_eq!(k.get("dotfiles"), Some(&(Kind::Container, true)));
        assert_eq!(k.get(r"dotfiles\.ssh"), Some(&(Kind::Denied, true)));
        let mut t = Mem::default();
        t.add(r"dotfiles\README");
        t.link(".config", Some(r"dotfiles\.config"));
        let (nodes, rules) = plan_resolved(&mut t, &super::tests::rules()).unwrap();
        assert!(!kinds(&nodes).contains_key(r"dotfiles\.config\hub"));
        assert!(rules.excludes(&names(&split_path(r"dotfiles\.config\hub"))));

        let mut t = Mem::default();
        t.add(r"dotfiles\.ssh\id").add(r"Documents\a.txt");
        t.link(".ssh", Some(r"dotfiles\.ssh"));
        t.broken.push(".ssh".to_owned());
        let k = kinds(&plan(&mut t, &super::tests::rules()).unwrap());
        assert_eq!(k.get(".ssh").map(|v| v.0), Some(Kind::Skipped));
        assert_eq!(k.get("").map(|v| v.0), Some(Kind::Container));
        assert_eq!(k.get("Documents").map(|v| v.0), Some(Kind::Granted));
    }

    /// A rule carried over to a link's target keeps the source rule's
    /// way of being applied.
    #[test]
    fn a_carried_over_rule_keeps_the_flags_of_its_source() {
        let mut t = Mem::default();
        t.add(r"data\Local\sandbox-runtime\state.db")
            .add(r"data\Local\Microsoft\Credentials\blob")
            .add(r"data\Local\Programs\tool.exe")
            .add(r"AppData\Roaming\npm\x.cmd");
        t.link(r"AppData\Local", Some(r"data\Local"));
        let original = rules();
        let (nodes, rules) = plan_resolved(&mut t, &original).unwrap();
        let state = by(&nodes, r"data\Local\sandbox-runtime");
        assert_eq!(state.kind, Kind::Denied);
        assert!(!state.stamp, "the state directory is left to its owner");
        let creds = by(&nodes, r"data\Local\Microsoft\Credentials");
        assert!(creds.kind == Kind::Denied && creds.stamp);
        assert!(rules.ungranted(&names(&split_path(r"data\Local\Temp"))));
        assert!(!rules.excludes(&names(&split_path(r"data\Local\Temp"))));
        assert!(rules.rules.len() > original.rules.len());
        for d in &rules.rules[original.rules.len()..] {
            assert!(
                original.rules.iter().any(|r| {
                    r.stamp == d.stamp
                        && r.placeholder == d.placeholder
                        && r.ungranted == d.ungranted
                        && (0..r.pats.len()).any(|j| d.pats.ends_with(&r.pats[j..]))
                }),
                "{:?} has the flags of no rule it could come from",
                d.spelled
            );
        }
    }

    #[test]
    fn links_in_chains_upwards_outwards_and_in_circles() {
        let mut t = Mem::default();
        t.add(r"a\cfg\other\x")
            .add(r"b\gh\hosts.yml")
            .add(r"b\keep.txt");
        t.link(".config", Some(r"a\cfg"))
            .link(r"a\cfg\gh", Some(r"b\gh"));
        let (nodes, rules) = plan_resolved(&mut t, &rules()).unwrap();
        let k = kinds(&nodes);
        assert_eq!(k.get(r"b\gh").map(|v| v.0), Some(Kind::Denied));
        assert_eq!(k.get("b").map(|v| v.0), Some(Kind::Container));
        assert_eq!(k.get(r"b\keep.txt").map(|v| v.0), Some(Kind::File));
        assert_eq!(k.get(r"a\cfg").map(|v| v.0), Some(Kind::Container));
        assert_eq!(k.get(r"a\cfg\gh").map(|v| v.0), Some(Kind::Skipped));
        assert!(rules.spelled().iter().any(|s| s == r"b\gh"));

        let mut t = Mem::default();
        t.add(r".config\git\config");
        t.link(r".config\gh", Some(".config"));
        let k = kinds(&plan(&mut t, &super::tests::rules()).unwrap());
        assert_eq!(k.get(".config").map(|v| v.0), Some(Kind::Denied));
        assert!(!k.contains_key(r".config\git"));

        let mut t = Mem::default();
        t.add(r"Documents\a.txt");
        t.link(".ssh", None);
        let (nodes, rules) = plan_resolved(&mut t, &super::tests::rules()).unwrap();
        let k = kinds(&nodes);
        assert_eq!(k.get(".ssh").map(|v| v.0), Some(Kind::Skipped));
        assert_eq!(k.get("Documents").map(|v| v.0), Some(Kind::Granted));
        assert_eq!(rules.spelled(), super::tests::rules().spelled());

        let mut t = Mem::default();
        t.link(".ssh", Some(".aws")).link(".aws", Some(".ssh"));
        let k = kinds(&plan(&mut t, &super::tests::rules()).unwrap());
        assert_eq!(k.get(".ssh").map(|v| v.0), Some(Kind::Skipped));
        assert_eq!(k.get(".aws").map(|v| v.0), Some(Kind::Skipped));

        let mut t = Mem::default();
        t.add(r"work\x");
        t.link("shortcut", Some("work"));
        let (nodes, rules) = plan_resolved(&mut t, &super::tests::rules()).unwrap();
        assert_eq!(kinds(&nodes).get("work").map(|v| v.0), Some(Kind::Granted));
        assert_eq!(rules.spelled(), super::tests::rules().spelled());

        let mut t = Mem::default();
        t.link(".ssh", Some(""));
        assert!(plan(&mut t, &super::tests::rules()).is_err());

        let hops = MAX_LINK_ROUNDS + 3;
        let long: Vec<String> = (1..=hops + 1).map(|i| format!("x{i}")).collect();
        let chain = |links: usize| {
            let mut t = Mem::default();
            for i in 1..=links {
                let at = if i == 1 {
                    "x1".to_owned()
                } else {
                    format!(r"h{}\x{i}", i - 1)
                };
                t.add(&format!(r"h{i}\keep.txt"));
                t.link(&at, Some(&format!("h{i}")));
            }
            t
        };
        let with_long = Rules::new(None, None, std::slice::from_ref(&long));
        assert!(plan(&mut chain(hops), &with_long).is_err());
        let (nodes, rules) = plan_resolved(&mut chain(3), &with_long).unwrap();
        assert_eq!(kinds(&nodes).get("h3").map(|v| v.0), Some(Kind::Container));
        let rest = long[3..].join("\\");
        assert!(rules.spelled().contains(&format!(r"h3\{rest}")));
    }

    #[test]
    fn reparse_points_and_unreadable_directories_are_skipped_at_every_level() {
        let mut t = Mem::default();
        t.add(r"link\")
            .add(r"OneDrive\")
            .add(r"AppData\Local\junction\")
            .add(r"AppData\Local\app\link.lnk")
            .add(r".config\x\")
            .add(r".ssh\");
        t.entry_mut("link").skip = Some("reparse point".into());
        t.entry_mut("OneDrive").skip = Some("cloud placeholder".into());
        t.entry_mut(r"AppData\Local\junction").skip = Some("reparse point".into());
        t.entry_mut(r"AppData\Local\app\link.lnk").skip = Some("reparse point".into());
        t.entry_mut(".ssh").skip = Some("reparse point".into());
        t.unreadable.push(".config".into());
        let nodes = plan(&mut t, &rules()).unwrap();
        let k = kinds(&nodes);
        for p in [
            "link",
            "OneDrive",
            r"AppData\Local\junction",
            r"AppData\Local\app\link.lnk",
            ".ssh",
            ".config",
        ] {
            assert_eq!(k.get(p).map(|v| v.0), Some(Kind::Skipped), "{p}");
        }
        assert!(!k.keys().any(|p| p.starts_with(r".config\")));
        let skipped: Vec<&Node> = nodes.iter().filter(|n| n.kind == Kind::Skipped).collect();
        assert!(skipped.iter().all(|n| n.note.is_some()));
        let mut bad = Mem::default();
        bad.unreadable.push(String::new());
        assert!(plan(&mut bad, &rules()).is_err());
    }

    #[test]
    fn a_name_cannot_be_respelled_past_an_exclusion() {
        let r = rules();
        let ex = |p: &str| r.excludes(&names(&split_path(p)));
        for p in [
            ".ssh",
            ".SSH",
            ".ssh.",
            ".ssh ",
            ".ssh. .",
            ".ssh::$INDEX_ALLOCATION",
            ".ssh:stream",
            r".ssh\id_rsa",
            r".Ssh.\ID_RSA",
            ".netrc::$DATA",
            ".NETRC",
            "NTUSER.DAT",
            "ntuser.dat.LOG2",
            "NTUSER.DAT{guid}.TM.blf",
            r"appdata\roaming\microsoft\CREDENTIALS",
            r"AppData\Local\Anything\EBWebView\Default",
            r"AppData\Local\Microsoft\Olk\EBWebView",
            r"AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1",
            r".cargo\Credentials.TOML",
        ] {
            assert!(ex(p), "{p} is not excluded");
        }
        assert!(!ex(r"AppData\Local\Temp"));
        assert!(!ex(r"AppData\Local\Temp\x\y"));
        for p in [r"AppData\Local\Temp", r"appdata\LOCAL\temp.\x\y"] {
            assert!(r.ungranted(&names(&split_path(p))), "{p}");
        }
        assert!(!r.ungranted(&names(&split_path(r"AppData\Local\Temp2"))));
        assert!(!r.ungranted(&names(&split_path(".ssh"))));
        for p in [
            ".sshx",
            "ssh",
            ".npmrc",
            ".gitconfig",
            r".cargo\config.toml",
            r"Documents\.ssh",
            r"AppData\Local\EBWebView",
            r"AppData\Roaming\npm",
            "..",
            ". .",
        ] {
            assert!(!ex(p), "{p} is excluded");
        }
        let short = |long: &str, short: &str| Name {
            long: long.to_owned(),
            short: Some(short.to_owned()),
        };
        let r = Rules::new(
            None,
            None,
            &[
                vec!["MYSECR~1".to_owned()],
                vec!["Long Secret Dir".to_owned()],
            ],
        );
        assert!(r.excludes(&[short("My Secrets", "MYSECR~1")]));
        assert!(r.excludes(&[short("Long Secret Dir", "LONGSE~1")]));
        assert!(r.excludes(&[Name::long("LONG SECRET DIR. ")]));
        assert!(!r.excludes(&[short("My Secrets 2", "MYSECR~2")]));
        let mut t = Mem::default();
        t.add(r"My Secrets\k");
        t.entry_mut("My Secrets").name.short = Some("MYSECR~1".into());
        let k = kinds(&plan(&mut t, &r).unwrap());
        assert_eq!(k.get("My Secrets").map(|v| v.0), Some(Kind::Denied));
    }

    #[test]
    fn exclusion_paths_from_configuration() {
        let profile = r"\\?\C:\Users\me";
        let ok = |p: &str| rel_components(profile, p).unwrap().join("\\");
        assert_eq!(ok(r"C:\Users\me\.myapp"), ".myapp");
        assert_eq!(ok(r"c:/users/ME/.myapp/tokens"), r".myapp\tokens");
        assert_eq!(
            ok(r"\\?\C:\Users\me\AppData\Roaming\MyApp"),
            r"AppData\Roaming\MyApp"
        );
        assert_eq!(ok(r".myapp\"), ".myapp");
        assert_eq!(ok(r"C:\Users\me"), "");
        for bad in [
            r"C:\Users\other\.myapp",
            r"C:\Users\me\..\other",
            r"D:\x",
            r".myapp\*",
            r".\x",
            r"C:\Users\me2",
        ] {
            assert!(rel_components(profile, bad).is_err(), "{bad}");
        }
        let r = Rules::new(None, None, &[vec![".myapp".to_owned()], vec![]]);
        assert!(r.excludes(&names(&split_path(r".MyApp\token"))));
        assert!(!r.excludes(&names(&split_path("Documents"))));
        assert!(r.excludes(&names(&split_path(".ssh"))));
        let spelled = r.spelled();
        for want in [
            ".myapp",
            ".ssh",
            r"AppData\Roaming\Microsoft\Credentials",
            r"AppData\Local\*\EBWebView",
            "NTUSER.DAT*",
            r"AppData\Local\sandbox-runtime",
        ] {
            assert_eq!(
                spelled.iter().filter(|s| s.as_str() == want).count(),
                1,
                "{want}"
            );
        }
        assert_eq!(r.spelled_ungranted(), [r"AppData\Local\Temp"]);
        assert!(!spelled.contains(&r"AppData\Local\Temp".to_owned()));
    }

    /// Both spellings of an application-data location are covered:
    /// the conventional one and a known folder that sits elsewhere in
    /// the profile.
    #[test]
    fn application_data_entries_follow_the_known_folders() {
        let moved = ["Data".to_owned(), "Roam".to_owned()];
        let r = Rules::new(Some(&moved), None, &[]);
        let ex = |p: &str| r.excludes(&names(&split_path(p)));
        assert!(ex(r"Data\Roam\Microsoft\Credentials"));
        assert!(ex(r"Data\Roam\gcloud"));
        assert!(ex(r"AppData\Roaming\Microsoft\Credentials"));
        assert!(r.ungranted(&names(&split_path(r"AppData\Local\Temp"))));
        assert!(!ex(r"Data\Roam\npm"));
        let r = rules();
        for (base, path) in [
            (Roaming, "gcloud"),
            (Roaming, "GitHub CLI"),
            (Roaming, "com.vercel.cli"),
            (Roaming, "netlify"),
            (Local, "heroku"),
            (Local, ".IdentityService"),
            (Local, "MicrosoftCredentialProvider"),
            (Local, r"Microsoft\IdentityCache"),
            (Local, r"Microsoft\TokenBroker"),
            (Local, r"Microsoft\OneAuth"),
            (Local, r"Microsoft\Windows\INetCookies"),
            (Local, r"Microsoft\Windows\UsrClass.dat"),
            (Profile, r".config\gcloud"),
            (Profile, r".config\gh"),
            (Local, r"github-copilot\hosts.json"),
            (Profile, r".config\github-copilot\apps.json"),
            (Profile, r".gem\credentials"),
            (Profile, r".pulumi\credentials.json"),
            (Roaming, r"postgresql\pgpass.conf"),
            (Profile, ".pgpass"),
            (Roaming, r"Composer\auth.json"),
            (Profile, r".composer\auth.json"),
            (Profile, r".config\doctl\config.yaml"),
            (Profile, r".config\hub"),
            (Profile, r".config\op\config"),
            (Profile, r".kaggle\kaggle.json"),
            (Profile, ".databrickscfg"),
            (Profile, r".snowsql\config"),
            (Profile, ".boto"),
            (Profile, ".s3cfg"),
            (Profile, r".oci\config"),
            (Profile, r".fly\config.yml"),
            (Local, r"Google\Chrome Beta\User Data\Default\Cookies"),
            (Local, r"Chromium\User Data"),
            (Local, r"Vivaldi\User Data"),
            (Local, r"Yandex\YandexBrowser\User Data"),
            (Roaming, r"Opera Software\Opera GX Stable"),
            (Roaming, r"Thunderbird\Profiles"),
        ] {
            let prefix = match base {
                Roaming => r"AppData\Roaming\",
                Local => r"AppData\Local\",
                Profile => "",
            };
            let full = format!("{prefix}{path}");
            assert!(r.excludes(&names(&split_path(&full))), "{full}");
        }
        assert!(BUILT_IN.iter().all(|e| !e.path.is_empty()
            && !e.path.starts_with('\\')
            && !e.path.contains('/')
            && !e.path.contains(':')));
        for tool in [
            r".pulumi\bin\pulumi.exe",
            r".fly\bin\flyctl.exe",
            r".gem\specs",
        ] {
            assert!(!r.excludes(&names(&split_path(tool))), "{tool}");
        }
        for (base, path, _) in READABLE_CONFIG {
            let prefix = match base {
                Roaming => r"AppData\Roaming\",
                Local => r"AppData\Local\",
                Profile => "",
            };
            let full = format!("{prefix}{path}");
            assert!(!r.excludes(&names(&split_path(&full))), "{full}");
        }
    }

    /// A small deterministic generator, so the property below needs
    /// no dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    const POOL: &[&str] = &[
        ".ssh",
        ".SSH.",
        ".aws",
        ".config",
        "gcloud",
        "gh",
        "git",
        "credentials",
        "config",
        ".cargo",
        "credentials.toml",
        "AppData",
        "Roaming",
        "Local",
        "Temp",
        "Microsoft",
        "Credentials",
        "Windows",
        "UsrClass.dat",
        "EBWebView",
        "Google",
        "Chrome",
        "User Data",
        "Packages",
        ".npmrc",
        ".netrc",
        "NTUSER.DAT",
        "Documents",
        "src",
        "a",
        "b",
        "c.txt",
        "d.exe",
        ".myapp",
        "tokens",
        "keys",
    ];

    fn random_tree(rng: &mut Rng) -> Mem {
        let mut t = Mem::default();
        t.dirs.entry(String::new()).or_default();
        for _ in 0..rng.below(40) + 5 {
            let depth = rng.below(5) + 1;
            let mut p: Vec<&str> = (0..depth).map(|_| POOL[rng.below(POOL.len())]).collect();
            match rng.below(4) {
                0 => p.insert(0, "AppData"),
                1 => {
                    p.insert(0, "Local");
                    p.insert(0, "AppData");
                }
                _ => {}
            }
            let mut path = p.join("\\");
            if rng.below(2) == 0 {
                path.push('\\');
            }
            let comps = split_path(&path);
            let clash = (0..comps.len()).any(|i| {
                let parent = comps[..i].join("\\");
                let dir = i + 1 < comps.len() || path.ends_with('\\');
                t.dirs
                    .get(&parent)
                    .is_some_and(|l| l.iter().any(|e| e.name.long == comps[i] && e.is_dir != dir))
            });
            if !clash {
                t.add(&path);
            }
        }
        let keys: Vec<String> = t.dirs.keys().filter(|k| !k.is_empty()).cloned().collect();
        for k in &keys {
            match rng.below(10) {
                0 => {
                    let target = match rng.below(4) {
                        0 => None,
                        _ => Some(keys[rng.below(keys.len())].clone()),
                    };
                    t.link(k, target.as_deref());
                }
                1 => t.unreadable.push(k.clone()),
                _ => {}
            }
        }
        t
    }

    /// The invariant, over generated trees: no excluded path — on
    /// disk now or created later — has an ancestor carrying an
    /// inheriting allow, and nothing excluded is granted itself.
    #[test]
    fn no_exclusion_ever_lies_beneath_an_inheriting_allow() {
        let extra = vec![
            vec![".myapp".to_owned(), "tokens".to_owned()],
            vec!["Documents".to_owned(), "a".to_owned()],
            split_path(r"AppData\Local\Temp\keys"),
        ];
        let rules = Rules::new(None, None, &extra);
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let original = rules;
        for round in 0..600 {
            let mut t = random_tree(&mut rng);
            let (nodes, rules) = plan_resolved(&mut t, &original).unwrap();
            for (n, d) in rules.rules.iter().enumerate().skip(original.rules.len()) {
                assert!(
                    rules.rules[..n].iter().any(|r| {
                        r.stamp == d.stamp
                            && r.placeholder == d.placeholder
                            && r.ungranted == d.ungranted
                            && (0..=r.pats.len()).any(|j| d.pats.ends_with(&r.pats[j..]))
                    }),
                    "round {round}: {:?} has the flags of no rule it could come from",
                    d.spelled
                );
            }
            let by_rel: BTreeMap<String, &Node> =
                nodes.iter().map(|n| (n.rel.join("\\"), n)).collect();
            assert_eq!(by_rel.len(), nodes.len(), "round {round}: a path twice");
            for n in &nodes {
                let rel = names(&n.rel);
                let path = n.rel.join("\\");
                match n.kind {
                    Kind::Granted => {
                        assert!(!rules.excludes(&rel), "round {round}: {path}");
                        assert!(
                            !rules.could_exclude_beneath(&rel),
                            "round {round}: an exclusion can lie beneath granted {path}"
                        );
                    }
                    Kind::File => assert!(!rules.excludes(&rel), "round {round}: {path}"),
                    Kind::Denied => assert!(rules.excludes(&rel), "round {round}: {path}"),
                    Kind::Ungranted => {
                        assert!(rules.ungranted(&rel), "round {round}: {path}");
                        assert!(!rules.excludes(&rel), "round {round}: {path}");
                    }
                    Kind::Container | Kind::Skipped => {}
                }
                if rules.ungranted(&rel) {
                    assert!(
                        matches!(n.kind, Kind::Ungranted | Kind::Denied | Kind::Skipped),
                        "round {round}: {path} is {:?} inside an ungranted-only directory",
                        n.kind
                    );
                }
                for up in 1..n.rel.len() {
                    let anc = n.rel[..up].join("\\");
                    let a = by_rel
                        .get(&anc)
                        .unwrap_or_else(|| panic!("round {round}: {path} has no planned parent"));
                    assert!(
                        matches!(a.kind, Kind::Container | Kind::Ungranted),
                        "round {round}: {path} under {anc} ({:?})",
                        a.kind
                    );
                }
                if !n.rel.is_empty() {
                    assert_eq!(by_rel[""].kind, Kind::Container);
                }
            }
            for (link, _) in t.links.iter().filter(|(l, _)| {
                let parent = split_path(l);
                by_rel
                    .get(l.as_str())
                    .is_some_and(|n| n.kind == Kind::Skipped)
                    && !original.ungranted(&names(&parent[..parent.len() - 1]))
            }) {
                let Some(target) = t.real(link) else { continue };
                for n in &nodes {
                    let real = n.rel.join("\\");
                    let rest = if real == target {
                        ""
                    } else if let Some(r) = real.strip_prefix(&format!("{target}\\")) {
                        r
                    } else if target.is_empty() {
                        real.as_str()
                    } else {
                        continue;
                    };
                    let alias = names(&split_path(&format!("{link}\\{rest}")));
                    if original.excludes(&alias) {
                        assert!(
                            matches!(n.kind, Kind::Denied | Kind::Skipped),
                            "round {round}: {real} is {:?} though excluded as {link}\\{rest}",
                            n.kind
                        );
                    }
                    if n.kind == Kind::Granted {
                        assert!(
                            !original.could_exclude_beneath(&alias),
                            "round {round}: granted {real} is {link}\\{rest}, beneath which \
                             an exclusion can lie"
                        );
                    }
                    if original.ungranted(&alias) {
                        assert!(
                            matches!(n.kind, Kind::Ungranted | Kind::Denied | Kind::Skipped),
                            "round {round}: {real} is {:?} though ungranted as {link}\\{rest}",
                            n.kind
                        );
                    }
                }
            }
            for (dir, entries) in &t.dirs {
                let parent = split_path(dir);
                let walked = (0..=parent.len()).all(|up| {
                    by_rel.get(&parent[..up].join("\\")).is_some_and(|n| {
                        matches!(n.kind, Kind::Container | Kind::Ungranted) && !n.missing
                    })
                });
                if !walked {
                    continue;
                }
                for e in entries {
                    let mut rel = parent.clone();
                    rel.push(e.name.long.clone());
                    if rules.excludes(&names(&rel)) {
                        let k = by_rel[&rel.join("\\")].kind;
                        assert!(
                            matches!(k, Kind::Denied | Kind::Skipped),
                            "round {round}: excluded {} planned as {k:?}",
                            rel.join("\\")
                        );
                    }
                }
            }
        }
    }

    /// Deleting an excluded item, or creating one that was not
    /// there, changes no directory from container to granted.
    #[test]
    fn the_containers_do_not_depend_on_what_exists() {
        let rules = rules();
        let mut with = Mem::default();
        with.add(r".config\gcloud\credentials.db")
            .add(r".config\other\x")
            .add(r".cargo\credentials.toml")
            .add(r"AppData\Roaming\Microsoft\Credentials\c")
            .add(r"AppData\Roaming\Microsoft\Other\o");
        let mut without = Mem::default();
        without
            .add(r".config\other\x")
            .add(r".cargo\")
            .add(r"AppData\Roaming\Microsoft\Other\o");
        let a = kinds(&plan(&mut with, &rules).unwrap());
        let b = kinds(&plan(&mut without, &rules).unwrap());
        for p in [
            ".config",
            ".cargo",
            "AppData",
            r"AppData\Roaming",
            r"AppData\Roaming\Microsoft",
        ] {
            assert_eq!(a[p].0, Kind::Container, "{p}");
            assert_eq!(b[p].0, Kind::Container, "{p}");
        }
    }

    #[test]
    fn configuration_pointers_name_only_readable_files() {
        let profile = r"C:\Users\me";
        let roaming = r"C:\Users\me\AppData\Roaming";
        let all = |_: &str| true;
        let none = |_: &str| false;
        let unset = |_: &str| None;
        let got = env_pointers(profile, Some(roaming), &all, &none, &unset);
        assert_eq!(
            got,
            vec![
                ("NPM_CONFIG_USERCONFIG", r"C:\Users\me\.npmrc".to_owned()),
                ("GIT_CONFIG_GLOBAL", r"C:\Users\me\.gitconfig".to_owned()),
                (
                    "PIP_CONFIG_FILE",
                    r"C:\Users\me\AppData\Roaming\pip\pip.ini".to_owned()
                ),
                (
                    "MAVEN_ARGS",
                    "-s \"C:\\Users\\me\\.m2\\settings.xml\" \
                     \"-Dsettings.security=C:\\Users\\me\\.m2\\settings-security.xml\""
                        .to_owned()
                ),
            ]
        );
        assert!(env_pointers(profile, Some(roaming), &none, &none, &unset).is_empty());
        let only =
            |want: &'static [&'static str]| move |p: &str| want.iter().any(|w| p.ends_with(w));
        let got = env_pointers(
            profile,
            Some(roaming),
            &only(&[r".config\git\config", r"me\pip\pip.ini", "settings.xml"]),
            &none,
            &unset,
        );
        assert_eq!(
            got,
            vec![
                (
                    "GIT_CONFIG_GLOBAL",
                    r"C:\Users\me\.config\git\config".to_owned()
                ),
                ("PIP_CONFIG_FILE", r"C:\Users\me\pip\pip.ini".to_owned()),
                (
                    "MAVEN_ARGS",
                    "-s \"C:\\Users\\me\\.m2\\settings.xml\"".to_owned()
                ),
            ]
        );
        let got = env_pointers(profile, None, &only(&["pip.conf"]), &none, &unset);
        assert_eq!(
            got,
            vec![(
                "PIP_CONFIG_FILE",
                r"C:\Users\me\.config\pip\pip.conf".to_owned()
            )]
        );
        for (var, _) in env_pointers(profile, Some(roaming), &all, &all, &unset) {
            assert!(
                ![
                    "USERPROFILE",
                    "HOME",
                    "APPDATA",
                    "LOCALAPPDATA",
                    "TEMP",
                    "TMP",
                    "GRADLE_USER_HOME",
                ]
                .contains(&var)
            );
        }
    }

    /// `RUSTUP_HOME` and `CARGO_HOME` are named where the grant reaches them, at
    /// the place the real user's environment says, else the default one.
    #[test]
    fn the_rust_homes_are_named_where_the_grant_reaches_them() {
        let profile = r"C:\Users\me";
        let none = |_: &str| false;
        let unset = |_: &str| None;
        let rust = |dirs: &dyn Fn(&str) -> bool, env: &dyn Fn(&str) -> Option<String>| {
            env_pointers(profile, None, &none, dirs, env)
        };
        assert_eq!(
            rust(&|_| true, &unset),
            vec![
                ("RUSTUP_HOME", r"C:\Users\me\.rustup".to_owned()),
                ("CARGO_HOME", r"C:\Users\me\.cargo".to_owned()),
            ]
        );
        assert!(rust(&none, &unset).is_empty());
        assert_eq!(
            rust(&|p| p.ends_with(".cargo"), &unset),
            vec![("CARGO_HOME", r"C:\Users\me\.cargo".to_owned())]
        );
        let own = |var: &str| match var {
            "RUSTUP_HOME" => Some(r"C:\Users\me\tools\rustup\".to_owned()),
            "CARGO_HOME" => Some(r"D:\cargo".to_owned()),
            _ => None,
        };
        assert_eq!(
            rust(&|p| p.starts_with(r"C:\Users\me\"), &own),
            vec![("RUSTUP_HOME", r"C:\Users\me\tools\rustup".to_owned())]
        );
        assert_eq!(
            rust(&|_| true, &|_| Some(String::new())).len(),
            2,
            "the defaults"
        );
    }

    /// Variables that move a protected store name what is protected
    /// there; the cargo home is offered only once its credential
    /// files are on record.
    #[test]
    fn stores_moved_by_the_environment_are_named() {
        let env = |var: &str| match var {
            "CARGO_HOME" => Some(r"C:\Users\me\tools\cargo\".to_owned()),
            "GRADLE_USER_HOME" => Some(r"C:\Users\me\g".to_owned()),
            "GNUPGHOME" => Some("C:/Users/me/keys".to_owned()),
            "KUBECONFIG" => Some(r"C:\Users\me\k\a.yaml;;D:\k\b.yaml; ".to_owned()),
            "NETRC" => Some(String::new()),
            _ => None,
        };
        assert_eq!(
            env_exclusions(&env).0,
            [
                r"C:\Users\me\tools\cargo\credentials",
                r"C:\Users\me\tools\cargo\credentials.toml",
                r"C:\Users\me\g\enterprise\keys.properties",
                r"C:\Users\me\g\develocity\keys.properties",
                r"C:\Users\me\keys",
                r"C:\Users\me\k\a.yaml",
                r"D:\k\b.yaml",
            ]
        );
        assert!(env_exclusions(&|_| None).0.is_empty());
        // A relative value names nothing fixed: ignored, and said.
        let relative = |var: &str| match var {
            "KUBECONFIG" => Some(r"kubeconfig;C:\k\a.yaml;.kube\b".to_owned()),
            "CARGO_HOME" => Some("cargo".to_owned()),
            "NETRC" => Some(r"C:netrc".to_owned()),
            "GNUPGHOME" => Some(r"\\srv\share\gnupg".to_owned()),
            _ => None,
        };
        let (kept, ignored) = env_exclusions(&relative);
        assert_eq!(kept, [r"\\srv\share\gnupg", r"C:\k\a.yaml"]);
        assert_eq!(
            ignored,
            [
                "CARGO_HOME=cargo",
                "NETRC=C:netrc",
                "KUBECONFIG=kubeconfig",
                r"KUBECONFIG=.kube\b"
            ]
        );
        for (var, _) in ENV_STORES {
            assert!(!["RUSTUP_HOME", "PIP_CONFIG_FILE", "NPM_CONFIG_USERCONFIG"].contains(var));
        }
        let recorded = vec![
            r"\\?\C:\Users\me\.cargo\credentials".to_owned(),
            r"\\?\C:\Users\me\.cargo\credentials.toml".to_owned(),
            r"\\?\C:\Users\me\tools\cargo\credentials.toml".to_owned(),
        ];
        assert!(cargo_home_protected(&recorded, r"C:\Users\ME\.cargo"));
        assert!(cargo_home_protected(&recorded, r"C:\Users\me\.cargo\"));
        assert!(!cargo_home_protected(&recorded, r"C:\Users\me\tools\cargo"));
        assert!(!cargo_home_protected(&recorded, r"C:\Users\me\other"));
        assert!(!cargo_home_protected(&[], r"C:\Users\me\.cargo"));
    }

    /// `.rustup` is granted whole; `.cargo` is a container whose credential
    /// files are denied on themselves.
    #[test]
    fn a_container_is_traversable_and_its_exclusions_stay_denied() {
        let mut t = Mem::default();
        t.add(r".cargo\credentials.toml")
            .add(r".cargo\config.toml")
            .add(r".cargo\registry\index\x")
            .add(r".rustup\toolchains\stable\bin\cargo.exe");
        let k = kinds(&plan(&mut t, &rules()).unwrap());
        let kind = |p: &str| k.get(p).map(|v| v.0);
        assert_eq!(kind(".rustup"), Some(Kind::Granted));
        assert_eq!(kind(".cargo"), Some(Kind::Container));
        assert_eq!(kind(r".cargo\registry"), Some(Kind::Granted));
        assert_eq!(kind(r".cargo\config.toml"), Some(Kind::File));
        assert_eq!(kind(r".cargo\credentials.toml"), Some(Kind::Denied));
    }

    #[test]
    fn a_session_grant_is_measured_against_the_recorded_exclusions() {
        let p = |rel: &str| format!(r"\\?\C:\Users\me\{rel}");
        let protected = vec![
            p(".ssh"),
            p(r"AppData\Local\*\EBWebView"),
            p("NTUSER.DAT*"),
            p(r"AppData\Local\Temp\keys"),
        ];
        let ungranted = vec![p(r"AppData\Local\Temp")];
        let on_disk = |dir: &str| -> Listing {
            let d = dir.to_lowercase();
            let names: &[&str] = if d.ends_with(r"\appdata\local") {
                &["App", "Tool", "npm-cache", "Temp"]
            } else if d.ends_with(r"\appdata\local\app") {
                &["EBWebView", "data"]
            } else if d.ends_with(r"\appdata\local\tool") {
                &["bin"]
            } else if d.ends_with(r"\appdata") {
                &["Local", "Roaming"]
            } else if d.ends_with(r"\users\me") {
                &["AppData", "Documents"]
            } else {
                return Listing::Nothing;
            };
            Listing::Entries(names.iter().map(|n| (*n).to_owned()).collect())
        };
        let check = |rel: &str, write: bool, admitted: &[String]| {
            session_grant_refusal(&p(rel), write, &protected, &ungranted, admitted, &on_disk)
        };
        let refused = |rel: &str, write: bool| check(rel, write, &[]).is_some();
        for write in [false, true] {
            assert!(refused(".ssh", write));
            assert!(refused(r".SSH.\keys", write));
            assert!(refused(r"AppData\Local\App\EBWebView\Default", write));
            assert!(refused("ntuser.dat.LOG1", write));
            assert!(refused(r"AppData\Local\App", write));
            assert!(refused("AppData", write));
            assert!(!refused(r"AppData\Local\Tool", write));
            assert!(!refused(r"AppData\Local\npm-cache", write));
            assert!(!refused(r"AppData\Local\Tool\bin", write));
            assert!(refused(r"AppData\Local\Temp", write));
            assert!(refused(r"AppData\Local", write));
            assert!(!refused(r"AppData\Local\Temp\session", write));
            assert!(!refused(r"AppData\Local\Temp\session\work", write));
            assert!(refused(r"AppData\Local\Temp\keys", write));
            assert!(refused(r"AppData\Local\Temp\keys\sub", write));
            assert!(!refused("Documents", write));
            assert!(!refused(".sshx", write));
            assert!(!refused(r"AppData\Local\App\data", write));
        }
        for root in [r"\\?\C:\Users\me", r"\\?\C:\Users", r"\\?\C:\"] {
            for write in [false, true] {
                assert!(
                    session_grant_refusal(root, write, &protected, &ungranted, &[], &on_disk)
                        .is_some(),
                    "{root}"
                );
            }
        }
        for other in [r"\\?\D:\work", r"\\?\C:\Users\other\.ssh"] {
            assert_eq!(
                session_grant_refusal(other, true, &protected, &ungranted, &[], &on_disk),
                None
            );
        }
        let ssh = [p(".ssh")];
        assert_eq!(check(".ssh", false, &ssh), None);
        assert!(check(".ssh", true, &ssh).is_some());
        assert!(check(r".ssh\keys", false, &ssh).is_some());
        assert_eq!(check(r".ssh\keys", false, &[p(r".ssh\keys")]), None);
        assert!(check("AppData", false, &[p("AppData")]).is_some());
        let temp = [p(r"AppData\Local\Temp")];
        assert!(check(r"AppData\Local\Temp", false, &temp).is_some());
        let empty = |_: &str| Listing::Nothing;
        let bare = |rel: &str| {
            session_grant_refusal(&p(rel), true, &protected, &ungranted, &[], &empty).is_some()
        };
        assert!(!bare(r"AppData\Local\App"));
        assert!(bare(r"AppData\Local\App\EBWebView"));
        assert!(bare(r"AppData\Local"));
        assert!(bare(""));
        let deep = |dir: &str| -> Listing {
            let d = dir.to_lowercase();
            if d.ends_with(r"\local\x") {
                Listing::Entries(vec!["y".to_owned()])
            } else if d.ends_with(r"\local\x\y") {
                Listing::Entries(vec!["EBWebView".to_owned()])
            } else {
                Listing::Nothing
            }
        };
        assert_eq!(
            session_grant_refusal(
                &p(r"AppData\Local\x"),
                true,
                &protected,
                &ungranted,
                &[],
                &deep
            ),
            None
        );
        let two = vec![p(r"apps\*\*\store")];
        let with = |at_apps: Listing, at_a: Listing| {
            move |dir: &str| -> Listing {
                let d = dir.to_lowercase();
                if d.ends_with(r"\apps") {
                    at_apps.clone()
                } else if d.ends_with(r"\apps\a") {
                    at_a.clone()
                } else {
                    Listing::Nothing
                }
            }
        };
        let names = |n: &[&str]| Listing::Entries(n.iter().map(|s| (*s).to_owned()).collect());
        let verdict = |list: &dyn Fn(&str) -> Listing| {
            session_grant_refusal(&p("apps"), true, &two, &[], &[], list)
        };
        assert_eq!(verdict(&with(names(&["a"]), names(&["b"]))), None);
        assert_eq!(verdict(&with(names(&["a"]), Listing::Nothing)), None);
        assert_eq!(verdict(&with(Listing::Nothing, Listing::Nothing)), None);
        assert_eq!(verdict(&with(names(&["a"]), Listing::Link)), None);
        for (at_apps, at_a) in [
            (Listing::Failed("access denied".into()), Listing::Nothing),
            (Listing::Failed("i/o error".into()), Listing::Nothing),
            (names(&["a"]), Listing::Failed("access denied".into())),
            (
                names(&["a", "z"]),
                Listing::Failed("sharing violation".into()),
            ),
            (Listing::Link, Listing::Nothing),
        ] {
            let why = verdict(&with(at_apps.clone(), at_a.clone()))
                .unwrap_or_else(|| panic!("{at_apps:?}/{at_a:?} was admitted"));
            assert!(why.contains("could not be examined"), "{why}");
        }
        let narrow = vec![p(r"apps\b\*\store")];
        assert_eq!(
            session_grant_refusal(
                &p("apps"),
                true,
                &narrow,
                &[],
                &[],
                &with(names(&["a"]), Listing::Failed("access denied".into()))
            ),
            None
        );
        let found = |dir: &str| -> Listing {
            let d = dir.to_lowercase();
            if d.ends_with(r"\apps") {
                names(&["a", "c"])
            } else if d.ends_with(r"\apps\a") {
                Listing::Failed("access denied".into())
            } else if d.ends_with(r"\apps\c") {
                names(&["d"])
            } else if d.ends_with(r"\apps\c\d") {
                names(&["store"])
            } else {
                Listing::Nothing
            }
        };
        let why = verdict(&found).unwrap();
        assert!(why.contains("narrower"), "{why}");
        let why = check("AppData", true, &[]).unwrap();
        assert!(why.contains("narrower"), "{why}");
        assert_eq!(relation(&p(".ssh"), &p(".ssh")), Some(Relation::Equal));
        assert_eq!(relation(&p(r".ssh\a"), &p(".ssh")), Some(Relation::Inside));
        assert_eq!(relation(&p(""), &p(".ssh")), Some(Relation::Above));
        assert_eq!(relation(&p("x"), &p(".ssh")), None);
    }

    #[test]
    fn a_read_deny_is_also_written_on_each_recorded_allow_beneath_it() {
        let root = r"\\?\C:\Users\me";
        let rec: Vec<(String, Kind)> = [
            ("", Kind::Container),
            (r"\Documents", Kind::Granted),
            (r"\.gitconfig", Kind::File),
            (r"\.ssh", Kind::Denied),
            (r"\AppData", Kind::Container),
            (r"\AppData\Local", Kind::Container),
            (r"\AppData\Local\Temp", Kind::Ungranted),
            (r"\AppData\Local\Programs", Kind::Granted),
            (r"\AppData\Local\IconCache.db", Kind::File),
            (r"\AppData\Roaming", Kind::Container),
            (r"\OneDrive", Kind::Skipped),
        ]
        .iter()
        .map(|(p, k)| (format!("{root}{p}"), *k))
        .collect();
        let also = |deny: &str| -> Vec<String> {
            covered_by_read_deny(
                &format!("{root}{deny}"),
                rec.iter().map(|(p, k)| (p.as_str(), *k)),
            )
            .into_iter()
            .map(|p| p[root.len()..].to_owned())
            .collect()
        };
        assert_eq!(
            also(r"\AppData"),
            [
                r"\AppData\Local",
                r"\AppData\Local\Programs",
                r"\AppData\Local\IconCache.db",
                r"\AppData\Roaming"
            ]
        );
        assert_eq!(also(r"\APPDATA\local.").len(), 2);
        assert!(also(r"\Documents").is_empty());
        assert!(also(r"\.gitconfig").is_empty());
        assert!(also(r"\Documents\work\secret").is_empty());
        assert!(also(r"\App").is_empty());
        assert_eq!(also("").len(), 7);

        let many: Vec<(String, Kind)> = (0..6000)
            .map(|i| {
                let kind = match i % 3 {
                    0 => Kind::Container,
                    1 => Kind::Granted,
                    _ => Kind::File,
                };
                (
                    format!(r"{root}\AppData\Local\dir{}\entry-{i}", i % 40),
                    kind,
                )
            })
            .chain((0..500).map(|i| (format!(r"{root}\Documents\d{i}"), Kind::Granted)))
            .collect();
        let got = covered_by_read_deny(
            &format!(r"{root}\AppData"),
            many.iter().map(|(p, k)| (p.as_str(), *k)),
        );
        assert_eq!(got.len(), 6000);
        assert!(got.iter().map(|p| p.len() + 14).sum::<usize>() > 32_767);
        let one = covered_by_read_deny(
            &format!(r"{root}\AppData\Local\dir7"),
            many.iter().map(|(p, k)| (p.as_str(), *k)),
        );
        assert_eq!(one.len(), 150);
    }

    /// The case table the library's tests read too
    /// (`tests/data/read-deny-cases.txt`).
    #[test]
    fn read_denies_and_session_allows_rank_as_the_library_ranks_them() {
        let table = include_str!("../tests/data/read-deny-cases.txt");
        let path = |p: &str| -> String {
            let p = p.trim();
            match p.strip_prefix('P') {
                Some(rest) => format!(r"\\?\C:\Users\me{rest}"),
                None => panic!("'{p}' is not beneath P"),
            }
        };
        let list = |v: &str| -> Vec<String> {
            v.split(" | ")
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(path)
                .collect()
        };
        let mut recorded: Vec<(String, Kind)> = Vec::new();
        #[derive(Default)]
        struct Case {
            name: String,
            /// Handed read and write grants.
            allows: Vec<String>,
            /// What a per-command deny is sent with, where the case
            /// says: the reduced list of grants.
            except: Option<Vec<String>>,
            denies: Vec<String>,
            expect: Vec<String>,
        }
        let mut cases: Vec<Case> = Vec::new();
        for line in table.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once(':').expect("key: value");
            let value = value.trim();
            match key {
                "recorded" => {
                    for item in value.split(" | ") {
                        let (kind, p) = item.trim().split_once(' ').unwrap();
                        recorded.push((path(p), Kind::parse(kind).unwrap()));
                    }
                }
                "case" => cases.push(Case {
                    name: value.to_owned(),
                    ..Default::default()
                }),
                "handed-read" | "handed-write" => {
                    cases.last_mut().unwrap().allows.extend(list(value))
                }
                "handed-deny" => cases.last_mut().unwrap().denies = list(value),
                "except" => cases.last_mut().unwrap().except = Some(list(value)),
                "expect" => cases.last_mut().unwrap().expect = list(value),
                "read" | "write" | "deny" | "credential" => {}
                other => panic!("unknown key '{other}'"),
            }
        }
        assert!(cases.len() >= 12 && recorded.len() >= 10);
        let index = RecordedAllows::new(recorded.iter().map(|(p, k)| (p.as_str(), *k)));
        assert!(cases.iter().any(|c| c.except.is_some()));
        let runs = cases.iter().flat_map(|c| {
            std::iter::once((&c.name, &c.allows, &c.denies, &c.expect)).chain(
                c.except
                    .as_ref()
                    .map(|reduced| (&c.name, reduced, &c.denies, &c.expect)),
            )
        });
        for (name, allows, denies, expect) in runs {
            let mut got: Vec<String> = Vec::new();
            for d in denies {
                let d_norm = norm_path(d);
                got.extend(
                    recorded
                        .iter()
                        .filter(|(p, k)| {
                            matches!(k, Kind::Container | Kind::Granted | Kind::File)
                                && norm_path(p) == d_norm
                        })
                        .map(|(p, _)| p.clone()),
                );
                got.extend(index.covered(d, allows).into_iter().map(str::to_owned));
            }
            let sorted = |mut v: Vec<String>| {
                v.sort();
                v.dedup();
                v
            };
            assert_eq!(sorted(got), sorted(expect.clone()), "case: {name}");
        }
    }

    /// What an object's own access list lets the sandbox account do,
    /// and so what an exclusion is whose deny could not be written.
    #[test]
    fn an_unwritable_exclusion_is_judged_by_its_own_access_list() {
        const USER: &str = "S-1-5-21-1-2-3-1001";
        const GROUP: &str = "S-1-5-21-1-2-3-1002";
        const OWNER: &str = "S-1-5-21-1-2-3-500";
        const SYSTEM: &str = "S-1-5-18";
        const ADMINS: &str = "S-1-5-32-544";
        const RX: u32 = 0x1200a9;
        const FULL: u32 = 0x1f01ff;
        let certain: Vec<&str> = [USER, GROUP].into_iter().chain(SANDBOX_ALWAYS).collect();
        let allow = |sid, mask| AceFact {
            deny: false,
            sid,
            mask,
            inherit_only: false,
            inherited_beneath: true,
            inherited: false,
        };
        let deny = |sid, mask| AceFact {
            deny: true,
            sid,
            mask,
            inherit_only: false,
            inherited_beneath: true,
            inherited: false,
        };
        let class =
            |dacl: &[AceFact<'_>]| unstamped_exclusion(Ok(Some(dacl)), &certain, &SANDBOX_MAYBE);

        assert_eq!(
            class(&[allow(OWNER, FULL), allow(SYSTEM, FULL), allow(ADMINS, FULL)]),
            Unstamped::SelfClosed
        );
        assert_eq!(
            class(&[
                deny("S-1-1-0", RX),
                deny("S-1-5-11", RX),
                deny("S-1-5-32-545", RX),
                allow(OWNER, FULL),
                allow("S-1-5-32-545", RX),
            ]),
            Unstamped::SelfClosed
        );
        assert_eq!(
            class(&[
                allow("S-1-1-0", RX),
                allow(SYSTEM, FULL),
                allow(ADMINS, FULL)
            ]),
            Unstamped::Unprotected
        );
        for sid in certain.iter().chain(&SANDBOX_MAYBE) {
            assert_eq!(class(&[allow(sid, RX)]), Unstamped::Unprotected, "{sid}");
        }
        assert_eq!(
            class(&[allow("S-1-5-32-545", RX), deny("S-1-1-0", RX)]),
            Unstamped::Unprotected
        );
        assert_eq!(
            class(&[deny(GROUP, 0x1), allow("S-1-1-0", FULL)]),
            Unstamped::SelfClosed
        );
        assert_eq!(
            class(&[deny("S-1-5-4", RX), allow("S-1-1-0", RX)]),
            Unstamped::Unprotected
        );
        assert_eq!(
            class(&[deny("S-1-1-0", 0x10000), allow("S-1-1-0", 0x100080)]),
            Unstamped::SelfClosed
        );
        let only_beneath = |a: AceFact<'static>| AceFact {
            inherit_only: true,
            inherited_beneath: true,
            ..a
        };
        let only_here = |a: AceFact<'static>| AceFact {
            inherited_beneath: false,
            ..a
        };
        for sid in ["S-1-1-0", "S-1-5-11", "S-1-5-32-545", GROUP, "S-1-5-4"] {
            assert_eq!(
                class(&[allow(OWNER, FULL), only_beneath(allow(sid, RX))]),
                Unstamped::Unprotected,
                "{sid}"
            );
        }
        assert_eq!(
            class(&[
                only_here(deny("S-1-1-0", RX)),
                only_beneath(allow("S-1-5-32-545", RX)),
            ]),
            Unstamped::Unprotected
        );
        assert_eq!(
            class(&[
                only_beneath(deny("S-1-1-0", RX)),
                only_beneath(allow("S-1-5-32-545", RX)),
                only_here(allow(OWNER, FULL)),
            ]),
            Unstamped::SelfClosed
        );
        assert_eq!(
            class(&[
                only_beneath(deny("S-1-1-0", RX)),
                only_here(allow("S-1-5-32-545", RX)),
            ]),
            Unstamped::Unprotected
        );
        assert_eq!(
            class(&[
                only_beneath(allow(OWNER, FULL)),
                only_here(allow(SYSTEM, FULL))
            ]),
            Unstamped::SelfClosed
        );
        assert_eq!(
            class(&[allow("S-1-1-0", 0x8000_0000)]),
            Unstamped::Unprotected
        );
        assert_eq!(
            class(&[allow("S-1-5-11", 0x1000_0000)]),
            Unstamped::Unprotected
        );
        let copy = |a: AceFact<'static>| AceFact {
            inherited: true,
            ..a
        };
        let list = [
            allow(OWNER, FULL),
            copy(allow(GROUP, RX)),
            allow("S-1-1-0", RX),
        ];
        let by = reading_entry(&list, &certain, &SANDBOX_MAYBE).unwrap();
        assert!(by.sid == GROUP && by.inherited);
        let list = [deny("S-1-1-0", 0x10000), allow(GROUP, RX)];
        let by = reading_entry(&list, &certain, &SANDBOX_MAYBE).unwrap();
        assert!(by.sid == GROUP && !by.inherited);
        let list = [allow("S-1-5-32-545", RX), allow(GROUP, RX)];
        assert_eq!(
            reading_entry(&list, &certain, &SANDBOX_MAYBE).unwrap().sid,
            "S-1-5-32-545"
        );
        assert!(reading_entry(&[allow(OWNER, FULL)], &certain, &SANDBOX_MAYBE).is_none());
        assert_eq!(class(&[]), Unstamped::SelfClosed);
        assert_eq!(
            unstamped_exclusion(Ok(None), &certain, &SANDBOX_MAYBE),
            Unstamped::Unprotected
        );
        assert_eq!(
            unstamped_exclusion(Err(()), &certain, &SANDBOX_MAYBE),
            Unstamped::Unverifiable
        );
    }

    #[test]
    fn kind_names_round_trip() {
        for k in [
            Kind::Container,
            Kind::Granted,
            Kind::File,
            Kind::Denied,
            Kind::Ungranted,
            Kind::Skipped,
        ] {
            assert_eq!(Kind::parse(k.as_str()), Some(k));
        }
        assert_eq!(Kind::parse("x"), None);
    }
}
