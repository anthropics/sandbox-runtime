//! `srt-win` CLI dispatch — exposed as a library entry point so an
//! embedding multicall binary can link the crate and route to it when
//! `argv[1] == `[`SRT_WIN_DISPATCH_ARG1`] instead of shipping a
//! separate `srt-win.exe`. Dispatch keys on `argv[1]`, not `argv[0]`:
//! Windows cannot preserve a spoofed `argv[0]` across
//! `CreateProcessWithLogonW` / `ShellExecuteExW(runas)`, so a
//! Unix-style multicall-on-argv0 would lose the route on every
//! internal re-spawn. The standalone binary (`main.rs`) is a
//! one-line shim over [`run_from_args`].
//!
//! Subcommands:
//!   install | uninstall                — provision/remove the
//!                                         `srt-sandbox` user account +
//!                                         user-SID-keyed WFP filters
//!                                         (one UAC prompt)
//!   status                             — combined `{user, wfp}` JSON
//!   user   status | read-cred | trust-ca — inspect the sandbox user
//!   wfp    status | verify | uninstall — inspect/probe/remove WFP filters
//!   acl    stamp | grant | restore | revoke | recover
//!                                       — additive sandbox-user ACEs
//!   exec   -- <target> [args...]       — spawn under the two-hop
//!                                         sandbox-user lockdown
//!
//! `status` subcommands write one line of JSON to stdout and exit 0.
//! Mutating subcommands require elevation and write human-readable
//! progress to stderr. `exec` propagates the child's exit code.
//!
//! Several arms call `std::process::exit` directly (exec's child
//! propagation, install's structured exit codes, self-elevate's
//! cancel path). [`run_from_args`] therefore returns the exit code
//! only for the fall-through (`Ok` → 0, `Err` → 1) cases; an
//! embedder must be prepared for the process to exit from inside the
//! dispatch.

// Re-alias so paths from this file's prior life as the [[bin]]
// crate root (`srt_win::…`) keep resolving now that it's a lib
// module.
use crate as srt_win;

use clap::{Parser, Subcommand};
use std::ffi::OsString;

/// `argv[1]` sentinel an embedding multicall binary's dispatcher
/// matches against to route into [`run_from_args`]. The two internal
/// re-spawn sites (`logon::spawn_runner`, [`maybe_self_elevate`])
/// always emit it, so the dispatch survives the
/// `CreateProcessWithLogonW` runner hop and the
/// `ShellExecuteExW(runas)` elevation hop — neither of which can
/// preserve a spoofed `argv[0]` on Windows. [`run_from_args`] strips
/// it before clap, so the standalone binary accepts it harmlessly.
pub const SRT_WIN_DISPATCH_ARG1: &str = "--srt-win";

/// Library entry point for the `srt-win` CLI. Parses `args` (with
/// `args[0]` as the binary name, same convention as
/// `std::env::args_os()`), runs the matching subcommand, and returns
/// the process exit code for the fall-through paths. See the module
/// doc for the arms that `process::exit` directly.
///
/// `--help` / `--version` / parse errors print to the appropriate
/// stream and `process::exit` (clap's `parse_from` behaviour).
///
/// **Multicall dispatch.** An embedder's `main()` checks
/// `argv[1] == SRT_WIN_DISPATCH_ARG1` and on match calls
/// `run_from_args(argv)` with the FULL argv (sentinel included);
/// `run_from_args` strips the sentinel before clap. The sentinel
/// survives every internal re-spawn — both `logon::spawn_runner`
/// (the runtime `exec` / `wfp verify` / `user trust-ca` hop) and
/// [`maybe_self_elevate`] (the `install` / `uninstall` /
/// `wfp uninstall` UAC hop) emit it as the first parameter, and the
/// child binary is always `current_exe()` — so the embedder's
/// dispatcher routes back into `srt-win` regardless of what
/// `argv[0]` the OS sets.
pub fn run_from_args<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let mut args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    if args.get(1).map(OsString::as_os_str) == Some(SRT_WIN_DISPATCH_ARG1.as_ref()) {
        args.remove(1);
    }
    match run(Cli::parse_from(&args), &args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("srt-win: error: {e:#}");
            1
        }
    }
}

#[derive(Parser)]
#[command(name = "srt-win", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Provision the dedicated `srt-sandbox` user account + the
    /// user-SID-keyed WFP filter set in one elevated step.
    ///
    /// Self-elevates via UAC if not already running as admin (one
    /// prompt; the elevated child does the work and the parent
    /// relays its exit code). Idempotent — re-running rotates the
    /// sandbox user's password and refreshes the WFP filters.
    ///
    /// Exit codes:
    ///   0  — installed (or already installed with the same
    ///        port-range; no changes)
    ///   10 — UAC prompt cancelled by the user
    ///   12 — WFP filter install failed
    ///   13 — already installed under this sublayer with a
    ///        DIFFERENT port-range or sandbox-user name; pass
    ///        `--force` to replace
    ///   14 — sandbox user provisioning failed
    ///   1  — other error (parse, elevation check, etc.)
    Install {
        /// Sublayer GUID (default: compile-time constant).
        #[arg(long)]
        sublayer_guid: Option<String>,
        /// Loopback port range (`LOW-HIGH`, default 60080-60089).
        #[arg(long, value_name = "LOW-HIGH")]
        proxy_port_range: Option<String>,
        /// Name for the sandbox user account. Default:
        /// `srt-sandbox`. srt-win only manages an account it
        /// created — a name that already resolves to a principal
        /// srt-win didn't provision is refused (exit 14).
        #[arg(long)]
        sandbox_user: Option<String>,
        /// Replace an existing install whose port-range or
        /// sandbox-user name differs (otherwise exits 13).
        #[arg(long)]
        force: bool,
    },
    /// Remove the srt-win WFP filters under the sublayer and the
    /// `srt-sandbox` account, its credential file, and the setup
    /// marker (unless `--keep-user`). Self-elevates via UAC if not
    /// already admin. Best-effort also removes the legacy
    /// `sandbox-runtime-net` discriminator group if a prior install
    /// left it behind.
    Uninstall {
        #[arg(long)]
        sublayer_guid: Option<String>,
        /// Keep the `srt-sandbox` account, its credential file,
        /// and the setup marker. Without this flag they are all
        /// removed (the credential is useless without the
        /// account and vice versa, so they're treated as one
        /// unit).
        #[arg(long)]
        keep_user: bool,
    },
    /// Print `{user: <user-status>, wfp: <wfp-status>}` as one line
    /// of JSON — the same objects `user status` and `wfp status`
    /// emit, in a single spawn. The host's readiness check calls
    /// this instead of two separate subprocesses. Exit 0.
    Status {
        #[arg(long)]
        sublayer_guid: Option<String>,
    },
    /// Inspect the sandbox user account that `srt-win install`
    /// provisions (and that the sandboxed child runs as).
    User {
        #[command(subcommand)]
        sub: UserCmd,
    },
    /// Inspect/remove the persistent WFP filters.
    Wfp {
        #[command(subcommand)]
        sub: WfpCmd,
    },
    /// Add/remove explicit ACEs for the sandbox user on file paths
    /// so the sandboxed child can (`grant`) or cannot (`stamp`)
    /// read/write them. State is persisted in
    /// `%LOCALAPPDATA%\sandbox-runtime\state.db` so concurrent
    /// brokers refcount and a crash mid-session is recoverable by
    /// the next `acl` op.
    Acl {
        #[command(subcommand)]
        sub: AclCmd,
    },
    /// Spawn a process inside the sandbox.
    ///
    /// Two-hop launch: this process (the broker, real user) reads
    /// the credential then `CreateProcessWithLogonW`s `srt-win
    /// runner` under the `srt-sandbox` account. The runner builds a
    /// restricted token (LUA, Admins flipped deny-only, Medium IL,
    /// all privs stripped except SeChangeNotify), self-protects,
    /// assigns the child to a kill-on-close job with full UI
    /// lockdown, places it on a non-interactive desktop, applies
    /// process-mitigation policies + an explicit handle whitelist,
    /// and waits for it to exit. Propagates the child's exit code.
    ///
    /// The child inherits the runner's environment (= the sandbox
    /// user's `LOGON_WITH_PROFILE` defaults) with the `--env` overlay
    /// applied — proxy configuration is single-sourced by the caller
    /// (TS `generateProxyEnvVars`) and passed here via `--env`.
    ///
    /// Requires `srt-win install` to have provisioned the user;
    /// otherwise exits **15**.
    Exec {
        /// Per-exec read-deny: add an additive `(D;OICI;FA;;;<sb>)`
        /// ACE for the sandbox user on `<PATH>` (and a parent
        /// `FILE_DELETE_CHILD` DENY) for the lifetime of this exec
        /// — under THIS process's PID as holder, released after the
        /// child exits. Repeatable. Same chokepoint as `acl stamp`;
        /// fails the exec if any path cannot be stamped (per-exec
        /// is "deny THIS one command", so a missing path is a
        /// caller error, not a skip).
        #[arg(long = "deny-read")]
        deny_read: Vec<String>,
        /// Per-exec write-deny — see `--deny-read`.
        #[arg(long = "deny-write")]
        deny_write: Vec<String>,
        /// `KEY=VALUE` pair overlaid on the sandbox-user runner's
        /// profile environment when building the child's env block.
        /// Repeatable. The broker forwards exactly these — it does
        /// NOT enumerate its own environment for proxy/CA vars; the
        /// caller (whose `generateProxyEnvVars` is the single
        /// source) passes them here explicitly.
        #[arg(long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Suppress informational stderr (progress lines,
        /// per-exec-deny summary, seclogon-job note). Actual
        /// errors still print. The host sets this by default so
        /// the sandboxed child's stderr is not polluted with
        /// broker chatter.
        #[arg(long)]
        quiet: bool,
        /// Target executable followed by its arguments. Use `--`
        /// to terminate srt-win's own option parsing.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            required = true,
            num_args = 1..,
        )]
        target: Vec<String>,
    },
    /// Inside-the-logon half of `exec`. Reads a length-prefixed
    /// `RunnerCmd` from stdin and dispatches as the current user —
    /// which, when launched by the broker via
    /// `CreateProcessWithLogonW`, is `srt-sandbox`. Not intended to
    /// be invoked directly.
    #[command(hide = true)]
    Runner,
}

#[derive(Subcommand)]
enum UserCmd {
    /// Print the sandbox user's provisioning state as JSON:
    /// `{user: {exists, sid?, group_exists, group_sid?,
    /// in_builtin_users, in_sandbox_group, hidden_from_logon},
    /// cred_present, marker_version?, marker_user_sid?,
    /// ca_cert_thumb?, ca_cert_pem?}`.
    Status,
    /// Print the sandbox user's decrypted password (and only the
    /// password) to stdout. The broker uses this for
    /// `CreateProcessWithLogonW`. Fails when run as the sandbox
    /// user itself — the state-DB directory carries an explicit
    /// DENY for `sandbox-runtime-users`, and machine-scope DPAPI
    /// is **not** a confidentiality boundary without that DENY.
    ReadCred,
    /// Install (or replace) the MITM CA in the **sandbox user's**
    /// `CurrentUser\Root` and record it in the state DB. The cert
    /// has a separate lifecycle from `srt-win install` — install
    /// provisions the account/filters and never touches the CA;
    /// this is the only command that sets it. Does NOT require
    /// elevation. Persistent until `srt-win uninstall`.
    TrustCa {
        /// PEM- or DER-encoded CA certificate file.
        #[arg(value_name = "PATH")]
        path: String,
    },
}

#[derive(Subcommand)]
enum AclCmd {
    /// Read `{denyRead:[…], denyWrite:[…]}` from stdin and add an
    /// additive `(D;OICI;mask;;;<sid>)` ACE for the sandbox user on
    /// each target plus a `(D;OICI;FILE_DELETE_CHILD;;;<sid>)` on
    /// the parent — NO PROTECTED rewrite, no SD snapshot.
    /// Refcounted per holder; `acl restore` removes the ACE when
    /// the last holder releases. Globs are rejected; directory
    /// targets get an `(OI)(CI)` inheriting ACE covering the
    /// subtree.
    Stamp {
        /// PID of the LONG-LIVED process that owns these ACEs —
        /// normally the Node host (sandbox-runtime), which calls
        /// `acl stamp` at initialize() and `acl restore` at reset()
        /// from a SEPARATE short-lived `srt-win` process. The ACE
        /// persists until this PID exits or restores. Required:
        /// the `srt-win acl` process exits immediately, so keying
        /// on its own PID would orphan the ACE instantly.
        #[arg(long)]
        holder_pid: u32,
        /// SID to deny — the dedicated sandbox user
        /// (`srt-win user status` → `marker_user_sid`).
        #[arg(long)]
        sandbox_user_sid: String,
    },
    /// Read `{read:[…], write:[…]}` from stdin and add an
    /// inheritable `(OI)(CI)` ALLOW ACE for `--sandbox-user-sid` on
    /// each path (`FILE_GENERIC_READ|EXECUTE` for `read`,
    /// `MODIFY_NO_FDC` for `write`). Additive — the path's
    /// existing DACL and inheritance are untouched. Refcounted per
    /// holder; `acl revoke` removes the ACE when the last holder
    /// releases.
    Grant {
        /// Holder PID (see `acl stamp`).
        #[arg(long)]
        holder_pid: u32,
        /// SID to grant — the dedicated sandbox user
        /// (`srt-win user status` → `marker_user_sid`).
        #[arg(long)]
        sandbox_user_sid: String,
    },
    /// Drop the holder's claim on every granted path; remove the
    /// sandbox-user ACE on any path whose refcount falls to zero.
    Revoke {
        #[arg(long)]
        holder_pid: u32,
        #[arg(long)]
        sandbox_user_sid: String,
        #[arg(long)]
        json: bool,
    },
    /// Drop the holder's claim on every DENY ACE it stamped;
    /// remove the sandbox-user ACE on any path whose refcount falls
    /// to zero.
    Restore {
        /// Holder PID whose stamps to release (see `acl stamp`).
        /// Must match the value passed at stamp time.
        #[arg(long)]
        holder_pid: u32,
        /// The sandbox user's SID — must match `acl stamp`.
        #[arg(long)]
        sandbox_user_sid: String,
        /// Emit a single JSON array of per-path
        /// `{path, status}` objects on stdout (exit 0 always); the
        /// host raises any error AFTER reading the array. Without
        /// this flag, the existing human-readable summary goes to
        /// stderr.
        #[arg(long)]
        json: bool,
    },
    /// Run crash-recovery only: prune dead holders, drop any
    /// orphaned sandbox-user ACEs.
    Recover {
        #[arg(long)]
        force: bool,
        /// Emit `{"deadBrokers": N, "acesRevoked": N}` on stdout.
        /// (Not the per-path array — recover sweeps by trustee SID
        /// and does not enumerate paths.)
        #[arg(long)]
        json: bool,
    },
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct AclStampInput {
    #[serde(default)]
    deny_read: Vec<String>,
    #[serde(default)]
    deny_write: Vec<String>,
}

#[derive(serde::Deserialize, Default)]
struct AclGrantInput {
    #[serde(default)]
    read: Vec<String>,
    #[serde(default)]
    write: Vec<String>,
}

/// One per-path entry of `acl revoke --json` / `acl restore
/// --json`.
#[derive(serde::Serialize)]
struct AceReleaseEntry {
    path: String,
    status: &'static str,
}

/// Output of [`canonicalize_ace_targets`].
struct AceTargets {
    /// `(canonical_path, ace)` to hand to `apply_aces`.
    targets: Vec<(String, srt_win::acl::SbAce)>,
    /// Inputs that could not be canonicalized (soft-skip → exit 2).
    bad_inputs: Vec<(String, String)>,
}

/// Canonicalize `(paths, ace)` pairs for `acl grant`/`acl stamp`
/// (additive sandbox-user ACE). Per-path canonicalize failure is
/// soft (skipped, exit 2); a glob is a HARD error. Directory
/// targets are accepted (the inheritable ACE covers the subtree;
/// stamping a root is allowed because the additive ACE on `C:\` is
/// wide but not destructive — the user can remove it).
///
/// A `Deny` target that does not exist is materialized via
/// [`create_placeholder_chain`] (trailing `\`/`/` ⇒ directory
/// leaf). The leaf gets the input's full deny mask; placeholder
/// INTERMEDIATES — this call's and, via
/// [`placeholder_ancestors_of`], any earlier holder's — get
/// [`SbAce::DenyDelete`], so every holder holds the FULL chain and
/// releasing any one holder cannot strip an intermediate another
/// holder still depends on.
///
/// A `Deny` target the broker cannot create (`PermissionDenied` —
/// e.g. under `Program Files` non-elevated) or that names a UNC
/// path is soft-DROPPED, not `bad_inputs`: the sandbox user
/// cannot create there either. Approximation — an asymmetric ACL
/// that grants the sandbox account create where the real user is
/// denied is possible but rare. A `Grant` on a missing path stays
/// a soft-skip (nothing to grant on).
///
/// Runs under `with_init_lock` so placeholder creation, its DB
/// record, and the ancestor-discovery query are all serialized
/// with `apply_aces`.
///
/// [`create_placeholder_chain`]: srt_win::path_id::create_placeholder_chain
/// [`placeholder_ancestors_of`]: srt_win::state_db::Locked::placeholder_ancestors_of
/// [`SbAce::DenyDelete`]: srt_win::acl::SbAce::DenyDelete
fn canonicalize_ace_targets(
    db: &srt_win::state_db::Locked,
    label: &str,
    inputs: &[(&[String], srt_win::acl::SbAce)],
) -> anyhow::Result<AceTargets> {
    use anyhow::anyhow;
    use srt_win::acl::SbAce;
    use srt_win::path_id::{
        CanonError, canonicalize_path, create_placeholder_chain, is_unc_path, strip_extended_prefix,
    };
    use std::io::ErrorKind;
    let mut targets = Vec::new();
    let mut bad_inputs = Vec::new();
    // Deepest-first so overlapping non-existent denies (`['y',
    // 'y\secret']`) materialize as `y/` DIR + `secret` FILE, not
    // `y` FILE (which would then fail `y\secret` with "ancestor is
    // a FILE"). Strip any `\\?\` prefix and normalize `/`→`\`
    // before counting so `\\?\C:\y` and `C:/y` depth-compare
    // correctly, and trim a trailing separator so it doesn't skew
    // the sort.
    let mut flat: Vec<(&String, SbAce)> = inputs
        .iter()
        .flat_map(|(list, ace)| list.iter().map(move |p| (p, *ace)))
        .collect();
    flat.sort_by_cached_key(|(p, _)| {
        std::cmp::Reverse(
            strip_extended_prefix(p)
                .trim_end_matches(['\\', '/'])
                .bytes()
                .filter(|b| *b == b'\\' || *b == b'/')
                .count(),
        )
    });
    for (p, ace) in flat {
        let canon = match canonicalize_path(p) {
            Ok((c, _is_dir)) => c,
            Err(CanonError::Glob) => {
                return Err(anyhow!(
                    "Windows fs {label} requires explicit file \
                     or directory paths; got glob '{p}'."
                ));
            }
            Err(CanonError::NotFound(_)) if matches!(ace, SbAce::Deny(_)) => {
                if is_unc_path(p) {
                    eprintln!(
                        "srt-win: deny target '{p}' is a UNC path \
                         and does not exist; dropping — the local \
                         ACL model does not cover SMB shares"
                    );
                    continue;
                }
                let leaf_is_dir = p.ends_with(['\\', '/']);
                match create_placeholder_chain(p, leaf_is_dir, |c| db.record_placeholder(c)) {
                    Ok((leaf_canon, chain)) => {
                        if !chain.is_empty() {
                            eprintln!(
                                "srt-win: deny target '{p}' does \
                                 not exist; created {} placeholder \
                                 component(s) and stamping the chain",
                                chain.len(),
                            );
                        }
                        leaf_canon
                    }
                    Err(e) => {
                        // Soft-drop per the doc above (NotFound =
                        // unwind removed a half-built chain); any
                        // other kind fails loudly via bad_inputs.
                        let io_kind = e
                            .root_cause()
                            .downcast_ref::<std::io::Error>()
                            .map(|io| io.kind());
                        if matches!(
                            io_kind,
                            Some(ErrorKind::PermissionDenied | ErrorKind::NotFound)
                        ) {
                            eprintln!(
                                "srt-win: cannot create placeholder \
                                 for deny target '{p}' ({e:#}); \
                                 dropping — the sandbox cannot \
                                 create there either"
                            );
                        } else {
                            bad_inputs.push((p.clone(), format!("{e:#}")));
                        }
                        continue;
                    }
                }
            }
            Err(CanonError::NotFound(e) | CanonError::Other(e)) => {
                bad_inputs.push((p.clone(), format!("{e:#}")));
                continue;
            }
        };
        targets.push((canon.clone(), ace));
        // Full-chain hold (see doc). Duplicates across inputs are
        // harmless — `apply_aces` is idempotent per
        // `(path, kind, holder)`.
        if matches!(ace, SbAce::Deny(_)) {
            for anc in db.placeholder_ancestors_of(&canon)? {
                targets.push((anc, SbAce::DenyDelete));
            }
        }
    }
    Ok(AceTargets {
        targets,
        bad_inputs,
    })
}

/// Build the `user status` JSON object (sandbox-user provisioning
/// state + credential/marker/CA rows from `state.db`). Shared by
/// `user status` and the top-level combined `status`.
fn user_status_json() -> anyhow::Result<serde_json::Value> {
    use serde_json::json;
    use srt_win::{install, user};
    let setup = install::read_setup().ok().flatten();
    let name = setup
        .as_ref()
        .map(|s| s.sandbox_user.as_str())
        .unwrap_or(user::SANDBOX_USER);
    let st = user::status(name)?;
    let ca = install::read_ca_cert()?;
    let ca = ca.as_ref();
    Ok(json!({
        "user": st,
        "cred_present": setup.is_some(),
        "marker_version": setup.as_ref().map(|s| s.marker_version),
        "marker_user_sid": setup.as_ref()
            .map(|s| s.sandbox_user_sid.as_str()),
        // The calling (real) user's SID — surfaced for diagnostics.
        "real_user_sid": srt_win::sid::current_user_sid()?,
        "ca_cert_thumb": ca.map(|c| c.thumb()).transpose()?,
        "ca_cert_pem": ca.map(|c| c.to_pem()).transpose()?,
    }))
}

/// Read `path` and decode it as a single DER-encoded X.509
/// certificate (PEM, base64, or raw DER input — see
/// [`srt_win::cert_store::CertDer::from_pem_or_der`]). Used by
/// `user trust-ca`.
fn read_ca_der(path: &str) -> anyhow::Result<srt_win::cert_store::CertDer> {
    use anyhow::Context;
    srt_win::cert_store::CertDer::from_pem_or_der(
        &std::fs::read(path).with_context(|| format!("read CA cert '{path}'"))?,
    )
    .with_context(|| format!("decode CA cert '{path}'"))
}

/// Drop-guarded per-exec restore. Constructed immediately after a
/// successful per-exec deny-ACE so EVERY exit path between stamp
/// and `process::exit` — `?`, panic, or normal return — runs the
/// matching release for `holder`. A leaked ACE is fail-closed and
/// crash-recovery reaps it once `holder` is observed dead by the
/// next `with_init_lock`, so `failed > 0` is logged but never
/// changes the child's exit code.
struct PerExecRestore {
    holder: srt_win::state_db::HolderPid,
    sandbox_sid: String,
    quiet: bool,
}

impl Drop for PerExecRestore {
    fn drop(&mut self) {
        use srt_win::state_db;
        let (failed, err) = match state_db::with_init_lock(self.holder, false, |db| {
            db.release_aces(&self.sandbox_sid, state_db::KIND_DENY)
        }) {
            Ok(((_, failed), _)) => (failed, None),
            Err(e) => (0, Some(e)),
        };
        // `failed > 0` is fail-closed (leftover ACEs are reaped by
        // the next `acl` op) so it's informational; `err` is a real
        // state-DB failure and prints regardless of `--quiet`.
        if failed > 0 && !self.quiet {
            eprintln!(
                "srt-win: WARNING: per-exec restore left {failed} \
                 path(s) stamped (fail-closed) — see prior \
                 per-path warnings; `acl recover` will clear \
                 them once pid {} is dead",
                self.holder.0,
            );
        }
        if let Some(e) = err {
            eprintln!(
                "srt-win: WARNING: per-exec restore failed \
                 ({e:#}); leftover stamps stay fail-closed and \
                 are reaped by the next `acl` op once pid {} is \
                 dead",
                self.holder.0,
            );
        }
    }
}

#[derive(Subcommand)]
enum WfpCmd {
    /// Print WFP fence state as JSON: `{state, filters,
    /// port_range?, user_sid?, hint?}`. BFE's
    /// `FwpmFilterCreateEnumHandle0` is admin-gated, so a
    /// non-elevated caller gets `{state:"cannot-read", hint:…}`
    /// (exit 0). The non-elevated readiness check is `wfp verify`.
    Status {
        #[arg(long)]
        sublayer_guid: Option<String>,
    },
    /// Behavioral egress-block probe — the non-elevated readiness
    /// check for the WFP fence. Spawns the runner as `srt-sandbox`
    /// (via `CreateProcessWithLogonW`) which attempts a direct TCP
    /// connect to `target`.
    ///
    /// Prints `{"egress_probe":"blocked"|"connected"|"unreachable",
    /// "target":…}` and exits **0** (blocked = fence active),
    /// **3** (connected = fence MISSING), **2** (unreachable =
    /// timeout/no-route; treat as failure), or **15** when the
    /// sandbox user is not provisioned. Any other code (including
    /// 1, the runner's own anyhow `Err` path) maps to
    /// `egress_probe:"error"`. Does not require elevation. This
    /// is the non-elevated readiness check the host's
    /// `initialize()` runs; `wfp status` is the elevated
    /// ground-truth enum.
    Verify {
        /// Probe target (`host:port`). The host binds a local
        /// listener on an ephemeral loopback port OUTSIDE the WFP
        /// loopback-permit range and passes it here, so the
        /// fence-inactive case is deterministic without depending
        /// on any external host.
        #[arg(long)]
        target: String,
    },
    /// Remove every srt-win-tagged WFP filter under the sublayer.
    /// Self-elevates via UAC if not already admin.
    Uninstall {
        #[arg(long)]
        sublayer_guid: Option<String>,
    },
}

fn run(cli: Cli, args: &[OsString]) -> anyhow::Result<()> {
    use anyhow::{Context, anyhow};
    use serde_json::json;
    use srt_win::wfp;

    let resolve_sublayer = |s: &Option<String>| -> anyhow::Result<windows::core::GUID> {
        match s {
            Some(g) => wfp::parse_guid(g),
            None => Ok(wfp::DEFAULT_SUBLAYER_GUID),
        }
    };

    match cli.cmd {
        // ─── install / uninstall ───────────────────────────────────
        Cmd::Install {
            sublayer_guid,
            proxy_port_range,
            sandbox_user,
            force,
        } => {
            use srt_win::{install, user};
            if let Some(code) = maybe_self_elevate(args)? {
                std::process::exit(code);
            }
            let sl = resolve_sublayer(&sublayer_guid)?;
            let range = match &proxy_port_range {
                Some(s) => wfp::parse_port_range(s)
                    .with_context(|| format!("invalid --proxy-port-range '{s}'"))?,
                None => wfp::DEFAULT_PROXY_PORT_RANGE,
            };
            let name = sandbox_user.as_deref().unwrap_or(user::SANDBOX_USER);
            // Idempotency / conflict pre-check. With a DIFFERENT
            // port-range or sandbox-user name and no --force, refuse
            // (exit 13) so an unintended config drift surfaces
            // instead of silently overwriting. With the SAME config,
            // only return early when the install is COMPLETE — i.e.
            // the sandbox user is provisioned and the marker is
            // current. A partial install falls through and the
            // (idempotent) steps below complete it. A pre-existing
            // install whose tags lack a port_range (legacy) is
            // treated as "different" and requires --force.
            let existing = install::read_setup().ok().flatten();
            let name_changed = existing.as_ref().is_some_and(|s| s.sandbox_user != name);
            if !force
                && let Ok(st) = wfp::filter_status(&sl)
                && st.state == "installed"
            {
                let want = [range.0, range.1];
                if st.port_range != Some(want) || name_changed {
                    let have_range = st
                        .port_range
                        .map(|[l, h]| format!("{l}-{h}"))
                        .unwrap_or_else(|| "<unknown>".into());
                    let have_name = existing
                        .as_ref()
                        .map(|s| s.sandbox_user.as_str())
                        .unwrap_or("<none>");
                    eprintln!(
                        "srt-win: error: already installed under \
                         sublayer {sl:?} with port_range={have_range}, \
                         sandbox_user='{have_name}'; requested \
                         port_range={}-{}, sandbox_user='{name}'. \
                         Pass --force to replace, or run `srt-win \
                         uninstall` first.",
                        range.0, range.1,
                    );
                    std::process::exit(13);
                }
                // Same config — early-out only if COMPLETE.
                let us = user::status(name)?;
                let mv = existing.as_ref().map(|s| s.marker_version);
                if us.exists && us.in_sandbox_group && mv == Some(install::SETUP_VERSION) {
                    eprintln!(
                        "srt-win: already installed (sublayer={sl:?}, \
                         port_range={}-{}, sandbox_user='{name}', \
                         filters={}); no changes",
                        range.0, range.1, st.filters,
                    );
                    return Ok(());
                }
                eprintln!(
                    "srt-win: partial install detected \
                     (user_provisioned={}, marker_version={:?}) — \
                     completing",
                    us.exists, mv,
                );
                // Fall through; the steps are idempotent.
            }
            // With --force and a changed name, do NOT delete the
            // prior account — it may be enterprise-managed. The old
            // WFP filters are replaced (they key on the new SID);
            // write_setup_info clears the old row. The account
            // itself is left for the operator.
            if force && name_changed {
                let old = &existing.as_ref().unwrap().sandbox_user;
                eprintln!(
                    "srt-win: WARNING: replacing install with \
                     sandbox_user='{old}' → '{name}'. The prior \
                     '{old}' account is NOT deleted (may be \
                     enterprise-managed) — remove it manually if \
                     unused.",
                );
            }
            // Sandbox user account + credential file + setup marker
            // + user-SID-keyed WFP filters. `we_own_it` gates
            // provision()'s create-or-rotate: the DEFAULT name is
            // ours by definition (so a stale/absent marker — e.g.
            // schema-upgrade re-install — still rotates); an
            // EXPLICIT `--sandbox-user` is create-only unless the
            // marker records that name from a prior install.
            let we_own_it =
                sandbox_user.is_none() || existing.as_ref().is_some_and(|s| s.sandbox_user == name);
            let pu = match (|| -> anyhow::Result<srt_win::user::ProvisionedUser> {
                let pu = user::provision(name, we_own_it).context("provision sandbox user")?;
                install::write_setup(&pu)
                    .context("write sandbox credential + setup marker to state DB")?;
                Ok(pu)
            })() {
                Ok(pu) => pu,
                Err(e) => {
                    eprintln!("srt-win: error: sandbox user step: {e:#}");
                    std::process::exit(14);
                }
            };
            if let Err(e) = wfp::install_filters(&sl, &pu.sid, range) {
                eprintln!("srt-win: error: WFP install: {e:#}");
                std::process::exit(12);
            }
            // Best-effort migration: a pre-v2-e install left the
            // legacy `sandbox-runtime-net` discriminator group.
            // Remove it now (idempotent on NERR_GroupNotFound).
            // Uninstall does the same; doing it here means the
            // upgrade path (re-run install) cleans up without a
            // separate uninstall step.
            let _ = srt_win::sam::delete_local_group("sandbox-runtime-net");
            eprintln!(
                "srt-win: installed (sublayer={sl:?}, \
                 proxy_port_range={}-{}, filters={})",
                range.0,
                range.1,
                wfp::FILTER_COUNT,
            );
            eprintln!(
                "srt-win: sandbox user '{}' provisioned (sid={}, \
                 group={} sid={})",
                pu.username,
                pu.sid,
                srt_win::user::SANDBOX_GROUP,
                pu.group_sid,
            );
        }
        Cmd::Uninstall {
            sublayer_guid,
            keep_user,
        } => {
            if let Some(code) = maybe_self_elevate(args)? {
                std::process::exit(code);
            }
            let sl = resolve_sublayer(&sublayer_guid)?;
            let n = wfp::uninstall_filters(&sl)?;
            let user_note = if keep_user {
                "Sandbox user kept (--keep-user)."
            } else {
                use srt_win::{install, user};
                // Read the recorded name (may not be the default),
                // then deprovision BEFORE clear_setup so a failed
                // NetUserDel is retryable with the recorded name
                // still intact. No marker (partial install that
                // bailed before write_setup, or a stale/corrupt
                // state DB) → fall back to the default name so
                // SANDBOX_GROUP and any default-named account are
                // still cleaned up; deprovision is idempotent on
                // absent state.
                let name = install::read_setup()
                    .ok()
                    .flatten()
                    .map(|s| s.sandbox_user)
                    .unwrap_or_else(|| user::SANDBOX_USER.into());
                user::deprovision(&name).context("deprovision sandbox user")?;
                install::clear_setup().context("clear credential + setup marker")?;
                "Sandbox user, credential, and setup marker removed."
            };
            // Migration: best-effort remove the legacy
            // discriminator group if a prior install left it.
            // Idempotent on already-absent.
            let _ = srt_win::sam::delete_local_group("sandbox-runtime-net");
            eprintln!("srt-win: uninstalled ({n} filter(s) removed). {user_note}");
        }

        // ─── status (combined) ─────────────────────────────────────
        Cmd::Status { sublayer_guid } => {
            let sl = resolve_sublayer(&sublayer_guid)?;
            println!(
                "{}",
                json!({
                    "user": user_status_json()?,
                    "wfp": wfp::filter_status(&sl)?,
                })
            );
        }

        // ─── user ──────────────────────────────────────────────────
        Cmd::User {
            sub: UserCmd::Status,
        } => {
            println!("{}", user_status_json()?);
        }
        Cmd::User {
            sub: UserCmd::ReadCred,
        } => {
            let cred = srt_win::install::read_cred()?;
            // Password only, no trailing whitespace, so a caller
            // can capture stdout verbatim.
            print!("{}", cred.pw);
        }
        Cmd::User {
            sub: UserCmd::TrustCa { path },
        } => {
            use srt_win::install;
            let der = read_ca_der(&path)?;
            let cred = install::read_cred()?;
            let sb_sid = install::read_setup()?
                .ok_or_else(|| anyhow!("sandbox user not provisioned"))?
                .sandbox_user_sid;
            install::trust_ca(&der, &cred, &sb_sid)?;
            eprintln!(
                "srt-win: CA installed into sandbox-user Root \
                 (thumb={})",
                der.thumb()?,
            );
        }

        // ─── wfp ───────────────────────────────────────────────────
        Cmd::Wfp {
            sub: WfpCmd::Status { sublayer_guid },
        } => {
            let sl = resolve_sublayer(&sublayer_guid)?;
            let st = wfp::filter_status(&sl)?;
            println!("{}", serde_json::to_string(&st)?);
        }
        Cmd::Wfp {
            sub: WfpCmd::Verify { target },
        } => {
            use srt_win::{install, logon, runner};
            // The WFP BLOCK fires at ALE_AUTH_CONNECT before any
            // packet leaves, so an active fence gives WSAEACCES
            // (~0ms, exit 0); a MISSING fence lets the connect
            // succeed (exit 3). The host passes a local loopback
            // listener bound outside the WFP permit range so
            // fence-missing is distinguishable from fence-active
            // without depending on any external host.
            let r = install::read_cred().and_then(|c| {
                let s = install::read_setup()?
                    .ok_or_else(|| anyhow!("sandbox user not provisioned"))?;
                Ok((s.sandbox_user_sid, c))
            });
            let (sb_sid, cred) = match r {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("srt-win: error: wfp verify: {e:#}");
                    std::process::exit(15);
                }
            };
            let code = logon::spawn_runner(
                &cred.user,
                &cred.pw,
                &sb_sid,
                None,
                &runner::RunnerCmd::ProbeEgress {
                    target: target.clone(),
                },
                false,
            )
            .context("spawn runner for egress probe")?;
            let probe = match code {
                0 => "blocked",
                3 => "connected",
                2 => "unreachable",
                // 1 is the runner's own anyhow `Err` path
                // (`main()` → `eprintln!` + `exit(1)`); anything
                // else is an unmapped runner state. Neither is a
                // valid probe outcome.
                _ => "error",
            };
            println!(
                "{}",
                json!({
                    "egress_probe": probe,
                    "target": target,
                    "runner_exit": code,
                })
            );
            // `process::exit`'s rt::cleanup flushes stdout, but be
            // explicit — this is the only arm that prints to stdout
            // and then `process::exit`s instead of returning Ok(()).
            let _ = std::io::Write::flush(&mut std::io::stdout());
            std::process::exit(code as i32);
        }
        Cmd::Wfp {
            sub: WfpCmd::Uninstall { sublayer_guid },
        } => {
            if let Some(code) = maybe_self_elevate(args)? {
                std::process::exit(code);
            }
            let sl = resolve_sublayer(&sublayer_guid)?;
            let n = wfp::uninstall_filters(&sl)?;
            eprintln!("srt-win: removed {n} WFP filter(s)");
        }

        // ─── acl ───────────────────────────────────────────────────
        Cmd::Acl {
            sub:
                AclCmd::Stamp {
                    holder_pid,
                    sandbox_user_sid,
                },
        } => {
            // Deny is an additive DENY ACE for the sandbox user
            // (plus parent-FDC DENY) — same lifecycle as
            // `acl grant`, no PROTECTED rewrite.
            use srt_win::{acl, state_db};
            let holder = state_db::HolderPid(holder_pid);
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).context("read stdin")?;
            let input: AclStampInput = serde_json::from_str(&buf)
                .context("parse stdin JSON {denyRead:[…], denyWrite:[…]}")?;
            let ((at, witnesses, failed), report) =
                state_db::with_init_lock(holder, false, |db| {
                    let at = canonicalize_ace_targets(
                        db,
                        "deny",
                        &[
                            (&input.deny_read, acl::SbAce::Deny(acl::DenyMask::ReadDeny)),
                            (
                                &input.deny_write,
                                acl::SbAce::Deny(acl::DenyMask::WriteDeny),
                            ),
                        ],
                    )?;
                    for (p, e) in &at.bad_inputs {
                        eprintln!("srt-win: skipped: '{p}': {e}");
                    }
                    let (w, f) = db.apply_aces(&sandbox_user_sid, &at.targets)?;
                    Ok((at, w, f))
                })?;
            let AceTargets {
                targets,
                bad_inputs,
            } = at;
            let fresh = witnesses.iter().filter(|w| !w.already).count();
            eprintln!(
                "srt-win: acl stamp (deny-ace) — {} target(s) → {} \
                 ACE(s) ({} fresh{}{}); recovery pruned {} dead \
                 broker(s), revoked {} orphan ACE(s)",
                targets.len(),
                witnesses.len(),
                fresh,
                if !bad_inputs.is_empty() {
                    format!(", {} skipped", bad_inputs.len())
                } else {
                    String::new()
                },
                if failed > 0 {
                    format!(", {failed} FAILED — rolled back")
                } else {
                    String::new()
                },
                report.dead_brokers,
                report.aces_revoked,
            );
            if failed > 0 {
                return Err(anyhow!(
                    "{failed} of {} path(s) could not be stamped; \
                     batch rolled back",
                    targets.len(),
                ));
            }
            if !bad_inputs.is_empty() {
                eprintln!(
                    "srt-win: {} input path(s) skipped (see above); \
                     exiting 2 (partial)",
                    bad_inputs.len()
                );
                std::process::exit(2);
            }
        }
        Cmd::Acl {
            sub:
                AclCmd::Grant {
                    holder_pid,
                    sandbox_user_sid,
                },
        } => {
            use srt_win::{acl, state_db};
            let holder = state_db::HolderPid(holder_pid);
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).context("read stdin")?;
            let input: AclGrantInput =
                serde_json::from_str(&buf).context("parse stdin JSON {read:[…], write:[…]}")?;
            let ((at, witnesses, failed), report) =
                state_db::with_init_lock(holder, false, |db| {
                    let at = canonicalize_ace_targets(
                        db,
                        "grant",
                        &[
                            (&input.read, acl::SbAce::Grant(acl::GrantMask::ReadOnly)),
                            (&input.write, acl::SbAce::Grant(acl::GrantMask::Modify)),
                        ],
                    )?;
                    for (p, e) in &at.bad_inputs {
                        eprintln!("srt-win: skipped: '{p}': {e}");
                    }
                    let (w, f) = db.apply_aces(&sandbox_user_sid, &at.targets)?;
                    Ok((at, w, f))
                })?;
            let AceTargets {
                targets,
                bad_inputs,
            } = at;
            let fresh = witnesses.iter().filter(|w| !w.already).count();
            eprintln!(
                "srt-win: acl grant — {} path(s) ({} fresh, {} \
                 already held{}{}); recovery pruned {} dead \
                 broker(s), revoked {} orphan ACE(s)",
                targets.len(),
                fresh,
                witnesses.len() - fresh,
                if !bad_inputs.is_empty() {
                    format!(", {} skipped", bad_inputs.len())
                } else {
                    String::new()
                },
                if failed > 0 {
                    format!(", {failed} FAILED — rolled back")
                } else {
                    String::new()
                },
                report.dead_brokers,
                report.aces_revoked,
            );
            if failed > 0 {
                return Err(anyhow!(
                    "{failed} of {} path(s) could not be granted; \
                     batch rolled back",
                    targets.len(),
                ));
            }
            if !bad_inputs.is_empty() {
                eprintln!(
                    "srt-win: {} input path(s) skipped (see above); \
                     exiting 2 (partial)",
                    bad_inputs.len()
                );
                std::process::exit(2);
            }
        }
        Cmd::Acl {
            sub:
                AclCmd::Revoke {
                    holder_pid,
                    sandbox_user_sid,
                    json,
                },
        } => {
            use srt_win::state_db;
            let holder = state_db::HolderPid(holder_pid);
            let ((entries, failed), report) = state_db::with_init_lock(holder, false, |db| {
                db.release_aces(&sandbox_user_sid, state_db::KIND_GRANT)
            })?;
            eprintln!(
                "srt-win: acl revoke — {} path(s){}; recovery \
                 revoked {} orphan grant(s)",
                entries.len(),
                if failed > 0 {
                    format!(", {failed} FAILED (ACE left in place)")
                } else {
                    String::new()
                },
                report.aces_revoked,
            );
            if json {
                let out: Vec<AceReleaseEntry> = entries
                    .iter()
                    .map(|(p, r)| AceReleaseEntry {
                        path: p.clone(),
                        status: r.as_str(),
                    })
                    .collect();
                serde_json::to_writer(std::io::stdout(), &out)
                    .context("write --json revoke result")?;
                println!();
            }
            if failed > 0 {
                return Err(anyhow!("acl revoke: {failed} path(s) could not be revoked"));
            }
        }
        Cmd::Acl {
            sub:
                AclCmd::Restore {
                    holder_pid,
                    sandbox_user_sid,
                    json,
                },
        } => {
            // Restore = release the holder's DENY ACEs (target +
            // parent-FDC) via walk-and-filter.
            use srt_win::state_db;
            let holder = state_db::HolderPid(holder_pid);
            let ((entries, failed), report) = state_db::with_init_lock(holder, false, |db| {
                db.release_aces(&sandbox_user_sid, state_db::KIND_DENY)
            })?;
            eprintln!(
                "srt-win: acl restore (deny-ace) — {} ACE(s){}; \
                 recovery revoked {} orphan ACE(s)",
                entries.len(),
                if failed > 0 {
                    format!(", {failed} FAILED (ACE left in place)")
                } else {
                    String::new()
                },
                report.aces_revoked,
            );
            if json {
                let out: Vec<AceReleaseEntry> = entries
                    .iter()
                    .map(|(p, r)| AceReleaseEntry {
                        path: p.clone(),
                        status: r.as_str(),
                    })
                    .collect();
                serde_json::to_writer(std::io::stdout(), &out)
                    .context("write --json restore result")?;
                println!();
            }
            if failed > 0 {
                return Err(anyhow!(
                    "acl restore: {failed} path(s) could not be \
                     restored (ACE left, fail-closed)"
                ));
            }
        }
        Cmd::Acl {
            sub: AclCmd::Recover { force, json },
        } => {
            use srt_win::state_db;
            // recover only runs crash-recovery (holder-agnostic);
            // the holder PID is irrelevant, pass our own.
            let ((), report) =
                state_db::with_init_lock(state_db::HolderPid(std::process::id()), force, |_db| {
                    Ok(())
                })?;
            eprintln!(
                "srt-win: acl recover — pruned {} dead broker(s), \
                 revoked {} orphan ACE(s)",
                report.dead_brokers, report.aces_revoked,
            );
            if json {
                println!(
                    "{}",
                    json!({
                        "deadBrokers": report.dead_brokers,
                        "acesRevoked": report.aces_revoked,
                    })
                );
            }
        }

        // ─── runner ────────────────────────────────────────────────
        Cmd::Runner => {
            let code = srt_win::runner::run()?;
            std::process::exit(code as i32);
        }

        // ─── exec ──────────────────────────────────────────────────
        Cmd::Exec {
            deny_read,
            deny_write,
            env,
            quiet,
            target,
        } => {
            use srt_win::install;

            // Credential + setup read happens FIRST so the
            // exit-15 fast-fail (not provisioned / stale cred)
            // fires before any WFP/ACL work.
            let (cred, sb_sid) = match install::read_cred().and_then(|c| {
                let s = install::read_setup()?
                    .ok_or_else(|| anyhow!("sandbox user not provisioned"))?;
                Ok((c, s.sandbox_user_sid))
            }) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "srt-win: error: sandbox user not \
                         provisioned ({e:#}). Run `srt-win install` \
                         (one UAC prompt)."
                    );
                    std::process::exit(15);
                }
            };

            // Share-lock current_exe() so a sandboxed child can't
            // rename/overwrite the broker binary mid-exec — see
            // `self_protect::share_lock_current_exe` for the threat
            // model. Acquired BEFORE per-exec stamps: held for the
            // duration of the stamp attempt; on stamp failure the
            // child never launches so lock release on unwind is
            // moot. Warn-and-continue: defense-in-depth must not
            // DoS the primary path when a third-party opener
            // (AV/indexer/updater) holds DELETE access. `--quiet`
            // gates the warning — that failure mode is a persistent
            // per-machine condition that would otherwise print on
            // every exec.
            let _exe_lock = srt_win::self_protect::share_lock_current_exe()
                .inspect_err(|e| {
                    if !quiet {
                        eprintln!(
                            "srt-win: WARNING: share-lock current_exe: \
                             {e:#} (proceeding; defense-in-depth only)"
                        )
                    }
                })
                .ok();

            // No WFP pre-flight here: BFE enumeration is
            // admin-gated, so a non-elevated broker can't read it.
            // The fence is verified BEHAVIORALLY by `srt-win wfp
            // verify` at the host's `initialize()` (it spawns the
            // runner as the sandbox user and expects WSAEACCES on a
            // direct connect). Standalone `srt-win exec` callers
            // should run `srt-win wfp verify` once per session.

            // Per-exec file deny — `--deny-read`/`--deny-write`. The
            // session-level stamp (under `--holder-pid`) is applied
            // once at the host's `initialize()`; these flags add
            // PER-EXEC paths via the same additive DENY-ACE path as
            // session `acl stamp`, under THIS exec process's own
            // PID as a DISTINCT holder. Release downgrades the mask
            // from the remaining holders' MAX(want_mask). Any stamp
            // error (glob, canon-fail, apply-fail) FAILS the exec
            // rather than running the child with an incomplete deny
            // set.
            let per_exec_guard = if deny_read.is_empty() && deny_write.is_empty() {
                None
            } else {
                use srt_win::{acl, state_db};
                let own = state_db::HolderPid(std::process::id());
                let ((at, _w, failed), _r) = state_db::with_init_lock(own, false, |db| {
                    let at = canonicalize_ace_targets(
                        db,
                        "deny",
                        &[
                            (&deny_read, acl::SbAce::Deny(acl::DenyMask::ReadDeny)),
                            (&deny_write, acl::SbAce::Deny(acl::DenyMask::WriteDeny)),
                        ],
                    )?;
                    if let Some((p, e)) = at.bad_inputs.first() {
                        return Err(anyhow!("per-exec --deny-*: '{p}': {e}"));
                    }
                    let (w, f) = db.apply_aces(&sb_sid, &at.targets)?;
                    Ok((at, w, f))
                })
                .context("per-exec deny-ace")?;
                let n = at.targets.len();
                if failed > 0 {
                    return Err(anyhow!(
                        "per-exec deny: {failed} of {n} path(s) \
                         could not be stamped; rolled back"
                    ));
                }
                let guard = PerExecRestore {
                    holder: own,
                    sandbox_sid: sb_sid.clone(),
                    quiet,
                };
                if !quiet {
                    eprintln!(
                        "srt-win: per-exec deny (deny-ace): \
                         holder_pid={} → {n} target(s)",
                        own.0,
                    );
                }
                Some(guard)
            };

            // Self-protect the BROKER (real user) before the logon.
            // The runner self-protects too; this covers the
            // broker→child hop. `extra_allow = real-user SID` — the
            // child runs as `srt-sandbox`, so this ACE doesn't match
            // it; non-elevated real-user siblings can still
            // query/debug the broker. Best-effort.
            let real_user = srt_win::sid::current_user_sid()?;
            if let Err(e) = srt_win::self_protect::install_broker_dacl(Some(&real_user)) {
                eprintln!("srt-win: WARNING: install_broker_dacl: {e:#}");
            }
            // env_overlay = exactly what the caller passed via
            // `--env`. The broker does not enumerate its own
            // environment; the caller (whose proxy/CA-var builder
            // is the single source) supplies the full overlay
            // explicitly.
            let env_overlay: Vec<(String, String)> = env
                .iter()
                .map(|kv| {
                    kv.split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .ok_or_else(|| {
                            anyhow!(
                                "--env value '{kv}' has no '=' \
                                 (expected KEY=VALUE)"
                            )
                        })
                })
                .collect::<anyhow::Result<_>>()?;
            if !quiet {
                eprintln!(
                    "srt-win: launching runner as '{}' (overlay={} var(s))",
                    cred.user,
                    env_overlay.len(),
                );
            }
            use srt_win::{logon, runner};
            let cwd = std::env::current_dir()
                .ok()
                .and_then(|p| p.to_str().map(String::from));
            let code = match logon::spawn_runner(
                &cred.user,
                &cred.pw,
                &sb_sid,
                cwd.as_deref(),
                &runner::RunnerCmd::Exec(runner::RunnerSpec {
                    argv: target,
                    env_overlay,
                }),
                quiet,
            ) {
                Ok(c) => c,
                Err(e) => {
                    // Mapped/network-drive cwd (see
                    // `logon::MappedDriveCwd`): emit a one-line
                    // JSON error the TS caller can parse and exit
                    // 16 — distinct from the child's own exit
                    // status. `?` propagates any other
                    // spawn_runner error unchanged.
                    let m = e.downcast::<logon::MappedDriveCwd>()?;
                    eprintln!(
                        "{}",
                        json!({
                            "code": "mapped_drive_cwd",
                            "drive": m.drive,
                            "message": m.to_string(),
                        })
                    );
                    drop(per_exec_guard);
                    std::process::exit(16);
                }
            };
            // `cred` drops here → `SandboxCred::Drop` zeroes the
            // password. process::exit skips destructors, so the
            // per-exec restore guard's Drop must be explicit
            // BEFORE it.
            drop(per_exec_guard);
            std::process::exit(code as i32);
        }
    }
    Ok(())
}

fn is_elevated() -> anyhow::Result<bool> {
    use anyhow::Context;
    use std::ffi::c_void;
    use std::mem::size_of;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok).context("OpenProcessToken")?;
        let mut elev = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        let r = GetTokenInformation(
            tok,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        );
        let _ = CloseHandle(tok);
        r.context("GetTokenInformation(TokenElevation)")?;
        Ok(elev.TokenIsElevated != 0)
    }
}

/// Hard elevation gate: returns an error (no UAC relaunch) when not
/// admin. The granular admin mutators self-elevate via
/// [`maybe_self_elevate`], so this currently has no caller — it's
/// retained as the non-interactive counterpart for code paths that
/// must NOT pop a UAC prompt, hence `allow(dead_code)`.
#[allow(dead_code)]
fn require_elevated() -> anyhow::Result<()> {
    if is_elevated()? {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "this command requires elevation — run from an \
             administrator prompt"
        ))
    }
}

/// If not already elevated, re-launch ourselves with the same
/// argv via `ShellExecuteExW(verb="runas")` — one UAC prompt —
/// wait for the elevated child, and return its exit code. If
/// already elevated, returns `Ok(None)` and the caller proceeds
/// in-process. If the user cancels the UAC dialog
/// (`ERROR_CANCELLED`), exits with code **10** so the caller's
/// exit-code contract holds without the caller needing a
/// separate match.
///
/// The elevated child runs in its own (hidden) console, so its
/// stdout/stderr are NOT relayed to the parent. For
/// `install`/`uninstall` that's acceptable: the exit code is the
/// contract; the convenience commands' stderr is informational
/// only. `wfp uninstall` calls this too; its stderr is likewise
/// informational. Read-only subcommands (`user status`,
/// `wfp status`, `exec`) run as the broker and never self-elevate.
///
/// `args` is the post-sentinel-strip argv [`run_from_args`] was
/// called with; the elevated parameters are rebuilt from `args[1..]`
/// (NOT `std::env::args()`, which in a multicall embedder is the
/// host's argv) with [`SRT_WIN_DISPATCH_ARG1`] prepended so the
/// elevated child's dispatcher routes back into `srt-win`.
fn maybe_self_elevate(args: &[OsString]) -> anyhow::Result<Option<i32>> {
    use anyhow::Context;
    use srt_win::launch::quote_arg;
    use srt_win::util::wstr;
    use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, GetLastError};
    use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    use windows::Win32::UI::Shell::{
        SEE_MASK_NO_CONSOLE, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
    use windows::core::PCWSTR;

    if is_elevated()? {
        return Ok(None);
    }

    let exe = std::env::current_exe().context("current_exe")?;
    let exe_str = exe.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "current_exe path '{}' is not representable as UTF-8 \
             (contains unpaired surrogates); cannot self-elevate",
            exe.display()
        )
    })?;
    let exe_w = wstr(exe_str);
    // Rebuild `args[1..]` (the post-sentinel-strip argv
    // `run_from_args` was given — not `std::env::args()`) with
    // CommandLineToArgvW-compatible quoting so the elevated child
    // parses identically. `lpFile` fixes the elevated child's
    // argv[0] to the real exe path (ShellExecuteExW has no argv0
    // slot), so prepend `SRT_WIN_DISPATCH_ARG1` so a multicall
    // dispatcher in the elevated child routes back here. Harmless
    // for the standalone binary (`run_from_args` strips it).
    let params = std::iter::once(SRT_WIN_DISPATCH_ARG1.into())
        .chain(args.iter().skip(1).map(|a| quote_arg(&a.to_string_lossy())))
        .collect::<Vec<_>>()
        .join(" ");
    let params_w = wstr(&params);
    let verb_w = wstr("runas");

    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE,
        lpVerb: PCWSTR(verb_w.as_ptr()),
        lpFile: PCWSTR(exe_w.as_ptr()),
        lpParameters: PCWSTR(params_w.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: sei is fully initialized; the wide-string buffers
    // outlive the call.
    let ok = unsafe { ShellExecuteExW(&mut sei) };
    if ok.is_err() {
        let err = unsafe { GetLastError() };
        if err == ERROR_CANCELLED {
            eprintln!("srt-win: UAC prompt cancelled by user");
            std::process::exit(10);
        }
        return Err(anyhow::anyhow!(
            "ShellExecuteExW(runas): {} ({}",
            std::io::Error::from_raw_os_error(err.0 as i32),
            err.0,
        ));
    }
    let h = sei.hProcess;
    if h.is_invalid() {
        return Err(anyhow::anyhow!(
            "ShellExecuteExW returned no process handle"
        ));
    }
    let wait = unsafe { WaitForSingleObject(h, INFINITE) };
    if wait == windows::Win32::Foundation::WAIT_FAILED {
        let err = std::io::Error::last_os_error();
        unsafe {
            let _ = CloseHandle(h);
        }
        return Err(anyhow::anyhow!(
            "WaitForSingleObject(elevated child): {err}"
        ));
    }
    let mut code: u32 = 1;
    unsafe {
        GetExitCodeProcess(h, &mut code).context("GetExitCodeProcess(elevated child)")?;
        let _ = CloseHandle(h);
    }
    // 259 (STILL_ACTIVE) after a successful wait is a real exit
    // code (the wait already proved the process exited), not the
    // still-running sentinel.
    Ok(Some(code as i32))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `run_from_args` strips the `argv[1]` sentinel before clap so
    /// the same argv shape works whether the embedder's dispatcher
    /// or the standalone `srt-win.exe` is the entry. The CPWLW /
    /// runas re-spawn hops are covered by smoke-exec.ps1; this
    /// proves both shapes parse to the same `Cmd`. Uses
    /// `try_parse_from` (not `run_from_args`) so the test doesn't
    /// touch the host or `process::exit`.
    #[test]
    fn dispatch_sentinel_is_transparent_to_clap() {
        let strip = |args: Vec<&str>| {
            let mut v: Vec<OsString> = args.into_iter().map(OsString::from).collect();
            if v.get(1).map(OsString::as_os_str) == Some(SRT_WIN_DISPATCH_ARG1.as_ref()) {
                v.remove(1);
            }
            v
        };
        // Multicall shape: argv[0] = host exe, argv[1] = sentinel.
        let with = Cli::try_parse_from(strip(vec![
            "host.exe",
            SRT_WIN_DISPATCH_ARG1,
            "user",
            "status",
        ]))
        .expect("with-sentinel should parse");
        assert!(matches!(
            with.cmd,
            Cmd::User {
                sub: UserCmd::Status
            }
        ));
        // Standalone shape: no sentinel.
        let without = Cli::try_parse_from(strip(vec!["srt-win.exe", "user", "status"]))
            .expect("without-sentinel should parse");
        assert!(matches!(
            without.cmd,
            Cmd::User {
                sub: UserCmd::Status
            }
        ));
        // The sentinel is NOT a clap flag — without the strip, it
        // must be rejected (otherwise a typo'd dispatcher silently
        // works on `try_parse_from` while the real binary errors).
        assert!(
            Cli::try_parse_from(["srt-win.exe", SRT_WIN_DISPATCH_ARG1, "user", "status",]).is_err()
        );
    }

    /// Top-level `status` parses with and without `--sublayer-guid`.
    #[test]
    fn status_subcommand_parses() {
        let bare = Cli::try_parse_from(["srt-win", "status"]).expect("parse");
        assert!(matches!(
            bare.cmd,
            Cmd::Status {
                sublayer_guid: None
            }
        ));
        let with_sl = Cli::try_parse_from([
            "srt-win",
            "status",
            "--sublayer-guid",
            "12345678-1234-1234-1234-1234567890ab",
        ])
        .expect("parse");
        assert!(matches!(
            with_sl.cmd,
            Cmd::Status {
                sublayer_guid: Some(_)
            }
        ));
    }

    /// `--quiet` on `exec` parses and defaults false. Placement
    /// before `--` (where the TS wrapper puts it) is accepted.
    #[test]
    fn exec_quiet_flag_parses() {
        let with =
            Cli::try_parse_from(["srt-win", "exec", "--quiet", "--", "cmd.exe"]).expect("parse");
        assert!(matches!(with.cmd, Cmd::Exec { quiet: true, .. }));
        let without = Cli::try_parse_from(["srt-win", "exec", "--", "cmd.exe"]).expect("parse");
        assert!(matches!(without.cmd, Cmd::Exec { quiet: false, .. }));
    }
}
