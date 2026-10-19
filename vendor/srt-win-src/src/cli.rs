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
//!   acl    stamp | grant | restore | revoke | recover | forget
//!                                       — additive sandbox-user ACEs,
//!                                         and write grants kept
//!                                         between sessions
//!   profile grant | forget | status    — the opt-in read grant on
//!                                         the real user's profile
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
        // Kept out by a profile grant or forget in progress: its own
        // exit code and one line of JSON, so the caller can say so.
        Err(e) if e.is::<srt_win::state_db::ProfileBusy>() => {
            eprintln!("srt-win: error: {e:#}");
            eprintln!(
                "{}",
                serde_json::json!({
                    "code": "profile_operation_in_progress",
                    "message": e.to_string(),
                })
            );
            srt_win::state_db::EXIT_PROFILE_BUSY
        }
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
    ///        DIFFERENT port-range, loopback mode or
    ///        sandbox-user name; pass `--force` to replace
    ///   14 — sandbox user provisioning failed
    ///   1  — other error (parse, elevation check, etc.)
    Install {
        /// Sublayer GUID (default: compile-time constant).
        #[arg(long)]
        sublayer_guid: Option<String>,
        /// Loopback port range (`LOW-HIGH`, default 60080-60089).
        #[arg(long, value_name = "LOW-HIGH")]
        proxy_port_range: Option<String>,
        /// Open loopback: the sandbox account may connect to
        /// 127.0.0.0/8 and ::1 on every TCP and UDP port, as
        /// `network.allowLocalBinding` allows on macOS (port 1 alone
        /// stays blocked, for the fence check). Default: closed (only the
        /// proxy port range is reachable). Every listener on
        /// localhost — whoever owns it — becomes reachable from the
        /// sandbox, including any local forwarder that carries
        /// traffic off the machine. Changing the mode means running
        /// `install` again (with `--force`); a session configured
        /// with the other mode than the installed one is refused.
        #[arg(long)]
        allow_loopback: bool,
        /// Name for the sandbox user account. Default:
        /// `srt-sandbox`. srt-win only manages an account it
        /// created — a name that already resolves to a principal
        /// srt-win didn't provision is refused (exit 14).
        #[arg(long)]
        sandbox_user: Option<String>,
        /// Replace an existing install whose port-range, loopback
        /// mode or sandbox-user name differs (otherwise exits 13).
        #[arg(long)]
        force: bool,
    },
    /// Remove the srt-win WFP filters under the sublayer and the
    /// `srt-sandbox` account, its credential file, and the setup
    /// marker (unless `--keep-user`). Self-elevates via UAC if not
    /// already admin. Best-effort also removes the legacy
    /// `sandbox-runtime-net` discriminator group if a prior install
    /// left it behind. Unless `--keep-user`, the calling user's
    /// persistent write grants (`acl grant --persistent`) are removed
    /// first, as by `acl forget --all`, and so is their profile read
    /// grant, as by `profile forget`.
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
        /// Set by `uninstall` itself on the elevated process it
        /// starts: do the machine-wide removal only. The grants kept
        /// for the calling user are that user's to forget, in the
        /// process that asked.
        #[arg(long, hide = true)]
        elevated_step: bool,
    },
    /// Print `{user: <user-status>, wfp: <wfp-status>}` as one line
    /// of JSON — the same objects `user status` and `wfp status`
    /// emit (so Secondary Logon readiness is `user.seclogon`), in a
    /// single spawn. The host's readiness check calls
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
    /// read/write them. State is persisted in the shared state
    /// per-user session DB so concurrent brokers refcount
    /// and a crash mid-session is recoverable by the next `acl`
    /// op.
    Acl {
        #[command(subcommand)]
        sub: AclCmd,
    },
    /// The profile read grant: make the calling user's profile
    /// readable to the sandbox group, except for credential stores.
    /// Opt-in; nothing else in `srt-win` writes it. Runs as the user
    /// whose profile it is, without elevation.
    Profile {
        #[command(subcommand)]
        sub: ProfileCmd,
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
    /// Requires `srt-win install` to have provisioned the user, by a
    /// build with this one's setup version; otherwise exits **15**.
    /// Typed launch failures print one line of JSON
    /// `{"code":…,"message":…}` to stderr and exit with a dedicated
    /// code: **16** `mapped_drive_cwd`, **18** `seclogon_disabled`
    /// (the Secondary Logon service is disabled or absent), **19**
    /// `wfp_loopback_mismatch` (the installed loopback mode is not
    /// the one `--allow-loopback`, or its absence, names; nothing is
    /// launched — re-run `srt-win install` for this mode).
    Exec {
        /// This session expects loopback open. Must be given exactly
        /// when `srt-win install --allow-loopback` installed it:
        /// on a difference in either direction nothing is launched
        /// and the exit code is 19.
        #[arg(long)]
        allow_loopback: bool,
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
        /// A path the caller's session is granted (read or write)
        /// that lies beneath a `--deny-read` path. While a profile
        /// read grant is recorded, a read deny is also written on the
        /// recorded paths beneath it; one at or beneath a path given
        /// here is left out, as the session's own allow there ranks
        /// above a deny set further up. Repeatable. A path that
        /// cannot be resolved spares nothing.
        #[arg(long = "deny-read-except", value_name = "PATH")]
        deny_read_except: Vec<String>,
        /// The process whose session this command belongs to and
        /// which is recorded as one (`acl grant --holder-pid`, with
        /// or without `--persistent`). Checked: if that process is not
        /// alive or is not recorded — or without the flag — this
        /// process records itself, under either token, as a session
        /// and as the holder of each `--write-root`: the profile read
        /// grant is not made or removed beside the command, and no
        /// root is removed from under it.
        ///
        /// A command started for a recorded session ends with it: if
        /// that process exits while the command runs, the command and
        /// everything it started are terminated and this exits **26**.
        /// A recorded, live session that cannot be watched fails the
        /// command before anything is started.
        #[arg(long = "held-by", value_name = "PID")]
        held_by: Option<u32>,
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
        /// Build the child token with the `WRITE_RESTRICTED` flag and
        /// the restricting SIDs `[<sandbox user>, Everyone,
        /// RESTRICTED]`, so write access held by `BUILTIN\Users` /
        /// `Authenticated Users` no longer reaches the child. Off
        /// unless passed; the library always passes it. Fails the
        /// exec if that token cannot be built —
        /// there is no fallback to the ordinary token. Schannel-based
        /// TLS clients (System32 `curl.exe`, schannel-backend git,
        /// .NET / PowerShell web requests) fail under it. Pair with
        /// `wfp verify --write-restricted-token`.
        ///
        /// Without this flag the exec is refused (exit **20**) while
        /// any persistent write grant exists (`acl grant
        /// --persistent`): such a grant lets the sandbox account
        /// write its tree under the ordinary token. It is refused the
        /// same way while a profile read grant exists (`profile
        /// grant`), or while either record cannot be read: grants that
        /// outlive a session are made for the write-restricted token
        /// only.
        #[arg(long)]
        write_restricted_token: bool,
        /// A write root of this command's session, granted with `acl
        /// grant --persistent`. Repeatable. The root's capability SID
        /// is added to the child token's restricting SIDs, which is
        /// what lets the child write there — and only there, among
        /// the persistent roots. Fails the exec if no capability SID
        /// is recorded for the path.
        #[arg(
            long = "write-root",
            value_name = "PATH",
            requires = "write_restricted_token"
        )]
        write_root: Vec<String>,
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
    /// Self-checks that report what the calling process's own token
    /// can do. `wfp verify --write-restricted-token` runs `probe
    /// connect` as the sandboxed child. Not intended to be invoked
    /// directly.
    #[command(hide = true)]
    Probe {
        #[command(subcommand)]
        sub: ProbeCmd,
    },
}

#[derive(Subcommand)]
enum ProbeCmd {
    /// Attempt a direct TCP connect to `--target`. Exits **0** when
    /// the WFP fence refused it (`WSAEACCES`), **3** when it
    /// connected, **2** on any other error.
    Connect {
        #[arg(long)]
        target: String,
    },
    /// The fence probe (`srt_win::probe::run`) made by this process
    /// under its own token; exits with the report encoded, as the
    /// runner's `ProbeEgress` does. `wfp verify
    /// --write-restricted-token` runs it as the sandboxed child.
    Egress {
        #[arg(long)]
        target: String,
        #[arg(long)]
        anonymous_target: Option<String>,
        #[arg(long)]
        anonymous_egress: bool,
        #[arg(long)]
        allow_loopback: bool,
    },
    /// Print this process's token restriction as JSON:
    /// `{write_restricted, restricted_sids}`. CI smoke hook: only in
    /// builds with the `test-hooks` feature.
    #[cfg(feature = "test-hooks")]
    Token,
    /// Try to open the parent process and each of its threads with
    /// every write / code-execution / impersonation right, and print
    /// which opens succeeded as JSON: `{parent_pid, threads, opened,
    /// errors}`. CI smoke hook: only in builds with the `test-hooks`
    /// feature.
    #[cfg(feature = "test-hooks")]
    ParentAccess,
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Write, or bring up to date, the read grant on the calling
    /// user's profile for the sandbox group.
    ///
    /// The profile directory and every directory that could hold an
    /// excluded path get an entry that lets the sandbox list them and
    /// pass through; their other children are granted read + execute
    /// one by one (a directory with one inheriting entry, a file with
    /// its own). Protected paths — key and credential stores, browser
    /// and password-manager data, the registry hives, and what
    /// `--exclude` adds — are never granted and get a read deny,
    /// written before the first allow; a protected directory that
    /// does not exist is created empty to carry it. The temporary
    /// directory is left as it is: nothing in it is granted, and it
    /// is not denied, so a session can still grant a directory of its
    /// own inside it.
    /// Junctions, symbolic links and cloud placeholders are skipped.
    /// No entry grants a write, delete or change-permissions right.
    ///
    /// The first run touches every file under the granted
    /// directories and can take minutes on a large profile; progress
    /// goes to stderr. A later run writes only what changed: a new
    /// child of the profile directory (or of another directory whose
    /// children are granted one by one) is not readable until then.
    /// Other `srt-win acl` commands of the same user wait while a run
    /// is in progress.
    ///
    /// Exits **15** unless the install's setup marker is this
    /// build's, **21** when run as a service account (LocalSystem,
    /// LocalService, NetworkService), **24** — nothing changed — while
    /// a sandbox session or command is running, and **25** while
    /// another profile operation is. A path that cannot be written is
    /// reported by what that leaves and does not fail the run.
    Grant {
        /// A path inside the profile to exclude in addition to the
        /// built-in list (absolute, or relative to the profile).
        /// Repeatable. The exclusions added by earlier runs stay in
        /// force as well. Nothing removes a built-in exclusion.
        #[arg(long = "exclude", value_name = "PATH")]
        exclude: Vec<String>,
        /// Make the `--exclude` paths of this run the whole added
        /// list, dropping the ones earlier runs recorded (with no
        /// `--exclude`: drop them all).
        #[arg(long)]
        replace_excludes: bool,
        /// Print the result as one JSON object on stdout:
        /// `{profile, list_version, complete, containers, granted,
        /// files, denied, placeholders, writes, unchanged, removed,
        /// skipped, failed, elapsed_ms}`.
        #[arg(long)]
        json: bool,
        /// No progress lines on stderr.
        #[arg(long)]
        quiet: bool,
        /// Treat this directory as the profile, with its `AppData`
        /// folders beneath it; the `SRT_WIN_TEST_PROFILE` environment
        /// variable does the same when the flag is absent. CI hook:
        /// only in builds with the `test-hooks` feature — a default
        /// build has neither the flag nor the variable.
        #[cfg(feature = "test-hooks")]
        #[arg(long, value_name = "DIR")]
        test_profile: Option<String>,
    },
    /// Remove the grant: the sandbox group's entry from every
    /// recorded path (each DACL is left as it was before the grant),
    /// the empty directories the grant created, and the record. Exits
    /// non-zero if a path could not be completed; it stays recorded.
    Forget {
        /// Print `{removed, absent, placeholders_removed, failed}` on
        /// stdout, also when exiting non-zero.
        #[arg(long)]
        json: bool,
        /// Remove nothing, print `{"held_by": [{pid, kind, path}]}`
        /// on stdout and exit 22, if a live session other than the
        /// one of this process id is running on a kept grant.
        #[arg(long, value_name = "PID")]
        unless_held_by_others: Option<u32>,
    },
    /// Print the recorded grant as JSON: `{state, reason?, profile,
    /// list_version, recorded_list_version, extra_exclusions,
    /// exclusions, ungranted_only, containers, granted, files, denied,
    /// env?, paths?}`.
    /// `exclusions` is every protected path the grant was made to
    /// keep unreadable (wildcards as written), existing or not;
    /// `ungranted_only` the directories it leaves ungranted without
    /// denying them. `state` is
    /// `none`, `current`, `outdated`, `incomplete` or `unknown`; only
    /// `current` is a grant a session may rely on. Asked while a
    /// grant or forget is running it is `in_progress`, with nothing
    /// else but `capabilities`. `env` lists the
    /// configuration-file variables an embedder may set for a
    /// sandboxed command. Reads the registry and opens the profile
    /// directory; nothing below it. Exit 0.
    Status {
        /// Include every recorded path with its kind.
        #[arg(long)]
        paths: bool,
        /// See `profile grant --test-profile`.
        #[cfg(feature = "test-hooks")]
        #[arg(long, value_name = "DIR")]
        test_profile: Option<String>,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    /// Print the sandbox user's provisioning state as JSON:
    /// `{user: {exists, sid?, group_exists, group_sid?,
    /// in_builtin_users, in_sandbox_group, hidden_from_logon},
    /// cred_present, marker_version?, setup_version,
    /// marker_user_sid?, ca_cert_thumb?, ca_cert_pem?,
    /// persistent_grants: {state, roots, reason?}, profile_grant:
    /// {state, reason?}, session_user_sid?, seclogon}`. The install is
    /// usable by this build only when `marker_version` equals
    /// `setup_version`; otherwise re-run `srt-win install`.
    /// `seclogon` is the Secondary Logon service every launch depends
    /// on: `"ok"|"disabled"|"missing"|"cannot-read"` (read-only SCM
    /// query — see `logon::seclogon_state`).
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
    /// elevation. Persistent until `srt-win uninstall`. Exits
    /// **18** (with the `seclogon_disabled` JSON line on stderr)
    /// when the Secondary Logon service is disabled or absent.
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
    ///
    /// Refused while a persistent grant exists (see `--persistent`);
    /// `acl forget --all` removes those.
    Grant {
        /// Holder PID (see `acl stamp`).
        #[arg(long)]
        holder_pid: u32,
        /// SID to grant — the dedicated sandbox user
        /// (`srt-win user status` → `marker_user_sid`).
        #[arg(long)]
        sandbox_user_sid: String,
        /// Session start for `exec --write-restricted-token`. Each
        /// `write` path becomes a persistent root: it gets a
        /// capability SID of its own and ACEs for the sandbox GROUP
        /// and that SID (none for the sandbox user), which are KEPT
        /// when the session ends — `acl revoke` does not touch them,
        /// `acl forget` removes them. A root already granted costs
        /// one DACL read. stdin may also carry `denyRead` /
        /// `denyWrite`: targets under a persistent root are stamped
        /// for the sandbox group and kept with it; the others, and
        /// the `read` paths, are per-session as without this flag.
        /// Pass each root to `exec` as `--write-root`.
        ///
        /// Exits **15** unless the install's setup marker is this
        /// build's: no grant is kept on a machine where a build of
        /// another setup version would still launch the sandbox
        /// account.
        #[arg(long)]
        persistent: bool,
        /// While a profile read grant is recorded, no path is granted
        /// here that is a protected exclusion of it, lies inside one,
        /// or lies above one, nor one that is or lies above a
        /// directory it leaves ungranted as a whole (the temporary
        /// directory): the command fails and grants nothing. This
        /// flag names a `read` path that may be granted although it is
        /// a protected exclusion or lies inside one. Repeatable. It
        /// admits no `write` path, and no path above an exclusion.
        #[arg(long = "allow-profile-exclusion", value_name = "PATH")]
        allow_profile_exclusion: Vec<String>,
    },
    /// Drop the holder's claim on every granted path; remove the
    /// sandbox-user ACE on any path whose refcount falls to zero.
    ///
    /// Exits non-zero when any grant could not be released (status
    /// `unreadable` or `failed`: the ACE may still be on disk and its
    /// rows are kept for a retry). A caller that goes on to
    /// `acl restore` must not do so in that case.
    Revoke {
        #[arg(long)]
        holder_pid: u32,
        #[arg(long)]
        sandbox_user_sid: String,
        /// Emit a single JSON array of per-path `{path, status}`
        /// objects on stdout. The array is complete — it includes
        /// the paths that could not be released — and is written
        /// before a non-zero exit.
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
    /// Remove persistent write grants (`acl grant --persistent`):
    /// the root's ACEs, the deny ACEs kept with it, its capability
    /// SID and its record. One walk of the tree per root. Exits
    /// non-zero if any root could not be completed; that root stays
    /// recorded.
    Forget {
        /// Every root recorded for the calling user.
        #[arg(long, conflicts_with = "roots")]
        all: bool,
        /// Emit a JSON array of per-root `{path, status}` objects on
        /// stdout (`removed`, `absent`, `failed`, `dropped`), also when
        /// exiting non-zero.
        #[arg(long)]
        json: bool,
        /// With `--all` only: remove nothing, print `{"held_by":
        /// [{pid, kind, path}]}` on stdout and exit 22, if a live
        /// session other than the one of this process id is running on
        /// any kept write root. (Not offered for named roots: a hold
        /// is recorded by path, a root is forgotten by the object it
        /// is, and the two would have to be matched.)
        #[arg(long, value_name = "PID", requires = "all", conflicts_with = "roots")]
        unless_held_by_others: Option<u32>,
        /// Stop waiting for the volume of a grant that `forget`
        /// reported as pending, and drop its record: for a volume that
        /// will not come back (reformatted, discarded). The entries on
        /// that object are NOT removed — it cannot be reached — and
        /// nothing will remove them later; the command says so, with
        /// the group they name. Nothing else ever drops a pending
        /// record. Repeatable; an unknown path is an error.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["all", "roots"])]
        drop_pending: Vec<String>,
        /// With `--all`: a root whose object can no longer be located
        /// (its drive is gone, say) is reported and its record dropped
        /// instead of failing the command. Its ACEs may still be on disk.
        #[arg(long, requires = "all", conflicts_with = "roots")]
        force: bool,
        /// The roots to forget.
        #[arg(value_name = "PATH")]
        roots: Vec<String>,
    },
    /// Run crash-recovery only: release the holds of dead holders
    /// (grants first; a holder's deny ACEs are kept while one of its
    /// grants could not be released) and prune them. Exits non-zero
    /// when a grant is still pending.
    Recover {
        /// Drop the record of a dead holder's grant that can no longer
        /// be located (its path is gone and its file id cannot be
        /// looked up), then release that holder's deny ACEs. Each
        /// dropped path is printed; its ACE may still be on disk.
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
#[serde(rename_all = "camelCase")]
struct AclGrantInput {
    #[serde(default)]
    read: Vec<String>,
    #[serde(default)]
    write: Vec<String>,
    /// `--persistent` only — see `acl grant`.
    #[serde(default)]
    deny_read: Vec<String>,
    #[serde(default)]
    deny_write: Vec<String>,
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
    /// Recorded paths of the profile read grant that a read deny among
    /// `targets` is written on as well — for
    /// `Locked::apply_aces_and`. They exist only because of the
    /// expansion: they are denied for the holder's session, and are
    /// never handed to `persist::apply` to be kept with a write root.
    also_read_deny: Vec<String>,
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
///
/// `allows` are the canonical paths the same session is granted (read
/// or write): a read deny is not carried onto a recorded profile path
/// that such a grant allows more specifically
/// (`RecordedAllows::covered`).
fn canonicalize_ace_targets(
    db: &srt_win::state_db::Locked,
    label: &str,
    inputs: &[(&[String], srt_win::acl::SbAce)],
    allows: &[String],
) -> anyhow::Result<AceTargets> {
    use anyhow::anyhow;
    use srt_win::acl::SbAce;
    use srt_win::path_id::{
        CanonError, canonicalize_path, create_placeholder_chain, is_unc_path, strip_extended_prefix,
    };
    use std::io::ErrorKind;
    let mut targets = Vec::new();
    let mut bad_inputs = Vec::new();
    let mut also_read_deny: Vec<String> = Vec::new();
    // The profile read grant's record, read at the first read deny
    // and once for all of them.
    let mut recorded: Option<srt_win::profile_plan::RecordedAllows> = None;
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
        // A read deny holds against the profile read grant only if it is
        // also on each recorded path beneath it that carries its own allow.
        if matches!(ace, SbAce::Deny(srt_win::acl::DenyMask::ReadDeny)) {
            let recorded = match &recorded {
                Some(r) => r,
                None => recorded.insert(srt_win::profile::recorded_allows()?),
            };
            for also in recorded.covered(&canon, allows) {
                if !also_read_deny.iter().any(|p| p == also) {
                    also_read_deny.push(also.to_owned());
                }
            }
        }
        // Full-chain hold (see doc). Duplicates are merged below.
        if matches!(ace, SbAce::Deny(_)) {
            for anc in db.placeholder_ancestors_of(&canon)? {
                targets.push((anc, SbAce::DenyDelete));
            }
        }
    }
    let targets = merge_ace_targets(targets);
    // A path named outright is not also an expansion.
    also_read_deny.retain(|p| {
        !targets
            .iter()
            .any(|(t, a)| t == p && matches!(a, SbAce::Deny(srt_win::acl::DenyMask::ReadDeny)))
    });
    Ok(AceTargets {
        targets,
        bad_inputs,
        also_read_deny,
    })
}

/// One entry per `(path, kind)`, where the path first came up, with
/// the widest of the masks asked for it ([`SbAce::max`]).
///
/// INVARIANT: a batch hands `apply_aces` no `(path, kind)` twice. A
/// holder has ONE row per `(path, kind)` and a later entry overwrites
/// its mask, so a path in `denyRead` and in `denyWrite` (or named by
/// two spellings of one object) would end at the write deny, which
/// leaves read open.
///
/// [`SbAce::max`]: srt_win::acl::SbAce::max
fn merge_ace_targets(
    targets: Vec<(String, srt_win::acl::SbAce)>,
) -> Vec<(String, srt_win::acl::SbAce)> {
    let mut at = std::collections::HashMap::new();
    let mut merged: Vec<(String, srt_win::acl::SbAce)> = Vec::with_capacity(targets.len());
    for (canon, ace) in targets {
        match at.entry((canon.clone(), ace.kind())) {
            std::collections::hash_map::Entry::Occupied(seen) => {
                let held: &mut (String, srt_win::acl::SbAce) = &mut merged[*seen.get()];
                held.1 = held.1.max(ace);
            }
            std::collections::hash_map::Entry::Vacant(new) => {
                new.insert(merged.len());
                merged.push((canon, ace));
            }
        }
    }
    merged
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
        // The HKLM Cred\Blob value (a SYSTEM/fleet install must
        // read as present from any user's session).
        "cred_present": setup.is_some() && install::cred_present(),
        "marker_version": setup.as_ref().map(|s| s.marker_version),
        // An install whose `marker_version` differs must be re-run.
        "setup_version": install::SETUP_VERSION,
        "marker_user_sid": setup.as_ref()
            .map(|s| s.sandbox_user_sid.as_str()),
        // The calling (real) user's SID — surfaced for diagnostics.
        "real_user_sid": srt_win::sid::current_user_sid()?,
        "ca_cert_thumb": ca.map(|c| c.thumb()).transpose()?,
        "ca_cert_pem": ca.map(|c| c.to_pem()).transpose()?,
        // `none` unless persistent write grants exist or cannot be ruled out.
        "persistent_grants": srt_win::persist::status_json(),
        // Whether a profile read grant is recorded (`none`, `present`
        // or `unknown`); `profile status` says whether it is current.
        "profile_grant": srt_win::profile::brief_status_json(),
        "capabilities": srt_win::profile::CAPABILITIES,
        // The owner of the interactive session (`null` if unknown): an
        // install applies the profile grant only when run as that user.
        "session_user_sid": session_user_sid_for_status(),
        "seclogon": srt_win::logon::seclogon_state(),
    }))
}

/// Remove `sublayer`'s filters, then its recorded loopback mode.
/// Returns how many filters were removed.
fn remove_fence(sublayer: &windows::core::GUID) -> anyhow::Result<usize> {
    use anyhow::Context;
    use srt_win::{install, wfp};
    let n = wfp::uninstall_filters(sublayer)?;
    install::clear_loopback_mode(sublayer).context("clear the recorded loopback mode")?;
    Ok(n)
}

/// `wfp::filter_status` with the recorded loopback mode folded in —
/// the `wfp` object both status commands print.
fn wfp_status(sublayer: &windows::core::GUID) -> anyhow::Result<srt_win::wfp::WfpStatus> {
    use srt_win::{install, wfp};
    let st = wfp::filter_status(sublayer)?;
    // An unreadable record is treated as none here; `wfp verify` and
    // `exec` fail on it and say why.
    let recorded = install::read_loopback_mode(sublayer).ok().flatten();
    Ok(wfp::apply_recorded_loopback(st, recorded))
}

/// Exit code of a launch that failed on [`srt_win::logon::SeclogonDisabled`].
const EXIT_SECLOGON_DISABLED: i32 = 18;

/// The one-line stderr JSON for a [`srt_win::logon::SeclogonDisabled`]
/// failure, seen through `.context(…)` layers; `None` for any other error.
fn seclogon_error_json(e: &anyhow::Error) -> Option<serde_json::Value> {
    let s = e.downcast_ref::<srt_win::logon::SeclogonDisabled>()?;
    Some(serde_json::json!({
        "code": "seclogon_disabled",
        "state": s.state(),
        "message": s.to_string(),
    }))
}

/// Emit the [`seclogon_error_json`] line and exit
/// [`EXIT_SECLOGON_DISABLED`] when `e` is that typed failure;
/// otherwise hand `e` back unchanged for the caller's own handling.
fn exit_if_seclogon_disabled(e: anyhow::Error) -> anyhow::Error {
    if let Some(j) = seclogon_error_json(&e) {
        eprintln!("{j}");
        std::process::exit(EXIT_SECLOGON_DISABLED);
    }
    e
}

/// Install-time ambient write-deny state: the recorded paths (HKLM
/// `AmbientDenies` — admin-written, trustworthy) plus whether each
/// deny ACE is on disk (an admin `icacls /reset` clears it;
/// re-running `srt-win install` repairs). Empty when no install.
fn ambient_status_json() -> anyhow::Result<serde_json::Value> {
    use serde_json::json;
    use srt_win::{acl, install};
    // Degrade like user_status_json: a registry read error (beyond
    // not-found) must not abort the whole status document.
    let sid = install::read_setup()
        .ok()
        .flatten()
        .map(|s| s.sandbox_user_sid);
    let mut paths = Vec::new();
    for p in install::ambient_recorded_paths()? {
        let present = match &sid {
            Some(sid) => acl::sandbox_deny_present(&p, sid).unwrap_or(false),
            None => false,
        };
        paths.push(json!({ "path": p, "present": present }));
    }
    Ok(json!({ "paths": paths }))
}

fn quoted_list<S: AsRef<str>>(paths: &[S]) -> String {
    paths
        .iter()
        .map(|p| format!("'{}'", p.as_ref()))
        .collect::<Vec<_>>()
        .join(", ")
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
    /// port_range?, allow_loopback, loopback_notice?, user_sid?,
    /// hint?}`. `allow_loopback` is whether the installed set opens
    /// loopback (read off the filters when elevated, off the install
    /// record otherwise); when it does, `loopback_notice` says in
    /// plain words what that exposes.
    /// BFE's
    /// `FwpmFilterCreateEnumHandle0` is admin-gated, so a
    /// non-elevated caller gets `{state:"cannot-read", hint:…}`
    /// (exit 0). The non-elevated readiness check is `wfp verify`.
    ///
    /// `state:"loopback-mismatch"` (with a `hint`): the loopback mode
    /// of the filters is not the one the install recorded. Only an
    /// elevated caller can see it.
    Status {
        #[arg(long)]
        sublayer_guid: Option<String>,
    },
    /// Behavioral egress-block probe — the non-elevated readiness
    /// check for the WFP fence. Spawns the runner as `srt-sandbox`
    /// (via `CreateProcessWithLogonW`), which attempts direct TCP
    /// connects under each token shape a sandboxed process can
    /// present (`srt_win::probe`).
    ///
    /// Prints one JSON line. Each `*_probe` is `blocked`,
    /// `connected`, `refused`, `unreachable`, `skipped` or `error`:
    ///
    ///   - `egress_probe` — own token, to `target`.
    ///   - `anonymous_probe` — impersonating the anonymous token, to
    ///     `anonymous_target`.
    ///   - `anonymous_loopback_probe` — impersonating the anonymous
    ///     token, to `target`.
    ///   - `deny_only_probe` — a copy of the own token with the user
    ///     SID deny-only, to `target`.
    ///   - `low_integrity_probe`, `low_integrity_loopback_probe` — a
    ///     copy of the own token at low integrity, to
    ///     `anonymous_target` and to `target`.
    ///   - `untrusted_integrity_probe`,
    ///     `untrusted_integrity_loopback_probe` — the same at
    ///     untrusted integrity.
    ///   - `open_loopback_probe` — own token, to `target`, only with
    ///     `--allow-loopback` (else `skipped`): it must connect.
    ///   - `residuals` — names of the gaps `anonymous_probe`,
    ///     `anonymous_loopback_probe` and `deny_only_probe` found
    ///     open (`anonymous-egress`, `anonymous-loopback`,
    ///     `deny-only-user-sid`). The filters do not close these;
    ///     they are reported, with a warning on stderr, and do not
    ///     change the exit code. `anonymous-egress` is expected
    ///     wherever the machine has an off-loopback address: no
    ///     filter is keyed on the anonymous token.
    ///     `lowered-integrity-unprobed` is named when a
    ///     lowered-integrity probe is `error`: that token shape could
    ///     not be set up, so no connect under it was observed.
    ///
    /// With `--allow-loopback` one loopback port stays blocked for
    /// the sandbox account (`wfp::LOOPBACK_PROBE_PORT`), and nothing
    /// listens on it. `egress_probe` and the lowered-integrity
    /// loopback probes go there (`egress_target`) and pass only on
    /// the filter's refusal: for `egress_probe`, a refusal by the
    /// stack, a connect or no answer in time all mean the block did
    /// not fire (exit 3). `anonymous_loopback_probe` and
    /// `deny_only_probe` are `skipped`.
    ///
    /// Every probe but `egress_probe` and `open_loopback_probe`
    /// (both run under the runner's own token) makes its connect
    /// twice: once on a socket created before the token is assumed
    /// and once on a socket created after, since the engine
    /// attributes a connect to the token in effect when its socket
    /// was created. The JSON carries the worse of the two results for
    /// the fence; stderr carries one line per ordering, each naming
    /// it (`socket before token`, `socket after token`).
    ///
    /// Every other probe but `open_loopback_probe` must be blocked:
    /// `egress_probe` and the four lowered-integrity ones, whose
    /// token still carries the sandbox account's SID. Exits **0**
    /// (`egress_probe` was blocked; each lowered-integrity one was
    /// blocked, skipped for want of an off-loopback address, or
    /// `error`; and with `--allow-loopback`
    /// `open_loopback_probe` connected = fence active), **3** (one
    /// got past the filters = fence MISSING), **2** (`egress_probe`
    /// was not blocked, or a connect that was made got no answer;
    /// treat as failure), **19** when the installed loopback mode is
    /// not the one `--allow-loopback` (or its absence) names, or
    /// when the connect to the loopback listener was blocked
    /// (`allow_loopback_mismatch: true`, with a `hint`), **15**
    /// when the sandbox user is not provisioned, or **18** (no
    /// stdout; the `seclogon_disabled` JSON line on stderr) when the
    /// Secondary Logon service is disabled or absent. A runner
    /// exit that is not a probe report prints every probe as
    /// `error` and exits 1. Does not require elevation. This is the
    /// non-elevated readiness check the host's `initialize()` runs;
    /// `wfp status` is the elevated ground-truth enum.
    ///
    /// With `--allow-loopback` the JSON carries `allow_loopback: true`
    /// and a `loopback_notice` (also printed to stderr): loopback is
    /// open, so a pass means direct connections off the machine are
    /// blocked, not that nothing on localhost forwards traffic off
    /// it.
    Verify {
        /// Probe target (`host:port`). The host binds a local
        /// listener on an ephemeral loopback port OUTSIDE the WFP
        /// permit range and passes it here, so the fence-inactive
        /// case is deterministic without depending on any external
        /// host. With `--allow-loopback` it is the listener
        /// `open_loopback_probe` must reach, and must be a loopback
        /// address (exit 1 otherwise).
        #[arg(long)]
        target: String,
        /// This session expects loopback open. Compared with the
        /// installed mode (exit 19 on a difference in either
        /// direction) and, when given, probed.
        #[arg(long)]
        allow_loopback: bool,
        /// Off-loopback target (`host:port`) for the attempt made
        /// while impersonating the anonymous token, and for the
        /// lowered-integrity attempts' off-loopback half. Default: this
        /// machine's own outbound address at `target`'s port —
        /// nothing needs to listen there, since a refused connect
        /// shows the filters let it through just as a completed one
        /// does. With no such address the attempt is skipped.
        #[arg(long)]
        anonymous_target: Option<String>,
        /// Also make the off-loopback attempt under the anonymous
        /// token (`anonymous_probe`, residual `anonymous-egress`).
        /// No filter refuses it, so it never changes the exit code,
        /// and it can wait on its destination; without this flag it
        /// is `skipped`.
        #[arg(long)]
        anonymous_egress: bool,
        /// Probe with the token `exec --write-restricted-token` gives
        /// the child, instead of the default one. The connects are then
        /// made by a lockdown child (`srt-win probe egress`) holding
        /// that token, because the WFP block filter matches by an
        /// access check of the connecting token and a restricted
        /// token is checked differently from the runner's. A host
        /// that runs commands with `--write-restricted-token` must
        /// verify with this flag.
        #[arg(long)]
        write_restricted_token: bool,
        /// The session's write roots, as given to `exec`: the probe
        /// child's token then carries the same capability SIDs.
        #[arg(
            long = "write-root",
            value_name = "PATH",
            requires = "write_restricted_token"
        )]
        write_root: Vec<String>,
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
            allow_loopback,
            sandbox_user,
            force,
        } => {
            use srt_win::{install, user};
            // The range is validated before the elevation prompt: one
            // that will be refused should not cost a prompt.
            let range = match &proxy_port_range {
                Some(s) => wfp::parse_port_range(s)
                    .with_context(|| format!("invalid --proxy-port-range '{s}'"))?,
                None => wfp::DEFAULT_PROXY_PORT_RANGE,
            };
            // The proxy PERMIT would open the port the fence check needs blocked.
            if allow_loopback && range.0 <= wfp::LOOPBACK_PROBE_PORT {
                return Err(anyhow!(
                    "invalid --proxy-port-range {}-{} with --allow-loopback: port {} \
                     stays blocked for the fence check",
                    range.0,
                    range.1,
                    wfp::LOOPBACK_PROBE_PORT,
                ));
            }
            if let Some(code) = maybe_self_elevate(args)? {
                std::process::exit(code);
            }
            let sl = resolve_sublayer(&sublayer_guid)?;
            let name = sandbox_user.as_deref().unwrap_or(user::SANDBOX_USER);
            // Idempotency / conflict pre-check. With a DIFFERENT
            // port-range, loopback mode or sandbox-user name
            // and no --force, refuse
            // (exit 13) so an unintended config drift surfaces
            // instead of silently overwriting. With the SAME config,
            // only return early when the install is COMPLETE — i.e.
            // the sandbox user is provisioned and the marker is
            // current. A partial install falls through and the
            // (idempotent) steps below complete it. A pre-existing
            // install whose tags lack a port_range (legacy) is
            // treated as "different" and requires --force.
            let existing = install::read_setup().ok().flatten();
            // Shared by the early-out completeness check and the
            // stamping step below (env reads + a stat per entry).
            let ambient_targets = srt_win::ambient::ambient_deny_targets();
            let name_changed = existing.as_ref().is_some_and(|s| s.sandbox_user != name);
            if !force
                && let Some(why) = existing
                    .as_ref()
                    .and_then(|s| install::newer_setup_refusal(s.marker_version))
            {
                eprintln!("srt-win: {why}");
                std::process::exit(13);
            }
            if !force
                && let Ok(st) = wfp::filter_status(&sl)
                && st.state == "installed"
            {
                let want = [range.0, range.1];
                if st.port_range != Some(want)
                    || st.allow_loopback != allow_loopback
                    || name_changed
                {
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
                         loopback={}, \
                         sandbox_user='{have_name}'; requested \
                         port_range={}-{}, loopback={}, \
                         sandbox_user='{name}'. \
                         Pass --force to replace, or run `srt-win \
                         uninstall` first.",
                        wfp::fmt_loopback(st.allow_loopback),
                        range.0,
                        range.1,
                        wfp::fmt_loopback(allow_loopback),
                    );
                    std::process::exit(13);
                }
                // Same config — early-out only if COMPLETE. The
                // ambient half is part of completeness (an install
                // that failed between the setup marker and the
                // stamps must fall through and finish; a drifted
                // ACE makes re-running install the repair), and is
                // checked last: it reads a DACL per target, so it
                // only runs once the cheap conjuncts pass.
                let us = user::status(name)?;
                let mv = existing.as_ref().map(|s| s.marker_version);
                let ambient_ok = || match &existing {
                    Some(s) => install::ambient_complete(&s.sandbox_user_sid, &ambient_targets),
                    None => false,
                };
                // The credential is part of completeness: a
                // missing/undecryptable Cred\Blob with a healthy
                // marker must fall through and be rewritten rather
                // than early-outing on "already installed".
                // So is the loopback mode: the filters and the record must
                // both have the one asked for.
                if us.exists
                    && us.in_sandbox_group
                    && mv == Some(install::SETUP_VERSION)
                    && st.state == "installed"
                    && st.allow_loopback == allow_loopback
                    && install::read_loopback_mode(&sl)
                        .ok()
                        .flatten()
                        .unwrap_or(false)
                        == allow_loopback
                    && install::cred_present()
                    && ambient_ok()
                {
                    // Re-assert the logon-type denials BEFORE the
                    // early-out: they must reach installs from
                    // binaries that predate them, and a domain GPO
                    // refresh can strip local LSA user-right
                    // assignments between runs. Idempotent and
                    // cheap; a failure falls through to the full
                    // (also idempotent) install steps.
                    if let Some(gsid) = us.group_sid.as_deref() {
                        if let Err(e) = user::apply_logon_denials(gsid) {
                            eprintln!(
                                "srt-win: warning: re-asserting logon denials: {e:#} — completing full install",
                            );
                        } else {
                            eprintln!(
                                "srt-win: already installed (sublayer={sl:?}, \
                         port_range={}-{}, sandbox_user='{name}', \
                         filters={}); no changes",
                                range.0, range.1, st.filters,
                            );
                            return Ok(());
                        }
                    }
                }
                match mv {
                    // An install by a build with another setup
                    // version: the same steps bring it to this one.
                    Some(v) if v != install::SETUP_VERSION => eprintln!(
                        "srt-win: existing install has setup version {v}; \
                         upgrading it to {}",
                        install::SETUP_VERSION,
                    ),
                    _ => eprintln!(
                        "srt-win: partial install detected \
                         (user_provisioned={}, marker_version={:?}) — \
                         completing",
                        us.exists, mv,
                    ),
                }
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
                // Machine store BEFORE write_setup: the dir must
                // exist with its install-owned ACLs before the
                // credential file is written into it.
                install::provision_machine_store(&pu.group_sid)
                    .context("provision machine state store")?;
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
            // Ambient write-deny stamps: Windows' stock world-
            // writable system dirs (`ambient.rs`), stamped
            // `(D;OICI;WriteDeny)` for the sandbox SID only and
            // recorded in the state DB so session recomposes and
            // crash recovery preserve them. Idempotent; runs before
            // the WFP step so a failure here leaves the install
            // visibly partial (filters absent) rather than
            // marker-complete with the stamps missing.
            match install::set_ambient_denies(&pu.sid, &ambient_targets) {
                Ok(r) if r.applied.is_empty() && !r.failed.is_empty() => {
                    // Every stamp failed — treat as a real install
                    // failure (per-path oddities are best-effort, a
                    // clean sweep of failures is not).
                    eprintln!(
                        "srt-win: error: ambient write-deny stamps: all \
                         {} target(s) failed (see warnings above)",
                        r.failed.len(),
                    );
                    std::process::exit(17);
                }
                Ok(r) => eprintln!(
                    "srt-win: ambient write-deny stamped on {} system \
                     path(s){}",
                    r.applied.len(),
                    if r.failed.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " ({} failed — recorded; `srt-win status` \
                             shows present:false)",
                            r.failed.len(),
                        )
                    },
                ),
                Err(e) => {
                    eprintln!("srt-win: error: ambient write-deny stamps: {e:#}");
                    std::process::exit(17);
                }
            }
            // A changing (or unreadable) loopback mode: make the record unusable
            // FIRST, or a failure could leave it beside filters of the other mode.
            let mode_kept = install::read_loopback_mode(&sl)
                .is_ok_and(|recorded| recorded.unwrap_or(false) == allow_loopback);
            if !mode_kept && let Err(e) = install::mark_loopback_mode_changing(&sl) {
                eprintln!("srt-win: error: mark the loopback mode as changing: {e:#}");
                std::process::exit(12);
            }
            if let Err(e) = wfp::install_filters(&sl, &pu.sid, range, allow_loopback) {
                eprintln!("srt-win: error: WFP install: {e:#}");
                std::process::exit(12);
            }
            // Only now that the filters are committed: the non-elevated
            // broker goes by this record, as it cannot enumerate them.
            if let Err(e) = install::write_loopback_mode(&sl, allow_loopback) {
                eprintln!("srt-win: error: record loopback mode: {e:#}");
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
                 proxy_port_range={}-{}, loopback={}, \
                 filters={})",
                range.0,
                range.1,
                wfp::fmt_loopback(allow_loopback),
                wfp::filter_count(allow_loopback),
            );
            if allow_loopback {
                eprintln!("srt-win: warning: {}", wfp::open_loopback_notice());
            }
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
            elevated_step,
        } => {
            // The group's SID is read while the install record is there:
            // this process forgets the grants after the removal.
            let ids = if keep_user || elevated_step {
                None
            } else {
                srt_win::persist::Ids::load().ok()
            };
            // Not from under a live session. Checked once: a session
            // that starts before the elevated step is not kept out.
            if !keep_user && !elevated_step {
                let holder = srt_win::state_db::HolderPid(std::process::id());
                srt_win::state_db::with_init_lock(holder, false, |db| {
                    exit_unless_quiet(db, None, EXIT_HELD_BY_OTHERS, "uninstall")
                })?;
            }
            let mut for_step: Vec<OsString> = args.to_vec();
            for_step.push("--elevated-step".into());
            if !elevated_step && let Some(code) = maybe_self_elevate(&for_step)? {
                use srt_win::persist::{AfterElevation, after_elevation};
                if keep_user {
                    // Nothing of the caller's goes with --keep-user.
                    std::process::exit(code);
                }
                // By what is true now, not by the step's word alone.
                let install_present = srt_win::install::read_setup()
                    .map(|s| s.is_some())
                    .unwrap_or(true);
                match after_elevation(code, install_present) {
                    AfterElevation::LeaveEverything(code) => {
                        eprintln!(
                            "srt-win: the elevated step did not remove the sandbox account \
                             (exit {code}). The grants kept for this user are unchanged."
                        );
                        std::process::exit(code);
                    }
                    AfterElevation::ForgetGrants { step_failed } => {
                        if let Some(code) = step_failed {
                            eprintln!(
                                "srt-win: the elevated step removed the sandbox account and \
                                 then reported a failure (exit {code}); the grants kept for \
                                 this user are removed all the same."
                            );
                        }
                        let forgot = forget_grants_after_removal(ids.as_ref(), keep_user);
                        std::process::exit(step_failed.unwrap_or(forgot));
                    }
                }
            }
            let sl = resolve_sublayer(&sublayer_guid)?;
            let n = remove_fence(&sl)?;
            // Read setup up front: the ambient cleanup and the
            // deprovision fallback both need the recorded name/SID
            // before clear_setup wipes them.
            let recorded = srt_win::install::read_setup().ok().flatten();
            let user_note = if keep_user {
                // Ambient write-deny stamps key on the ACCOUNT, not
                // the sublayer, and this uninstall may be tearing
                // down one sublayer of several (the smoke/TS suites
                // do exactly that) — so --keep-user keeps the
                // account's ambient floor along with the account.
                // The full (account-removing) branch below is what
                // takes the stamps off.
                "Sandbox user kept (--keep-user; ambient write-deny stamps kept with it)."
            } else {
                use srt_win::user;
                // Use the recorded name (may not be the default),
                // then deprovision BEFORE clear_setup so a failed
                // NetUserDel is retryable with the recorded name
                // still intact. No marker (partial install that
                // bailed before write_setup, or a stale/corrupt
                // state DB) → fall back to the default name so
                // SANDBOX_GROUP and any default-named account are
                // still cleaned up; deprovision is idempotent on
                // absent state.
                // Ambient write-deny stamps come off with the
                // account they key on. Best-effort per path: an ACL
                // failure on one system dir must not wedge the
                // uninstall; a failed removal keeps its row so
                // `status` surfaces it. Runs BEFORE deprovision so
                // the SID's ACEs are removed while the account still
                // resolves.
                if let Some(s) = &recorded {
                    match srt_win::install::clear_ambient_denies(&s.sandbox_user_sid) {
                        Ok(n) if n > 0 => {
                            eprintln!("srt-win: ambient write-deny removed from {n} system path(s)",)
                        }
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("srt-win: warning: ambient write-deny cleanup: {e:#}")
                        }
                    }
                }
                let name = recorded
                    .as_ref()
                    .map(|s| s.sandbox_user.clone())
                    .unwrap_or_else(|| user::SANDBOX_USER.into());
                user::deprovision(&name).context("deprovision sandbox user")?;
                srt_win::install::clear_setup().context("clear credential + setup marker")?;
                "Sandbox user, credential, and setup marker removed."
            };
            // Migration: best-effort remove the legacy
            // discriminator group if a prior install left it.
            // Idempotent on already-absent.
            let _ = srt_win::sam::delete_local_group("sandbox-runtime-net");
            eprintln!("srt-win: uninstalled ({n} filter(s) removed). {user_note}");
            // Started elevated by the user, so no hop: this process is
            // also the calling user's half.
            if !elevated_step {
                let code = forget_grants_after_removal(ids.as_ref(), keep_user);
                if code != 0 {
                    std::process::exit(code);
                }
            }
        }

        // ─── status (combined) ─────────────────────────────────────
        Cmd::Status { sublayer_guid } => {
            let sl = resolve_sublayer(&sublayer_guid)?;
            println!(
                "{}",
                json!({
                    "user": user_status_json()?,
                    "wfp": wfp_status(&sl)?,
                    "ambient": ambient_status_json()?,
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
            install::trust_ca(&der, &cred, &sb_sid).map_err(exit_if_seclogon_disabled)?;
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
            let st = wfp_status(&sl)?;
            println!("{}", serde_json::to_string(&st)?);
        }
        Cmd::Wfp {
            sub:
                WfpCmd::Verify {
                    target,
                    allow_loopback,
                    anonymous_target,
                    anonymous_egress,
                    write_restricted_token,
                    write_root,
                },
        } => {
            use srt_win::{install, logon, probe, runner};
            // With loopback open, `target` is the listener that must be reachable.
            if allow_loopback
                && !target
                    .parse::<std::net::SocketAddr>()
                    .is_ok_and(|a| a.ip().is_loopback())
            {
                return Err(anyhow!(
                    "wfp verify: with --allow-loopback, --target must be a                      loopback listener (`127.0.0.1:<port>`), got '{target}'"
                ));
            }
            // The host passes a loopback listener outside the permit range, so
            // a MISSING fence connects where an active one gives WSAEACCES.
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
            fn finish(doc: serde_json::Value, exit: i32) -> ! {
                println!("{doc}");
                // Explicit flush: this arm prints to stdout and then
                // `process::exit`s instead of returning Ok(()).
                let _ = std::io::Write::flush(&mut std::io::stdout());
                std::process::exit(exit)
            }
            // `allow_loopback_mismatch` tells the host that the repair
            // is an install with THIS session's loopback mode.
            if let Err(hint) = install::require_allow_loopback(allow_loopback) {
                eprintln!("srt-win: error: wfp verify: {hint}");
                finish(
                    json!({
                        "egress_probe": "not-run",
                        "target": target,
                        "allow_loopback_mismatch": true,
                        "allow_loopback": allow_loopback,
                        "hint": hint,
                    }),
                    probe::EXIT_LOOPBACK_MISMATCH,
                );
            }
            let anonymous_target = anonymous_target.or_else(|| {
                let port = target.parse::<std::net::SocketAddr>().ok()?.port();
                probe::off_loopback_target(port).map(|a| a.to_string())
            });
            // Where the plain attempt goes: the reserved port when loopback is open.
            let egress_target = if allow_loopback {
                probe::blocked_loopback_target().to_string()
            } else {
                target.clone()
            };
            // Write-restricted: the runner launches `probe egress` as a
            // lockdown child, so the connects are made under the child token.
            let cmd = if write_restricted_token {
                // A root with no capability SID fails the verify — never
                // a probe under a shorter list.
                let capability_sids = srt_win::persist::capability_sids_for(&write_root)
                    .context("wfp verify --write-root")?;
                let exe = std::env::current_exe().context("current_exe")?;
                let exe = exe
                    .to_str()
                    .ok_or_else(|| anyhow!("current_exe is not UTF-8"))?;
                let mut argv = vec![
                    exe.to_owned(),
                    SRT_WIN_DISPATCH_ARG1.to_owned(),
                    "probe".to_owned(),
                    "egress".to_owned(),
                    "--target".to_owned(),
                    target.clone(),
                ];
                if let Some(a) = &anonymous_target {
                    argv.extend(["--anonymous-target".to_owned(), a.clone()]);
                }
                if anonymous_egress {
                    argv.push("--anonymous-egress".to_owned());
                }
                if allow_loopback {
                    argv.push("--allow-loopback".to_owned());
                }
                runner::RunnerCmd::Exec(runner::RunnerSpec {
                    argv,
                    env_overlay: Vec::new(),
                    write_restricted_token: true,
                    capability_sids,
                })
            } else {
                runner::RunnerCmd::ProbeEgress {
                    target: target.clone(),
                    anonymous_target: anonymous_target.clone(),
                    anonymous_egress,
                    allow_loopback,
                }
            };
            let code = logon::spawn_runner(&cred.user, &cred.pw, &sb_sid, None, &cmd, false, None)
                .map_err(exit_if_seclogon_disabled)
                .context("spawn runner for egress probe")?;
            let Some(report) = probe::Report::decode(code) else {
                // Not a report: exit 1 is the runner's own `Err` path, and
                // anything else is an unmapped runner state.
                finish(
                    json!({
                        "egress_probe": "error",
                        "anonymous_probe": "error",
                        "anonymous_loopback_probe": "error",
                        "deny_only_probe": "error",
                        "low_integrity_probe": "error",
                        "low_integrity_loopback_probe": "error",
                        "untrusted_integrity_probe": "error",
                        "untrusted_integrity_loopback_probe": "error",
                        "open_loopback_probe": "error",
                        "target": target,
                        "egress_target": egress_target,
                        "anonymous_target": anonymous_target,
                        "allow_loopback": allow_loopback,
                        "residuals": [],
                        "runner_exit": code,
                    }),
                    1,
                );
            };
            let verdict = probe::verdict(&report, allow_loopback);
            for residual in &verdict.residuals {
                eprintln!(
                    "srt-win: warning: wfp verify: residual '{residual}': {}",
                    match *residual {
                        probe::RESIDUAL_ANONYMOUS_EGRESS =>
                            "a connect to an off-loopback destination made \
                             while impersonating the anonymous token is not \
                             blocked: no filter is keyed on that token \
                             (see the per-ordering lines above)",
                        probe::RESIDUAL_ANONYMOUS_LOOPBACK =>
                            "a connect to a loopback destination made while \
                             impersonating the anonymous token is not blocked \
                             (see the per-ordering lines above)",
                        probe::RESIDUAL_LOWERED_INTEGRITY_UNPROBED =>
                            "a lowered-integrity copy of the sandbox token \
                             could not be set up, so no connect under it was \
                             observed (see the per-ordering lines above)",
                        _ =>
                            "a connect made under a copy of the sandbox token \
                             whose user SID is deny-only is not blocked \
                             (see the per-ordering lines above)",
                    },
                );
            }
            let mut doc = json!({
                "egress_probe": report.plain.label(),
                "anonymous_probe": report.anonymous.label(),
                "anonymous_loopback_probe": report.anonymous_loopback.label(),
                "deny_only_probe": report.deny_only.label(),
                "low_integrity_probe": report.low_integrity.label(),
                "low_integrity_loopback_probe": report.low_integrity_loopback.label(),
                "untrusted_integrity_probe": report.untrusted_integrity.label(),
                "untrusted_integrity_loopback_probe":
                    report.untrusted_integrity_loopback.label(),
                "open_loopback_probe": report.open_loopback.label(),
                "target": target,
                "egress_target": egress_target,
                "anonymous_target": anonymous_target,
                "allow_loopback": allow_loopback,
                "residuals": verdict.residuals,
                "runner_exit": code,
            });
            if write_restricted_token {
                doc["write_restricted_token"] = json!(true);
            }
            // Loopback is open: whatever the probes say about direct
            // egress, say what else is reachable.
            if allow_loopback {
                let notice = wfp::open_loopback_notice();
                eprintln!("srt-win: warning: wfp verify: {notice}");
                doc["loopback_notice"] = json!(notice);
            }
            // Recorded open, yet the connect to the loopback listener was
            // blocked: the filters in place are not the recorded ones.
            if verdict.exit == probe::EXIT_LOOPBACK_MISMATCH {
                let hint = wfp::loopback_closed_hint();
                eprintln!("srt-win: error: wfp verify: {hint}");
                doc["allow_loopback_mismatch"] = json!(true);
                doc["hint"] = json!(hint);
            }
            finish(doc, verdict.exit);
        }
        Cmd::Wfp {
            sub: WfpCmd::Uninstall { sublayer_guid },
        } => {
            if let Some(code) = maybe_self_elevate(args)? {
                std::process::exit(code);
            }
            let sl = resolve_sublayer(&sublayer_guid)?;
            let n = remove_fence(&sl)?;
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
                        &[],
                    )?;
                    for (p, e) in &at.bad_inputs {
                        eprintln!("srt-win: skipped: '{p}': {e}");
                    }
                    let (w, f) =
                        db.apply_aces_and(&sandbox_user_sid, &at.targets, &at.also_read_deny)?;
                    Ok((at, w, f))
                })?;
            let AceTargets {
                targets,
                bad_inputs,
                ..
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
                    persistent,
                    allow_profile_exclusion,
                },
        } => {
            use srt_win::{acl, persist, state_db};
            let holder = state_db::HolderPid(holder_pid);
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).context("read stdin")?;
            // Kept grants are made only on an install of this build's setup
            // version; checked before the session database is opened.
            if persistent && let Err(e) = srt_win::install::require_current_setup() {
                eprintln!("srt-win: error: acl grant --persistent: {e:#}");
                std::process::exit(15);
            }
            let input: AclGrantInput =
                serde_json::from_str(&buf).context("parse stdin JSON {read:[…], write:[…]}")?;
            let has_denies = !input.deny_read.is_empty() || !input.deny_write.is_empty();
            if has_denies && !persistent {
                return Err(anyhow!(
                    "acl grant: denyRead/denyWrite are read only with --persistent; \
                     use `acl stamp`"
                ));
            }
            let ((at, witnesses, failed, kept), report) =
                state_db::with_init_lock(holder, false, |db| {
                    let mut at = canonicalize_ace_targets(
                        db,
                        "grant",
                        &[
                            (&input.read, acl::SbAce::Grant(acl::GrantMask::ReadOnly)),
                            (&input.write, acl::SbAce::Grant(acl::GrantMask::Modify)),
                        ],
                        &[],
                    )?;
                    // At every session start, for every path, kept roots included:
                    // no grant may reach what the profile read grant excludes.
                    let grants: Vec<(String, bool)> = at
                        .targets
                        .iter()
                        .filter_map(|(p, a)| match a {
                            acl::SbAce::Grant(m) => Some((p.clone(), *m == acl::GrantMask::Modify)),
                            _ => None,
                        })
                        .collect();
                    srt_win::profile::check_session_grants(&grants, &allow_profile_exclusion)?;
                    if !persistent {
                        // These grants are for the ordinary token.
                        let paths: Vec<String> =
                            at.targets.iter().map(|(p, _)| p.clone()).collect();
                        persist::clear_for_unrestricted_grant(db, &paths)?;
                        for (p, e) in &at.bad_inputs {
                            eprintln!("srt-win: skipped: '{p}': {e}");
                        }
                        let (w, f) = db.apply_aces(&sandbox_user_sid, &at.targets)?;
                        // A session exists from here: recorded, so that the profile
                        // grant is not made or removed beside it.
                        db.hold_kept(&[], Some(state_db::KEPT_PROFILE_PATH))?;
                        return Ok((at, w, f, None));
                    }
                    let ids = persist::Ids::load()?;
                    if ids.sandbox_user_sid.as_deref() != Some(sandbox_user_sid.as_str()) {
                        return Err(anyhow!(
                            "--sandbox-user-sid {sandbox_user_sid} is not the installed \
                             sandbox user"
                        ));
                    }
                    // A read deny is not carried onto a recorded profile path
                    // that this same call allows more specifically.
                    let allowed: Vec<String> = grants.iter().map(|(p, _)| p.clone()).collect();
                    let denies = canonicalize_ace_targets(
                        db,
                        "deny",
                        &[
                            (&input.deny_read, acl::SbAce::Deny(acl::DenyMask::ReadDeny)),
                            (
                                &input.deny_write,
                                acl::SbAce::Deny(acl::DenyMask::WriteDeny),
                            ),
                        ],
                        &allowed,
                    )?;
                    at.bad_inputs.extend(denies.bad_inputs);
                    for (p, e) in &at.bad_inputs {
                        eprintln!("srt-win: skipped: '{p}': {e}");
                    }
                    let modify = acl::SbAce::Grant(acl::GrantMask::Modify);
                    let roots: Vec<String> = at
                        .targets
                        .iter()
                        .filter(|(_, a)| *a == modify)
                        .map(|(p, _)| p.clone())
                        .collect();
                    let (kept, per_session_denies) =
                        persist::apply(db, &ids, &roots, &denies.targets)?;
                    // The session row is taken whether or not a profile
                    // grant is recorded: none is made or changed beside it.
                    db.hold_kept(&roots, Some(state_db::KEPT_PROFILE_PATH))?;
                    // Per session, for the sandbox user SID: the read
                    // grants, and the denies under no persistent root.
                    let mut rest: Vec<(String, acl::SbAce)> = at
                        .targets
                        .iter()
                        .filter(|(_, a)| *a != modify)
                        .cloned()
                        .collect();
                    rest.extend(per_session_denies);
                    // Plus, for this session only, a read deny on each recorded
                    // profile path those denies cover; never kept with a root.
                    let (w, f) =
                        db.apply_aces_and(&sandbox_user_sid, &rest, &denies.also_read_deny)?;
                    at.targets.extend(denies.targets);
                    Ok((at, w, f, Some(kept)))
                })?;
            let AceTargets {
                targets,
                bad_inputs,
                ..
            } = at;
            let fresh = witnesses.iter().filter(|w| !w.already).count();
            if let Some(k) = kept {
                // `DACL write(s)` counts tree walks: 0 once every root is
                // granted. Object-only writes are counted apart.
                eprintln!(
                    "srt-win: acl grant (persistent) — {} root(s): {} DACL write(s), \
                     {} path(s) unchanged, {} written without a walk of the tree",
                    k.roots, k.writes, k.unchanged, k.local_writes,
                );
            }
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
                AclCmd::Forget {
                    all,
                    json,
                    unless_held_by_others,
                    drop_pending,
                    force,
                    roots,
                },
        } => {
            use srt_win::{path_id, persist, state_db};
            if !drop_pending.is_empty() {
                let holder = state_db::HolderPid(std::process::id());
                let ids = persist::Ids::load()?;
                let (dropped, _) = state_db::with_init_lock(holder, false, |db| {
                    persist::drop_pending(db.conn(), &ids, &drop_pending)
                })?;
                for p in &dropped {
                    eprintln!(
                        "srt-win: no longer waiting for the volume of '{}'. The entries the \
                         kept grant wrote on that object (for the group {}) were NOT removed \
                         and will not be: if the volume is ever attached again, they are \
                         still on it.",
                        p.path,
                        if p.group_sid.is_empty() {
                            "that was installed then"
                        } else {
                            p.group_sid.as_str()
                        },
                    );
                }
                if json {
                    let entries: Vec<AceReleaseEntry> = dropped
                        .iter()
                        .map(|p| AceReleaseEntry {
                            path: p.path.clone(),
                            status: "abandoned",
                        })
                        .collect();
                    serde_json::to_writer(std::io::stdout(), &entries)
                        .context("write --json forget result")?;
                    println!();
                }
                return Ok(());
            }
            if !all && roots.is_empty() {
                return Err(anyhow!(
                    "acl forget: name the roots to forget, or pass --all"
                ));
            }
            let ids = persist::Ids::load()?;
            // No holder of its own: the PID is this process's, unless
            // the caller says whose session is asking.
            let holder =
                state_db::HolderPid(unless_held_by_others.unwrap_or_else(std::process::id));
            let (out, _report) = state_db::with_init_lock(holder, false, |db| {
                // A root that no longer resolves is looked up as
                // given: it may be recorded under that spelling.
                let targets: Vec<String> = roots
                    .iter()
                    .map(|r| {
                        path_id::canonicalize_path(r)
                            .map(|(c, _)| c)
                            .unwrap_or_else(|_| r.clone())
                    })
                    .collect();
                if unless_held_by_others.is_some() {
                    exit_if_roots_held_by_others(db)?;
                }
                persist::forget(db, &ids, &targets, all, force)
            })?;
            let failed = out
                .iter()
                .filter(|(_, r)| matches!(r, persist::Forgot::Failed(_)))
                .count();
            let pending = out
                .iter()
                .filter(|(_, r)| *r == persist::Forgot::Pending)
                .count();
            let dropped = out
                .iter()
                .filter(|(_, r)| *r == persist::Forgot::Dropped)
                .count();
            eprintln!(
                "srt-win: acl forget — {} root(s){}{}{}",
                out.len(),
                if failed > 0 {
                    format!(", {failed} FAILED (still recorded)")
                } else {
                    String::new()
                },
                if pending > 0 {
                    format!(", {pending} on a volume that is not mounted (removed when it is back)")
                } else {
                    String::new()
                },
                if dropped > 0 {
                    format!(", {dropped} DROPPED (not located; ACEs may remain)")
                } else {
                    String::new()
                },
            );
            if json {
                let entries: Vec<AceReleaseEntry> = out
                    .iter()
                    .map(|(p, r)| AceReleaseEntry {
                        path: p.clone(),
                        status: r.as_str(),
                    })
                    .collect();
                serde_json::to_writer(std::io::stdout(), &entries)
                    .context("write --json forget result")?;
                println!();
            }
            if failed > 0 {
                return Err(anyhow!(
                    "acl forget: {failed} persistent grant(s) could not be removed"
                ));
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
                // The session is ending: it no longer runs on the
                // kept grants either.
                db.release_kept()?;
                db.release_aces(&sandbox_user_sid, state_db::KIND_GRANT)
            })?;
            // Grants whose ACE may still be on disk (rows kept).
            let pending: Vec<&str> = entries
                .iter()
                .filter(|(_, r)| r.is_pending())
                .map(|(p, _)| p.as_str())
                .collect();
            eprintln!(
                "srt-win: acl revoke — {} path(s){}; recovery \
                 revoked {} orphan grant(s)",
                entries.len(),
                if pending.is_empty() {
                    String::new()
                } else {
                    format!(", {} NOT RELEASED (ACE left in place)", pending.len())
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
            if failed > 0 || !pending.is_empty() {
                return Err(anyhow!(
                    "acl revoke: {} grant(s) could not be released \
                     and may still be on disk (rows kept for retry): {}",
                    pending.len(),
                    quoted_list(&pending),
                ));
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
            // Denies whose ACE is still on disk (rows kept).
            let kept = entries.iter().filter(|(_, r)| r.is_pending()).count();
            let grant_pending = entries
                .iter()
                .any(|(_, r)| *r == state_db::AceRelease::GrantPending);
            eprintln!(
                "srt-win: acl restore (deny-ace) — {} ACE(s){}; \
                 recovery revoked {} orphan ACE(s)",
                entries.len(),
                if kept > 0 {
                    format!(", {kept} NOT RELEASED (ACE left in place)")
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
            if grant_pending {
                return Err(anyhow!(
                    "acl restore: refused — the holder still has a grant \
                     recorded; run `acl revoke` first (deny ACEs kept)"
                ));
            }
            if failed > 0 || kept > 0 {
                return Err(anyhow!(
                    "acl restore: {kept} path(s) could not be \
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
                 revoked {} orphan ACE(s){}",
                report.dead_brokers,
                report.aces_revoked,
                if report.grants_dropped.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; dropped the record of {} grant(s) that could not \
                         be located: {}",
                        report.grants_dropped.len(),
                        quoted_list(&report.grants_dropped),
                    )
                },
            );
            if json {
                println!(
                    "{}",
                    json!({
                        "deadBrokers": report.dead_brokers,
                        "acesRevoked": report.aces_revoked,
                        "grantsPending": report.grants_pending,
                        "grantsDropped": report.grants_dropped,
                    })
                );
            }
            if !report.grants_pending.is_empty() {
                return Err(anyhow!(
                    "acl recover: {} grant(s) could not be released \
                     and may still be on disk (rows, and their \
                     holders' deny ACEs, kept for retry): {}",
                    report.grants_pending.len(),
                    quoted_list(&report.grants_pending),
                ));
            }
        }

        // ─── profile ───────────────────────────────────────────────
        Cmd::Profile {
            sub:
                ProfileCmd::Grant {
                    exclude,
                    replace_excludes,
                    json,
                    quiet,
                    #[cfg(feature = "test-hooks")]
                    test_profile,
                },
        } => {
            use srt_win::{persist, profile, state_db};
            #[cfg(not(feature = "test-hooks"))]
            let test_profile: Option<String> = None;
            #[cfg(feature = "test-hooks")]
            let test_profile = test_profile.or_else(test_profile_from_env);
            // A service account runs no sessions: its profile gets no grant.
            let me = srt_win::sid::current_user_sid()?;
            if test_profile.is_none() && is_service_account(&me) {
                eprintln!(
                    "srt-win: error: profile grant: running as the service account {me}; \
                     run it as the user whose sessions are to read their profile"
                );
                std::process::exit(21);
            }
            // As for a kept write grant: only on an install of this
            // build's setup version, checked before any state exists.
            if let Err(e) = srt_win::install::require_current_setup() {
                eprintln!("srt-win: error: profile grant: {e:#}");
                std::process::exit(15);
            }
            let ids = persist::Ids::load()?;
            let layout = profile::Layout::resolve(test_profile.as_deref())?;
            // Exclusive: under the one lock for the whole run, and only
            // while no live session or command holds anything.
            let report = state_db::with_profile_lock(|db| {
                exit_unless_quiet(db, None, EXIT_GRANT_BLOCKED_BY_SESSION, "profile grant")?;
                state_db::mark_profile_operation()?;
                profile::grant(
                    &profile::Store::of(db.conn()),
                    &ids,
                    &layout,
                    &exclude,
                    replace_excludes,
                    !quiet,
                )
            })?;
            for s in &report.skipped {
                eprintln!("srt-win: profile grant: skipped '{}': {}", s.path, s.reason);
            }
            for r in &report.forgotten_roots {
                eprintln!(
                    "srt-win: profile grant: the write grant kept on '{}' was removed: {}",
                    r.path, r.reason
                );
            }
            for v in &report.env_ignored {
                eprintln!(
                    "srt-win: profile grant: {v} is a relative path and names no store to \
                     protect; ignored"
                );
            }
            for (what, items) in [
                ("not granted", &report.not_granted),
                (
                    "excluded, closed by its own access list",
                    &report.self_closed,
                ),
                ("excluded, could not be examined", &report.unverifiable),
                ("EXCLUDED BUT READABLE", &report.unprotected),
                (
                    "STILL READABLE THROUGH AN EARLIER ENTRY",
                    &report.stale_allow,
                ),
            ] {
                for i in items {
                    eprintln!("srt-win: profile grant: {what}: '{}': {}", i.path, i.reason);
                }
            }
            eprintln!(
                "srt-win: profile grant — '{}': {} container(s), {} directory(ies) and {} \
                 file(s) granted, {} excluded ({} created), {} skipped, {} not granted, {} \
                 exclusion(s) without a deny ({} of them readable to the sandbox account); \
                 {} DACL write(s), {} written without a walk of the tree, {} unchanged, \
                 {} stale removed; {} ms",
                report.profile,
                report.containers,
                report.granted,
                report.files,
                report.denied,
                report.placeholders,
                report.skipped.len(),
                report.not_granted.len(),
                report.self_closed.len() + report.unverifiable.len() + report.unprotected.len(),
                report.unprotected.len(),
                report.tree_walks,
                report.local_writes,
                report.unchanged,
                report.removed,
                report.elapsed_ms,
            );
            if json {
                println!("{}", serde_json::to_string(&report)?);
            }
        }
        Cmd::Profile {
            sub:
                ProfileCmd::Forget {
                    json,
                    unless_held_by_others,
                },
        } => {
            use srt_win::{persist, profile, state_db};
            let ids = persist::Ids::load()?;
            // As the grant, except that the session that asks is not counted.
            let out = state_db::with_profile_lock(|db| {
                exit_unless_quiet(
                    db,
                    unless_held_by_others,
                    EXIT_HELD_BY_OTHERS,
                    "profile forget",
                )?;
                state_db::mark_profile_operation()?;
                profile::forget(&profile::Store::of(db.conn()), &ids)
            })?;
            eprintln!(
                "srt-win: profile forget — {} path(s) cleared, {} carried nothing, {} empty \
                 directory(ies) removed{}",
                out.removed,
                out.absent,
                out.placeholders_removed,
                if out.failed.is_empty() {
                    String::new()
                } else {
                    format!(", {} FAILED (still recorded)", out.failed.len())
                },
            );
            if json {
                println!("{}", serde_json::to_string(&out)?);
            }
            if !out.failed.is_empty() {
                return Err(anyhow!(
                    "profile forget: {} path(s) could not be completed",
                    out.failed.len()
                ));
            }
        }
        Cmd::Profile {
            sub:
                ProfileCmd::Status {
                    paths,
                    #[cfg(feature = "test-hooks")]
                    test_profile,
                },
        } => {
            use srt_win::{persist, profile};
            #[cfg(not(feature = "test-hooks"))]
            let test_profile: Option<String> = None;
            #[cfg(feature = "test-hooks")]
            let test_profile = test_profile.or_else(test_profile_from_env);
            // While a grant or forget runs the record is half-written by
            // design: not to be read as a run that was killed.
            let mut status = if srt_win::state_db::profile_operation_running() {
                json!({ "state": "in_progress" })
            } else {
                profile::status_json(
                    persist::MARKER_KEY,
                    profile::Layout::resolve(test_profile.as_deref()),
                    paths,
                )
            };
            // Whatever the state: what this build does, by name.
            if let Some(o) = status.as_object_mut() {
                o.insert("capabilities".to_owned(), json!(profile::CAPABILITIES));
            }
            println!("{status}");
        }

        // ─── runner ────────────────────────────────────────────────
        Cmd::Runner => {
            let code = srt_win::runner::run()?;
            std::process::exit(code as i32);
        }

        // ─── probe ─────────────────────────────────────────────────
        Cmd::Probe {
            sub: ProbeCmd::Connect { target },
        } => {
            let code = srt_win::probe::connect(&target)?;
            std::process::exit(code as i32);
        }
        Cmd::Probe {
            sub:
                ProbeCmd::Egress {
                    target,
                    anonymous_target,
                    anonymous_egress,
                    allow_loopback,
                },
        } => {
            let report = srt_win::probe::run(
                &target,
                anonymous_target.as_deref(),
                anonymous_egress,
                allow_loopback,
            )?;
            std::process::exit(report.encode() as i32);
        }
        #[cfg(feature = "test-hooks")]
        Cmd::Probe {
            sub: ProbeCmd::Token,
        } => {
            let t = srt_win::token::own_token_restriction()?;
            println!("{}", serde_json::to_string(&t)?);
        }
        #[cfg(feature = "test-hooks")]
        Cmd::Probe {
            sub: ProbeCmd::ParentAccess,
        } => {
            let r = srt_win::probe::parent_access()?;
            println!("{}", serde_json::to_string(&r)?);
        }

        // ─── exec ──────────────────────────────────────────────────
        Cmd::Exec {
            allow_loopback,
            deny_read,
            deny_read_except,
            held_by,
            deny_write,
            env,
            quiet,
            write_restricted_token,
            write_root,
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
                        "srt-win: error: the sandbox install cannot be \
                         used ({e:#}). Run `srt-win install` (one UAC \
                         prompt)."
                    );
                    std::process::exit(15);
                }
            };

            // A Secondary Logon service that cannot launch is reported
            // here, before anything is stamped or granted for the command.
            {
                use srt_win::logon::{SeclogonDisabled, SeclogonState, seclogon_state};
                let state = seclogon_state();
                if matches!(state, SeclogonState::Disabled | SeclogonState::Missing) {
                    let missing = state == SeclogonState::Missing;
                    return Err(exit_if_seclogon_disabled(
                        SeclogonDisabled { missing }.into(),
                    ));
                }
            }

            // Without the flag nothing may run while a persistent grant
            // exists: its sandbox-group ACE is all the ordinary token needs.
            let capability_sids = if write_restricted_token {
                srt_win::persist::capability_sids_for(&write_root).context("exec --write-root")?
            } else if let Some(why) = srt_win::persist::unrestricted_block_reason() {
                eprintln!(
                    "srt-win: error: refusing to run without \
                     --write-restricted-token: {why}. Grants kept between \
                     sessions are made for that token only: a kept write \
                     grant lets the sandbox account write its tree under the \
                     ordinary one. Remove them first: `srt-win acl forget \
                     --all` (write grants), `srt-win profile forget` (profile \
                     read grant)."
                );
                std::process::exit(20);
            } else {
                Vec::new()
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

            // The non-elevated broker cannot enumerate filters; the recorded
            // loopback mode is what it can check before launching.
            if let Err(hint) = install::require_allow_loopback(allow_loopback) {
                eprintln!(
                    "{}",
                    json!({ "code": "wfp_loopback_mismatch", "message": hint })
                );
                std::process::exit(srt_win::probe::EXIT_LOOPBACK_MISMATCH);
            }

            // A named session is verified and WATCHED. Not recorded, or gone,
            // this process holds for itself: it lives as long as the command.
            let session = match held_by {
                Some(pid) => srt_win::state_db::watch_session(pid)?,
                None => None,
            };
            let self_hold: Option<Vec<String>> = session.is_none().then(|| {
                write_root
                    .iter()
                    .filter_map(|r| srt_win::path_id::canonicalize_path(r).ok())
                    .map(|(canon, _)| canon)
                    .collect()
            });
            let hold_for_self = |db: &srt_win::state_db::Locked| -> anyhow::Result<()> {
                match &self_hold {
                    Some(roots) => db.hold_kept(roots, Some(srt_win::state_db::KEPT_PROFILE_PATH)),
                    None => Ok(()),
                }
            };
            let per_exec_guard = if deny_read.is_empty() && deny_write.is_empty() {
                if self_hold.is_some() {
                    let own = srt_win::state_db::HolderPid(std::process::id());
                    // No crash recovery here: starting a command must not release
                    // what a holder that is gone left behind.
                    srt_win::state_db::with_init_lock_unrecovered(own, |db| hold_for_self(db))
                        .context("hold the kept grants for this command")?;
                }
                None
            } else {
                use srt_win::{acl, state_db};
                let own = state_db::HolderPid(std::process::id());
                let deny_read_except: Vec<String> = deny_read_except
                    .iter()
                    .filter_map(|p| srt_win::path_id::canonicalize_path(p).ok())
                    .map(|(canon, _)| canon)
                    .collect();
                let ((at, _w, failed), _r) = state_db::with_init_lock(own, false, |db| {
                    // The same acquisition takes the hold.
                    hold_for_self(db)?;
                    let at = canonicalize_ace_targets(
                        db,
                        "deny",
                        &[
                            (&deny_read, acl::SbAce::Deny(acl::DenyMask::ReadDeny)),
                            (&deny_write, acl::SbAce::Deny(acl::DenyMask::WriteDeny)),
                        ],
                        &deny_read_except,
                    )?;
                    if let Some((p, e)) = at.bad_inputs.first() {
                        return Err(anyhow!("per-exec --deny-*: '{p}': {e}"));
                    }
                    let (w, f) = db.apply_aces_and(&sb_sid, &at.targets, &at.also_read_deny)?;
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
                    write_restricted_token,
                    capability_sids,
                }),
                quiet,
                session.as_ref().map(|h| h.raw()),
            ) {
                Ok(c) => c,
                // The session ended first: the tree is gone. What this
                // command held is released, and the caller is told.
                Err(e) if e.is::<logon::HolderGone>() => {
                    drop(per_exec_guard);
                    eprintln!("srt-win: error: {e}");
                    eprintln!(
                        "{}",
                        json!({ "code": "session_ended", "message": e.to_string() })
                    );
                    std::process::exit(EXIT_SESSION_ENDED);
                }
                Err(e) => {
                    // Same one-line JSON shape as below, exit 18. The per-exec
                    // restore runs first: `process::exit` skips destructors.
                    if let Some(j) = seclogon_error_json(&e) {
                        eprintln!("{j}");
                        drop(per_exec_guard);
                        std::process::exit(EXIT_SECLOGON_DISABLED);
                    }
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

/// `SRT_WIN_TEST_PROFILE`, for a `test-hooks` build whose caller
/// cannot pass `--test-profile` (the library, driven by a test suite).
#[cfg(feature = "test-hooks")]
fn test_profile_from_env() -> Option<String> {
    std::env::var("SRT_WIN_TEST_PROFILE")
        .ok()
        .filter(|s| !s.is_empty())
}

/// `session_user_sid` of `user status`. A `test-hooks` build that was
/// given a made-up profile has no session owner to compare it with,
/// and reports the caller.
fn session_user_sid_for_status() -> Option<String> {
    #[cfg(feature = "test-hooks")]
    if test_profile_from_env().is_some() {
        return srt_win::sid::current_user_sid().ok();
    }
    srt_win::profile::session_user_sid()
}

/// LocalSystem, LocalService or NetworkService.
fn is_service_account(sid: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20")
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

/// Exit code of `profile grant` when any live session or command
/// holds anything: nothing was written. The grant changes the
/// profile's entries only on a quiet machine.
const EXIT_GRANT_BLOCKED_BY_SESSION: i32 = 24;

/// Exit code of `exec` when the session named with `--held-by` ended
/// while the command ran: the command and everything it started were
/// terminated. (25 is `state_db::EXIT_PROFILE_BUSY`.)
const EXIT_SESSION_ENDED: i32 = 26;

/// Exit code of `acl forget` / `profile forget` with
/// `--unless-held-by-others` when another live session runs on a kept
/// grant: nothing was removed.
const EXIT_HELD_BY_OTHERS: i32 = 22;

/// For an operation that needs a quiet machine: if any live session or
/// command other than `except` holds anything, print `{"held_by": […]}`
/// on stdout and exit `code` with nothing changed. Call under the lock.
fn exit_unless_quiet(
    db: &srt_win::state_db::Locked,
    except: Option<u32>,
    code: i32,
    what: &str,
) -> anyhow::Result<()> {
    let held = srt_win::state_db::live_holders(db, except)?;
    if held.is_empty() {
        return Ok(());
    }
    let mut pids: Vec<u32> = held.iter().map(|h| h.pid).collect();
    pids.dedup();
    eprintln!(
        "srt-win: error: {what}: {} sandbox session(s) or command(s) are running (process {}). \
         Nothing was changed; end them and run it again.",
        pids.len(),
        pids.iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    );
    println!("{}", serde_json::json!({ "held_by": held }));
    std::process::exit(code);
}

/// Under the init lock: if a live session other than the lock's holder
/// runs on a kept write root, print `{"held_by": […]}` and exit
/// [`EXIT_HELD_BY_OTHERS`] before anything is removed.
fn exit_if_roots_held_by_others(db: &srt_win::state_db::Locked) -> anyhow::Result<()> {
    use srt_win::state_db::KIND_KEPT_ROOT;
    // Only holds on what is about to be removed count.
    let held: Vec<_> = db
        .other_kept_holders()?
        .into_iter()
        .filter(|h| h.kind == KIND_KEPT_ROOT)
        .collect();
    if held.is_empty() {
        return Ok(());
    }
    for h in &held {
        eprintln!(
            "srt-win: a live session (pid {}) is running on the kept write grant on '{}'",
            h.pid, h.path
        );
    }
    eprintln!("srt-win: nothing was removed");
    println!("{}", serde_json::json!({ "held_by": held }));
    std::process::exit(EXIT_HELD_BY_OTHERS);
}

/// Exit code of `uninstall` when the machine-wide removal succeeded
/// and the calling user's grants could not all be forgotten: they stay
/// recorded, and `acl forget --all` / `profile forget` finish the job.
const EXIT_GRANTS_NOT_FORGOTTEN: i32 = 23;

/// The calling user's half of `uninstall`, after the machine-wide removal:
/// forget their profile read grant and kept write grants. Returns 0, or
/// [`EXIT_GRANTS_NOT_FORGOTTEN`] when something stays recorded.
fn forget_grants_after_removal(ids: Option<&srt_win::persist::Ids>, keep_user: bool) -> i32 {
    if keep_user {
        return 0;
    }
    let mut incomplete = false;
    match srt_win::profile::forget_everything_as(ids) {
        Ok(None) => {}
        Ok(Some(f)) if f.failed.is_empty() => eprintln!(
            "srt-win: profile read grant removed ({} path(s))",
            f.removed + f.absent
        ),
        Ok(Some(f)) => {
            incomplete = true;
            eprintln!(
                "srt-win: WARNING: the profile read grant could not be removed from {} \
                 path(s), which stay recorded; run `srt-win profile forget`",
                f.failed.len()
            );
        }
        Err(e) => {
            incomplete = true;
            eprintln!("srt-win: WARNING: profile read grant not removed: {e:#}");
        }
    }
    match srt_win::persist::forget_everything_as(ids) {
        Ok(f) => {
            if f.roots > 0 && f.failed == 0 {
                eprintln!(
                    "srt-win: persistent write grants removed from {} root(s)",
                    f.roots - f.pending.len()
                );
            }
            if f.failed > 0 {
                incomplete = true;
                eprintln!(
                    "srt-win: WARNING: {} of {} persistent write grant(s) could not be \
                     removed and stay recorded; run `srt-win acl forget --all`",
                    f.failed, f.roots
                );
            }
            if !f.pending.is_empty() {
                eprintln!(
                    "srt-win: NOTE: {} grant(s) are on volumes that are not mounted and are \
                     still on disk there. They stay recorded and are removed by `srt-win acl \
                     forget --all` once the volume is back:",
                    f.pending.len()
                );
                for p in &f.pending {
                    eprintln!("srt-win:   {p}");
                }
            }
        }
        Err(e) => {
            incomplete = true;
            eprintln!("srt-win: WARNING: persistent write grants not removed: {e:#}");
        }
    }
    // Nothing kept a session from starting after the quiet check. One
    // that did has lost its account: named, so the user can end it.
    let holder = srt_win::state_db::HolderPid(std::process::id());
    if let Ok((held, _)) = srt_win::state_db::with_init_lock(holder, false, |db| {
        srt_win::state_db::live_holders(db, None)
    }) && !held.is_empty()
    {
        let mut pids: Vec<String> = held.iter().map(|h| h.pid.to_string()).collect();
        pids.dedup();
        eprintln!(
            "srt-win: NOTE: a sandbox session started while the uninstall ran (process {}). \
             The sandbox account is gone: its commands will fail. End it.",
            pids.join(", ")
        );
    }
    if incomplete {
        eprintln!(
            "srt-win: the sandbox account and filters are removed, but not every grant kept \
             for this user was (see above). What is left stays recorded; once nothing else \
             is running, `srt-win profile forget` and `srt-win acl forget --all` remove it."
        );
        EXIT_GRANTS_NOT_FORGOTTEN
    } else {
        0
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
            eprintln!("srt-win: UAC prompt cancelled by user; nothing was changed");
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

    /// The typed JSON survives `.context(…)`; other errors yield `None`.
    #[test]
    fn seclogon_error_json_shape() {
        use srt_win::logon::SeclogonDisabled;
        let bare = anyhow::Error::from(SeclogonDisabled { missing: false });
        assert_eq!(
            seclogon_error_json(&bare).expect("typed"),
            serde_json::json!({
                "code": "seclogon_disabled",
                "state": "disabled",
                "message": SeclogonDisabled { missing: false }.to_string(),
            }),
        );
        let wrapped = anyhow::Error::from(SeclogonDisabled { missing: true })
            .context("spawn runner for CA install");
        assert_eq!(
            seclogon_error_json(&wrapped).expect("typed through context")["state"],
            "missing",
        );
        assert!(seclogon_error_json(&anyhow::anyhow!("CreateProcessWithLogonW: other")).is_none());
        assert_eq!(EXIT_SECLOGON_DISABLED, 18);
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

    /// On `exec` the flag goes before `--`, where the TS wrapper puts it.
    #[test]
    fn allow_loopback_flag_parses() {
        let cli = Cli::try_parse_from([
            "srt-win",
            "exec",
            "--allow-loopback",
            "--quiet",
            "--",
            "cmd.exe",
        ])
        .expect("parse");
        assert!(matches!(
            cli.cmd,
            Cmd::Exec {
                allow_loopback: true,
                quiet: true,
                ..
            }
        ));
        let cli = Cli::try_parse_from(["srt-win", "exec", "--", "cmd.exe"]).expect("parse");
        assert!(matches!(
            cli.cmd,
            Cmd::Exec {
                allow_loopback: false,
                ..
            }
        ));
        // After `--` it belongs to the target, not to srt-win.
        let cli = Cli::try_parse_from(["srt-win", "exec", "--", "cmd.exe", "--allow-loopback"])
            .expect("parse");
        assert!(matches!(
            cli.cmd,
            Cmd::Exec { allow_loopback: false, ref target, .. } if target.len() == 2
        ));
        let cli = Cli::try_parse_from(["srt-win", "install", "--allow-loopback"]).expect("parse");
        assert!(matches!(
            cli.cmd,
            Cmd::Install {
                allow_loopback: true,
                ..
            }
        ));
        let cli = Cli::try_parse_from(["srt-win", "install"]).expect("parse");
        assert!(matches!(
            cli.cmd,
            Cmd::Install {
                allow_loopback: false,
                ..
            }
        ));
        for (argv, want) in [
            (
                &[
                    "srt-win",
                    "wfp",
                    "verify",
                    "--target",
                    "127.0.0.1:9229",
                    "--allow-loopback",
                ][..],
                true,
            ),
            (
                &["srt-win", "wfp", "verify", "--target", "127.0.0.1:49999"][..],
                false,
            ),
        ] {
            let cli = Cli::try_parse_from(argv).expect("parse");
            assert!(matches!(
                cli.cmd,
                Cmd::Wfp {
                    sub: WfpCmd::Verify { allow_loopback, .. }
                } if allow_loopback == want
            ));
        }
        // There is no range form of the option.
        assert!(
            Cli::try_parse_from(["srt-win", "install", "--loopback-port-range", "3000-3099"])
                .is_err()
        );
    }

    /// The flag is off unless given, and the hidden `probe` subcommands parse.
    #[test]
    fn write_restricted_token_flag_parses() {
        let on = Cli::try_parse_from([
            "srt-win",
            "exec",
            "--quiet",
            "--write-restricted-token",
            "--",
            "cmd.exe",
        ])
        .expect("parse");
        assert!(matches!(
            on.cmd,
            Cmd::Exec {
                write_restricted_token: true,
                ..
            }
        ));
        let off = Cli::try_parse_from(["srt-win", "exec", "--", "cmd.exe"]).expect("parse");
        assert!(matches!(
            off.cmd,
            Cmd::Exec {
                write_restricted_token: false,
                ..
            }
        ));
        // After `--` the flag belongs to the target, not to srt-win.
        let target_arg = Cli::try_parse_from([
            "srt-win",
            "exec",
            "--",
            "cmd.exe",
            "--write-restricted-token",
        ])
        .expect("parse");
        assert!(matches!(
            target_arg.cmd,
            Cmd::Exec {
                write_restricted_token: false,
                ..
            }
        ));
        let v_on = Cli::try_parse_from([
            "srt-win",
            "wfp",
            "verify",
            "--target",
            "127.0.0.1:1",
            "--write-restricted-token",
        ])
        .expect("parse");
        assert!(matches!(
            v_on.cmd,
            Cmd::Wfp {
                sub: WfpCmd::Verify {
                    write_restricted_token: true,
                    ..
                }
            }
        ));
        let v_off = Cli::try_parse_from(["srt-win", "wfp", "verify", "--target", "127.0.0.1:1"])
            .expect("parse");
        assert!(matches!(
            v_off.cmd,
            Cmd::Wfp {
                sub: WfpCmd::Verify {
                    write_restricted_token: false,
                    ..
                }
            }
        ));
        let roots = Cli::try_parse_from([
            "srt-win",
            "exec",
            "--write-restricted-token",
            "--write-root",
            r"C:\a",
            "--write-root",
            r"C:\b",
            "--",
            "cmd.exe",
        ])
        .expect("parse");
        match roots.cmd {
            Cmd::Exec { write_root, .. } => assert_eq!(write_root, [r"C:\a", r"C:\b"]),
            _ => panic!("wrong subcommand"),
        }
        assert!(
            Cli::try_parse_from(["srt-win", "exec", "--write-root", r"C:\a", "--", "cmd.exe"])
                .is_err()
        );
        let v_roots = Cli::try_parse_from([
            "srt-win",
            "wfp",
            "verify",
            "--target",
            "127.0.0.1:1",
            "--write-restricted-token",
            "--write-root",
            r"C:\a",
        ])
        .expect("parse");
        match v_roots.cmd {
            Cmd::Wfp {
                sub: WfpCmd::Verify { write_root, .. },
            } => assert_eq!(write_root, [r"C:\a"]),
            _ => panic!("wrong subcommand"),
        }
        assert!(
            Cli::try_parse_from([
                "srt-win",
                "wfp",
                "verify",
                "--target",
                "127.0.0.1:1",
                "--write-root",
                r"C:\a",
            ])
            .is_err()
        );
        let probe = Cli::try_parse_from(["srt-win", "probe", "connect", "--target", "127.0.0.1:1"])
            .expect("parse");
        assert!(matches!(
            probe.cmd,
            Cmd::Probe {
                sub: ProbeCmd::Connect { .. }
            }
        ));
        // What `wfp verify --write-restricted-token` runs as the child.
        let egress = Cli::try_parse_from([
            "srt-win",
            "probe",
            "egress",
            "--target",
            "127.0.0.1:49999",
            "--anonymous-target",
            "192.0.2.7:49999",
            "--allow-loopback",
        ])
        .expect("parse");
        assert!(matches!(
            egress.cmd,
            Cmd::Probe {
                sub: ProbeCmd::Egress {
                    allow_loopback: true,
                    anonymous_egress: false,
                    anonymous_target: Some(_),
                    ..
                }
            }
        ));
    }

    #[test]
    fn persistent_grant_subcommands_parse() {
        let grant = |extra: &[&str]| {
            let mut argv = vec![
                "srt-win",
                "acl",
                "grant",
                "--holder-pid",
                "7",
                "--sandbox-user-sid",
                "S-1-5-21-1",
            ];
            argv.extend(extra);
            match Cli::try_parse_from(argv).expect("parse").cmd {
                Cmd::Acl {
                    sub: AclCmd::Grant { persistent, .. },
                } => persistent,
                _ => panic!("wrong subcommand"),
            }
        };
        assert!(!grant(&[]));
        assert!(grant(&["--persistent"]));

        let forget = |argv: &[&str]| Cli::try_parse_from(argv).map(|c| c.cmd);
        assert!(matches!(
            forget(&["srt-win", "acl", "forget", "--all", "--json"]),
            Ok(Cmd::Acl {
                sub: AclCmd::Forget {
                    all: true,
                    json: true,
                    ..
                }
            })
        ));
        match forget(&["srt-win", "acl", "forget", r"C:\a", r"C:\b"]) {
            Ok(Cmd::Acl {
                sub: AclCmd::Forget { all, roots, .. },
            }) => {
                assert!(!all);
                assert_eq!(roots, [r"C:\a", r"C:\b"]);
            }
            _ => panic!("wrong subcommand"),
        }
        // Either every root or the named ones.
        assert!(forget(&["srt-win", "acl", "forget", "--all", r"C:\a"]).is_err());
        match forget(&["srt-win", "acl", "forget", "--drop-pending", r"E:\w"]) {
            Ok(Cmd::Acl {
                sub: AclCmd::Forget {
                    drop_pending, all, ..
                },
            }) => {
                assert!(!all);
                assert_eq!(drop_pending, [r"E:\w"]);
            }
            _ => panic!("wrong subcommand"),
        }
        for mixed in [
            &[
                "srt-win",
                "acl",
                "forget",
                "--all",
                "--drop-pending",
                r"E:\w",
            ][..],
            &[
                "srt-win",
                "acl",
                "forget",
                r"C:\a",
                "--drop-pending",
                r"E:\w",
            ][..],
            &["srt-win", "acl", "forget", "--drop-pending"][..],
        ] {
            assert!(forget(mixed).is_err(), "{mixed:?}");
        }
        // --force is for --all only.
        assert!(matches!(
            forget(&["srt-win", "acl", "forget", "--all", "--force"]),
            Ok(Cmd::Acl {
                sub: AclCmd::Forget { force: true, .. }
            })
        ));
        assert!(forget(&["srt-win", "acl", "forget", "--force", r"C:\a"]).is_err());

        // The deny lists ride in the same stdin document.
        let input: AclGrantInput = serde_json::from_str(
            r#"{"read":["r"],"write":["w"],"denyRead":["dr"],"denyWrite":["dw"]}"#,
        )
        .unwrap();
        assert_eq!(
            (input.read, input.write, input.deny_read, input.deny_write),
            (
                vec!["r".to_owned()],
                vec!["w".to_owned()],
                vec!["dr".to_owned()],
                vec!["dw".to_owned()]
            )
        );
        let plain: AclGrantInput = serde_json::from_str(r#"{"write":["w"]}"#).unwrap();
        assert!(plain.deny_read.is_empty() && plain.deny_write.is_empty());
    }

    /// `probe token` / `probe parent-access` parse only in a `test-hooks` build.
    #[test]
    fn profile_subcommands_parse() {
        let parse = |argv: &[&str]| Cli::try_parse_from(argv).map(|c| c.cmd);
        match parse(&[
            "srt-win",
            "profile",
            "grant",
            "--exclude",
            r"C:\Users\me\.myapp",
            "--exclude",
            ".other",
            "--json",
        ]) {
            Ok(Cmd::Profile {
                sub:
                    ProfileCmd::Grant {
                        exclude,
                        json,
                        quiet,
                        ..
                    },
            }) => {
                assert_eq!(exclude, [r"C:\Users\me\.myapp", ".other"]);
                assert!(json && !quiet);
            }
            _ => panic!("wrong subcommand"),
        }
        assert!(matches!(
            parse(&["srt-win", "profile", "grant", "--quiet"]),
            Ok(Cmd::Profile {
                sub: ProfileCmd::Grant {
                    quiet: true,
                    replace_excludes: false,
                    ..
                }
            })
        ));
        assert!(matches!(
            parse(&["srt-win", "profile", "grant", "--replace-excludes"]),
            Ok(Cmd::Profile {
                sub: ProfileCmd::Grant {
                    replace_excludes: true,
                    ..
                }
            })
        ));
        match parse(&[
            "srt-win",
            "acl",
            "grant",
            "--holder-pid",
            "7",
            "--sandbox-user-sid",
            "S-1-5-21-1",
            "--persistent",
            "--allow-profile-exclusion",
            r"C:\Users\me\.ssh",
        ]) {
            Ok(Cmd::Acl {
                sub:
                    AclCmd::Grant {
                        allow_profile_exclusion,
                        ..
                    },
            }) => assert_eq!(allow_profile_exclusion, [r"C:\Users\me\.ssh"]),
            _ => panic!("wrong subcommand"),
        }
        assert!(is_service_account("S-1-5-18"));
        assert!(!is_service_account("S-1-5-21-1-2-3-1001"));
        assert!(matches!(
            parse(&["srt-win", "profile", "forget", "--json"]),
            Ok(Cmd::Profile {
                sub: ProfileCmd::Forget {
                    json: true,
                    unless_held_by_others: None,
                }
            })
        ));
        assert!(matches!(
            parse(&[
                "srt-win",
                "profile",
                "forget",
                "--unless-held-by-others",
                "41"
            ]),
            Ok(Cmd::Profile {
                sub: ProfileCmd::Forget {
                    unless_held_by_others: Some(41),
                    ..
                }
            })
        ));
        assert!(matches!(
            parse(&[
                "srt-win",
                "acl",
                "forget",
                "--all",
                "--unless-held-by-others",
                "41"
            ]),
            Ok(Cmd::Acl {
                sub: AclCmd::Forget {
                    all: true,
                    unless_held_by_others: Some(41),
                    ..
                }
            })
        ));
        assert!(matches!(
            parse(&["srt-win", "profile", "status", "--paths"]),
            Ok(Cmd::Profile {
                sub: ProfileCmd::Status { paths: true, .. }
            })
        ));
        for sub in ["grant", "status"] {
            let parsed = parse(&["srt-win", "profile", sub, "--test-profile", r"C:\x"]);
            assert_eq!(
                parsed.is_ok(),
                cfg!(feature = "test-hooks"),
                "profile {sub} --test-profile"
            );
        }
        assert!(parse(&["srt-win", "profile", "grant", "--include", ".ssh"]).is_err());
    }

    #[test]
    fn probe_test_hooks_follow_the_feature() {
        for sub in ["token", "parent-access"] {
            let parsed = Cli::try_parse_from(["srt-win", "probe", sub]);
            assert_eq!(parsed.is_ok(), cfg!(feature = "test-hooks"), "probe {sub}");
        }
    }

    /// A path in `denyRead` and in `denyWrite` keeps the read deny,
    /// whichever comes first. smoke-aces.ps1 A32 shows it on disk.
    #[test]
    fn a_batch_names_each_path_and_kind_once_with_the_widest_mask() {
        use srt_win::acl::{DenyMask, GrantMask, SbAce};
        let read = SbAce::Deny(DenyMask::ReadDeny);
        let write = SbAce::Deny(DenyMask::WriteDeny);
        let t = |p: &str, ace: SbAce| (p.to_string(), ace);
        for (first, second) in [(read, write), (write, read)] {
            assert_eq!(
                merge_ace_targets(vec![t(r"C:\a", first), t(r"C:\a", second)]),
                vec![t(r"C:\a", read)]
            );
        }
        assert_eq!(
            merge_ace_targets(vec![
                t(r"C:\a", SbAce::Grant(GrantMask::ReadOnly)),
                t(r"C:\a", SbAce::Grant(GrantMask::Modify)),
            ]),
            vec![t(r"C:\a", SbAce::Grant(GrantMask::Modify))]
        );
        // Another kind on the same path is another row, another path
        // is another entry, and each stays where it first came up.
        assert_eq!(
            merge_ace_targets(vec![
                t(r"C:\b", write),
                t(r"C:\a", SbAce::DenyDelete),
                t(r"C:\a", write),
                t(r"C:\b", write),
                t(r"C:\a", SbAce::DenyDelete),
                t(r"C:\a", read),
            ]),
            vec![
                t(r"C:\b", write),
                t(r"C:\a", SbAce::DenyDelete),
                t(r"C:\a", read),
            ]
        );
    }
}
