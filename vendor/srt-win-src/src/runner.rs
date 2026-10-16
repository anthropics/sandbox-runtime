//! `srt-win runner` — the inside-the-logon half of the two-hop
//! launch.
//!
//! The broker (running as the **real** user) decrypts the sandbox
//! user's password and `CreateProcessWithLogonW`s **this**
//! subcommand under the `srt-sandbox` account. The runner reads a
//! [`RunnerCmd`] from stdin and either runs
//! [`crate::launch::run_lockdown`] (restricted token, job, desktop,
//! mitigations, handle whitelist), or — at install time — writes
//! the MITM CA into the sandbox user's `CurrentUser\Root` (see
//! [`crate::cert_store`]). The child inherits the runner's stdio,
//! which are the broker's pipes, so stdout/stderr flow broker ←
//! runner ← child without an extra pump.
//!
//! All state-DB work happens in the **broker**, never here: the
//! state-DB directory carries an explicit DENY for
//! `sandbox-runtime-users`, so the runner cannot open it.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::launch;

/// What the broker asks the runner to do. Passed over stdin (4-byte
/// LE length prefix + JSON). Stdin — not argv or env — because the
/// env overlay can exceed what `lpCommandLine` reliably carries, and
/// a temp file would need a path the sandbox user can read (the
/// broker's `%TEMP%` may not be).
#[derive(Debug, Serialize, Deserialize)]
pub enum RunnerCmd {
    /// Per-exec: run the target under [`crate::launch::run_lockdown`].
    Exec(RunnerSpec),
    /// Install-time, one-shot: write the DER-encoded CA into the
    /// **sandbox user's** `CurrentUser\Root` (direct
    /// `HKEY_USERS\<own-SID>\…\Root\Certificates\<thumb>` registry
    /// write — see [`crate::cert_store`]). Persistent until
    /// `srt-win uninstall` deletes the profile. Exit non-zero on
    /// failure.
    InstallCa { der: crate::cert_store::CertDer },
    /// `wfp verify` probe: attempt direct TCP connects **as the
    /// sandbox user**, one per token shape a sandboxed process can
    /// present to the filtering engine — see [`crate::probe`].
    /// `target` (`host:port`) is the loopback probe target;
    /// `anonymous_target` the off-loopback one for the attempt made
    /// while impersonating the anonymous token (`None` skips it).
    /// With loopback open, `open_loopback_target` is the broker's own
    /// loopback listener and `open_off_loopback_target` an
    /// off-loopback address at its port (`None` skips each).
    ///
    /// A BLOCK filter fires at `ALE_AUTH_CONNECT` — before any packet
    /// leaves — so a fenced connect yields WSAEACCES immediately. The
    /// runner exits with every result encoded
    /// ([`crate::probe::Report::encode`]); exit 1 stays reserved for
    /// the runner's own anyhow `Err` path, and never decodes as a
    /// report. No desk/grants/lockdown — the probe runs as the bare
    /// runner (same as [`InstallCa`](Self::InstallCa)); the filters
    /// key on the token, which the runner already carries.
    ///
    /// This is the probe for the **ordinary** child token. The
    /// write-restricted token differs from the runner's in a way a
    /// filter's access check can see, so `wfp verify
    /// --write-restricted-token` does not use this command: it sends
    /// an [`Exec`](Self::Exec) of `srt-win probe fence`, which runs
    /// the same attempts from a process holding the child token and
    /// exits with the same encoded report.
    ProbeEgress {
        target: String,
        #[serde(default)]
        anonymous_target: Option<String>,
        #[serde(default)]
        open_off_loopback_target: Option<String>,
        #[serde(default)]
        open_loopback_target: Option<String>,
    },
}

/// Inputs to a single [`RunnerCmd::Exec`].
#[derive(Debug, Serialize, Deserialize)]
pub struct RunnerSpec {
    /// `argv[0]` = target executable; `argv[1..]` = its arguments.
    pub argv: Vec<String>,
    /// `(KEY, VALUE)` pairs overlaid on the runner's own environment
    /// (= the sandbox user's `LOGON_WITH_PROFILE` defaults) when
    /// building the child's env block. Overlay wins on key conflict
    /// (case-insensitive), so the broker's `PATH` replaces the
    /// sandbox user's machine-only `PATH` while `USERPROFILE` /
    /// `TEMP` stay isolated. The proxy var set rides here too.
    pub env_overlay: Vec<(String, String)>,
    /// Build the child token write-restricted (`srt-win exec
    /// --write-restricted-token`; see [`crate::token`]). Off unless
    /// the broker asks for it.
    #[serde(default)]
    pub write_restricted_token: bool,
    /// Capability SIDs of the write roots this command's session was
    /// given (`crate::persist`), looked up by the broker; they join
    /// the child token's restricting SIDs. Only with
    /// `write_restricted_token`; the runner accepts nothing here that
    /// is not a capability SID.
    #[serde(default)]
    pub capability_sids: Vec<String>,
}

/// Sanity cap shared by every length-prefixed stdin frame (the
/// runner spec, `exec`'s `--env-stdin` overlay). The payloads are a
/// few KB; anything in the MB range means the two sides of the pipe
/// are out of sync.
const FRAME_CAP: usize = 4 * 1024 * 1024;

/// Read one `<u32 LE length><payload>` frame from `r`. The length
/// prefix lets the reader know where the frame ends without the
/// writer closing its end. Bytes after the frame stay available to
/// further reads from the SAME reader — but a buffered reader (e.g.
/// `Stdin`) may have pulled them into its userland buffer, so they
/// are not guaranteed to still be in the underlying pipe for a
/// different handle holder.
fn read_frame(r: &mut impl Read, what: &str) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .with_context(|| format!("{what}: read length prefix"))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > FRAME_CAP {
        return Err(anyhow!("{what}: length {len} exceeds 4 MiB sanity cap"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .with_context(|| format!("{what}: read body"))?;
    Ok(buf)
}

/// Read a 4-byte little-endian length prefix followed by that many
/// bytes of JSON from stdin. The length prefix lets the runner know
/// when the spec ends without the broker closing the write end
/// (which it does anyway — the prefix is just robustness against a
/// future stdin-after-spec use).
fn read_cmd_from_stdin() -> Result<RunnerCmd> {
    let mut stdin = std::io::stdin().lock();
    let buf = read_frame(&mut stdin, "runner: spec")?;
    serde_json::from_slice(&buf).context("runner: parse spec JSON")
}

/// Decode the caller→`exec` env-overlay frame (`--env-stdin`):
/// `<u32 LE length><JSON [[KEY,VALUE],…]>` read from `srt-win
/// exec`'s **own** stdin. Carries overlay entries whose values embed
/// the per-session proxy auth token, so the token never appears on
/// any command line (command lines are freely readable by same-user
/// sibling processes). Same framing as [`RunnerCmd`]; the writer is
/// the host's `wrapCommandWithSandboxWindows`.
pub fn decode_env_frame(r: &mut impl Read) -> Result<Vec<(String, String)>> {
    let buf = read_frame(r, "exec: --env-stdin overlay")?;
    serde_json::from_slice(&buf).context("exec: parse --env-stdin overlay JSON")
}

/// Append a decoded `--env-stdin` frame to the `--env` overlay. The
/// writer-side invariant is that each key rides EXACTLY ONE channel
/// (the TS wrapper partitions by key), so a case-insensitive overlap
/// means the two sides disagree about the contract — fail loudly
/// instead of silently picking a winner.
pub fn merge_env_overlay(
    mut base: Vec<(String, String)>,
    extra: Vec<(String, String)>,
) -> Result<Vec<(String, String)>> {
    let base_keys: std::collections::HashSet<String> =
        base.iter().map(|(k, _)| k.to_ascii_uppercase()).collect();
    if let Some((k, _)) = extra
        .iter()
        .find(|(k, _)| base_keys.contains(&k.to_ascii_uppercase()))
    {
        return Err(anyhow!(
            "exec: --env-stdin frame key '{k}' duplicates an --env \
             argument (case-insensitive) — the caller must put each \
             key on exactly one channel"
        ));
    }
    base.extend(extra);
    Ok(base)
}

/// Frame `json` as `<u32 LE length><payload>` — the single writer-side
/// definition of the wire format [`read_frame`] consumes.
fn encode_frame(json: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend(json);
    out
}

/// Serialize env-overlay entries as `<u32 LE length><JSON>` — the
/// inverse of [`decode_env_frame`]. Test-only: the production writer
/// is the TS host (`encodeEnvStdinFrame`); this exists so the Rust
/// tests exercise the same wire shape.
#[cfg(test)]
fn encode_env_frame(entries: &[(String, String)]) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(entries).context("encode env frame")?;
    Ok(encode_frame(json))
}

/// Serialize `cmd` as `<u32 LE length><JSON>`. Broker-side helper —
/// lives here so the wire format has one definition.
pub fn encode_cmd(cmd: &RunnerCmd) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(cmd).context("runner: encode cmd")?;
    Ok(encode_frame(json))
}

/// Entry point for `srt-win runner`. Reads the command from stdin,
/// dispatches, and returns the exit code.
pub fn run() -> Result<u32> {
    match read_cmd_from_stdin()? {
        RunnerCmd::Exec(spec) => {
            if spec.argv.is_empty() {
                return Err(anyhow!("runner: spec.argv is empty"));
            }
            if std::env::var_os("SANDBOX_RUNTIME_WIN_DEBUG").is_some() {
                eprintln!(
                    "srt-win: runner: spec read (argv={} env_overlay={})",
                    spec.argv.len(),
                    spec.env_overlay.len(),
                );
            }
            let exe = std::path::PathBuf::from(&spec.argv[0]);
            launch::run_lockdown(
                &exe,
                &spec.argv[1..],
                &spec.env_overlay,
                spec.write_restricted_token,
                &spec.capability_sids,
            )
        }
        RunnerCmd::InstallCa { der } => {
            let thumb = crate::cert_store::install_root_ca(&der)?;
            eprintln!(
                "srt-win: runner: CA installed into sandbox-user \
                 CurrentUser\\Root (thumb={thumb})"
            );
            Ok(0)
        }
        RunnerCmd::ProbeEgress {
            target,
            anonymous_target,
            open_off_loopback_target,
            open_loopback_target,
        } => Ok(crate::probe::run(crate::probe::Targets {
            target: &target,
            anonymous: anonymous_target.as_deref(),
            open_off_loopback: open_off_loopback_target.as_deref(),
            open_loopback: open_loopback_target.as_deref(),
        })?
        .encode()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_roundtrip() {
        let s = RunnerCmd::Exec(RunnerSpec {
            argv: vec!["cmd.exe".into(), "/c".into(), "echo hi".into()],
            env_overlay: vec![("PATH".into(), r"C:\a;C:\b".into())],
            write_restricted_token: true,
            capability_sids: vec!["S-1-0-1936880739-1-2-3-4".into()],
        });
        let bytes = encode_cmd(&s).unwrap();
        assert_eq!(
            u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize,
            bytes.len() - 4
        );
        let back: RunnerCmd = serde_json::from_slice(&bytes[4..]).unwrap();
        match back {
            RunnerCmd::Exec(r) => {
                assert_eq!(r.argv, ["cmd.exe", "/c", "echo hi"]);
                assert_eq!(r.env_overlay.len(), 1);
                assert!(r.write_restricted_token);
                assert_eq!(r.capability_sids, ["S-1-0-1936880739-1-2-3-4"]);
            }
            _ => panic!("wrong variant"),
        }
        // A spec without the field is the ordinary token.
        let legacy = br#"{"Exec":{"argv":["cmd.exe"],"env_overlay":[]}}"#;
        match serde_json::from_slice::<RunnerCmd>(legacy).unwrap() {
            RunnerCmd::Exec(r) => {
                assert!(!r.write_restricted_token);
                assert!(r.capability_sids.is_empty());
            }
            _ => panic!("wrong variant"),
        }
        let ca = RunnerCmd::InstallCa {
            der: crate::cert_store::CertDer::raw(vec![0x30, 0x82]),
        };
        let bytes = encode_cmd(&ca).unwrap();
        let back: RunnerCmd = serde_json::from_slice(&bytes[4..]).unwrap();
        assert!(matches!(
            back, RunnerCmd::InstallCa { der } if der.as_bytes() == [0x30, 0x82]
        ));
        let probe = RunnerCmd::ProbeEgress {
            target: "127.0.0.1:49999".into(),
            anonymous_target: Some("192.0.2.7:49999".into()),
            open_off_loopback_target: Some("192.0.2.7:3000".into()),
            open_loopback_target: Some("127.0.0.1:3000".into()),
        };
        let bytes = encode_cmd(&probe).unwrap();
        let back: RunnerCmd = serde_json::from_slice(&bytes[4..]).unwrap();
        assert!(matches!(
            back,
            RunnerCmd::ProbeEgress {
                target,
                anonymous_target,
                open_off_loopback_target,
                open_loopback_target,
            }
                if target == "127.0.0.1:49999"
                    && anonymous_target.as_deref() == Some("192.0.2.7:49999")
                    && open_off_loopback_target.as_deref() == Some("192.0.2.7:3000")
                    && open_loopback_target.as_deref() == Some("127.0.0.1:3000")
        ));
        // Every target but the first is optional on the wire.
        let back: RunnerCmd =
            serde_json::from_str(r#"{"ProbeEgress":{"target":"127.0.0.1:1"}}"#).unwrap();
        assert!(matches!(
            back,
            RunnerCmd::ProbeEgress {
                anonymous_target: None,
                open_off_loopback_target: None,
                open_loopback_target: None,
                ..
            }
        ));
    }

    #[test]
    fn env_frame_roundtrip() {
        let entries = vec![
            (
                "HTTPS_PROXY".to_string(),
                "http://u:tok-secret@localhost:60080".to_string(),
            ),
            (
                "http_proxy".to_string(),
                "http://u:tok-secret@localhost:60080".to_string(),
            ),
        ];
        let bytes = encode_env_frame(&entries).unwrap();
        assert_eq!(
            u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize,
            bytes.len() - 4
        );
        let back = decode_env_frame(&mut &bytes[..]).unwrap();
        assert_eq!(back, entries);
    }

    #[test]
    fn env_frame_leaves_trailing_bytes_unread() {
        // The frame is self-delimiting: the decoder reads exactly
        // the prefix + body and leaves later bytes on the reader.
        let entries = vec![("K".to_string(), "V".to_string())];
        let mut bytes = encode_env_frame(&entries).unwrap();
        bytes.extend_from_slice(b"user input after the frame");
        let mut r = &bytes[..];
        let back = decode_env_frame(&mut r).unwrap();
        assert_eq!(back, entries);
        assert_eq!(r, b"user input after the frame");
    }

    #[test]
    fn merge_env_overlay_appends_disjoint_and_rejects_overlap() {
        let base = vec![("PATH".to_string(), "C:\\bin".to_string())];
        let extra = vec![(
            "HTTPS_PROXY".to_string(),
            "http://u:tok@localhost:60080".to_string(),
        )];
        let merged = merge_env_overlay(base.clone(), extra.clone()).unwrap();
        assert_eq!(
            merged,
            vec![
                ("PATH".to_string(), "C:\\bin".to_string()),
                (
                    "HTTPS_PROXY".to_string(),
                    "http://u:tok@localhost:60080".to_string()
                ),
            ]
        );

        // Case-insensitive overlap = writer-side contract violation.
        let overlapping_base = vec![
            ("PATH".to_string(), "C:\\bin".to_string()),
            (
                "https_proxy".to_string(),
                "http://localhost:60080".to_string(),
            ),
        ];
        let e = merge_env_overlay(overlapping_base, extra).unwrap_err();
        assert!(format!("{e:#}").contains("exactly one channel"), "{e:#}");
    }

    #[test]
    fn env_frame_rejects_oversize_and_truncated() {
        // Length over the 4 MiB cap → rejected before allocation.
        let mut oversize = Vec::new();
        oversize.extend_from_slice(&(5u32 * 1024 * 1024).to_le_bytes());
        let e = decode_env_frame(&mut &oversize[..]).unwrap_err();
        assert!(format!("{e:#}").contains("sanity cap"), "{e:#}");

        // Truncated body → read error, not a hang or partial parse.
        let entries = vec![("K".to_string(), "V".to_string())];
        let bytes = encode_env_frame(&entries).unwrap();
        let e = decode_env_frame(&mut &bytes[..bytes.len() - 1]).unwrap_err();
        assert!(format!("{e:#}").contains("read body"), "{e:#}");

        // Valid frame, garbage JSON → parse error.
        let mut garbage = Vec::new();
        garbage.extend_from_slice(&3u32.to_le_bytes());
        garbage.extend_from_slice(b"nop");
        let e = decode_env_frame(&mut &garbage[..]).unwrap_err();
        assert!(format!("{e:#}").contains("parse"), "{e:#}");
    }
}
