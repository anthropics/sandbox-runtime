# Handoff: update `ltic-ai-guidelines/sandbox-runtime-config` for srt `0.0.81-ltic.1`

Audience: an agent working in `~/ltic/aitools/ltic-ai-guidelines/` with no other context.
Goal: one PR that brings `sandbox-runtime-config/` (README.md, DETAILS.md, justfile, the two
`.srt-claude-*.json`, `.zshrc.example`, `.bashrc.example`, `srt-violations.mjs`) in line with
the fork release described below. Everything stated here as verified was run on 2026-10-27
against the built fork, through the repo's own `_ccx_run` wrapper and the deployed configs.

## 1. Ground truth

- The fork `ubc/sandbox-runtime`, branch `ltic-main`, moved from `0.0.77-ltic.1` to
  **`0.0.81-ltic.1`**: upstream `anthropic-experimental/sandbox-runtime` main at v0.0.81 + 4
  commits. Release notes: upstream `releases/tag/v0.0.78`, `v0.0.79`, `v0.0.80`, `v0.0.81`.
  The fork's own write-up is `0.77_to_0.81_NEW_FEATURES.md` next to this file.
- **No mandatory config changes.** Both repo configs are byte-identical to the deployed
  `~/.srt-claude-denyall.json` and `~/.srt-claude-allowall.json` apart from JSON formatting,
  and both load on the new build with no "unrecognized settings key" warning.
- **One fork delta is retired: the macOS socat `GIT_SSH_COMMAND`.** Upstream v0.0.80 (#681)
  does authenticated git-over-SSH on macOS with stock `/usr/bin/nc`. **socat is no longer a
  dependency** of the ccx setup. The fork now has three deltas, not four: `allowAllDomains`,
  the violations file, the unrecognized-key warning.
- **One new prerequisite: Node ≥ 22.12** (upstream `engines`).
- **Optional hardening** became available: `network.requireHostMatch`. See section 4.
- The `-ltic` version check, the violations hook (`srt-violations.mjs`), the shell wrapper
  files and the CA trust steps are unchanged.

## 2. Verified behaviour you may document as fact

Build: `npm install && npm run build && npm run typecheck` clean. `npm test`: 3400 pass, 1179 skipped (Linux/Windows only), 28 fail;
every failure also fails on pristine upstream on the same Mac (Bun 1.4.4 vs upstream CI's
1.4.2; macOS 26's tcsh/csh), none in fork code.

```
$ srt --version
0.0.81-ltic.1
$ srt --settings ~/.srt-claude-denyall.json -- true     # and allowall: exit 0, no output
```

Inside `_ccx_run ~/.srt-claude-denyall.json sh -c '…'` (so: real wrapper, per-launch config
with `allowUnixSockets` for the ssh-agent socket and the persistent CA paths):

```
SRT_VIOLATIONS_FILE=/Users/<you>/.local/state/srt/violations-<pid>.log
GIT_SSH_COMMAND=ssh -o ControlMaster=no -o ControlPath=none -o ProxyCommand="/bin/sh -c 'eval \"\${SRT_SSH_PROXY_COMMAND:?unset, but GIT_SSH_COMMAND needs it}\"' sh '%h' %p"
SRT_SSH_PROXY_COMMAND=LC_ALL=C; no() { printf "sandbox proxy: %s\n" "$*" >&2; exit 1; }; … | /usr/bin/nc 127.0.0.1 <proxy-port> | …

$ curl -s -o /dev/null -w '%{http_code}' https://example.com/        → 200
$ curl --noproxy '' -s -o /dev/null -w '%{http_code}' http://169.254.169.254/   → 403
$ curl -sI https://gist.github.com | head -1
HTTP/1.1 403 Creating gists is blocked by sandbox policy (exfiltration risk). Write to a file in the repo instead.

$ gh api user --jq .login                                            → <login>
$ PATH=/usr/bin:/bin command -v socat                                → (nothing)
$ git ls-remote git@github.com:ubc/sandbox-runtime.git HEAD          → <sha>	HEAD   (exit 0)
$ eval "$GIT_SSH_COMMAND -T git@github.com"
Hi <login>! You've successfully authenticated, but GitHub does not provide shell access.
$ eval "$GIT_SSH_COMMAND -T git@gist.github.com"
sandbox proxy: gist.github.com:22: 403 Creating gists is blocked by sandbox policy (exfiltration risk). Write to a file in the repo instead.
Connection closed by UNKNOWN port 65535
```

Same results for `git ls-remote` and `gh api user` under `~/.srt-claude-allowall.json`.
The git-over-SSH runs had `/opt/homebrew/bin` removed from `PATH` inside the sandbox, so
socat was not reachable: the ProxyCommand uses `/bin/sh`, `/usr/bin/nc` and `/bin/cat` by
absolute path.

Violations file after that session (denyall):

```
… deny network-outbound gist.github.com:443 (Creating gists is blocked by sandbox policy (exfiltration risk). Write to a file in the repo instead.)
… deny network-outbound 169.254.169.254:80 (host is not on the allow list)
… ssh(<pid>) deny(1) mach-lookup com.apple.dnssd.service
… ssh(<pid>) deny(1) mach-lookup com.apple.usymptomsd
… ssh(<pid>) deny(1) file-read-data /Users/<you>/.ssh/id_ed25519-github-ubc      ← expected: agent signs, key file stays denied
… zsh(<pid>) deny(1) file-read-metadata /Users/<you>/.zshenv                       ← ssh runs ProxyCommand via $SHELL -c
```

Bare `ssh -T git@github.com` (without the `eval "$GIT_SSH_COMMAND …"` recipe) fails with
`Could not resolve hostname github.com`, exactly as before this release.

## 3. File-by-file edits

### `README.md`

1. **Step 1 "Install the patched `srt` from the fork"** (currently "plus three more deltas:
   … and git-over-SSH works on macOS via an auth-capable socat ProxyCommand"):
   make it two more deltas (violations file, unrecognized-key warning) and drop the socat
   clause. Keep the PR #283 link for `allowAllDomains`.
2. Same step, the version line `srt --version      # → 0.0.77-ltic.1` → `0.0.81-ltic.1`.
3. Same step, **delete the whole paragraph** "Also install socat (`just deps`) — it's what
   carries sandboxed SSH through the authenticated proxy …" and change the code block
   `brew install socat jq` → `brew install jq`.
4. Add a **prerequisite line**: Node ≥ 22.12 (the nvm note in that step is the natural
   place; `node --version` as the check). Say that an older Node fails at `npm install`
   with an `engines` error.
5. **"Git, SSH and GitHub"** bullet "**git-over-SSH works via the forwarded ssh-agent** —
   needs socat and keys loaded with `ssh-add` …": remove "needs socat and". Add one
   sentence: a destination refused by `deniedDomains` now prints its configured reason on
   ssh's stderr (`sandbox proxy: <host>:22: 403 <reason>`), and `git` shows the same line.
   Keep the `eval "$GIT_SSH_COMMAND git@github.com"` recipe; it is verified.
6. **"Upgrading"**: no structural change; the pointer to "upgrade notes by version" covers
   the new DETAILS entry. Optionally note that `brew uninstall socat` is safe afterwards
   if nothing else uses it.
7. **"Shared between both"** (the postures section): if Greg adopts `requireHostMatch`
   (section 4), add one bullet describing it. Otherwise no change.

### `DETAILS.md`

1. **"## The fork"**: "Four deltas over upstream `srt`:" → three. Delete item 4 ("Working
   git-over-SSH on macOS … PR #452 …"). Add a short "Retired deltas" note after the list,
   beside the existing denyReadAlways history if there is one: `denyReadAlways` (retired at
   0.0.77, upstream deny-within-allow) and the macOS socat `GIT_SSH_COMMAND` (retired at
   0.0.81, upstream #681 nc-based ProxyCommand; PR #452 superseded).
2. **New "### Upstream changes in 0.0.81"** after "### Upstream changes in 0.0.77", same
   bullet style. Content (macOS-relevant; PR numbers in parentheses):
   - git-over-SSH on macOS uses stock `/usr/bin/nc`: `SRT_SSH_PROXY_COMMAND` holds an
     authenticated `CONNECT` script, `GIT_SSH_COMMAND`'s ProxyCommand evals it; the token
     never appears in ssh's argv (#681).
   - A refused CONNECT carries the deny reason as the `403` status phrase, so curl, git and
     ssh print it in-band; the violations file still gets the line too (#681).
   - Path entries with glob characters are also read as the path they spell where it
     exists; brackets that spell no character set are text; `{ "path": …, "literal": true }`
     marks an entry literal in any filesystem list (#620–#622, #687, #718).
   - macOS read rules apply under both spellings of a path, as written and realpath'd
     (#680). `credentials.files` entries beat `allowRead`/`allowWrite` everywhere (#680, #686).
   - The sandbox write-denies srt's own install directory, and `checkDependencies()` warns
     if srt is installed somewhere the sandbox can write (#595).
   - TLS termination runs in-process; new `network.tlsTerminate.maxTunnels` (default 256,
     past it a CONNECT gets `503 X-Proxy-Error: too-many-tunnels` and a violation) and
     `handshakeTimeoutMs` (default 10000) (#665, #700).
   - New `network.requireHostMatch`, `refuseOpaqueTunnels`, `stripResponseHeaders`,
     `allowPlaintextHeaderSet`, `ambiguousRequestTarget` (#663, #698); see section 4 for
     which apply here.
   - Proxy: invalid upstream status lines get `502` instead of crashing the proxy (#660);
     over-long bodies are passed whole (#717); cert serials never start with 0x00 (#685).
   - Node ≥ 22.12 (#636). The ask callback only allows on `true` (#591; the CLI has none).
3. **"### Upgrade notes by version"**: add, above the 0.70 → 0.77 entry:
   `**0.0.77-ltic.1 → 0.0.81-ltic.1.** No config migration. socat is no longer needed
   (`just deps` and `just check` stop asking for it; `brew uninstall socat` is optional).
   Node must be ≥ 22.12. After `just upgrade`, `just check` should pass unchanged; if the
   configs were customized, nothing in them needs to move. Optional: add
   `"requireHostMatch": true` under `network` in both configs (below).`
4. **"## SSH" → "Transport." paragraph**: replace "srt sets `GIT_SSH_COMMAND` with a
   `ProxyCommand`; with socat on PATH (fork delta 4) that is an authenticated HTTP CONNECT
   tunnel — without socat srt falls back to `nc`, which can't authenticate, and
   git-over-SSH dies at the handshake." with: srt sets `GIT_SSH_COMMAND` whose
   `ProxyCommand` runs `/bin/sh -c 'eval "$SRT_SSH_PROXY_COMMAND" sh %h %p'`; that script
   (also in the environment) sends an authenticated `CONNECT %h:%p` through `/usr/bin/nc`
   to the session proxy and relays with `cat`. Nothing beyond what macOS ships is needed.
   A refused destination prints `sandbox proxy: host:22: 403 <reason>`. Keep the rest of
   the paragraph (opaque pass-through, `deniedDomains` still apply, the `eval` recipe).
5. **"## Using on Linux"**: add the Linux-only changes: sandboxed commands can no longer
   create user or mount namespaces by default (Chromium/Electron sandboxes, rootless
   podman/buildah, nested bwrap and `unshare -r` fail inside; `allowNestedUserNamespaces:
   true` lifts it, at the cost of write-deny enforcement against a hostile command; needs
   the seccomp helper or bwrap ≥ 0.8.0 not setuid) (#588, #617); `denyWrite` now beats
   `allowWrite` however nested, so `denyWrite: ["~"]` makes a project under `~` read-only
   (#684); the read-deny glob walk is ~6× faster and no longer blocks the event loop
   (#627 ff.); bubblewrap 0.4 works again (#580); the first network call of a command is
   no longer refused because the in-sandbox relays were not yet listening (#639).
6. **"## Future directions"**: refresh. Three of the five ideas now have upstream
   primitives, all library-level (not reachable from `srt --settings` configs): per-tool
   egress via `SandboxManager.registerCommandNetworkLists(commandId, { allowedDomains })`
   (#591); URL/header-level policy via `filterRequest` with `setHeaders`/`removeHeaders`/
   `onResponse` (#663); an external policy engine via `srt proxy` / `srt-proxy`, the HTTP
   proxy alone with an external decider process (`docs/srt-proxy.md`, #666). Keep "egress
   audit logging" as still open. Note `credentials.files` masking is still Linux-only.
7. **"0.0.62-ltic.1 → later"** entry mentions "socat and jq became dependencies": leave as
   history, but it is fine to append "(socat dropped again at 0.0.81)".

### `justfile`

1. **`deps`**: the loop `for f in socat jq; do …` → `for f in jq; do …`. Update the recipe
   comment "install socat + jq via Homebrew" accordingly. Add a Node version check, e.g.
   `node -e 'const [M,m]=process.versions.node.split(".").map(Number); process.exit(M>22||(M===22&&m>=12)?0:1)' && echo "  ok   node $(node --version)" || echo "  FAIL node $(node --version) — srt 0.0.81 needs >= 22.12"`.
2. **`check` step 1 "tools"**: `for t in srt socat jq node openssl` → drop `socat`; add the
   same Node floor check.
3. **`check`, optional new step** after the `gh api user` smoke test: when `ssh-add -l`
   exits 0, run
   `_ccx_run "$deny" sh -c 'eval "$GIT_SSH_COMMAND -T git@github.com" 2>&1'` and pass on
   output containing `successfully authenticated` (ssh exits 1 there; judge the text, not
   the status). Skip with a note when the agent holds no keys.
4. `upgrade`, `install-*`, `trust-ca` unchanged.

### `.srt-claude-denyall.json`, `.srt-claude-allowall.json`

No required edits. Two optional, separately decided additions (ask Greg; default is to
leave them out of this PR unless told otherwise):

- Hardening, both files, under `network`: `"requireHostMatch": true`. Verify afterwards
  with `just check` and a few tool runs (`npm view`, `cargo search`, `uv pip install
  --dry-run`, `gh api user`); a tool that sends a Host header or SNI not matching its
  CONNECT target would now get `421` and a violation line.
- Policy, both files: `"github.com:22"` and `"ssh.github.com"` in `deniedDomains` with
  matching `deniedDomainReasons` (e.g. "SSH to GitHub is blocked; use an https remote,
  gh auth is injected by the proxy"). Closes the SSH path that bypasses token masking.
  Only sensible if the documented push path moves to HTTPS remotes.
- Noise (optional): the ssh hop produced three benign denials under `denyall`
  (`mach-lookup com.apple.dnssd.service`, `mach-lookup com.apple.usymptomsd`,
  `/.zshenv` read). They may be added to `ignoreViolations["*"]` if they annoy.

### `.zshrc.example`, `.bashrc.example`, `srt-violations.mjs`

No changes. The wrapper's per-launch `allowUnixSockets` and CA-path injection, the
credential seeding and the hook are all exercised by the verified runs above.

## 4. Acceptance checklist for the PR

- [ ] `just check` passes **with socat uninstalled or hidden from PATH**.
- [ ] `srt --version` → `0.0.81-ltic.1` and `just check` reports it as the fork.
- [ ] Both configs load with no "unrecognized settings key" warning.
- [ ] `ccx_exec gh api user --jq .login` prints the login.
- [ ] `ccx_exec sh -c 'eval "$GIT_SSH_COMMAND -T git@github.com"'` prints "successfully
      authenticated" (needs a key in the agent).
- [ ] `ccx_exec curl -sI https://gist.github.com | head -1` shows the configured reason in
      the 403 line, and the same line appears in `$SRT_VIOLATIONS_FILE`.
- [ ] README no longer mentions socat as a requirement; DETAILS lists three fork deltas,
      has the 0.0.81 upstream-changes section, the 0.77 → 0.81 upgrade note, the rewritten
      SSH transport paragraph, and the refreshed Linux and future-directions sections.
- [ ] If `requireHostMatch` was adopted: both configs carry it and the tool smoke tests
      above still pass.
