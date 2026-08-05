# Anthropic Sandbox Runtime (srt)

A lightweight sandboxing tool for enforcing filesystem and network restrictions on arbitrary processes at the OS level, without requiring a container.

`srt` uses native OS sandboxing primitives (`sandbox-exec` on macOS, `bubblewrap` on Linux) and proxy-based network filtering. It can be used to sandbox the behaviour of agents, local MCP servers, bash commands and arbitrary processes.

> **Beta Research Preview**
>
> The Sandbox Runtime is a research preview developed for [Claude Code](https://www.claude.com/product/claude-code) to enable safer AI agents. It's being made available as an early open source preview to help the broader ecosystem build more secure agentic systems. As this is an early research preview, APIs and configuration formats may evolve. We welcome feedback and contributions to make AI agents safer by default!

## Installation

```bash
npm install -g @anthropic-ai/sandbox-runtime
```

## Basic Usage

```bash
# Network restrictions
$ srt "curl anthropic.com"
Running: curl anthropic.com
<html>...</html>  # Request succeeds

$ srt "curl example.com"
Running: curl example.com
Connection blocked by network allowlist  # Request blocked

# Filesystem restrictions
$ srt "cat README.md"
Running: cat README.md
# Anthropic Sandb...  # Current directory access allowed

$ srt "cat ~/.ssh/id_rsa"
Running: cat ~/.ssh/id_rsa
cat: /Users/ollie/.ssh/id_rsa: Operation not permitted  # Specific file blocked
```

## Overview

This package provides a standalone sandbox implementation that can be used as both a CLI tool and a library. It's designed with a **secure-by-default** philosophy tailored for common developer use cases: processes start with minimal access, and you explicitly poke only the holes you need.

**Key capabilities:**

- **Network restrictions**: Control which hosts/domains can be accessed via HTTP/HTTPS and other protocols
- **Filesystem restrictions**: Control which files/directories can be read/written
- **Unix socket restrictions**: Control access to local IPC sockets
- **Violation monitoring**: On macOS, tap into the system's sandbox violation log store for real-time alerts

### Example Use Case: Sandboxing MCP Servers

A key use case is sandboxing Model Context Protocol (MCP) servers to restrict their capabilities. For example, to sandbox the filesystem MCP server:

**Without sandboxing** (`.mcp.json`):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"]
    }
  }
}
```

**With sandboxing** (`.mcp.json`):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "srt",
      "args": ["npx", "-y", "@modelcontextprotocol/server-filesystem"]
    }
  }
}
```

Then configure restrictions in `~/.srt-settings.json`:

```json
{
  "filesystem": {
    "denyRead": [],
    "allowWrite": ["."],
    "denyWrite": ["~/sensitive-folder"]
  },
  "network": {
    "allowedDomains": [],
    "deniedDomains": []
  }
}
```

Now the MCP server will be blocked from writing to the denied path:

```
> Write a file to ~/sensitive-folder
✗ Error: EPERM: operation not permitted, open '/Users/ollie/sensitive-folder/test.txt'
```

## How It Works

The sandbox uses OS-level primitives to enforce restrictions that apply to the entire process tree:

- **macOS**: Uses `sandbox-exec` with dynamically generated [Seatbelt profiles](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf)
- **Linux**: Uses [bubblewrap](https://github.com/containers/bubblewrap) for containerization with network namespace isolation
- **Windows**: Runs the sandboxed process under a dedicated `srt-sandbox` local user account, with a [Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) egress fence keyed on that account's SID and per-session explicit ACEs on the working tree

![0d1c612947c798aef48e6ab4beb7e8544da9d41a-4096x2305](https://github.com/user-attachments/assets/76c838a9-19ef-4d0b-90bb-cbe1917b3551)

### Dual Isolation Model

Both filesystem and network isolation are required for effective sandboxing. Without file isolation, a compromised process could exfiltrate SSH keys or other sensitive files. Without network isolation, a process could escape the sandbox and gain unrestricted network access.

**Filesystem Isolation** enforces read and write restrictions:

- **Read** (deny-then-allow pattern): By default, read access is allowed everywhere. You can deny broad regions (e.g., `/Users`) and then re-allow specific paths within them (e.g., `.`). `allowRead` takes precedence over `denyRead` — the opposite of write, where `denyWrite` takes precedence over `allowWrite`.
- **Write** (allow-only pattern): By default, write access is denied everywhere. You must explicitly allow paths (e.g., `.`, `/tmp`). An empty allow list means no write access.

**Network Isolation** (allow-only pattern): By default, all network access is denied. You must explicitly allow domains. An empty allowedDomains list means no network access. Network traffic is routed through proxy servers running on the host:

- **Linux**: Requests are routed via the filesystem over a Unix domain socket. The network namespace of the sandboxed process is removed entirely, so all network traffic must go through the proxies running on the host (listening on Unix sockets that are bind-mounted into the sandbox)

- **macOS**: The Seatbelt profile allows communication only to a specific localhost port. The proxies listen on this port, creating a controlled channel for all network access

- **Windows**: A machine-wide WFP filter set blocks all outbound connections originating from the `srt-sandbox` account except loopback to the proxy port range. The proxies listen inside that range, creating a controlled channel for all network access

Both HTTP/HTTPS (via HTTP proxy) and other TCP traffic (via SOCKS5 proxy) are mediated by these proxies, which enforce your domain allowlists and denylists.

For more details on sandboxing in Claude Code, see:

- [Claude Code Sandboxing Documentation](https://docs.claude.com/en/docs/claude-code/sandboxing)
- [Beyond Permission Prompts: Making Claude Code More Secure and Autonomous](https://www.anthropic.com/engineering/claude-code-sandboxing)

## Architecture

```
src/
├── index.ts                  # Library exports
├── cli.ts                    # CLI entrypoint (srt command)
├── utils/                    # Shared utilities
│   ├── debug.ts             # Debug logging
│   ├── settings.ts          # Settings reader (permissions + sandbox config)
│   ├── platform.ts          # Platform detection
│   └── exec.ts              # Command execution utilities
└── sandbox/                  # Sandbox implementation
    ├── sandbox-manager.ts    # Main sandbox manager
    ├── sandbox-schemas.ts    # Zod schemas for validation
    ├── sandbox-violation-store.ts # Violation tracking
    ├── sandbox-utils.ts      # Shared sandbox utilities
    ├── http-proxy.ts         # HTTP/HTTPS proxy for network filtering
    ├── socks-proxy.ts        # SOCKS5 proxy for network filtering
    ├── linux-sandbox-utils.ts # Linux bubblewrap sandboxing
    ├── macos-sandbox-utils.ts # macOS sandbox-exec sandboxing
    └── windows-sandbox-utils.ts # Windows srt-win sandboxing
```

## Usage

### As a CLI tool

The `srt` command (Anthropic Sandbox Runtime) wraps any command with security boundaries:

```bash
# Run a command in the sandbox
srt echo "hello world"

# With debug logging
srt --debug curl https://example.com

# Specify custom settings file
srt --settings /path/to/srt-settings.json npm install
```

### As a library

```typescript
import {
  SandboxManager,
  type SandboxRuntimeConfig,
} from '@anthropic-ai/sandbox-runtime'
import { spawn } from 'child_process'

// Define your sandbox configuration
const config: SandboxRuntimeConfig = {
  network: {
    allowedDomains: ['example.com', 'api.github.com'],
    deniedDomains: [],
  },
  filesystem: {
    denyRead: ['~/.ssh'],
    allowWrite: ['.', '/tmp'],
    denyWrite: ['.env'],
  },
}

// Initialize the sandbox (starts proxy servers, etc.)
await SandboxManager.initialize(config)

// Wrap a command with sandbox restrictions
const sandboxedCommand = await SandboxManager.wrapWithSandbox(
  'curl https://example.com',
)

// Execute the sandboxed command
const child = spawn(sandboxedCommand, { shell: true, stdio: 'inherit' })

// Handle exit and cleanup after child process completes
child.on('exit', async code => {
  console.log(`Command exited with code ${code}`)
  // Cleanup when done (optional, happens automatically on process exit)
  await SandboxManager.reset()
})
```

**Violation attribution (`commandLabel`).** Violations observed while a wrapped command runs (seatbelt log lines, seccomp events, proxy denies) are stored under an attribution key derived from the command string, and `annotateStderrWithSandboxFailures(cmd, stderr)` / `getViolationsForCommand(cmd)` look them up by that same key. If the string you *execute* is not the string you *look up by* — e.g. you wrap an assembled `source <snapshot> && eval '<cmd>'` but query by the raw `<cmd>` — pass the lookup string as `commandLabel` so the two keys match; otherwise no `<sandbox_violations>` block is ever produced:

```typescript
const wrapped = await SandboxManager.wrapWithSandbox(
  assembledCommand, // what actually runs
  undefined,
  undefined,
  undefined,
  { commandLabel: rawCommand }, // what you'll look violations up by
)
// ... run it ...
const annotated = SandboxManager.annotateStderrWithSandboxFailures(rawCommand, stderr)
```

#### Available exports

```typescript
// Main sandbox manager
export { SandboxManager } from '@anthropic-ai/sandbox-runtime'

// Violation tracking
export { SandboxViolationStore } from '@anthropic-ai/sandbox-runtime'

// TypeScript types
export type {
  SandboxRuntimeConfig,
  NetworkConfig,
  FilesystemConfig,
  IgnoreViolationsConfig,
  SandboxAskCallback,
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
  NetworkRestrictionConfig,
} from '@anthropic-ai/sandbox-runtime'
```

## Configuration

### Settings File Location

By default, the sandbox runtime looks for configuration at `~/.srt-settings.json`. You can specify a custom path using the `--settings` flag:

```bash
srt --settings /path/to/srt-settings.json <command>
```

### Complete Configuration Example

```json
{
  "network": {
    "allowedDomains": [
      "github.com",
      "*.github.com",
      "lfs.github.com",
      "api.github.com",
      "npmjs.org",
      "*.npmjs.org"
    ],
    "deniedDomains": ["malicious.com"],
    "allowUnixSockets": ["/var/run/docker.sock"],
    "allowLocalBinding": false
  },
  "filesystem": {
    "denyRead": ["~/.ssh"],
    "allowRead": [],
    "allowWrite": [".", "src/", "test/", "/tmp"],
    "denyWrite": [".env", "config/production.json"]
  },
  "ignoreViolations": {
    "*": ["/usr/bin", "/System"],
    "git push": ["/usr/bin/nc"],
    "npm": ["/private/tmp"]
  },
  "enableWeakerNestedSandbox": false,
  "enableWeakerNetworkIsolation": false,
  "allowAppleEvents": false
}
```

### Configuration Options

#### Network Configuration

Uses an **allow-only pattern** - all network access is denied by default.

- `network.allowedDomains` - Array of allowed domains (supports wildcards like `*.example.com`). Empty array = no network access. An optional `:port` suffix (`api.example.com:443`, `*.example.com:8443`) restricts an entry to that destination port; entries without a port match any port.
- `network.deniedDomains` - Array of denied domains (checked first, takes precedence over allowedDomains). Same `:port` suffix, and a bare `*` (or `*:22`) is accepted for deny-all.
- `network.deniedDomainReasons` - Optional map from a `deniedDomains` entry (matched by exact string) to a model-facing reason that appears in the `<sandbox_violations>` line when that entry denies a connection — say what is blocked and the sanctioned alternative (e.g. `{"github.com:22": "SSH pushes to GitHub are blocked; use an https:// remote"}`). Entries without a reason report a generic one.
- `network.allowLocalBinding` - Allow binding to local ports (boolean, default: false)

**TLS termination** (`network.tlsTerminate`, experimental): when set, HTTPS CONNECTs are terminated in-process so SRT can see (and filter, via `network.filterRequest`) the decrypted requests. The sandboxed process is pointed at a trust bundle containing the MITM CA (`caCertPath`/`caKeyPath`, or an ephemeral CA if omitted) plus the host's regular roots, so proxy-minted certificates and real upstream certificates both verify.

- `network.tlsTerminate.excludeDomains` - Domain patterns (same syntax as `allowedDomains`) that are **not** terminated. Matching CONNECTs are tunnelled opaquely instead: they are still subject to the domain allowlist, but the client inside the sandbox completes its own TLS handshake with the real upstream, and `filterRequest` / credential injection do not apply to their HTTPS traffic. Use this for the two cases TLS termination fundamentally breaks:
  - **mTLS upstreams** - only the in-sandbox client holds the client certificate, so the proxy cannot re-originate the connection on its behalf.
  - **Certificate-pinning clients** - clients that verify the upstream's identity themselves (custom CAs, SAN pinning) and reject the MITM certificate.
- `network.tlsTerminate.extraCaCertPaths` - Paths to PEM CA certificate files appended to that trust bundle, after the MITM CA and the host's regular roots. Excluded (non-terminated) hosts are verified by the client inside the sandbox, and the trust env vars SRT sets (`SSL_CERT_FILE`, `GIT_SSL_CAINFO`, ...) _replace_ each tool's own trust configuration, so a site-local root (e.g. an internal mTLS CA) must be in the bundle or those hosts can never be verified. Only the `CERTIFICATE` blocks of each file are copied into the bundle (anything else, e.g. a private key in a combined PEM, is never exposed to the sandbox); files that are missing, unreadable, or contain no PEM `CERTIFICATE` block are skipped, so it is safe to list paths that exist on only some hosts.

```json
{
  "network": {
    "allowedDomains": ["*.example.com", "internal-mtls.example.net"],
    "deniedDomains": [],
    "tlsTerminate": {
      "excludeDomains": ["internal-mtls.example.net"],
      "extraCaCertPaths": ["/etc/internal-mtls-roots.pem"]
    }
  }
}
```

**Unix Socket Settings** (platform-specific behavior):

| Setting                        | macOS                     | Linux                                    |
| ------------------------------ | ------------------------- | ---------------------------------------- |
| `allowUnixSockets: string[]`   | Allowlist of socket paths | _Ignored_ (seccomp can't filter by path) |
| `allowAllUnixSockets: boolean` | Allow all sockets         | Disable seccomp blocking                 |

Unix sockets are **blocked by default** on both platforms.

- **macOS**: Use `allowUnixSockets` to allow specific paths (e.g., `["/var/run/docker.sock"]`), or `allowAllUnixSockets: true` to allow all.
- **Linux**: Blocking uses seccomp filters (x64/arm64 only). If seccomp isn't available, sockets are unrestricted and a warning is shown. Use `allowAllUnixSockets: true` to explicitly disable blocking.

#### Filesystem Configuration

Uses two different patterns:

**Read restrictions** (deny-then-allow pattern) - all reads allowed by default:

- `filesystem.denyRead` - Array of paths to deny read access. Empty array = full read access.
- `filesystem.allowRead` - Array of paths to re-allow read access within denied regions (takes precedence over denyRead). **Note:** this is the opposite of write, where `denyWrite` takes precedence over `allowWrite`.

**Write restrictions** (allow-only pattern) - all writes denied by default:

- `filesystem.allowWrite` - Array of paths to allow write access. Empty array = no write access.
- `filesystem.denyWrite` - Array of paths to deny write access within allowed paths (takes precedence over allowWrite)

**Path Syntax (macOS):**

Paths support git-style glob patterns on macOS, similar to `.gitignore` syntax:

- `*` - Matches any characters except `/` (e.g., `*.ts` matches `foo.ts` but not `foo/bar.ts`)
- `**` - Matches any characters including `/` (e.g., `src/**/*.ts` matches all `.ts` files in `src/`)
- `?` - Matches any single character except `/` (e.g., `file?.txt` matches `file1.txt`)
- `[abc]` - Matches any character in the set (e.g., `file[0-9].txt` matches `file3.txt`)

Examples:

- `"allowWrite": ["src/"]` - Allow write to entire `src/` directory
- `"allowWrite": ["src/**/*.ts"]` - Allow write to all `.ts` files in `src/` and subdirectories
- `"denyRead": ["~/.ssh"]` - Deny read to SSH directory
- `"denyRead": ["/Users"], "allowRead": ["."]` - Deny read to all of `/Users`, but re-allow the current directory
- `"denyWrite": [".env"]` - Deny write to `.env` file (even if current directory is allowed)

**Path Syntax (Linux):**

**Linux currently does not support glob matching.** Use literal paths only:

- `"allowWrite": ["src/"]` - Allow write to `src/` directory
- `"denyRead": ["/home/user/.ssh"]` - Deny read to SSH directory
- `"denyRead": ["/home"], "allowRead": ["."]` - Deny read to all of `/home`, but re-allow the current directory

**All platforms:**

- Paths can be absolute (e.g., `/home/user/.ssh`) or relative to the current working directory (e.g., `./src`)
- `~` expands to the user's home directory

#### Other Configuration

- `ignoreViolations` - Object mapping command patterns to arrays of paths where violations should be ignored
- `enableWeakerNestedSandbox` - Enable weaker sandbox mode for Docker environments (boolean, default: false)
- `enableWeakerNetworkIsolation` - Allow access to `com.apple.trustd.agent` in the macOS sandbox (boolean, default: false). This is needed for Go programs (`gh`, `gcloud`, `terraform`, `kubectl`, etc.) to verify TLS certificates when using `httpProxyPort` with a MITM proxy and custom CA. **Security warning:** enabling this opens a potential data exfiltration vector through the trustd service.
- `allowAppleEvents` - Allow sending Apple Events and Launch Services open requests from the macOS sandbox (boolean, default: false). Without this, commands like `open`, `osascript`, and anything that opens URLs or scripts other apps via AppleScript fail with AppleScript error `-600` ("Application isn't running") or LaunchServices errors (`-10822`, `-54`). **Security warning:** enabling this means the sandbox no longer provides code-execution isolation. A sandboxed command can launch other applications via `open` with no user prompt, and anything it launches runs outside the sandbox's filesystem and network restrictions; scripting already-running apps via Apple Events is additionally gated by the user's per-app TCC automation consent. Embedders should only source this option from trusted user-level configuration — never from project-local files in a checked-out repository, which would let an attacker-authored project elevate its own sandbox permissions.

### Common Configuration Recipes

**Allow GitHub access** (all necessary endpoints):

```json
{
  "network": {
    "allowedDomains": [
      "github.com",
      "*.github.com",
      "lfs.github.com",
      "api.github.com"
    ],
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": [],
    "allowWrite": ["."],
    "denyWrite": []
  }
}
```

**Restrict to specific directories:**

```json
{
  "network": {
    "allowedDomains": [],
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": ["~/.ssh"],
    "allowWrite": [".", "src/", "test/"],
    "denyWrite": [".env", "secrets/"]
  }
}
```

**Workspace-only filesystem access** (deny reads outside the workspace):

```json
{
  "network": {
    "allowedDomains": [],
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": ["/Users"],
    "allowRead": ["."],
    "allowWrite": ["."],
    "denyWrite": []
  }
}
```

This denies reading anything under `/Users` (or `/home` on Linux), then re-allows the current working directory. System paths (`/usr`, `/lib`, etc.) remain readable.

### Common Issues and Tips

**Running Jest:** Use `--no-watchman` flag to avoid sandbox violations:

```bash
srt "jest --no-watchman"
```

Watchman accesses files outside the sandbox boundaries, which will trigger permission errors. Disabling it allows Jest to run with the built-in file watcher instead.

## Platform Support

- **macOS**: Uses `sandbox-exec` with custom profiles (no additional dependencies)
- **Linux**: Uses `bubblewrap` (bwrap) for containerization
- **Windows**: Alpha — uses a bundled `srt-win.exe` helper (no additional dependencies). See [Windows (alpha)](#windows-alpha) below for setup, security model, and known limitations

### Platform-Specific Dependencies

**Linux requires:**

- `bubblewrap` - Container runtime
  - Ubuntu/Debian: `apt-get install bubblewrap`
  - Fedora: `dnf install bubblewrap`
  - Arch: `pacman -S bubblewrap`
- `socat` - Socket relay for proxy bridging
  - Ubuntu/Debian: `apt-get install socat`
  - Fedora: `dnf install socat`
  - Arch: `pacman -S socat`
- `ripgrep` - Fast search tool for deny path detection
  - Ubuntu/Debian: `apt-get install ripgrep`
  - Fedora: `dnf install ripgrep`
  - Arch: `pacman -S ripgrep`

**Ubuntu 24.04+ note:** These releases enable `kernel.apparmor_restrict_unprivileged_userns` by default, which allows `unshare(CLONE_NEWUSER)` but strips capabilities from the resulting namespace. Both bubblewrap and the seccomp isolation layer need capability-bearing user namespaces. Disable the restriction with:

```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

or add an AppArmor profile that grants `userns` to the relevant binaries.

**Optional Linux dependencies (for seccomp fallback):**

The package includes pre-generated seccomp BPF filters for x86-64 and arm architectures. These dependencies are only needed if you are on a different architecture where pre-generated filters are not available:

- `gcc` or `clang` - C compiler
- `libseccomp-dev` - Seccomp library development files
  - Ubuntu/Debian: `apt-get install gcc libseccomp-dev`
  - Fedora: `dnf install gcc libseccomp-devel`
  - Arch: `pacman -S gcc libseccomp`

**macOS requires:**

- `ripgrep` - Fast search tool for deny path detection
  - Install via Homebrew: `brew install ripgrep`
  - Or download from: https://github.com/BurntSushi/ripgrep/releases

**Windows requires:**

- No additional dependencies. The `srt-win.exe` helper (x64 and arm64) is bundled with the npm package. A one-time elevated `windows-install` step is required — see below.

## Windows (alpha)

Windows support is **alpha**. The sandboxed process runs under a dedicated `srt-sandbox` local user account, isolated from the calling user by native Windows security primitives — a Windows Filtering Platform (WFP) egress fence keyed on the sandbox account's SID, and per-session explicit ACEs that grant or deny that SID access to configured filesystem paths.

### Setup

Run once per machine (self-elevates; one UAC prompt):

```powershell
npx @anthropic-ai/sandbox-runtime windows-install
```

This provisions the `srt-sandbox` local user account (with a random password stored DPAPI-encrypted under `%LOCALAPPDATA%\sandbox-runtime\state.db`), the `sandbox-runtime-users` local group, and installs a machine-wide WFP filter set keyed on the `srt-sandbox` SID. It is **idempotent** — re-running it rotates the sandbox account's password and reconciles the filter set.

**No logout is required.** The WFP filters key on the dedicated sandbox account's SID, so your own network, services, and every other principal on the machine are unaffected.

After install, `SandboxManager.initialize()` and the `srt` CLI work as on other platforms. `initialize()` verifies the sandbox account and WFP fence are live, and fails with an actionable error if not.

Programmatic install/uninstall are exported as `installWindowsSandbox()` / `uninstallWindowsSandbox()`.

### Security model

The sandboxed command runs **as the `srt-sandbox` account**, not as the calling user. The bundled `srt-win.exe` helper does a two-hop launch: the broker calls `CreateProcessWithLogonW` to start a runner as `srt-sandbox`, and the runner spawns the target under a restricted token inside a job object. The child inherits the sandbox account's isolated profile (`%USERPROFILE%`, `%TEMP%`, `HKCU`) and a fresh environment overlaid with only the broker's `PATH` and the generated proxy variables.

Running under a distinct user SID structurally closes the surrogate-spawn class of escape (Task Scheduler, `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` onto a broker-owned process, BITS, out-of-process COM with `RunAs="Interactive User"`): any process the child manages to spawn out-of-band still carries the `srt-sandbox` SID, so it remains subject to the WFP egress fence and has no rights on the calling user's files.

**Network isolation** is a two-filter WFP set at `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`: a PERMIT for loopback destinations inside the configured proxy port range (default `60080–60089`), and a BLOCK for any connect whose token carries the `srt-sandbox` SID. The sandboxed process reaches the internet only via the JS HTTP/SOCKS5 proxies listening in that range; a process that strips its proxy environment and connects directly is blocked at the kernel.

**Filesystem isolation** is enforced by NTFS discretionary ACLs. The `srt-sandbox` account has no inherent rights on the calling user's files, so at `initialize()` the sandbox writes **additive, inheriting explicit ACEs for the `srt-sandbox` SID only** — it never rewrites or replaces a path's existing security descriptor:

- `filesystem.allowWrite` → an inheriting `MODIFY` ALLOW ACE (`READ|WRITE|EXECUTE|DELETE`, with `FILE_DELETE_CHILD` withheld). The sandboxed process can create, modify, and delete files inside the working tree; withholding `FILE_DELETE_CHILD` from the grant is defense-in-depth for the deny stamps below, not a guard on the tree root.
- `filesystem.allowRead` → an inheriting `READ|EXECUTE` ALLOW ACE
- `filesystem.denyRead` / `filesystem.denyWrite` → an inheriting DENY ACE on the target, plus an inheriting `FILE_DELETE_CHILD` DENY on its parent — together with the withheld `FILE_DELETE_CHILD` on the working-tree grant, this stops the sandboxed process from renaming or deleting a denied path via its parent directory

`reset()` removes every ACE this session added (refcounted across concurrent hosts via `state.db`; a crash-recovery pass on the next `initialize()` cleans up after an unclean exit). Directory targets are supported (the ACEs inherit to the whole subtree). Glob patterns are expanded to concrete paths at `initialize()` time — a matching path that appears later is not covered.

### TLS termination on Windows

`network.tlsTerminate` requires the MITM CA to be present in the **sandbox user's** `CurrentUser\Root` certificate store (schannel — the TLS backend used by `System32\curl.exe`, PowerShell `Invoke-WebRequest`, .NET, and default-backend `git` — trusts only the OS store, not environment variables). This is an install-time step, separate from `windows-install`:

```typescript
import { windowsTrustCa } from '@anthropic-ai/sandbox-runtime'
windowsTrustCa('/path/to/mitm-ca.crt') // or: srt-win user trust-ca <path>
```

`initialize()` compares the session CA's thumbprint against the installed one and fails with an actionable message on mismatch, so a stale install-time CA cannot silently break TLS inside the sandbox.

OpenSSL-backed clients (msys2 `curl`, `git -c http.sslBackend=openssl`, Node, Python, cargo) are covered by the env-var trust layer: the same trust bundle used on macOS/Linux is passed into the sandbox via `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `CARGO_HTTP_CAINFO`, etc., and the bundle path is added to the session's `allowRead` grant so the sandbox account can open it.

### Windows-specific configuration

The cross-platform `filesystem` and `network` blocks apply as described above. Windows-only settings live under `windows`:

- `windows.proxyPortRange` — `[low, high]` inclusive port range the JS proxies bind inside. **Must match** the range passed to `windows-install --proxy-port-range` (default `[60080, 60089]`) — the WFP loopback PERMIT only covers that range.
- `windows.sublayerGuid` — WFP sublayer GUID under which the filters were installed. Omit to use the compile-time default; set only when enterprise tooling installed the filters under a custom sublayer.
- `windows.srtWin.path` — path to the `srt-win` binary. Omit to resolve the packaged `vendor/srt-win/<arch>/srt-win.exe`. Set when embedding `srt-win`'s CLI into a multicall binary; spawns then pass `--srt-win` as `argv[1]` so the embedder's dispatcher can route to `srt_win::run_from_args`.

### Known limitations

- **Certificate revocation under schannel.** CryptoAPI's CRL/OCSP fetch goes out via WinHTTP under the caller's token, ignoring the proxy environment, so it is blocked by the WFP egress fence. Tools that use schannel with revocation checking on by default fail with `CRYPT_E_REVOCATION_OFFLINE` (`0x80092013`) unless revocation is disabled per tool: `curl --ssl-no-revoke`, `git -c http.schannelCheckRevoke=false`, `CARGO_HTTP_CHECK_REVOKE=false`. `Invoke-WebRequest`, .NET `HttpClient`, and `gh` do not check revocation by default and are unaffected. A CRL distribution point served from the loopback proxy is planned to remove this workaround.
- **Per-user tool installs are not reachable.** The sandboxed process runs as `srt-sandbox`, not as you, so tools installed under your profile (nvm/fnm-managed Node, per-user `winget`/Scoop packages, `pip install --user`, `%LOCALAPPDATA%\Programs\…`) resolve on the inherited `PATH` but cannot be opened by the sandbox account. Prefer machine-wide installs (`Program Files`, `choco`/`winget --scope machine`), or add the specific profile paths to `filesystem.allowRead`.
- **Per-exec `filesystem.allowRead` / `filesystem.allowWrite` overrides are not supported.** Session-level `allowRead`/`allowWrite` (in the config passed to `initialize()`) work as described above; passing them per-command in `wrapWithSandbox`'s `customConfig` throws — grants are applied session-wide via `srt-win acl grant` at `initialize()`, and `srt-win exec` only exposes per-exec denies.
- **`proxyAuthToken` is visible in the runner's command line.** The proxy environment (including `HTTP_PROXY=http://srt:<token>@127.0.0.1:…`) is passed to the two-hop runner as `--env` arguments on `srt-win exec`'s argv, so the token is readable by any local principal that can open the runner process for `PROCESS_QUERY_LIMITED_INFORMATION`. The token exists so the sandboxed process can authenticate to the loopback proxy, so it is not a secret from the sandbox itself; on a single-user development machine this is generally acceptable, but on a shared host treat the proxy allowlist as reachable by other same-session principals.
- **DNS resolution via the system resolver is not fenced.** `getaddrinfo()` is serviced by the `Dnscache` service running as `NETWORK SERVICE`, so name resolution succeeds even though the subsequent `connect()` from the sandboxed process is blocked. Tools that do their own UDP/53 (`nslookup`, `dig`) are fenced. This mirrors the macOS behaviour.

### Uninstall

```powershell
npx @anthropic-ai/sandbox-runtime windows-uninstall
```

Removes the WFP filter set, the `srt-sandbox` account and its profile, the `sandbox-runtime-users` group, and clears the credential/setup marker from `state.db` (one UAC prompt). `%LOCALAPPDATA%\sandbox-runtime\state.db` itself is left in place (it is ACL-stamped broker-only); delete the directory manually for a full sweep.

## Development

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test

# Type checking
npm run typecheck

# Lint code
npm run lint

# Format code
npm run format
```

### Building Seccomp Binaries

The BPF filter and `apply-seccomp` loader are compiled from C source in `vendor/seccomp-src/` via `npm run build:seccomp` (Linux only; needs `gcc` and `libseccomp-dev`). CI runs it before tests on each Linux arch, and the release workflow builds both arches and bundles them into the published package.

## Implementation Details

### Network Isolation Architecture

The sandbox runs HTTP and SOCKS5 proxy servers on the host machine that filter all network requests based on permission rules:

1. **HTTP/HTTPS Traffic**: An HTTP proxy server intercepts requests and validates them against allowed/denied domains
2. **Other Network Traffic**: A SOCKS5 proxy handles all other TCP connections (SSH, database connections, etc.)
3. **Permission Enforcement**: The proxies enforce the `permissions` rules from your configuration

**Platform-specific proxy communication:**

- **Linux**: Requests are routed via the filesystem over Unix domain sockets (using `socat` for bridging). The network namespace is removed from the bubblewrap container, ensuring all network traffic must go through the proxies.

- **macOS**: The Seatbelt profile allows communication only to specific localhost ports where the proxies listen. All other network access is blocked.

- **Windows**: A WFP `ALE_AUTH_CONNECT` filter blocks every outbound connect from the `srt-sandbox` account except loopback to the configured proxy port range. The proxies bind inside that range. Environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, …) point tools at the proxies, but the WFP filter is the boundary — a process that ignores or unsets them is still fenced.

### Filesystem Isolation

Filesystem restrictions are enforced at the OS level:

- **macOS**: Uses `sandbox-exec` with dynamically generated Seatbelt profiles that specify allowed read/write paths
- **Linux**: Uses `bubblewrap` with bind mounts, marking directories as read-only or read-write based on configuration
- **Windows**: Writes additive `(OI)(CI)` explicit ACEs for the `srt-sandbox` SID onto the configured paths (ALLOW on `allowRead`/`allowWrite`, DENY on `denyRead`/`denyWrite`), then removes them at `reset()`

**Default filesystem permissions:**

- **Read** (deny-then-allow): Allowed everywhere by default. You can deny broad regions, then re-allow specific paths within them. `allowRead` takes precedence over `denyRead`.

  - Example: `denyRead: ["~/.ssh"]` to block access to SSH keys
  - Example: `denyRead: ["/Users"], allowRead: ["."]` to block all of `/Users` except the workspace
  - Empty `denyRead: []` = full read access (nothing denied)

- **Write** (allow-only): Denied everywhere by default. You must explicitly allow paths.
  - Example: `allowWrite: [".", "/tmp"]` to allow writes to current directory and /tmp
  - Empty `allowWrite: []` = no write access (nothing allowed)
  - `denyWrite` creates exceptions within allowed paths (deny takes precedence)

**Precedence is intentionally opposite for reads vs writes:** `allowRead` overrides `denyRead`, while `denyWrite` overrides `allowWrite`. This lets you carve out readable regions within denied areas, and carve out protected regions within writable areas.

### Mandatory Deny Paths (Auto-Protected Files)

Certain sensitive files and directories are **always blocked from writes**, even if they fall within an allowed write path. This provides defense-in-depth against sandbox escapes and configuration tampering.

**Always-blocked files:**

- Shell config files: `.bashrc`, `.bash_profile`, `.zshrc`, `.zprofile`, `.profile`
- Git config files: `.gitconfig`, `.gitmodules`
- Other sensitive files: `.ripgreprc`, `.mcp.json`

**Always-blocked directories:**

- IDE directories: `.vscode/`, `.idea/`
- Claude config directories: `.claude/commands/`, `.claude/agents/`
- Git hooks and config: `.git/hooks/`, `.git/config`

These paths are blocked automatically - you don't need to add them to `denyWrite`. For example, even with `allowWrite: ["."]`, writing to `.bashrc` or `.git/hooks/pre-commit` will fail:

```bash
$ srt 'echo "malicious" >> .bashrc'
/bin/bash: .bashrc: Operation not permitted

$ srt 'echo "bad" > .git/hooks/pre-commit'
/bin/bash: .git/hooks/pre-commit: Operation not permitted
```

**Note (Linux):** On Linux, mandatory deny paths only block files that already exist. Non-existent files in these patterns cannot be blocked by bubblewrap's bind-mount approach. macOS uses glob patterns which block both existing and new files.

**Linux search depth:** On Linux, the sandbox uses `ripgrep` to scan for dangerous files in subdirectories within allowed write paths. By default, it searches up to 3 levels deep for performance. You can configure this with `mandatoryDenySearchDepth`:

```json
{
  "mandatoryDenySearchDepth": 5,
  "filesystem": {
    "allowWrite": ["."]
  }
}
```

- Default: `3` (searches up to 3 levels deep)
- Range: `1` to `10`
- Higher values provide more protection but slower performance
- Files in CWD (depth 0) are always protected regardless of this setting

### Unix Socket Restrictions (Linux)

On Linux, the sandbox uses **seccomp BPF (Berkeley Packet Filter)** to block Unix domain socket creation at the syscall level. This provides an additional layer of security to prevent processes from creating new Unix domain sockets for local IPC (unless explicitly allowed).

**How it works:**

1. **Baked-in BPF filter**: The package ships a static `apply-seccomp` binary for x64 and arm64 with the seccomp BPF filter compiled in. The filter is architecture-specific but libc-independent, so the binary works with both glibc and musl.

2. **Runtime detection**: The sandbox automatically detects your system's architecture and uses the matching `apply-seccomp` binary.

3. **Syscall filtering**: The BPF filter intercepts the `socket()` syscall and blocks creation of `AF_UNIX` sockets by returning `EPERM`. This prevents sandboxed code from creating new Unix domain sockets.

4. **Two-stage application using apply-seccomp binary**:
   - Outer bwrap creates the sandbox with filesystem, network, and PID namespace restrictions
   - Network bridging processes (socat) start inside the sandbox (need Unix sockets)
   - apply-seccomp creates a nested user+PID+mount namespace and remounts `/proc`
   - Inside the nested namespace, apply-seccomp acts as PID 1 (non-dumpable init/reaper)
   - apply-seccomp forks, applies the seccomp filter via `prctl()`, and execs the user command
   - User command runs with all sandbox restrictions plus Unix socket creation blocking

**PID namespace isolation**: The nested PID namespace ensures the user command cannot see or address any process that runs without the seccomp filter (bwrap's init, the shell wrapper, or the socat helpers). This keeps the seccomp boundary intact regardless of `kernel.yama.ptrace_scope`, since unfiltered helpers are not reachable via `ptrace` or `/proc/N/mem`. The inner PID 1 sets `PR_SET_DUMPABLE=0` so it is not ptraceable either. If nested namespace creation fails, apply-seccomp aborts rather than running without isolation.

**Security limitations**: The filter blocks `socket(AF_UNIX, ...)` and the `io_uring_setup`/`io_uring_enter`/`io_uring_register` syscalls (the latter three because `IORING_OP_SOCKET` on Linux 5.19+ would otherwise bypass the `socket()` rule). It does not prevent operations on Unix socket file descriptors inherited from parent processes or passed via `SCM_RIGHTS`. For most sandboxing scenarios, blocking socket creation is sufficient to prevent unauthorized IPC.

**Zero runtime dependencies**: Pre-built static apply-seccomp binaries and pre-generated BPF filters are included for x64 and arm64 architectures. No compilation tools or external dependencies required at runtime.

**Architecture support**: x64 and arm64 are fully supported with pre-built binaries. Other architectures are not currently supported. To use sandboxing without Unix socket blocking on unsupported architectures, set `allowAllUnixSockets: true` in your configuration.

### Violation Detection and Monitoring

When a sandboxed process attempts to access a restricted resource:

1. **Blocks the operation** at the OS level (returns `EPERM` error)
2. **Logs the violation** (platform-specific mechanisms)
3. **Notifies the user** (in Claude Code, this triggers a permission prompt)

**macOS**: The sandbox runtime taps into macOS's system sandbox violation log store. This provides real-time notifications with detailed information about what was attempted and why it was blocked. This is the same mechanism Claude Code uses for violation detection.

```bash
# View sandbox violations in real-time
log stream --predicate 'process == "sandbox-exec"' --style syslog
```

**Linux**: Bubblewrap doesn't provide built-in violation reporting. Use `strace` to trace system calls and identify blocked operations:

```bash
# Trace all denied operations
strace -f srt <your-command> 2>&1 | grep EPERM

# Trace specific file operations
strace -f -e trace=open,openat,stat,access srt <your-command> 2>&1 | grep EPERM

# Trace network operations
strace -f -e trace=network srt <your-command> 2>&1 | grep EPERM
```

### Advanced: Bring Your Own Proxy

For more sophisticated network filtering, you can configure the sandbox to use your own proxy instead of the built-in ones. This enables:

- **Traffic inspection**: Use tools like [mitmproxy](https://mitmproxy.org/) to inspect and modify traffic
- **Custom filtering logic**: Implement complex rules beyond simple domain allowlists
- **Audit logging**: Log all network requests for compliance or debugging

**Example with mitmproxy:**

```bash
# Start mitmproxy with custom filtering script
mitmproxy -s custom_filter.py --listen-port 8888
```

Note: Custom proxy configuration is not yet supported in the new configuration format. This feature will be added in a future release.

**Important security consideration:** Even with domain allowlists, exfiltration vectors may exist. For example, allowing `github.com` lets a process push to any repository. With a custom MITM proxy and proper certificate setup, you can inspect and filter specific API calls to prevent this.

### Security Limitations

- Network Sandboxing Limitations: The network filtering system operates by restricting the domains that processes are allowed to connect to. It does not otherwise inspect the traffic passing through the proxy and users are responsible for ensuring they only allow trusted domains in their policy.

<Warning>
Users should be aware of potential risks that come from allowing broad domains like `github.com` that may allow for data exfiltration. Also, in some cases it may be possible to bypass the network filtering through [domain fronting](https://en.wikipedia.org/wiki/Domain_fronting).
</Warning>

- Privilege Escalation via Unix Sockets: The `allowUnixSockets` configuration can inadvertently grant access to powerful system services that could lead to sandbox bypasses. For example, if it is used to allow access to `/var/run/docker.sock` this would effectively grant access to the host system through exploiting the docker socket. Users are encouraged to carefully consider any unix sockets that they allow through the sandbox.
- Filesystem Permission Escalation: Overly broad filesystem write permissions can enable privilege escalation attacks. Allowing writes to directories containing executables in `$PATH`, system configuration directories, or user shell configuration files (`.bashrc`, `.zshrc`) can lead to code execution in different security contexts when other users or system processes access these files.
- Linux Sandbox Strength: The Linux implementation provides strong filesystem and network isolation but includes an `enableWeakerNestedSandbox` mode that enables it to work inside of Docker environments without privileged namespaces. This option considerably weakens security and should only be used in cases where additional isolation is otherwise enforced.
- Weaker Network Isolation (macOS): The `enableWeakerNetworkIsolation` option re-enables access to `com.apple.trustd.agent`, which is needed for Go programs to verify TLS certificates via the macOS Security framework. This opens a potential data exfiltration vector through the trustd service and should only be enabled when Go TLS verification is required (e.g., when using `httpProxyPort` with a MITM proxy and custom CA).
- Apple Events (macOS): The `allowAppleEvents` option re-enables sending Apple Events and Launch Services open requests (`(allow appleevent-send)`, `(allow lsopen)`, and mach-lookups for `com.apple.coreservices.appleevents`, `com.apple.CoreServices.coreservicesd`, and `com.apple.coreservices.quarantine-resolver`), which `open`, `osascript`, and URL-opening helpers require. With these allowed, a sandboxed command can launch arbitrary applications with no user prompt, and launched applications run outside the sandbox entirely — so this option removes code-execution isolation, not just weakens it. Scripting already-running applications via Apple Events is additionally gated by macOS TCC automation consent, but launching via `open` is not. Only enable this when commands inside the sandbox genuinely need to open URLs or applications.

### Known Limitations and Future Work

**Linux proxy bypass**: Currently uses environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) to direct traffic through proxies. This works for most applications but may be ignored by programs that don't respect these variables, leading to them being unable to connect to the internet.

**Future improvements:**

- **Proxychains support**: Add support for `proxychains` with `LD_PRELOAD` on Linux to intercept network calls at a lower level, making bypass more difficult

- **Linux violation monitoring**: Implement automatic `strace`-based violation detection for Linux, integrated with the violation store. Currently, Linux users must manually run `strace` to see violations, unlike macOS which has automatic violation monitoring via the system log store
