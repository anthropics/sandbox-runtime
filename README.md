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

- **Read** (deny-then-allow pattern): By default, read access is allowed everywhere. You can deny broad regions (e.g., `/Users`) and then re-allow specific paths within them (e.g., `.`). `allowRead` takes precedence over `denyRead` — the opposite of write, where `denyWrite` takes precedence over `allowWrite`. A `denyRead` entry that is more specific than the `allowRead` region it falls inside (e.g. `denyRead: ["**/.env"]` or `["./secrets"]` with `allowRead: ["."]`) still stays denied.
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

The settings file is optional — with no file at `~/.srt-settings.json`, `srt`
runs with built-in defaults: no network access, no writes outside the default
write paths, and unrestricted reads. A settings file that _is_ there but is
empty, cannot be read, or does not validate is an error: `srt` says so and
exits rather than falling back to those defaults, which are a different
config rather than a weaker one — falling back would drop the file's
`denyRead`, `allowRead` and credential rules along with everything else it
said. The same goes for a file named with `--settings`, which must also
exist.

#### Updating the config while the command runs: `--control-fd`

`--control-fd <fd>` reads config updates from a descriptor the caller has
already opened, one JSON object per line in the same shape as the settings
file. Each line replaces the whole config, but only the network lists
(`allowedDomains` / `deniedDomains`) change what is already running: the
proxy consults them per request. Filesystem rules are compiled into the
sandbox at wrap time, so a line that changes them applies to nothing in the
current run.

```bash
# fd 3 is the read end of a pipe the caller writes lines to
srt --control-fd 3 -- npm test
```

- The descriptor must be an integer **3 or above** and readable — `0`-`2`
  are the standard streams. srt exits with an error instead of running the
  command when it cannot read the descriptor it was given, so a dead
  channel never passes for a live one. A channel that dies before it has
  delivered a single update takes the command down with it; one that dies
  after says so and leaves the command running under the config last
  applied.
- A line that is not a valid config is reported on stderr and dropped; the
  previous config stays in force.
- srt **exits with the wrapped command** and does not wait for the writer
  to close the descriptor. End of input is not an error either: the
  command keeps running under the config last applied.
- Give srt a **dedicated, read-only end**. srt puts a pipe or socket into
  non-blocking mode, and that flag lives on the open file description, so
  anything else holding the same description — a shell's `exec 3<fifo`, a
  `pass_fds` of a descriptor the parent goes on using — gets `EAGAIN` from
  its own blocking reads from then on.
- On macOS and Linux the sandboxed command does not get the descriptor: srt
  points that slot at `/dev/null` for the command, so nothing inside the
  sandbox can read the updates or write a config of its own.

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

**Violation attribution (`commandId` / `commandText`).** Violations observed while a wrapped command runs (seatbelt log lines, seccomp events, proxy denies) are stored under an attribution key, and `annotateStderrWithSandboxFailures(key, stderr)` / `getViolationsForCommand(key)` look them up by that same key. By default the key is the wrapped string itself. Pass an opaque per-invocation `commandId` (e.g. a tool-use id) to key by that instead — recommended: keys compare on their first 100 characters, so long commands sharing a prefix would otherwise cross-attribute, and a rerun of the same text would inherit the earlier run's events. If the string you _execute_ is not the command the invocation _represents_ (e.g. you wrap an assembled `source <snapshot> && eval '<cmd>'`), also pass `commandText: '<cmd>'`: it is what `ignoreViolations` command patterns match against and what each violation reports as its `command`. A `commandId` you pass to `wrapWithSandbox` must be the same non-empty string you then pass to `annotateStderrWithSandboxFailures` / `getViolationsForCommand`; an empty one is treated as no `commandId` at all, so the key is the command.

Only the key is cut to 100 characters. As of v0.0.76 the reported `command` — and the text `ignoreViolations` command patterns are matched against — is the whole command for an invocation wrapped without a `commandId`, not its first 100 characters; a pattern can therefore only suppress more than it did before, never less. An attribution key no invocation of this process registered (the carriers are writable from inside the sandbox) is reported sanitized and cut to that same key length.

```typescript
const wrapped = await SandboxManager.wrapWithSandbox(
  assembledCommand, // what actually runs
  undefined,
  undefined,
  undefined,
  { commandId: invocationId, commandText: rawCommand },
)
// ... run it ...
const annotated = SandboxManager.annotateStderrWithSandboxFailures(
  invocationId,
  stderr,
)
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
  - IPv6 literals must be bracketed, RFC 3986-style: `[::1]`, `[2001:db8::1]:443`. An unbracketed multi-colon entry is rejected as ambiguous (`2001:db8::1:443` is itself a valid address).
- `network.deniedDomains` - Array of denied domains (checked first, takes precedence over allowedDomains). Same `:port` suffix, and a bare `*` (or `*:22`) is accepted for deny-all.
- `network.deniedDomainReasons` - Optional map from a `deniedDomains` entry (matched by exact string) to a model-facing reason that appears in the `<sandbox_violations>` line when that entry denies a connection — say what is blocked and the sanctioned alternative (e.g. `{"github.com:22": "SSH pushes to GitHub are blocked; use an https:// remote"}`). Entries without a reason report a generic one. For SSH destinations (port 22), the reason is also delivered in-band: an SSH client tunneled through a no-auth SOCKS ProxyCommand (e.g. BSD `nc -X 5`) receives a pre-key-exchange SSH disconnect whose description is the reason, which OpenSSH prints verbatim — keep such reasons under ~400 ASCII characters, imperative first, since OpenSSH truncates and escapes non-ASCII.
- `network.allowLocalBinding` - Allow binding to local ports (boolean, default: false)

**Resolved-address check.** The allow/deny lists match by _name_, but whoever controls a permitted name's DNS (or any label under a permitted wildcard) controls what it resolves to. So before dialing an allowed **hostname** directly, the proxy resolves it once, drops any address in a denied set, and connects to a surviving address (the address that passed the check is the one dialed — there is no second lookup). If nothing survives, the connection is refused like any other policy denial: HTTP/CONNECT get `403` (`X-Proxy-Error: blocked-by-sandbox-runtime`, the reason in the body), SOCKS gets "connection not allowed by ruleset", and a `deny network-outbound host:port (resolved to a loopback address)` line — naming the class of address (loopback, link-local, this host's, cloud metadata, deny-listed, listed, …), not the address itself, which only the debug log carries — is recorded in the violation store.

The denied set is: loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0/8`, `::`), link-local (`169.254.0.0/16`, `fe80::/10`), multicast (`224.0.0.0/4`, `ff00::/8`), broadcast, the cloud instance-metadata / platform endpoints that live outside link-local (`100.100.100.200`, `168.63.129.16`, `192.0.0.192`, `fd00:ec2::/32`, `fd20:ce::254`, `fd00:c1::a9fe:a9fe`, `fd00:42::42`), every address currently assigned to one of this host's own network interfaces (a service bound to `0.0.0.0` answers on the LAN or global address exactly as it does on loopback), every IP literal listed in `deniedDomains` (honouring its `:port` if it has one), and anything in `deniedResolvedAddresses`. IPv4 entries also match the IPv6 forms that carry an IPv4 address — IPv4-mapped, IPv4-compatible and IPv4-translated addresses, the NAT64 well-known prefix (`64:ff9b::/96`) and 6to4 (`2002::/16`) are judged by the IPv4 address they embed. The local-use NAT64 prefix `64:ff9b:1::/48` and network-specific prefixes are not decoded — their layout (RFC 6052 allows the IPv4 in several positions) can't be recognised from the address alone; on such a network, list the prefix's translations of the ranges you deny (e.g. `<prefix>::a00:0/104` for `10.0.0.0/8`). Addresses that reach this host without being assigned to it — a cloud instance's 1:1-NAT public address, a router port-forward, a container or VM host-gateway alias — are not covered automatically; list them in `deniedResolvedAddresses`.

What the check leaves alone: allowlist entries that **are** IP literals (allow-listing `127.0.0.1:3000` is an explicit choice) — and, by the same token, a hostname may resolve to an otherwise-denied address when that IP literal (on that port) is itself in `allowedDomains`, since reaching it by name grants nothing the literal entry does not (an IP literal in `deniedDomains` still wins, exactly as it does for a literal request). So a dev setup where `myapp.test` maps to a local server via `/etc/hosts` allow-lists `["myapp.test", "127.0.0.1:3000"]`; there is no separate carve-out list. `localhost` and names under `.localhost` resolve to loopback (or an allow-listed literal) and nothing else. The check is not evaluated for connections routed through `parentProxy` (including one picked up from `HTTP_PROXY` / `HTTPS_PROXY` in srt's own environment) or `mitmProxy` — that hop resolves the name and owns its own address policy — and it only governs what the proxy dials: on macOS, `allowLocalBinding` separately lets the sandboxed process connect to loopback ports without going through the proxy at all.

- `network.deniedResolvedAddresses` - Extra IP addresses / CIDR ranges (IPv4 or IPv6, unbracketed, any port) that allowed hostnames must not resolve to. Private-use space is not denied by default because allow-listing an intranet hostname is legitimate; list it here when allow-listed names must stay out of it, e.g. `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"]`. List IPv4 and IPv6 ranges separately — an IPv6 range broad enough to cover the IPv4-mapped block (`::ffff:0:0/96`), such as `::/0`, matches IPv4 answers on some runtimes but not others, so do not rely on it to deny IPv4.

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

A few paths are writable without being listed: the child's stdio and `/tmp/claude`, and as a convenience `~/.npm/_logs` and `~/.claude/debug`. Those two home directories are dropped when a `denyRead` entry covers them (and kept when an `allowRead` entry beneath that deny re-opens them), so list them in `allowWrite` if you want them writable under a home read-deny.

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

bubblewrap binds concrete paths, so glob support is narrower than on macOS:

- `allowWrite` / `denyWrite` take literal paths. A trailing `/**` is dropped (`src/**` means `src`); any other glob pattern there is skipped.
- `denyRead` / `allowRead` accept the same glob syntax as macOS, expanded to the entries that exist when the command is wrapped, so a file that appears later is not covered. The pattern needs a literal directory to start from (a relative pattern starts at the current directory): one with a wildcard in its first path component, such as `/**/*.pem` or `/opt*/keys/**`, is skipped on Linux. Only directories the pattern can match beneath are listed (`certs/*.pem` lists `certs` alone).
- A directory matched by a `denyRead` pattern ending in `/**` that holds at least one entry when the command is wrapped becomes one tmpfs mount, like a directory listed in `denyRead` literally: inside the sandbox it is an EMPTY WRITABLE directory, so a command that used to write through a read-denied `build/` still writes, into the tmpfs, and loses that output when the command exits. A file added to the directory on the host afterwards is hidden too. A matched directory that is empty when the command is wrapped gets no mount (a matched symlink to a directory always gets one, on the directory it leads to). An `allowRead` beneath a mounted directory is bound back over the tmpfs, but each entry beneath it that the pattern matches keeps its own mask: under a `/**` pattern that is every entry there, so only what is created beneath the `allowRead` later is readable.
- A directory the expansion cannot list is denied as a whole, and nothing is bound back beneath the mount that hides it, `allowRead` and `allowWrite` paths included: what the pattern matches under them cannot be found. A `denyRead` entry that cannot be inspected (its parent directory is readable but not searchable, say), or that leads to `/`, hides the nearest directory above it instead, in the same way.
- Symlinked directories are descended. A directory is listed once for each way the pattern can carry on beneath it, however many links lead to it, so the cost of the expansion follows the size of the tree and the length of the pattern, not the number or length of the names its links offer; what is found through a link is reported, and denied, where it really is. A link that leads back up the tree (to the directory holding it or above, or to the pattern's starting directory or above) is not descended. A `**` written against other text (`**.pem`, `a**/x`) and a bracket expression that can match `/` span directories as they do on macOS, through symlinked directories too. Only a pattern that does not read as written is matched against real paths alone, with every directory under its starting directory listed: one with a wildcard inside a bracket expression (`[a*]`), or with a second `[` that nothing closes. A link that itself matches it still denies what it leads to. Every `denyRead` mount goes where the path really is (bubblewrap 0.12 and later refuse to mount on a symlink), so an entry reached through a symlink is denied under every name that leads to it, and a link back up the tree denies everything it reaches, as a literal deny of the link would. A link that resolves to nothing is skipped. `allowRead` globs are not expanded through symlinks: they match the link itself.
- An `allowRead` or `allowWrite` path is bound back over a denied directory only where it really is, so no directory shows under a second name inside the sandbox.
- `denyRead: ["/"]` denies each directory in `/` (`/proc`, `/dev` and `/sys` aside); a symlink there (`/bin`, `/lib` on a usr-merged system) gets no mount of its own, because what it leads to is denied together with the directory that holds it.

Examples:

- `"allowWrite": ["src/"]` - Allow write to `src/` directory
- `"denyRead": ["/home/user/.ssh"]` - Deny read to SSH directory
- `"denyRead": ["**/build/**"]` - Deny read to every `build/` directory under the current directory
- `"denyRead": ["/home"], "allowRead": ["."]` - Deny read to all of `/home`, but re-allow the current directory

**All platforms:**

- Paths can be absolute (e.g., `/home/user/.ssh`) or relative to the current working directory (e.g., `./src`)
- `~` expands to the user's home directory
- A deny glob must not end in a separator: the separator becomes part of the compiled pattern, so the pattern can match no path. `denyRead`, `denyWrite` and a `mode: "deny"` credential file reject such an entry at config validation — write `/data/*`, or add a `**` segment to match at any depth.

#### Other Configuration

- `ignoreViolations` - Object mapping command patterns to arrays of paths where violations should be ignored
- `enableWeakerNestedSandbox` - Enable weaker sandbox mode for Docker environments (boolean, default: false)
- `javaAgentJarPath` - macOS/Linux: absolute path to `srt-proxy-agent.jar`, the JVM agent injected via `JAVA_TOOL_OPTIONS` (see "JVM tools" under Network Isolation). Only needed by consumers that bundle sandbox-runtime and ship the jar separately; a normal npm install finds it under `vendor/java-proxy-agent/`.
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

**Running as root:** a caller with euid 0 needs `CAP_SETFCAP` in its capability bounding set. Bubblewrap's user namespace maps the caller's uid, and Linux 5.12 — and the older distribution kernels that backported the change — lets a namespace map uid 0 only when its creator held that capability; the seccomp isolation layer's nested namespace has the same requirement. Without it every sandboxed command fails with `Operation not permitted` while writing a uid map, and `initialize()` refuses to start once bubblewrap has confirmed it. Grant the capability to the calling process — it is in Docker's default set, but `capsh --drop=cap_setfcap` and a tightened `CapabilityBoundingSet=` remove it — or run as a non-root user, for which none of this applies. The bounding set is what counts, because bubblewrap is reached by `execve` and the kernel recomputes a root caller's permitted set from it.

Prefer a non-root caller where there is the choice. Under the seccomp isolation layer a root caller's command still holds a full capability set inside the helper's nested user namespace, which is identity-mapped to the caller's uid 0; what holds the filesystem policy there is that the nested namespace's copies of the mounts are locked, not the command's capabilities. A non-root caller's command holds no capabilities at all.

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

This provisions the `srt-sandbox` local user account (with a random password stored DPAPI-encrypted in `HKLM\SOFTWARE\sandbox-runtime` — machine-wide, so fleet installs running as SYSTEM work and one user's rotation updates the copy the others read), the `sandbox-runtime-users` local group, and installs a machine-wide WFP filter set keyed on the `srt-sandbox` SID. It is **idempotent** — re-running it rotates the sandbox account's password and reconciles the filter set.

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

`reset()` removes every ACE this session added (refcounted across this user's concurrent hosts via the per-user session DB; a crash-recovery pass on the next `initialize()` cleans up after an unclean exit). Directory targets are supported (the ACEs inherit to the whole subtree). Glob patterns are expanded to concrete paths at `initialize()` time — a matching path that appears later is not covered.

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

Removes the WFP filter set, the `srt-sandbox` account and its profile, the `sandbox-runtime-users` group, and removes the `HKLM\SOFTWARE\sandbox-runtime` key (credential, marker, CA record) — one UAC prompt. `%ProgramData%\sandbox-runtime` (the CA key material) is left in place; delete it (and `%LOCALAPPDATA%\sandbox-runtime` per user) manually for a full sweep.

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

**JVM tools (macOS/Linux):** the JVM ignores `HTTPS_PROXY`/`NO_PROXY` and has no environment variable for proxy credentials — proxy selection comes from the `https.proxyHost` system properties and the credential can only be supplied through `java.net.Authenticator`. So JVM-based tools (Bazel's gRPC remote cache, Gradle, Maven, …) would otherwise dial the target directly and fail, or reach the proxy without its token and get a 407. To close that gap srt injects a small `-javaagent` via `JAVA_TOOL_OPTIONS` (the env var carries only the jar path, the credential stays in `HTTPS_PROXY`). At JVM start the agent sets `http[s].proxyHost`/`Port` and `http.nonProxyHosts` from the proxy env vars, re-enables Basic auth for CONNECT tunnels, and installs an Authenticator for the proxy endpoint. Explicit `-D` proxy properties on the JVM command line still win, and any inherited `JAVA_TOOL_OPTIONS` is preserved (unless it is a denied credential env var). Every JVM prints a `Picked up JAVA_TOOL_OPTIONS: …` line to stderr as a result; a jlink'd runtime built without the `java.instrument` module cannot load agents and will refuse to start under the sandbox — unset `JAVA_TOOL_OPTIONS` in the command for such a tool. The jar ships in the npm package as `vendor/java-proxy-agent/srt-proxy-agent.jar` (source: `vendor/java-proxy-agent-src/`; built by the release workflow, or locally with `npm run build:java-agent` — needs a JDK ≥ 17). If it is not found, `JAVA_TOOL_OPTIONS` is left alone and JVMs behave as before; bundlers can point at their own copy with `javaAgentJarPath`.

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

**Precedence is intentionally opposite for reads vs writes:** `allowRead` overrides `denyRead`, while `denyWrite` overrides `allowWrite`. This lets you carve out readable regions within denied areas, and carve out protected regions within writable areas. On Linux that also holds when the `denyWrite` entry is at or above the `allowWrite` one — `allowWrite: ["/", "/work"]` with `denyWrite: ["/"]` leaves `/work` read-only rather than writable — and with debug logging on (`SRT_DEBUG`) the wrap logs a warning naming both paths.

**Read-side rules (Linux):** an entry is matched by the name it is, not by what it points at.

- An `allowRead` entry re-allows the name it names, so a link planted at an allowed path cannot re-open a denied one. One that is itself a symlink is bound back at its own name, from the target it was checked against: the target's own path stays hidden, and the target's contents are reachable only through the name. A `denyRead` entry or a credential mask that overlaps that target — at it, inside it, or covering it — wins over the carve-out, which is then not restored at all: the name is absent inside the sandbox rather than serving what the deny hides. The denied directory the carve-out is being restored into is not such an overlap, nor is anything above it: those are what the carve-out is an exception to. Neither is an entry that denies nothing — one naming a path that is not there, or a file an `allowRead` entry lifts.
- A `denyRead` of `/` together with an `allowRead` of `/` denies nothing: the root deny is expanded into the root's children, and the allow covers every one of them.
- A `denyRead` entry naming a FILE is lifted only by an `allowRead` entry naming that same file. An `allowRead` entry that is a symlink to it names the link, so it does not cancel the deny of its target.
- A `denyRead` entry that cannot be inspected (a parent made unsearchable, a dead network mount) hides the deepest directory above it that can be — never `/`, so when `/` is the only one left the entry mounts nothing and that deny is not enforced (the wrap logs which entry, and why, under `SRT_DEBUG`). Such a stand-in hides more than was written: nothing beneath it is readable, carve-outs named there included, and a carve-out elsewhere that resolves beneath it is not restored either.

**Write denies on paths that do not exist yet (Linux):** bubblewrap can only deny a path by mounting over it, so for a `denyWrite` path that is absent under a writable directory it first creates a mount point there: an empty, read-only file (or an empty directory for a missing intermediate component) that is visible on the host for as long as a sandbox is alive and is removed afterwards. Host tools therefore see such a path as existing while a sandboxed command runs, which matters for paths whose existence is their meaning (a lockfile such as `.git/config.lock` makes `git config` report "could not lock config file"). A process that dies without an exit event (`SIGKILL`, OOM) cannot remove its mount points. An empty regular file with no write bits found at a `denyWrite` path under a writable directory is taken to be such a leftover: it is covered with `/dev/null` like an absent path and removed after the command — except at a `commondir` or `config.worktree`, where `/dev/null` is what git cannot read and a placeholder git accepts is written there instead (see **Mandatory Deny Paths** below). A leftover empty directory cannot be told from anyone else's and is left alone.

**Note (Linux, large profiles):** The wrapped string runs as one argument of `sh -c`, which Linux caps at 32 pages (128 KiB with 4 KiB pages). A profile that would not fit, with 4 KiB to spare for a prefix of the caller's own, has its mounts written to an unnamed file (`O_TMPFILE`) that the wrapping process holds open and bubblewrap reads through `--args`. The string then reads `/bin/sh -c '…' srt-args /proc/<wrapping pid>/fd/<n> bwrap … --args 9 …`: still a simple command, which opens the profile on fd 9 and runs bubblewrap. The environment and the command stay on the command line; the file holds mount paths only.

- The profile is never given a name, so nothing can be put in its place between the wrap and the execution — not a command the process sandboxed, not a sandbox another process of the same user started with tmpdir writable, not a rename of a directory above `TMPDIR`. Every sandbox this library starts has its own PID namespace and a fresh `/proc`, so none of them can reach `/proc/<wrapping pid>` either.
- Not covered: another process of the same user running outside a sandbox can read a pending profile through `/proc`. It can already read the wrapping process's memory, so this gives it nothing new.
- The string must be run while the process that produced it is alive, and before the runtime cleans up after that command (`cleanupAfterCommand()`), which is when the profile is released.
- The profile needs a directory that takes an `O_TMPFILE` file — `os.tmpdir()`, else `/dev/shm` — and a readable `/proc/self/fd`. Without them an over-long profile is refused at wrap time with the reason; there is no fallback to a named file. Profiles that fit the command line do not use any of this.
- bubblewrap parses at most 9000 arguments (about 3000 mounts). A profile past that, or a command too long for one argument by itself, fails at wrap time with an error. A repository's submodule denies are degraded until the profile fits rather than refused at that point — see **Which git directories are covered**.
- Every one of these wrap-time refusals is a `LinuxSandboxProfileError`, exported from the package root, with a `LinuxSandboxProfileErrorCode` on `.code` to tell the cases apart; branch on `.code` rather than on the message. They say the configuration expands to a profile this host cannot run, except `command_too_long` and `nul_in_path`, which also fire on what the embedding program passed in. A wrap that threw has already released what it held: do not call `cleanupAfterCommand()` for it, or a sandbox still running loses its mount points.

### Mandatory Deny Paths (Auto-Protected Files)

Certain sensitive files and directories are **always blocked from writes**, even if they fall within an allowed write path. This provides defense-in-depth against sandbox escapes and configuration tampering.

**Always-blocked files:**

- Shell config files: `.bashrc`, `.bash_profile`, `.zshrc`, `.zprofile`, `.profile`
- Git config files: `.gitconfig`, `.gitmodules`
- Other sensitive files: `.ripgreprc`, `.mcp.json`

**Always-blocked directories:**

- IDE directories: `.vscode/`, `.idea/`
- Claude config directories: `.claude/commands/`, `.claude/agents/`
- Git hooks and config: `hooks/`, `config`, `config.worktree` and `commondir` of a git directory — the working directory's repository, nested repositories, the submodule git directories they keep under `.git/modules/`, and a linked worktree's git directory. **Which git directories are covered** below says how each is found and what is denied where one cannot be.

These paths are blocked automatically - you don't need to add them to `denyWrite`. For example, even with `allowWrite: ["."]`, writing to `.bashrc` or `.git/hooks/pre-commit` will fail:

```bash
$ srt 'echo "malicious" >> .bashrc'
/bin/bash: .bashrc: Operation not permitted

$ srt 'echo "bad" > .git/hooks/pre-commit'
/bin/bash: .git/hooks/pre-commit: Operation not permitted
```

**Which git directories are covered.**

- `commondir` and `config.worktree` are denied because git reads the hooks and config through them: `commondir` moves them to another directory entirely, and `config.worktree` is read instead of `config` wherever `extensions.worktreeConfig` is on (`git sparse-checkout init` turns it on).
- An existing `.git` _file_ (a linked worktree's or submodule checkout's `gitdir:` pointer) is read-only and cannot be removed or renamed over; creating a new one inside an allowed write path is still possible. The hooks and config it leads to (the main repository's, for a worktree) are blocked as well, and so is filling in a git directory it names but that does not exist yet; one naming a directory that is not a git directory is not followed.
- A pointer is read the way git reads one — the whole file, `\n` and `\r` stripped from its end, the path ending at the first NUL — and one larger than the 1 MiB git accepts for a `.git` file is not followed, because git refuses it too. A pointer and a `commondir` are both denied under the path as written and, where a `..` in one follows a symlink, under the directory the kernel actually opens as well, since `link/../x` does not land where folding the path on paper says it does — and git opens that one: run against real git, `gitdir: hop/../evil` with `hop` a symlink opens the directory the kernel reaches, and a checkout whose pointer is a git directory only where the path folds is refused outright. Every symlink the path goes through is denied as well; see **A chain is held hop by hop** below.
- A directory a pointer or a `commondir` names that this cannot read is denied whole instead — git, running as the same user, cannot read through it either — and so is a directory under `.git/modules` the submodule walk cannot see through. A whole-directory deny leaves everything beneath it read-only inside the sandbox, a submodule's `objects`, `refs` and `index` included, so git writes inside such a tree stop working. Two things produce one under `.git/modules`: a directory the walk cannot list, and an entry whose target is there and cannot be inspected. What is denied is the deepest directory that can be reached towards it — towards the TARGET for an entry that is a symlink, not the directory holding it, which would be every submodule beside it — and that can be `.git/modules` itself where the walk cannot get past it. An entry that is a symlink loop reaches no directory at all, so nothing is denied for it: there is nothing behind it to protect, and a bind cannot be put at the link's own location either, since mounting there means resolving it.
- **An entry that is itself a symlink is two things, and both are denied.** `hooks`, `config`, `commondir`, `config.worktree` and an entry of a `.git/modules` can each be a link: what a write through it reaches is one thing, the link itself — which a command can unlink and leave its own `hooks/` in place of, for the host's git to run before the next command's scan sees anything — is another. Which of the two one deny covers is the backend's: a Linux bind lands on what the path resolves to, while Seatbelt compares its filter against the path the kernel resolved the operation to — which for an unlink or a rename is the link's own path, since the last component is not followed, and for a write through the link is the target. So the target is denied on its own, and on Linux the directory holding the link is denied WHOLE: the git directory for one of its own entries, the directory holding a `.git/modules` entry for one of those. Everything under a whole deny is read-only, so in a repository that has such a link `git status`, `log` and `diff` go on working while `git add`, `git commit` and anything else writing the index or an object fail read-only until the link is gone; on macOS nothing is denied whole and git keeps working, the entry's own deny being what holds the link there. A link whose target is **not there yet** is no exception: where it lands is denied as a git directory that does not exist, so the command cannot create it and leave hooks for the host's git. An entry this cannot classify at all — an `lstat` that fails for anything but absence — is taken for a link, both denies and all. A link that is a loop reaches nothing, so only the whole deny is left to it.
- **A chain is held hop by hop, not just at its two ends.** Neither end of a chain need point straight at the other. An entry can go through a link on the way: `hooks -> ../hooks-link` with `hooks-link -> .githooks`, or `hooks -> ../shared/hooks` with `shared` a symlinked directory. So can the VALUE of a `gitdir:` pointer or a `commondir`, which is a path git walks as the kernel does: `gitdir: hop/../evil`, or a git directory reached through a symlinked component. The file's or the entry's deny holds that end and the landing's deny holds the other; a link BETWEEN them is held by neither, and a command that retargets it — or renames it aside and puts its own directory there — moves where the chain resolves without touching either end, for the host's git to follow. So every hop is held as the entry or the pointer file is: its own path is denied, which is what holds it where a filter matches the name a rename or an unlink uses, and on Linux the directory HOLDING it is denied whole, which is what holds it where a deny resolves. On macOS a chain needs one thing more. A deny path whose own spelling goes through a link — everything under the git directory `gitdir: links/shared/gd` names, and everything under a submodule reached through a symlinked `.git/modules` entry — is compared against a resolved path it can never equal, so it holds the link's own name and nothing beneath it. Every path the git denies were read off disk is therefore named twice there, as it was written and at the landing the kernel walks it to, absent tails included; the two are the same string, and one entry, wherever no link is involved. A hop inside the git directory, or inside the directory holding a `.git/modules` entry, needs no directory of its own: the whole deny that entry already brings covers it. One that no allowed write path contains is read-only anyway. The chain is walked as the kernel walks it, so what a hop cannot be read past leaves the git directory denied whole, as an entry that cannot be classified does, and the hops before it are held all the same. A chain past the kernel's own hop limit reaches nothing — git fails on it too — so it has no hop to hold and the whole-directory deny its landing gets is the whole answer. A link ABOVE the entry or the pointer file is not a hop of the chain at all: a checkout reached through a symlink is where the repository lives, and the walk starts where the kernel already is.
- **Known limit: a hop the working directory or a write root holds.** `.git/hooks -> ../hooks-link` with `hooks-link` in the repository root is the common shape of the above — and so is a pointer whose value goes through a link in the checkout itself, where the directory holding the hop is the working directory by construction — and there is nothing to bind over the directory holding it: a read-only bind of the working directory, or of a write root, takes the whole tree the sandbox exists to let the command write. Such a layout is one the caller had before this library saw it, so the command is not refused for it either. Instead **one `SRT_DEBUG` warning per wrap** names the entry (or the pointer file, and what it names) and the hop and says it can be retargeted from inside the sandbox; both ends of the chain stay denied. A `denyWrite` entry naming the directory holding the link closes it, at the cost of that directory; moving the link inside the git directory, or spelling the pointer's path without it, closes it outright. Restoring the link after the command was considered and not done: a hop the command replaced with a directory cannot be put back by a symlink call, so a restore means removing what a command wrote inside the caller's own work tree; `cleanupAfterCommand` is the embedder's to call; and nothing of it closes the window while the command runs.
- The `.git/modules` walk has no depth bound: a submodule's name is its path and submodules nest, so how deep a tree goes is a question about the repository, and a submodule a hundred levels down has its hooks and config denied like any other. Each directory is visited once, keyed by where it really is, so a symlinked entry pointing back into the tree ends that branch rather than looping. What bounds the walk is time — as long as the `ripgrep` scan gets, since a tree that takes longer than that to walk is one the command about to run could have made — and running out of it refuses the command (`deny_scan_failed` on Linux, a `SubmoduleWalkBudgetError` on macOS) rather than sandboxing on the submodules the walk did reach. The clock is looked at as the entries go by, so one directory a command filled with entries is stopped in the middle rather than at the end of it, and a walk made after the scan takes a budget of its own of the same length rather than what a slow scan left.
- **Past what bubblewrap takes arguments for, the submodule denies are degraded (Linux).** A profile takes three of bubblewrap's 9000 words per mount. A repository with hundreds of submodules asks for more mounts than that — four denies and an ancestor pin for each submodule git directory, and for a checked-out one its `.git` pointer file and the pin of the directory holding it as well — and the ceiling is not this library's to lift. Refusing every command in such a repository is the wrong answer to it, so the wrap builds the profile, counts what bubblewrap will actually parse, and while that is past the cap degrades the submodule denies a step at a time and builds again, fail-closed and only as far as the count says it has to be. The working directory's own repository is served first and the nested repositories the scan found after it, in sorted order, so what is degraded is taken from the end:

  1. precise denies (`hooks`, `config`, `commondir`, `config.worktree`) while the profile fits;
  2. a submodule git directory that does not fit is denied WHOLE, one read-only bind — git writes inside that submodule fail read-only, its `objects`, `refs` and `index` with them, and nothing outside it changes. A checked-out submodule's `.git` pointer names the same git directory, so its copy of those denies goes with them; the pointer file keeps its own deny, which names a file and has nothing to collapse into, and so does what an entry that is a symlink leads to, which lies outside the git directory and no bind of it covers;
  3. where even one bind each does not fit, the enclosing `.git/modules` is denied whole and every submodule really under it goes with it. An entry the walk reached through a symlink can be anywhere, and one whose real path is outside keeps the deny it had: a bind of `modules` does not cover it.

  With one write root and no network restrictions, that starts at about 590 submodule git directories, or about 425 where each is checked out. A `SRT_DEBUG` warning says what was degraded, at which level, and for which repositories; there is no other wrap-time channel to report it on. The Linux violation monitor works the same denies out for itself, once for the session and with nothing degraded, so a command that forces a degrade later leaves it naming the path inside a submodule git directory the wrap has by then denied whole — the write is refused either way, and it is the path in the report that is stale, never what bubblewrap enforces. `too_many_arguments` is what is left for a profile that does not fit with every submodule deny degraded: measured at about 1475 CHECKED-OUT submodules, whose pointer files and pins no degrading saves, and at a few hundred separate nested repositories, whose own four denies are not submodule denies. Bare submodule git directories do not reach it at any count, multi-segment (`vendor/lib`) and nested names included: the one bind over `.git/modules` is where they end.

- On Linux, a nested repository is found by the per-command `ripgrep` scan, which never looks inside a `node_modules`: a repository under one is never found and its hooks stay writable. That exclusion is permanent — the scan walks gitignored data as it is, and a `node_modules` is where the cost of that would land.
- On macOS only the working directory's own `.git` file is followed, since nested pointers are matched by pattern; the working directory's own submodule git directories are enumerated exactly, while a nested repository's are matched as `.git/modules/<name>/`, which covers a single-segment submodule name. Nothing is ever collapsed there: a Seatbelt profile is a text file with no cap on how many entries it may carry, so every submodule keeps its precise denies however many there are.

**The mount point for an absent `commondir` or `config.worktree` (Linux).** Denying either where the file is not there means mounting something at it, and git reads whichever of them it finds: it refuses to run at all against a `commondir` it cannot read, which both a bound `/dev/null` and an empty file are. So the wrap writes the mount point itself, before bubblewrap starts, holding what git concludes with no file there — `.` for `commondir`, which makes git resolve the git directory it opened as its own common directory, and nothing for `config.worktree`, which reads as no worktree config — and binds a read-only copy of the same bytes over it.

- The file is removed after the command. One left behind by a killed process is claimed and removed by the next wrap — recognised by its content alone, so a `commondir` holding exactly `.` that somebody else put there is taken away with it — and an empty `commondir`, which git refuses outright, is repaired the same way; an empty `commondir` that still has write bits belongs to a host `git` caught between creating the file and writing it, and is left exactly as found.
- For as long as the command runs, git inside the sandbox and git on the host therefore both read a redirect git accepts — but not the same thing they read with no file there at all: `git rev-parse --git-common-dir` and `--git-path` print the absolute real path where they printed a relative one, so a script that compares `--git-dir` with `--git-common-dir` to decide "this is a linked worktree" answers yes for an ordinary repository until the deny is lifted.
- Where the git directory takes no mount point at all — one this process cannot write, such as a root-owned vendored checkout or a read-only mount — the git directory is bound read-only whole instead. That needs nothing written to the host, costs what was already unwritable, and is also what stops the command from making the directory writable and creating the file itself.
- Cleanup is deferred per process, not across processes: two processes wrapping commands in one repository can each claim the same mount point, and the one that cleans up first removes it while the other's sandbox is still running, which detaches that bind and stops that one deny applying inside it. The bind's source is the placeholder in the temporary directory rather than the mount point, so the sandbox still starts.

**Refusals a wrapped command can plant (Linux).** The wrap-time refusals below follow from what a sandboxed command is allowed to write, and the command that would put one right is refused as well, because every wrap in that working directory hits the same thing. Each names the offending path, or the line the scan printed, in the message, and **each is lifted only by a command run outside the sandbox**:

- `deny_git_metadata_unreadable` — a `.git` pointer file or a `commondir` whose target cannot be worked out the way git works it out: bytes that are not valid UTF-8, a `commondir` larger than 1 MiB, or one that is there and cannot be read. Creating a new `.git` pointer inside an allowed write path is deliberately allowed, so writing `gitdir: <invalid>` is one command. On macOS the same condition is a `GitMetadataError`, exported from the package root.
- `deny_scan_failed` where the scan failed for a reason no deny stands in for — an error code other than `ENOENT` or `EACCES`, or none at all. The raw stderr, truncated, is in the message.
- `deny_scan_failed` where a `.git/modules` tree takes longer to walk than the scan's own budget: a tree wide or slow enough is one a command can make, and the walk refuses rather than hand back a listing that stops somewhere unknown. Removing what makes it slow lifts it. On macOS the same condition is a `SubmoduleWalkBudgetError`, exported from the package root.

- `too_many_arguments` where a command plants enough CHECKED-OUT submodules — a `.git` pointer file and the git directory it names — that the profile does not fit with every submodule deny degraded, measured at about 1475 of them.

A directory the command makes unreadable does **not** refuse anything: it is denied whole, so the next command can neither read it nor open it up again. Neither does a wide `.git/modules`, which is writable inside the sandbox: a command can fill one, and what that costs the commands after it is degraded denies rather than a refusal — git writes inside the submodules that were degraded fail read-only until the entries are removed, which takes a command run outside the sandbox, since what holds them is by then read-only inside it. A symlink planted under a `.git/modules` costs the same way: from the next command on that `.git/modules` is denied whole, so every submodule under it is read-only until the link is removed.

**Git operations these denies break.** A git directory's `hooks/` and `config` are what a hook or a `core.fsmonitor` would be written to, so anything that writes or removes them fails inside the sandbox:

- removing a tree that holds a submodule checkout or a linked worktree (`rm -rf lib`, `git clean -ffdx`), because its `.git` pointer file cannot be removed;
- `git worktree remove`, `git worktree move`, `git worktree repair`, `git submodule deinit`, for the same reason;
- `git submodule update --init` for a submodule that has not been cloned yet, which copies template hooks into `.git/modules/<name>/hooks/` and writes its config;
- from a linked worktree, anything writing the main repository's config: `git push -u`, `git checkout -b x origin/y`;
- `git init` and `git clone` into a subdirectory, which create `.git/hooks/`;
- on Linux, every write inside a git directory whose `hooks`, `config`, `commondir` or `config.worktree` is a symlink (`git add`, `git commit`, `git checkout -b`), and every write inside a `.git/modules` one of whose entries is a symlink, because those directories are denied whole — see **Which git directories are covered**;
- on Linux, every write inside a directory that HOLDS a hop of such a chain — an entry's or a `gitdir:` pointer value's — for the same reason: with `hooks -> ../links/hop`, or with `gitdir: links/hop/gd`, the `links` directory is read-only for the command. Only the directory around the link, never what the link leads to.

**Known limit: a link that IS the git directory.** The denies above hold a link INSIDE a git directory or a `.git/modules`. A `.git` that is itself a symlink to a git directory elsewhere, or a `.git/modules` that is, is not one of them: what it points at is denied as any git directory is, and the link itself sits in the working tree, which the sandbox is there to let the command write. Replacing it makes the repository a different one, which the next command's scan covers — but a host git run between the two commands follows the new link. There is nothing to bind over: a mount at the link's own path resolves it, and the only handle above it is the working tree root.

**Known limit: a hook FILE that is a symlink into the work tree.** The install idiom `ln -s ../../scripts/pre-commit .git/hooks/pre-commit`, with `hooks` itself a real directory, is not one of the entries above: the hooks directory is denied, so no name can be added there and none re-linked, but the script the link leads to is ordinary project content, and its CONTENT is writable — directly and through the link — on every build. That is the sandbox doing its job: a tracked script in the work tree is exactly what a command is there to edit, and the sandbox has no way to tell the script the user chose to run as a hook from any other file in the repository. A `denyWrite` entry naming the script is the remedy where that matters.

**Known limit: a pre-existing HARD link of a denied file.** A bind protects a path, not an inode, so an append through a second name for `.git/config` elsewhere in the work tree lands. A sandboxed command cannot make such a link to a bound file (the bind is its own mount, and `link(2)` across one fails `EXDEV`), so it has to pre-exist.

**Known limit (macOS).** A pointer file or a pattern-matched path is protected where it is: a command may still rename the directory _holding_ it aside and create a fresh one in its place (`mv lib lib.old && mkdir lib && echo 'gitdir: …' > lib/.git`). On macOS that is blocked for the literal denies (the working directory's own repository and its submodule git directories) and not for the pattern ones. On Linux it is blocked for everything the scan reached: the ancestors of every denied path are pinned (see **Pinned directories** below), so renaming or removing the directory holding a denied pointer file, or the package directory above a nested repository's hooks, fails with `EBUSY`.

**Note (Linux):** On Linux, mandatory deny paths only block files that already exist. Non-existent files in these patterns cannot be blocked by bubblewrap's bind-mount approach (a blocked _directory_, such as a repository's `.git/hooks/`, does cover files created in it later). macOS uses glob patterns which block both existing and new files. The Linux scan ignores `.gitignore` and similar ignore files, since the sandboxed command can write those, and is run with `--no-config` so that a `RIPGREP_CONFIG_PATH` pointing inside the project cannot change what it lists. It fails closed, and which failures it can carry on from is decided by the `(os error N)` codes the run printed — never by the paths printed beside them, which are directory names whoever created them chose:

- every code `ENOENT`: entries that went away while the scan walked. Nothing is at those paths to deny, and the rest of the listing still counts.
- any code `EACCES`: a directory the scan could not read holds an unknown tree, so it is denied whole and the rest of the listing still counts. WHICH directories is settled by a bounded walk of the working directory, to the scan's own depth and inside the scan's own time budget, not by reading the paths off stderr.
- anything else, no code at all, or an `EACCES` the walk cannot find a directory for: the command is refused, with the raw stderr (truncated) in the message.

A scan that could not be run at all and one that does not finish in time are refused too. Each refusal is a `LinuxSandboxProfileError` with `deny_scan_failed` on `.code`; a missing `ripgrep` is refused earlier still, by the dependency check.

**Pinned directories (Linux):** Every existing ancestor of a protected path (a write-denied path, a read-denied file or directory, a masked credential file) up to the allowed write root covering it is made a mountpoint — "pinned" — and cannot be renamed or removed from inside the sandbox: `mv` or `rmdir` of such a directory (for example a nested repository's parent) fails with `EBUSY` ("Device or resource busy"), and `rm -rf` of a nested repository leaves the pinned directories and the protected files behind (as with `.git/hooks`). A pin is buried under the mounts above it, so it never appears on a lookup path: reads, writes, creation, renames and hard links inside or across a pinned directory are unaffected.

With `allowWrite: ["/"]` the pins reach every ancestor, including any other allowed write root that is one (`mv /work /work.bak` fails with `EBUSY` given `allowWrite: ["/", "/work"]` and a protected path inside `/work`). They stop below the top-level directory, which is bound writable over them, and that directory is the one new filesystem boundary: `mv` or `ln` between two top-level directories — say `/tmp` and `/home` — fails with `EXDEV` ("Invalid cross-device link"), as it does on any host where they are separate filesystems. `mv` falls back to a copy; `ln` and a raw `rename(2)` do not.

A wrap that carries no write restrictions at all — `filesystem.disabled` with credential masks still in force, or a library caller passing no write config while a `denyRead` entry or a mask still seeds a pin — is the same shape: the whole tree is bound writable, so it gets the same pins and the same top-level covers, and the same `EXDEV` boundary applies there too.

**Linux search depth:** On Linux, the sandbox uses `ripgrep` to scan for dangerous files in subdirectories within allowed write paths. By default, it searches up to 3 levels deep for performance, which reaches a nested repository directly beneath the working directory. You can configure this with `mandatoryDenySearchDepth`:

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

A nested repository is recognised by any regular file directly inside its `.git`, which is why it is found at the depth the repository sits at rather than one level further down where the hook files are. With `filesystem.allowGitConfig` off — the default — the deny of `config` keeps such a file there and it cannot be removed from inside the sandbox, so one command cannot hide the repository from the next command's scan. With `allowGitConfig` on it could, so each command additionally walks the working directory to the same depth, skipping `node_modules` as the scan does, and denies the `.git` directories it finds; that walk is the cost of allowing config writes and is not run otherwise.

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

- Network Sandboxing Limitations: The network filtering system operates by restricting the domains that processes are allowed to connect to. It does not otherwise inspect the traffic passing through the proxy and users are responsible for ensuring they only allow trusted domains in their policy. Allowed hostnames are additionally checked against a denied set of resolved addresses before a direct dial (see **Resolved-address check** above), so a permitted name cannot be pointed at loopback, link-local, this host's own addresses or an IP you listed in `deniedDomains`; other private ranges are only covered if you list them in `deniedResolvedAddresses` (a wildcard entry on a domain whose DNS you do not control can otherwise be aimed at services on your LAN), and connections that leave through `parentProxy`/`mitmProxy` rely on that hop for the equivalent check.

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
