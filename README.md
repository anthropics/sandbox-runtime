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
- **Windows**: Runs the sandboxed process under a dedicated `srt-sandbox` local user account, with a [Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) egress fence keyed on that account's SID, a write-restricted token, and explicit ACEs on the working tree

![0d1c612947c798aef48e6ab4beb7e8544da9d41a-4096x2305](https://github.com/user-attachments/assets/76c838a9-19ef-4d0b-90bb-cbe1917b3551)

### Dual Isolation Model

Both filesystem and network isolation are required for effective sandboxing. Without file isolation, a compromised process could exfiltrate SSH keys or other sensitive files. Without network isolation, a process could escape the sandbox and gain unrestricted network access.

**Filesystem Isolation** enforces read and write restrictions:

- **Read** (deny-then-allow pattern): By default, read access is allowed everywhere. You can deny broad regions (e.g., `/Users`) and then re-allow specific paths within them (e.g., `.`). `allowRead` takes precedence over `denyRead` — the opposite of write, where `denyWrite` takes precedence over `allowWrite`. A `denyRead` entry that is more specific than the `allowRead` region it falls inside (e.g. `denyRead: ["**/.env"]` or `["./secrets"]` with `allowRead: ["."]`) still stays denied.
- **Write** (allow-only pattern): By default, write access is denied everywhere. You must explicitly allow paths (e.g., `.`, `/tmp`). An empty allow list means no write access.

**Network Isolation** (allow-only pattern): By default, all network access is denied. You must explicitly allow domains. An empty allowedDomains list means no network access. Network traffic is routed through proxy servers running on the host:

- **Linux**: Requests are routed via the filesystem over a Unix domain socket. The network namespace of the sandboxed process is removed entirely, so all network traffic must go through the proxies running on the host (listening on Unix sockets that are bind-mounted into the sandbox)

- **macOS**: The Seatbelt profile allows communication only to a specific localhost port. The proxies listen on this port, creating a controlled channel for all network access

- **Windows**: A machine-wide WFP filter set blocks outbound connections made by processes running as the `srt-sandbox` account except loopback to the proxy port range. The proxies listen inside that range, creating a controlled channel for all network access. The filters do not follow a sandboxed process that puts a different token on a thread before creating a socket, nor traffic that a system service carries on its behalf; see the Windows [Known limitations](#known-limitations)

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
file. Each line replaces the whole config and is validated against the same
schema, so a line is a complete config rather than a patch: `network` and
`filesystem` are required, and a key the line leaves out goes back to its
default.

```bash
# fd 3 is the read end of a pipe the caller writes lines to
srt --control-fd 3 -- npm test
```

What an accepted line changes once the command is running:

- The network lists — `network.allowedDomains`, `deniedDomains` (with
  `deniedDomainReasons`) and `deniedResolvedAddresses` — take effect on the
  next connection, on every platform: the proxy consults them per request,
  and the resolved-address check is rebuilt from the same line. So do
  `network.mitmProxy` and `network.tlsTerminate.excludeDomains`, which it
  reads per request too.
- `credentials.sigv4` takes effect on the next request, provided srt
  started with a `credentials` block: the signing hook is installed only
  then, and reads the policies per request rather than capturing them.
- Nothing else changes. The filesystem rules are already in the seatbelt
  profile, the bubblewrap argv or the Windows ACEs, the credential masks
  were built when the command was wrapped, and the running proxy servers
  captured `network.parentProxy`, and whether TLS is terminated at all,
  when they started.
- On Windows, srt notices a line whose file-access set (`filesystem.*`
  together with `credentials.files`) differs from the one applied at
  startup, and says so only under `SRT_DEBUG`: the ACL grant is
  session-wide, so the set applied at startup stays in force. The rest of
  the line is applied as above.

How srt reads the channel, and what it refuses:

- The descriptor must be an integer **3 or above** and readable — `0`-`2`
  are the standard streams. srt exits with an error instead of running the
  command when it cannot read the descriptor it was given, so a dead
  channel never passes for a live one. A channel that dies before it has
  delivered a single update takes the command down with it; one that dies
  after says so and leaves the command running under the config last
  applied.
- A line that is not a valid config is reported on stderr and dropped; the
  previous config stays in force. The line itself goes to the debug log
  rather than to the terminal, and a blank line is ignored silently.
- srt starts reading only once the sandbox is up, so an update written
  before then waits in the channel rather than being lost — and cannot be
  overwritten by the config the sandbox starts with. Such a line may be read
  while the command is still being wrapped, and is then the config it is
  wrapped with, filesystem rules included. Whether it is read that early
  depends on how long the wrap takes (on Linux, a deny glob over a large
  tree is long enough), so a rule the command must start under belongs in
  the settings file.
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
  sandbox can read the updates or write a config of its own. On Windows the
  command is spawned with the three standard streams alone, so the control
  descriptor is not among the descriptors it is handed.

### As a standalone proxy with an external decider: `srt proxy`

`srt proxy` (or the single-file `srt-proxy` executable built by `bun run build:srt-proxy`) runs only SRT's HTTP proxy, with no sandboxed child, for a host that runs the workload elsewhere. It accepts on a listening socket the host hands in, terminates every CONNECT in-process, and forwards a request only when a separate decider process, reached over another inherited descriptor, allows it. See [docs/srt-proxy.md](docs/srt-proxy.md) for the command line, the decider protocol and the security model.

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

**Asking about a host no rule decides (the ask callback).** The second argument to `SandboxManager.initialize` is an optional `SandboxAskCallback`. It is asked about a destination that neither `network.deniedDomains`, nor `network.allowedDomains`, nor a per-command allow list (next section) decided, and it is never asked under `network.strictAllowlist`. Without a callback such a destination is denied. The callback resolves to one of:

- `true` - allow the connection. Only the value `true` allows.
- `false` - deny it. The violation line reports the generic reason `user denied`.
- `{ allow: false, reason: '...' }` - deny it, and report `reason` in the violation line in place of the generic text, so that whoever reads the `<sandbox_violations>` block (a model included) learns why and what to do instead. The sandboxed client reads it too, as the status phrase of the `403` that answers its CONNECT.

Any other answer denies, whether it is truthy or not, and reports the generic reason. That includes an object that carries a `reason` without saying `allow: false`, such as `{ allow: true, reason: '...' }`: its reason is not reported.

The reason is sanitized before it is stored, the way the rest of a violation line is. Each run of control characters (line breaks and tabs included) or of invisible ones (zero-width characters, the joiner among them, and bidi controls) becomes one space; `<` and `>` are removed, so `re-run with <host> listed` is stored as `re-run with host listed`; the ends are trimmed. The result is cut to 500 characters, counted as UTF-16 code units the way `String.prototype.length` counts them. A reason with nothing left after that falls back to `user denied`. Write it as one line of plain text.

**Behaviour change in the first release after 0.0.79:** the filter used to allow on any truthy answer, so a callback that resolved to a truthy value other than `true` (`1`, a string, any object) allowed the connection. It now denies. For the same reason, `{ allow: false, reason }` returned to an older release would be read there as an allow, because an object is truthy. `SandboxManager.askCallbackDenyReason` is `true` on a release that understands the object: check it before returning one, and deny with a plain `false` where it is absent.

```typescript
const deny = (reason: string) =>
  SandboxManager.askCallbackDenyReason
    ? { allow: false as const, reason }
    : false

await SandboxManager.initialize(config, async ({ host, port }) => {
  if (await userApproves(host, port)) return true
  return deny(`${host} was not approved for this session`)
})
```

**Per-command network allow lists (`registerCommandNetworkLists`).** One invocation can carry an allow list of its own, in addition to the configured one, for as long as it runs:

```typescript
import { randomBytes } from 'node:crypto'

// 128 bits of randomness, 22 characters. See below for why nothing less will do.
const commandId = randomBytes(16).toString('base64url')
const wrapped = await SandboxManager.wrapWithSandbox(
  command,
  undefined,
  undefined,
  undefined,
  { commandId },
)

SandboxManager.registerCommandNetworkLists(commandId, {
  allowedDomains: ['registry.example.org', '*.cdn.example.org:443'],
})
const child = spawn(wrapped, { shell: true })
const unregister = () => SandboxManager.unregisterCommandNetworkLists(commandId)
child.once('exit', unregister)
child.once('error', unregister) // the child never started
```

Entries use the grammar and the matcher of `network.allowedDomains` and get the same validation. `registerCommandNetworkLists` throws on an invalid entry, and on a `commandId` shorter than 22 characters (an unpaired surrogate does not count). Registering an id again replaces its list; `unregisterCommandNetworkLists` is a no-op for an id that has none; `reset()` removes every registration.

The order of evaluation for a connection is:

1. a `network.deniedDomains` match denies;
2. a `network.allowedDomains` match allows;
3. `network.strictAllowlist` denies;
4. a match in the list registered for the id the connection presents allows;
5. the ask callback decides if there is one, and otherwise the connection is denied.

So a per-command entry never overrides a configured `deniedDomains` entry, and is ignored entirely under `strictAllowlist`. It never enters `network.*` either: `getConfig()` and `getNetworkRestrictionConfig()` do not show it, and the default `injectHosts` scope of a masked credential, which is `network.allowedDomains`, does not grow. A host allowed this way still goes through the resolved-address check when it is dialed, and an IP literal in a per-command list adds no exemption there.

What the id has to be, and what this feature is not: the proxy learns which invocation a connection belongs to from the proxy username, and the username is presented by the client inside the sandbox. The id is therefore the **only** thing binding a connection to an allow list. It **must** be unguessable: at least 128 bits of randomness, never a counter, a timestamp or anything derived from the command. A sandboxed process that presents another live invocation's id gets that invocation's allows, so this is attribution, not a boundary between concurrent commands of one session. Register just before spawning the wrapped command, and unregister when the child exits or never started: a registration that outlives its command widens the window in which its id is worth presenting. As with every attribution key, only the first 100 characters of an id take part. Keep ids ASCII: a list under a non-ASCII id whose encoded form does not fit in the proxy username (255 bytes) registers and never applies.

No list applies while `network.httpProxyPort` names an external proxy: the wrap gives that proxy no username, so no connection carries an id. `registerCommandNetworkLists` still succeeds (and says so in one line under `SRT_DEBUG`), and every connection is decided as if no list existed.

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
  "allowNestedUserNamespaces": false,
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
- `network.deniedDomainReasons` - Optional map from a `deniedDomains` entry (matched by exact string) to a model-facing reason that appears in the `<sandbox_violations>` line when that entry denies a connection — say what is blocked and the sanctioned alternative (e.g. `{"github.com:22": "SSH pushes to GitHub are blocked; use an https:// remote"}`). Entries without a reason report a generic one. For SSH destinations (port 22), the reason is also delivered in-band: an SSH client tunneled through a no-auth SOCKS ProxyCommand (e.g. BSD `nc -X 5`) receives a pre-key-exchange SSH disconnect whose description is the reason, which OpenSSH prints verbatim — keep such reasons under ~400 ASCII characters, imperative first, since OpenSSH truncates and escapes non-ASCII. A client that does authenticate, as the `GIT_SSH_COMMAND` srt injects does, gets the reason on any port as the status phrase of the `403` that answers its CONNECT, which is what that command, and many an HTTP client, prints. There it is cleaned and cut as in the violation line, and every non-ASCII character becomes `?`, since clients disagree on how to read one in a status line.
- `network.allowLocalBinding` - Let sandboxed commands use local ports directly (boolean, default: false). macOS: bind and accept on any local port, and connect to `localhost` on any port. Windows: connect to loopback addresses on any TCP or UDP port; it is part of the machine-wide install, see [Local servers on Windows](#local-servers-on-windows). Linux: ignored — the sandbox has its own network namespace, whose loopback is always usable and is not the host's.

**Resolved-address check.** The allow/deny lists match by _name_, but whoever controls a permitted name's DNS (or any label under a permitted wildcard) controls what it resolves to. So before dialing an allowed **hostname** directly, the proxy resolves it once, drops any address in a denied set, and connects to a surviving address (the address that passed the check is the one dialed — there is no second lookup). If nothing survives, the connection is refused like any other policy denial: HTTP/CONNECT get `403` (`X-Proxy-Error: blocked-by-sandbox-runtime`, the reason in the body and, for a CONNECT, as the status phrase), SOCKS gets "connection not allowed by ruleset", and a `deny network-outbound host:port (resolved to a loopback address)` line — naming the class of address (loopback, link-local, this host's, cloud metadata, deny-listed, listed, …), not the address itself, which only the debug log carries — is recorded in the violation store.

The denied set is: loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0/8`, `::`), link-local (`169.254.0.0/16`, `fe80::/10`), multicast (`224.0.0.0/4`, `ff00::/8`), broadcast, the cloud instance-metadata / platform endpoints that live outside link-local (`100.100.100.200`, `168.63.129.16`, `192.0.0.192`, `fd00:ec2::/32`, `fd20:ce::254`, `fd00:c1::a9fe:a9fe`, `fd00:42::42`), every address currently assigned to one of this host's own network interfaces (a service bound to `0.0.0.0` answers on the LAN or global address exactly as it does on loopback), every IP literal listed in `deniedDomains` (honouring its `:port` if it has one), and anything in `deniedResolvedAddresses`. IPv4 entries also match the IPv6 forms that carry an IPv4 address — IPv4-mapped, IPv4-compatible and IPv4-translated addresses, the NAT64 well-known prefix (`64:ff9b::/96`) and 6to4 (`2002::/16`) are judged by the IPv4 address they embed. The local-use NAT64 prefix `64:ff9b:1::/48` and network-specific prefixes are not decoded — their layout (RFC 6052 allows the IPv4 in several positions) can't be recognised from the address alone; on such a network, list the prefix's translations of the ranges you deny (e.g. `<prefix>::a00:0/104` for `10.0.0.0/8`). Addresses that reach this host without being assigned to it — a cloud instance's 1:1-NAT public address, a router port-forward, a container or VM host-gateway alias — are not covered automatically; list them in `deniedResolvedAddresses`.

What the check leaves alone: allowlist entries that **are** IP literals (allow-listing `127.0.0.1:3000` is an explicit choice) — and, by the same token, a hostname may resolve to an otherwise-denied address when that IP literal (on that port) is itself in `allowedDomains`, since reaching it by name grants nothing the literal entry does not (an IP literal in `deniedDomains` still wins, exactly as it does for a literal request). So a dev setup where `myapp.test` maps to a local server via `/etc/hosts` allow-lists `["myapp.test", "127.0.0.1:3000"]`; there is no separate carve-out list. `localhost` and names under `.localhost` resolve to loopback (or an allow-listed literal) and nothing else. The check is not evaluated for connections routed through `parentProxy` (including one picked up from `HTTP_PROXY` / `HTTPS_PROXY` in srt's own environment) or `mitmProxy` — that hop resolves the name and owns its own address policy — and it only governs what the proxy dials: on macOS, `allowLocalBinding` separately lets the sandboxed process connect to loopback ports without going through the proxy at all.

- `network.deniedResolvedAddresses` - Extra IP addresses / CIDR ranges (IPv4 or IPv6, unbracketed, any port) that allowed hostnames must not resolve to. Private-use space is not denied by default because allow-listing an intranet hostname is legitimate; list it here when allow-listed names must stay out of it, e.g. `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"]`. List IPv4 and IPv6 ranges separately — an IPv6 range broad enough to cover the IPv4-mapped block (`::ffff:0:0/96`), such as `::/0`, matches IPv4 answers on some runtimes but not others, so do not rely on it to deny IPv4.

**TLS termination** (`network.tlsTerminate`, experimental): when set, HTTPS CONNECTs are terminated in-process so SRT can see (and filter, via `network.filterRequest`) the decrypted requests. The sandboxed process is pointed at a trust bundle containing the MITM CA (`caCertPath`/`caKeyPath`, or an ephemeral CA if omitted) plus the host's regular roots, so proxy-minted certificates and real upstream certificates both verify. It needs Node, or Bun 1.4 or later; on an older Bun, `SandboxManager.initialize` throws. See [TLS Termination](#tls-termination) for how it works, its limits, and what changed from the per-tunnel listener it replaced.

- `network.tlsTerminate.excludeDomains` - Domain patterns (same syntax as `allowedDomains`) that are **not** terminated. Matching CONNECTs are tunnelled opaquely instead: they are still subject to the domain allowlist, but the client inside the sandbox completes its own TLS handshake with the real upstream, and `filterRequest` / credential injection do not apply to their HTTPS traffic. Use this for the two cases TLS termination fundamentally breaks:
  - **mTLS upstreams** - only the in-sandbox client holds the client certificate, so the proxy cannot re-originate the connection on its behalf.
  - **Certificate-pinning clients** - clients that verify the upstream's identity themselves (custom CAs, SAN pinning) and reject the MITM certificate.
- `network.tlsTerminate.extraCaCertPaths` - Paths to PEM CA certificate files appended to that trust bundle, after the MITM CA and the host's regular roots. Excluded (non-terminated) hosts are verified by the client inside the sandbox, and the trust env vars SRT sets (`SSL_CERT_FILE`, `GIT_SSL_CAINFO`, ...) _replace_ each tool's own trust configuration, so a site-local root (e.g. an internal mTLS CA) must be in the bundle or those hosts can never be verified. Only the `CERTIFICATE` blocks of each file are copied into the bundle (anything else, e.g. a private key in a combined PEM, is never exposed to the sandbox); files that are missing, unreadable, or contain no PEM `CERTIFICATE` block are skipped, so it is safe to list paths that exist on only some hosts.
- `network.tlsTerminate.maxTunnels` - At most this many CONNECT tunnels are TLS-terminated at once (integer, 1 to 65536, default 256). Past it a CONNECT is answered `503` with `X-Proxy-Error: too-many-tunnels`, and the refusal is recorded as a violation, once per command until half the slots are free again. A tunnel holds its slot from its CONNECT until it closes, so idle keep-alive tunnels count until they are [closed](#tls-termination). The slot is taken before the client's first bytes are seen, so at the cap a non-TLS CONNECT (such as SSH) to a host that would be terminated is refused too; one that turns out not to carry TLS frees its slot. Hosts in `excludeDomains` do not count.
- `network.tlsTerminate.handshakeTimeoutMs` - A tunnel to be terminated must finish its TLS handshake within this many milliseconds of its CONNECT (integer, 100 to 600000, default 10000), or it is closed and its slot freed. A CONNECT whose client sends nothing is closed at the deadline too. A tunnel past its handshake is never timed out by it.

These two are read at each CONNECT, so `updateConfig` changes them for the tunnels that follow.

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

**Request rewriting** (with `network.filterRequest`, set by library consumers): an allow decision may also carry header edits (`removeHeaders`, `setHeaders`) and an `onResponse` observer, and a deny decision may choose its status (403 by default). These options are read when the proxy starts; `updateConfig` does not change them.

- `network.allowPlaintextHeaderSet` - Let an allow decision set headers on plain-HTTP requests. Off by default: a header set there would travel in cleartext, so while it is off an allow decision that carries `setHeaders` is refused with 403, and nothing is forwarded, for every request the proxy receives in cleartext (an absolute `https://` URI included). An allow without `setHeaders` is unaffected and removals always apply. The callback's second argument reports `scheme: 'http'` for these requests.
- `network.stripResponseHeaders` - Response headers never passed back to the sandboxed client, matched case-insensitively with `-`, `_` and `.` folded (e.g. `["set-cookie"]`).
- `network.refuseOpaqueTunnels` - Refuse every tunnel `filterRequest` cannot see into: an HTTP CONNECT that would not be TLS-terminated or carries no TLS, and every SOCKS CONNECT. Requires `tlsTerminate` to serve HTTPS at all, and stops CONNECT-carried SSH (such as `GIT_SSH_COMMAND`) through the proxy. Refusals are recorded as violations.
- `network.requireHostMatch` - Answer 421 to a request whose Host header, TLS server name or absolute-form authority does not name the host and port it is sent to, before `filterRequest` is asked. Refusals are recorded as violations.
- `network.ambiguousRequestTarget` - What becomes of a request whose target is ambiguous: normalised (dot segments and `%2e` resolved, `\` in the path read as `/`, a run of leading slashes collapsed to one) it names another path than as the client spelled it. Upstreams differ in how they read such a spelling, so a policy that judged one reading can be got around through another.
  - `"refuse"` (default) - Answered 400 with `X-Proxy-Error: ambiguous-request-target` before `filterRequest` is asked. Nothing is forwarded, and the refusal is recorded as a violation.
  - `"asSpelled"` - Forwarded as the client spelled it. The caller takes on that its `filterRequest` holds for every reading an upstream may make of the spelling: `/public/../admin` is `/admin` to one that resolves it, `/admin/../public/x` is under `/admin/` to one that does not, and `/a\b/../admin`, normalised `/a/admin`, is `/admin` to one that keeps the `\`. Needs Node, or Bun 1.4 or later: an older Bun's HTTP client resolves dot segments on the way out.
  - `"normalize"` - Forwarded normalised. A signature that covers the path no longer verifies (or, where the proxy re-signs for a masked AWS credential, is valid for the other path), and an upstream that takes the path literally, such as an object store where `a/../b` is a key, acts on another resource than the client named.

While `filterRequest` is set, on plain HTTP and inside a terminated tunnel, the target goes upstream byte for byte as the client spelled it, without a fragment (except under `"normalize"`), and the callback's second argument carries both forms, `requestTarget` as spelled and `normalizedRequestTarget`, and `requestTargetIsAmbiguous`: under `"asSpelled"` a callback can refuse an ambiguous target itself, for the hosts and with the status it chooses. `request.url` is a parsed URL, so, as in earlier releases, its path has dot segments already resolved and is not the spelling. Not ambiguous, and forwarded as spelled: `//` after the first segment, `%2F`, `;` parameters, dots in the query, a character the URL parser would only escape (`{`, `"`, `'`), and an empty query. A byte outside ASCII, which only Bun's listener for plain HTTP lets through, is percent-encoded in `requestTarget` and on the wire, as in earlier releases. A `#` and what follows it are cut off first, in every mode: a fragment is no part of a request target, but some clients leave it in the absolute form they send a proxy, and upstreams differ in what they make of one. So the callback, a signature, the upstream and a violation line all get the target without it; `%23` is data and stays.

Answered 400 in every mode, and recorded as a violation: a target that is not origin form, an absolute `http(s)` URI, or `*` for `OPTIONS`; and one with bytes that are not UTF-8, which the runtime has replaced by the time the proxy reads them. So is, inside a terminated tunnel and with or without `filterRequest`, a request the runtime's own HTTP parser refuses, which ends the tunnel: a raw byte outside ASCII in the target (`/café` has to be sent as `/caf%C3%A9`), a space, a malformed header.

While `filterRequest` is set, `TRACE` and `TRACK` requests are answered 405 before it is asked, on plain HTTP and inside a terminated tunnel, because their response would echo a header the decision set back to the client. Node's and Bun 1.4's HTTP parsers already answer `TRACK` 400 before the proxy sees it; under Bun 1.3 the connection is closed without an answer. Refusals are recorded as violations.

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
- `[abc]` - Matches any character in the set (e.g., `file[0-9].txt` matches `file3.txt`). Whatever stands between the brackets is a member, a `*` or a `?` too (`[*]` matches a `*` in a name). Brackets that spell no set, because a range in them runs backwards (`[user-id]`, `backup[2024-01-15]`) or there is nothing in them (`list[].ts`), are the text they are, on every platform; the rest of the entry is still a pattern (`app/**/[user-id]/*.env`)

Examples:

- `"allowWrite": ["src/"]` - Allow write to entire `src/` directory
- `"allowWrite": ["src/**/*.ts"]` - Allow write to all `.ts` files in `src/` and subdirectories
- `"denyRead": ["~/.ssh"]` - Deny read to SSH directory
- `"denyRead": ["/Users"], "allowRead": ["."]` - Deny read to all of `/Users`, but re-allow the current directory
- `"denyWrite": [".env"]` - Deny write to `.env` file (even if current directory is allowed)

**Path Syntax (Linux):**

bubblewrap binds concrete paths, so glob support is narrower than on macOS:

- `allowWrite` / `denyWrite` take literal paths. A trailing `/**` is dropped (`src/**` means `src`); any other glob pattern there is skipped, unless the entry is also the name of a path that exists (see "All platforms" below), and then that path is what is applied.
- `denyRead` / `allowRead` accept the same glob syntax as macOS, expanded to the entries that exist when the command is wrapped, so a file that appears later is not covered. The pattern needs a literal directory to start from (a relative pattern starts at the current directory): one with a wildcard in its first path component, such as `/**/*.pem` or `/opt*/keys/**`, is skipped on Linux. **A skipped pattern hides nothing**: as a `denyRead`, or as the path of a `mode: "deny"` credential file, it leaves every file it matches readable. `SandboxManager.getLinuxGlobPatternWarnings()` returns each such entry as configured, after the write patterns above, for the embedder to show; the only other sign is a line under `SRT_DEBUG`. Only directories the pattern can match beneath are listed (`certs/*.pem` lists `certs` alone).
- A directory matched by a `denyRead` pattern ending in `/**` that holds at least one entry when the command is wrapped becomes one tmpfs mount, like a directory listed in `denyRead` literally: inside the sandbox it is an EMPTY WRITABLE directory, so a command that used to write through a read-denied `build/` still writes, into the tmpfs, and loses that output when the command exits. A file added to the directory on the host afterwards is hidden too. A matched directory that is empty when the command is wrapped gets no mount (a matched symlink to a directory always gets one, on the directory it leads to). An `allowRead` beneath a mounted directory is bound back over the tmpfs, but each entry beneath it that the pattern matches keeps its own mask: under a `/**` pattern that is every entry there, so only what is created beneath the `allowRead` later is readable.
- A directory the expansion cannot list is denied as a whole, and nothing is bound back beneath the mount that hides it, `allowRead` and `allowWrite` paths included: what the pattern matches under them cannot be found. So is an entry that may be a directory for all the expansion can learn: one the file system lists without a type and that cannot be looked at either. A `denyRead` entry that cannot be inspected (its parent directory is readable but not searchable, say), or that leads to `/`, hides the nearest directory above it instead, in the same way.
- Symlinked directories are descended. A directory is listed once for each way the pattern can carry on beneath it, however many links lead to it, so the cost of the expansion follows the size of the tree and the length of the pattern, not the number or length of the names its links offer; what is found through a link is reported, and denied, where it really is. A link that leads back up the tree (to the directory holding it or above, or to the pattern's starting directory or above) is not descended. A `**` written against other text (`**.pem`, `a**/x`) and a bracket expression that can match `/` span directories as they do on macOS, through symlinked directories too. Every `denyRead` mount goes where the path really is (bubblewrap 0.12 and later refuse to mount on a symlink), so an entry reached through a symlink is denied under every name that leads to it; a link back up the tree is not descended, and denies what it reaches only when it is itself a match, which denies all of it, as a literal deny of the link would. A link that resolves to nothing is skipped. A link whose target cannot be looked at (a directory above the target is not searchable, say) is not followed: when the pattern would continue through it rather than match it, nothing is denied for it and what lies behind it is not masked. A link of that kind that is itself a match is still denied, under its own spelling. `allowRead` globs are not expanded through symlinks: they match the link itself.
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
- A directory may have `*`, `?`, `[` or `]` in its name (`[WIP] project`, `notes (draft?)`). An entry with those characters is read as a pattern, as described above, and **also** as the path it spells when the part of it that holds those characters exists on disk. With a folder `/work/[WIP] project` there, `/work/[WIP] project/keep` is both the pattern and the path, and `/work/[WIP] project/**/.env` is both the pattern and the pattern `**/.env` beneath that folder. A deny covers every reading and an allow allows every reading. What exists is looked at when the command is wrapped (on Windows, at `initialize()`), so a folder created later counts from the next command on (on Windows, from the next `initialize()`). For a deny, a symbolic link of that name counts as existing, and so does a path that cannot be looked at, whatever the entry: beneath a directory that cannot be searched when the command is wrapped, an ordinary pattern such as `/locked/*.pem` is also taken for the path it spells, and denied like any path there that cannot be looked at. For an allow the path has to be there as itself: if any component, from the first one with such a character on, is a symbolic link, the entry is a pattern only.
- A `*` or `?` in a folder's name also matches itself as a pattern, and so do a `[` or `]` without its partner and brackets that spell no set, so inside `build*`, `notes (draft?)` or `[user-id]` the pattern reading of an entry finds the path too. That shows in a deny ending in `/**`: it is applied as the pattern it is, under which on Linux every entry beneath the directory keeps its own mask (see above) and an `allowRead` beneath it opens only what is created later. Write such a deny without the `/**`.
- To name a path and nothing else, write `{ "path": "/work/*.env", "literal": true }` in place of the string. Such an entry is never a pattern, whether or not the path exists, so it can deny a file that is not there yet in a folder that is not there yet. `~` and relative paths are resolved as for a string, symbolic links are followed as for any path without such characters (a marked allow has no check for them), and a `/**` at the end is part of the name. `denyRead`, `allowRead`, `allowWrite` and `denyWrite` take this form; `credentials.files` does not. An object without `"literal": true`, or with any other key, is rejected.
- Not covered: on Linux, `allowWrite` and `denyWrite` still take no patterns, so a pattern beneath such a folder is skipped there, and `getLinuxGlobPatternWarnings()` still names every write entry with those characters that is not marked, and every read entry whose pattern is skipped, whether or not it is applied as a path. On Linux, a `denyRead` for a path that does not exist when the command is wrapped hides nothing in that command, marked or not. On Linux, the violation monitor takes its lists at `initialize()`: a folder created later counts for the commands wrapped after it, and the monitor does not learn of it. On macOS, an allow that is also the name of a path allows everything beneath that path, as any name does, where its pattern allows only what it matches: under `allowWrite: ["/work/*"]` a command can create a folder named `*` in `/work`, or rename one to that, and from the next command on write everything in it (under `allowRead`, read everything in it, whatever a `denyRead` pattern covers there). On Windows, `*` and `?` cannot be part of a name, so a marked path that holds one is skipped, and a UNC pattern is read as a pattern only, because finding out what exists would mean asking the share.
- For embedders: the four lists of `SandboxRuntimeConfig` are of type `FilesystemPathEntry[]`, which is `(string | { path: string; literal: true })[]`, and `getConfig()` gives entries back in the form they were given. Code that reads an entry as a string stops compiling; `typeof entry === 'string' ? entry : entry.path` is its path. Three things change without a compile error. A list joined into text prints `[object Object]` for a marked entry. `getFsReadConfig()` and `getFsWriteConfig()` carry marked entries in `literalDenyOnly`, `literalAllowWithinDeny`, `literalAllowOnly` and `literalDenyWithinAllow`, each of which may be absent when it has no entries, so hand those objects on whole instead of rebuilding them from `denyOnly` and `allowOnly`; `writeRootsOf(getFsWriteConfig())` is every path the command may write. And an empty `denyOnly` no longer means that nothing is read-denied. `getDefaultWritePaths()` and `expandWindowsFsPaths()` take the lists as configured. `wrapCommandWithSandboxLinux()` takes every path it is handed for a name, as bubblewrap does, and skips a string in `allowOnly` that has such characters and is not the name of a path by the rule above.

#### Other Configuration

- `ignoreViolations` - Object mapping command patterns to arrays of paths where violations should be ignored
- `enableWeakerNestedSandbox` - Enable weaker sandbox mode for Docker environments (boolean, default: false)
- `allowNestedUserNamespaces` - Linux: let the sandboxed command create user namespaces of its own (boolean, default: false). By default it cannot: see "The command stays in the namespaces made for it" under Platform-Specific Dependencies. Turn it on only where the commands run have to sandbox themselves that way (a browser with its namespace sandbox, rootless podman or buildah, a nested bubblewrap, `unshare -r` in a build script), and treat `denyWrite` and the mandatory denies as not holding against any command run under it. It can be given for a single command, in the configuration passed to `wrapWithSandbox`.
- `javaAgentJarPath` - macOS/Linux: absolute path to `srt-proxy-agent.jar`, the JVM agent injected via `JAVA_TOOL_OPTIONS` (see "JVM tools" under Network Isolation). Only needed by consumers that bundle sandbox-runtime and ship the jar separately; a normal npm install finds it under `vendor/java-proxy-agent/`.
- `enableWeakerNetworkIsolation` - Allow access to `com.apple.trustd.agent` in the macOS sandbox (boolean, default: false). This is needed for Go programs (`gh`, `gcloud`, `terraform`, `kubectl`, etc.) to verify TLS certificates when using `httpProxyPort` with a MITM proxy and custom CA. **Security warning:** enabling this opens a potential data exfiltration vector through the trustd service.
- `allowPty` - macOS only: allow pseudo-terminal operations (boolean, default: false). The seatbelt profile then carries `(allow pseudo-tty)` plus read, write and `ioctl` on `/dev/ptmx` and `/dev/ttys*`, which a command that allocates a pty of its own needs. Not read on Linux or Windows.
- `bwrapPath` - Linux only: absolute path to the `bwrap` (bubblewrap) binary, used instead of resolving `bwrap` on `PATH`. A path that is not executable is a dependency error, and no `PATH` lookup is tried after it.
- `socatPath` - Linux only: absolute path to the `socat` binary, used instead of resolving `socat` on `PATH`, with the same rule for a path that is not executable.
- `seccomp` - Linux only: `applyPath` points at the `apply-seccomp` binary to use instead of the packaged one, which is still used when nothing exists at that path. `argv0` invokes it as a multicall binary that dispatches on the `ARGV0` environment variable; `applyPath` is then used verbatim (no existence check) and must resolve inside the bubblewrap namespace.
- `ripgrep` - Linux only: how to invoke ripgrep for the deny-path scan (default: `{ "command": "rg" }`). `args` are passed before srt's own arguments, and `argv0` overrides `argv[0]` for a multicall binary.
- `git.safeDirectories` - Directories git should treat as `safe.directory` inside the sandbox, where the working tree is owned by another user — the repository top level when the command runs from a subdirectory, say. Injected through `GIT_CONFIG_*` environment variables, and it grants no write access of its own.
- `credentials` - Environment variables (`credentials.envVars`) and files (`credentials.files`) the sandboxed command must not read the real values of. `mode: "deny"` withholds the value; `mode: "mask"` puts a sentinel in its place inside the sandbox and has the proxy substitute the real value back on egress to the hosts that entry's `injectHosts` lists (default: `network.allowedDomains`). Masking requires `network.tlsTerminate`, so the real value only leaves over a verified TLS connection, unless `credentials.allowPlaintextInject` opts out. Files are masked on Linux only; macOS denies a masked file instead.
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

**Exit status under zsh (Linux):** From the first release after v0.0.77, a wrap that restricts the network reports the wrapped command's own exit status when `binShell` is zsh. Up to v0.0.77 a failing command could report 0 there: the wrapper's cleanup trap ended with a bare `exit`, which zsh resolves to the status of the trap's last command. bash (the default) and dash were not affected.

**zod 4 in the same dependency tree:** The `zod` dependency range is `^3.25.0`. The library imports `zod/v3`, which exists from zod 3.25 on, so that it keeps the v3 API where a dependency tree resolves `zod` to version 4.

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

**Supported bubblewrap versions:** 0.4.0 and later, except that one thing needs 0.5.0 or newer, a change to how bubblewrap prepares the mount point for a file bind: a `denyRead` entry or credential mask naming a path that is not a regular file — a fifo, a socket, a device node — cannot be applied on an older bubblewrap, which creates a file at the destination instead of binding over what is there (that fails on a read-only mount and blocks on a fifo). `checkDependencies()` runs `bwrap --version` (once for each path of `bwrap`: the answer, or that there was none, is kept for the life of the process) and returns a warning naming the version it found when bubblewrap is older than 0.5.0; it is a warning, not a refusal. CI runs the whole suite against the bubblewrap Ubuntu ships and against 0.12.0, and the Linux mount-plan suites against 0.4.1 as well.

**Ubuntu 24.04+ note:** These releases enable `kernel.apparmor_restrict_unprivileged_userns` by default, which allows `unshare(CLONE_NEWUSER)` but strips capabilities from the resulting namespace. Both bubblewrap and the seccomp isolation layer need capability-bearing user namespaces. Disable the restriction with:

```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

or add an AppArmor profile that grants `userns` to the relevant binaries.

**Running as root:** a caller with euid 0 needs `CAP_SETFCAP` in its capability bounding set. Bubblewrap's user namespace maps the caller's uid, and Linux 5.12 — and the older distribution kernels that backported the change — lets a namespace map uid 0 only when its creator held that capability; the seccomp isolation layer's nested namespace has the same requirement. Without it every sandboxed command fails with `Operation not permitted` while writing a uid map, and `initialize()` refuses to start once bubblewrap has confirmed it. Grant the capability to the calling process — it is in Docker's default set, but `capsh --drop=cap_setfcap` and a tightened `CapabilityBoundingSet=` remove it — or run as a non-root user, for which none of this applies. The bounding set is what counts, because bubblewrap is reached by `execve` and the kernel recomputes a root caller's permitted set from it.

Prefer a non-root caller where there is the choice. Under the seccomp isolation layer a root caller's command still holds a full capability set inside the helper's nested user namespace, which is identity-mapped to the caller's uid 0; what holds the filesystem policy there is the helper's namespaces filter (next paragraph), not the command's capabilities: the nested namespace's copies of the mounts are locked, which refuses the unmount of any one deny but not the whole tree being moved aside with `pivot_root`. A non-root caller's command holds no capabilities at all.

**The command stays in the namespaces made for it.** Every write deny on Linux is a read-only bind mount, and a bind protects a path only in the mount namespace it was made in. Creating a user namespace takes no capability and gives its creator a full capability set over a private copy of the mount tree, from which the binds can be removed; so a sandboxed command may not create one. The seccomp isolation layer enforces that with a second filter beside the Unix-socket one, which refuses `unshare` and `clone` with the user-namespace or the mount-namespace flag, `setns`, `mount`, `umount2`, `pivot_root` and the newer mount calls (`EPERM`), and `clone3` (`ENOSYS`, which sends libc and the language runtimes to `clone`), and with `user.max_user_namespaces` set to zero in the helper's own user namespace.

What stops working as a result is whatever sandboxes itself with user namespaces: Chromium's and Electron's namespace sandbox, rootless podman and buildah, a nested bubblewrap or `srt`, `unshare -r` in a build script. They fail with `EPERM` (`unshare: unshare failed: Operation not permitted`); a nested bubblewrap blames a kernel setting and suggests a `sysctl`, which does not apply here. A root caller's command also loses `mount`, `umount` and `setns` for purposes of its own (`unshare -m`, `nsenter`, `ip netns exec`), and a direct `clone3` call has no fallback. The cure is `allowNestedUserNamespaces: true`, at the price stated under that option. Known limits:

- With no seccomp helper in the chain (`allowAllUnixSockets`, or no helper for the architecture) bubblewrap is given `--disable-userns` instead, which refuses a new user namespace (`ENOSPC`, `No space left on device`) and nothing else. That needs bubblewrap 0.8.0 or later, not installed setuid, and `enableWeakerNestedSandbox` off; where it cannot be done nothing limits namespaces, and a warning is logged once per process. **So `allowAllUnixSockets` and `enableWeakerNestedSandbox` together leave the limit off,** as `allowNestedUserNamespaces` does: an application that takes its options from several sources should trust whoever may set those two as far as whoever may set that one.
- A helper built before this release (an embedder's own, through `seccomp.applyPath` or `seccomp.argv0`) imposes no limit, and nothing says so: rebuild it from this release's `vendor/seccomp-src`.

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

Windows support is **alpha**. The sandboxed process runs under a dedicated `srt-sandbox` local user account, isolated from the calling user by native Windows security primitives — a Windows Filtering Platform (WFP) egress fence keyed on the sandbox account's SID, a write-restricted token, and explicit ACEs that grant or deny the sandbox access to configured filesystem paths.

### Setup

Run once per machine (self-elevates; one UAC prompt):

```powershell
npx @anthropic-ai/sandbox-runtime windows-install
```

This provisions the `srt-sandbox` local user account (with a random password stored DPAPI-encrypted in `HKLM\SOFTWARE\sandbox-runtime` — machine-wide, so fleet installs running as SYSTEM work and one user's rotation updates the copy the others read), the `sandbox-runtime-users` local group, and installs a machine-wide WFP filter set keyed on the `srt-sandbox` SID. It is **idempotent** — re-running it rotates the sandbox account's password and reconciles the filter set.

After the elevated step, the install makes **your user profile readable to sandboxed commands, except for credential stores**, as the user who ran it and without elevation; on a large profile this takes minutes the first time. It first prints one line saying so, naming the configuration files that can hold feed tokens and how to skip (`--skip-profile-grant`) or undo it (`srt-win profile forget`). See [Reading your user profile](#reading-your-user-profile) for what is readable, what is excluded, and how to restrict or remove it — and read [Shared machines](#shared-machines) before installing on a computer that more than one person uses. The sandbox works without the grant; its commands then read nothing in your profile.

**No logout is required.** The WFP filters key on the dedicated sandbox account's SID, so your own network, services, and every other principal on the machine are unaffected.

After install, `SandboxManager.initialize()` and the `srt` CLI work as on other platforms. `initialize()` verifies the sandbox account and WFP fence are live, and fails with an actionable error if not.

Programmatic install/uninstall are exported as `installWindowsSandbox()` / `uninstallWindowsSandbox()`.

**Upgrading from an earlier release: run `windows-install` once more** (one UAC prompt). It upgrades the existing install in place; nothing has to be uninstalled first, and this is the only reinstall this release asks for. The install records a setup version, and this release raises it (2 → 3) because it keeps write grants on project directories between sessions (see [the child token and kept grants](#the-child-token-and-kept-write-grants)). Until the install is re-run, `initialize()` and `checkDependencies()` report that the sandbox was set up by a different release and say to re-run the install, and nothing is granted or run. Once it has been re-run, an older release on the same machine refuses to start its sandbox, instead of running commands under a token that the kept grants were not made for. Its message also says to re-run the install; with the older release that is a downgrade, so read the next paragraph first.

**Going back to an earlier release:** run `windows-uninstall` with this release first (or `srt-win acl forget --all` as each user who ran sandboxed sessions), then install the older one. An older release's install does not know about the kept grants and does not remove them, and under its token they would let any sandboxed command write those directories. `srt-win user status` lists the directories that still carry one (`persistent_grants.roots`).

### Security model

The sandboxed command runs **as the `srt-sandbox` account**, not as the calling user. The bundled `srt-win.exe` helper does a two-hop launch: the broker calls `CreateProcessWithLogonW` to start a runner as `srt-sandbox`, and the runner spawns the target under a restricted token inside a job object. The child inherits the sandbox account's isolated profile (`%USERPROFILE%`, `%TEMP%`, `HKCU`) and a fresh environment overlaid with only the broker's `PATH` and the generated proxy variables.

Running under a distinct user SID structurally closes the surrogate-spawn class of escape (Task Scheduler, `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` onto a broker-owned process, BITS, out-of-process COM with `RunAs="Interactive User"`): any process the child manages to spawn out-of-band still carries the `srt-sandbox` SID, so the connections it makes itself remain subject to the WFP egress fence and it has no rights on the calling user's files. Traffic a system service carries for such a process is a separate matter (see [Known limitations](#known-limitations)).

**Network isolation** is a set of two WFP filters, optionally three, at each of `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`, installed machine-wide:

- a PERMIT for loopback destinations inside the configured proxy port range (default `60080–60089`);
- optionally, a second PERMIT for loopback destinations on every port but one — absent unless installed with `--allow-loopback` (see [Local servers on Windows](#local-servers-on-windows));
- a BLOCK for any connect whose token is the `srt-sandbox` account — including an AppContainer process started under that account;

The BLOCK is keyed on the sandbox account alone, so no other process on the machine is restricted. The filtering engine attributes a connect to the token that was in effect when its socket was created; a sandboxed thread that puts another token on itself before creating a socket is therefore not recognised as `srt-sandbox`. Traffic that a system service carries on the process's behalf is not matched by these filters either (see [Known limitations](#known-limitations)).

A connection the sandboxed process makes itself reaches the internet only via the JS HTTP/SOCKS5 proxies listening in that range; a process that strips its proxy environment and connects directly is blocked at the kernel. `initialize()` proves this each session by running connects as the sandbox account — with its own token and under copies of its token with the integrity level lowered, each of the latter on a socket created before the token is assumed and on one created after — and refuses to start if any of them gets out. The connects are made under the token a sandboxed command gets; where that token does not let a lowered copy be assumed, the attempt is reported as not made (the `lowered-integrity-unprobed` residual), not as a failure. The same probe connects while impersonating the anonymous token and under a deny-only copy of its token; those are not fenced, and are reported, not refused (see [Known limitations](#known-limitations)). With loopback open, the connects that must be blocked go to the one loopback port that stays blocked (see [Local servers on Windows](#local-servers-on-windows)), and one more connect, to a loopback listener the library binds for the probe, must succeed.

The fence blocks the identities it can name and lets everything else through, which leaves two gaps for tokens a sandboxed process can put on a thread, beside the traffic that system services carry (see [Known limitations](#known-limitations)).

**Filesystem isolation** is enforced by NTFS discretionary ACLs. The `srt-sandbox` account has no inherent rights on the calling user's files, so at `initialize()` the sandbox writes **additive, inheriting explicit ACEs** — for the sandbox account, and for `allowWrite` roots for the sandbox group and an identifier of the root's own ([below](#the-child-token-and-kept-write-grants)) — and never rewrites or replaces a path's existing security descriptor:

- `filesystem.allowWrite` → an inheriting `MODIFY` ALLOW ACE (`READ|WRITE|EXECUTE|DELETE`, with `FILE_DELETE_CHILD` withheld). The sandboxed process can create, modify, and delete files inside the working tree; withholding `FILE_DELETE_CHILD` from the grant is defense-in-depth for the deny stamps below, not a guard on the tree root.
- `filesystem.allowRead` → an inheriting `READ|EXECUTE` ALLOW ACE
- `filesystem.denyRead` / `filesystem.denyWrite` → an inheriting DENY ACE on the target, plus an inheriting `FILE_DELETE_CHILD` DENY on its parent — together with the withheld `FILE_DELETE_CHILD` on the working-tree grant, this stops the sandboxed process from renaming or deleting a denied path via its parent directory
- `credentials.files` → the DENY of `denyRead`, for `mode: "deny"` and `mode: "mask"` alike: an ACL cannot redirect a read, so a masked file is unreadable inside the sandbox, as on macOS

The lists rank as on the other platforms. The ACEs set on an object come before the ones it inherits, so an `allowRead` beneath a `denyRead` directory is readable. An `allowWrite` at or beneath a `denyWrite` path grants `READ|EXECUTE` only, and an `allowRead` or `allowWrite` at or beneath a `credentials.files` entry grants nothing. "Beneath" is decided on the paths as they resolve on disk: links, junctions, 8.3 names and letter case make no difference (a UNC path is compared as spelled, whatever its case). A deny that one command brings in its `customConfig` ranks the same way against the session's grants.

`reset()` removes the ACEs this session added, except the write grants on `allowWrite` roots and the denies beneath them, which are kept for the next session ([below](#the-child-token-and-kept-write-grants)). What is removed is refcounted across this user's concurrent hosts via the per-user session DB; a crash-recovery pass on the next `initialize()` cleans up after an unclean exit. Directory targets are supported (the ACEs inherit to the whole subtree). Glob patterns are expanded to concrete paths at `initialize()` time — a matching path that appears later is not covered. A pattern is walked from the literal directory it starts with, a drive root or the root of a share included (`C:\Users*\.ssh\*`, `\\server\share\*.pem`); a `**` right below such a root lists the whole volume. In an entry without `*` or `?`, `[` and `]` are characters of the name. In a pattern they are read as a character class, as on the other platforms, and the pattern is also expanded beneath a folder that has them in its name.

### The child token and kept write grants

The sandbox account is a member of `BUILTIN\Users`, so an ordinary token for it can write wherever `Users` / `Authenticated Users` hold write access, whatever `filesystem.allowWrite` says: directories created under `C:\`, trees on data drives, `PATH` directories outside `Program Files`. The sandboxed process therefore runs under a **write-restricted token**. Its restricting SIDs are the sandbox account, `Everyone`, `RESTRICTED`, and one identifier per `allowWrite` root of the session, so those group-held write rights do not apply: only the session's `allowWrite` roots, the sandbox account's own profile, and locations writable by `Everyone` are writable. Reads are unaffected by the token.

**What does not work inside the sandbox: Schannel.** Windows does not hand TLS credentials to a restricted token, so a client that uses the operating system's TLS stack cannot complete an HTTPS handshake:

- `System32\curl.exe`
- PowerShell `Invoke-WebRequest` / `Invoke-RestMethod`
- .NET `HttpClient`, and with it `dotnet restore` / NuGet
- `winget`
- any other tool built on WinHTTP, WinINet or Schannel, including git with `http.sslBackend=schannel` and cargo, whose bundled libcurl uses Schannel on Windows

There is no workaround for these inside the sandbox: run such a tool outside it.

**What keeps working:** clients that bring their own TLS stack — Node, Python, Java, Go programs, msys2 / Git for Windows `curl` built with OpenSSL, and Git for Windows itself, which the sandbox steers to its OpenSSL backend (`http.sslBackend=openssl` in the injected git config). They take their trust roots from the environment variables described under [TLS termination](#tls-termination-on-windows). git on its OpenSSL backend reads a PEM bundle, not the Windows certificate store: a host that does not terminate TLS itself and whose network path needs a root that exists only in the store (a TLS-inspecting corporate proxy, say) must supply it by setting `GIT_SSL_CAINFO` to a PEM bundle that contains it.

**Write grants on `allowWrite` roots are kept between sessions.** Granting a directory means writing an access entry that Windows copies to every file below it, which takes time proportional to the tree — and as long again to take back. So a root is granted the first time it is used; afterwards `initialize()` reads one access list per root, and `reset()` leaves the grant in place.

- A session can write only the roots in its own `allowWrite`. Each kept root is tied to an identifier of its own, which only a session given that root carries in its token, so a session in one project cannot write another project's kept root.
- **Reads are not separated this way: any sandboxed session can read a kept root**, whether or not the root is in its lists, until the grant is removed. That includes sandboxed sessions started by other users of the same computer: the sandbox account and group are one per machine. They can read a kept root; they cannot write it.
- `denyRead` / `denyWrite` entries beneath a kept root are kept with it, and are added to but not removed by later sessions.
- Sandboxed programs cannot change the permissions of files they create under a kept root.
- The kept grants are removed by `windows-uninstall`, and by `srt-win acl forget <root>` or `srt-win acl forget --all`. `srt-win user status` lists them. For a kept root that can no longer be located (one on a removed drive, say), `srt-win acl forget --all --force` drops its record and reports it.

The library always passes `--write-restricted-token` to `srt-win exec`: there is no setting that runs a sandboxed command under the sandbox account's ordinary token. `srt-win` itself still accepts a call without the flag, and refuses it while a kept grant exists or its absence cannot be established.

`initialize()` verifies the egress fence under the write-restricted token and fails if the probe is not blocked; a passed check is remembered for the rest of the process, until the sandbox account changes (a re-install) or a session asks for the other loopback mode (`network.allowLocalBinding`). If the token cannot be created, or a command fails under it, the failure is reported: nothing retries under another token.

### Reading your user profile

Installing the sandbox makes your user profile readable to sandboxed commands, except for the credential stores listed below — as on macOS and Linux, where reads are open by default. Tools installed under the profile run, and npm, pip, NuGet, Maven, Gradle and git find your configuration, including the sign-in for a private package feed.

The read access is a grant kept on disk. `windows-install` (`installWindowsSandbox()` / `installWindowsSandboxAsync()`) applies it right after the elevated step, without elevation, as the user who ran the install and for that user's profile:

```typescript
const r = await installWindowsSandboxAsync({
  srtWin,
  profileExclude: ['.myapp'], // extra paths to keep unreadable
  onProfileGrantProgress: line => console.error(line), // "12/57 top-level item(s) done"
  profileGrantTimeoutMs: 30 * 60_000, // the default
})
// r.profileGrant: { applied: true, userSid, result } | { applied: false, reason }
```

- The elevation prompt may be answered by another (administrator) account; the grant is still made by, and for, the user whose process called the install.
- The grant is applied only when the installing process runs as the person using the session it is in. An install run as another account on someone's desktop (an administrator's elevated prompt, `runas`), as a service account (a machine-wide deployment), or where the session's owner cannot be determined, applies no grant and says why in `profileGrant.reason`. That person then runs the install, or `grantWindowsProfileRead({ srtWin })` (`srt-win profile grant`), as themselves.
- `onProfileGrantStart` receives one line describing what is about to become readable (`windowsProfileGrantNotice()`), for you to show; `windows-install` prints it.
- If the grant fails or times out, the install throws `profile_grant_failed`: the account and the filters are installed, the grant is recorded as incomplete, and no session starts on it. Run the install or `grantWindowsProfileRead()` again to finish it. If the grant was not attempted because sandbox sessions or commands are running, or because another profile operation is, the install throws `profile_grant_blocked_by_session` or `profile_operation_in_progress` instead: the account and the filters are installed, nothing was written, and a grant made earlier is still the current one.
- `skipProfileGrant: true` (`windows-install --skip-profile-grant`) installs without it. The sandbox then works as it does without the grant: sessions run, and nothing in the profile is readable beyond `filesystem.allowRead`.

**The grant being there is the switch.** `initialize()` never writes or refreshes it. With no grant recorded — skipped at install, or removed with `profile forget` — a session runs exactly as it would without this feature, and `SandboxManager.getWindowsProfileRead()` returns `'absent'`. With a current grant it returns `'granted'`. `initialize()` rejects, with `profile_grant_outdated`, only when a grant is recorded that cannot be relied on: its run did not finish, it was made by a release with an older exclusion list (a path excluded since would otherwise stay readable) or for another profile directory, or its record is unreadable or lacks its list of exclusions. Then run `grantWindowsProfileRead()` (or `windows-install`) again, or `forgetWindowsProfileRead()` to go without.

**What it does.** The grant is read + execute for the sandbox group, never write. Starting at the profile directory, each directory is handled in one of two ways:

- a directory that could hold an excluded path — the profile directory itself, `AppData`, `AppData\Roaming`, `AppData\Local` and its children, `.config`, `.cargo`, `.gradle`, … — can be listed and passed through, and its children are granted one by one. Its files are readable (in the profile directory itself: only the files named below), each through an entry of its own;
- every other directory is granted whole, with everything in it.

No excluded path ever sits beneath a directory that is granted whole, so an excluded directory or file that is deleted and created again, or replaced by a rename, does not become readable.

**What it does not do.**

- It grants no write access. Sandboxed commands still write only where `filesystem.allowWrite` says, and the sandboxed process keeps its own `USERPROFILE`, `HOME`, `APPDATA`, `LOCALAPPDATA`, `TEMP` and `TMP` — tools write caches under those.
- It does not follow links. Junctions, symbolic links and cloud-only (placeholder) directories are skipped and reported, wherever the walk meets one, and nothing is written through one.
- **New items need a refresh.** Something created later directly in the profile directory, or in another directory whose children are granted one by one, is not readable until `grantWindowsProfileRead()` (or `windows-install`) runs again. Items created inside a directory that was granted whole are readable at once.
- **It is not per session, and not per user.** Once granted, any sandboxed session on the machine can read your profile, whatever its own configuration says, until the grant is removed — see [Shared machines](#shared-machines).

**Cost.** The first run sets an entry on every file under the granted directories and on the excluded ones: expect minutes on a large profile, and no other session of yours can start while it runs. A refresh reads one access list per recorded path and writes only what changed.

#### Readable files that can contain package-feed tokens

These configuration files are readable by sandboxed commands. That is deliberate — a private feed's sign-in works inside the sandbox — and it means a sandboxed command can read any token stored in them:

| File | Read by |
| --- | --- |
| `%USERPROFILE%\.npmrc` | npm |
| `%APPDATA%\pip\pip.ini`, `%USERPROFILE%\pip\pip.ini`, `%USERPROFILE%\.config\pip\pip.conf` | pip |
| `%APPDATA%\NuGet\NuGet.Config` | NuGet |
| `%USERPROFILE%\.m2\settings.xml`, `settings-security.xml` | Maven |
| `%USERPROFILE%\.gradle\gradle.properties` | Gradle |
| `%USERPROFILE%\.gitconfig`, `%USERPROFILE%\.config\git\config` | git |

To keep one of them unreadable, list it in `credentials.files` or `filesystem.denyRead` (for your sessions), or exclude it from the grant (for every session — see [Restricting it](#restricting-it)).

The sandboxed process has its own profile, so a tool does not look in yours by itself. `windowsProfileReadEnv(getWindowsProfileReadStatus({ srtWin }), yourEnv)` returns the variables that point each tool at its file, for the files that exist; the library sets none of them — pass the ones you want with the command's environment:

| Variable | Tool | Notes |
| --- | --- | --- |
| `NPM_CONFIG_USERCONFIG` | npm | |
| `GIT_CONFIG_GLOBAL` | git 2.32+ | replaces both global files; left out when you set it yourself |
| `PIP_CONFIG_FILE` | pip | read in addition to pip's other files |
| `MAVEN_ARGS` (`-s … -Dsettings.security=…`) | Maven 3.9+ | older Maven needs `-s` on the command line |
| `RUSTUP_HOME` | rustup (`cargo`, `rustc`) | a directory: your `RUSTUP_HOME` if you set one, else `%USERPROFILE%\.rustup`; without it rustup's shims find no toolchain |
| `CARGO_HOME` | cargo | a directory: your `CARGO_HOME` if you set one, else `%USERPROFILE%\.cargo`; read-only — see below |
| — | NuGet | no variable names the user file: pass `--configfile`, or keep a `NuGet.Config` in or above the project |
| — | Gradle | no variable names `gradle.properties` (`GRADLE_USER_HOME` would move the caches too): pass properties as `ORG_GRADLE_PROJECT_<name>` or `-P` |

`RUSTUP_HOME` and `CARGO_HOME` are the two that name a directory rather than a file, and are returned only when the directory exists and the grant reaches it (a location outside your profile is not offered, and neither is the default in its place). With `CARGO_HOME` pointing at your real, read-only directory, cargo builds from what is already cached there (`--offline`) but cannot add to the registry cache or install binaries from inside the sandbox. That is the intended trade: an empty writable cache in the sandbox account's own profile would be no better, since cargo's downloads use the Windows TLS stack, which does not work under the sandbox token. `credentials` and `credentials.toml` in that directory stay unreadable — they are denied on the files themselves, whatever names the directory — so an operation that needs a registry token fails there. `config.toml` in it stays readable, like `.npmrc`: a registry token written there rather than in `credentials.toml` is readable to sandboxed commands.

**Stores you have moved.** The exclusion list protects each tool's store where the tool keeps it by default. If your own environment moves one to another place inside your profile, the grant protects what the variable names as well: `CARGO_HOME` (its `credentials` and `credentials.toml`), `GRADLE_USER_HOME` (its `enterprise\keys.properties` and `develocity\keys.properties`), `GNUPGHOME`, `DOCKER_CONFIG`, `AZURE_CONFIG_DIR`, `GH_CONFIG_DIR`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE`, `NETRC`, and each file in `KUBECONFIG`. They are read from the environment `srt-win profile grant` runs in, recorded with the grant (`env_exclusions` in `srt-win profile status`), and never dropped by a later run — not when the variable changes or goes away, not with `--replace-excludes`: what was protected once stays protected until the grant is forgotten. A variable set after the grant was made takes effect at the next `srt-win profile grant`; until then a moved cargo home is not offered as `CARGO_HOME`, and `srt-win profile status` says so under `env_withheld`. Other variables that move a credential store are not followed; add such a place with `--exclude`.

#### Exclusions

There are two kinds.

**Protected paths** hold credentials, keys or tokens. They are never granted, and they are denied explicitly to the sandbox group (the deny is written before anything is granted; the commonest of these directories are created empty, to carry it, where they do not exist yet). A session cannot grant read access to one, to anything inside one, or to a directory above one — see [Restricting it](#restricting-it). They are:

- **Keys and sign-ins in the profile:** `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.docker`, `.terraform.d`, `.wrangler`, `.vercel`, `.netlify`, `.claude`, `.config\gcloud`, `.config\gh`, `.config\configstore`
- **The same tools' Windows locations:** `%APPDATA%\gcloud`, `GitHub CLI`, `gnupg`, `com.vercel.cli`, `netlify`, `xdg.config`, `terraform.d`, `terraform.rc`; `%LOCALAPPDATA%\heroku`
- **Token files and directories of further tools:** `%LOCALAPPDATA%\github-copilot`, `.config\github-copilot`, `.config\doctl`, `%APPDATA%\doctl`, `.config\op`, `.config\hub`, `.gem\credentials`, `.pulumi\credentials.json`, `%APPDATA%\postgresql\pgpass.conf`, `.pgpass`, `%APPDATA%\Composer\auth.json`, `.composer\auth.json`, `.fly\config.yml`, `.databrickscfg`, `.boto`, `.s3cfg`, `%APPDATA%\s3cmd.ini`, `.kaggle`, `.snowsql`, `.oci`, `.bluemix`, `.ibmcloud`, `.railway`, `.supabase` (where a tool installs itself beside its token file, as Pulumi and Fly do, only the file is excluded)
- **Feed sign-in caches:** `%LOCALAPPDATA%\.IdentityService`, `%LOCALAPPDATA%\MicrosoftCredentialProvider`
- **Credential files:** `.git-credentials`, `.netrc`, `_netrc`, `.pypirc`, `.vault-token`, `.terraformrc`, `.cargo\credentials`, `.cargo\credentials.toml`, `.config\git\credentials`, `.gradle\enterprise\keys.properties`, `.gradle\develocity\keys.properties`
- **Registry hives:** `NTUSER.DAT*`, `ntuser.ini`, `ntuser.pol`, `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat*`
- **Browsers, mail and password managers:** the `User Data` directories of Chrome, Edge and Brave in every channel, Chromium, Vivaldi and Yandex Browser; Opera's directories; the profile directories of Firefox, SeaMonkey and Thunderbird; `EBWebView` directories under `%LOCALAPPDATA%\<app>` and `%LOCALAPPDATA%\Microsoft\<app>`; 1Password, Bitwarden, KeePass, KeePassXC
- **Windows' own stores,** under both `%APPDATA%\Microsoft` and `%LOCALAPPDATA%\Microsoft`: `Credentials`, `Protect`, `Vault`, `Crypto`, `SystemCertificates`; and `%LOCALAPPDATA%\Microsoft\IdentityCache`, `TokenBroker`, `OneAuth`, `Windows\INetCookies`, `Windows\INetCache`, `Windows\WebCache`
- **`%LOCALAPPDATA%\Packages`** (packaged applications' data) and this library's own state directory, `%LOCALAPPDATA%\sandbox-runtime` (its CA key is not in the profile: it is in `%ProgramData%\sandbox-runtime`)
- every other **file directly in the profile directory** except `.npmrc` and `.gitconfig` (not denied, just not granted)

**Left ungranted, but not closed:** `%LOCALAPPDATA%\Temp`. Every program you run drops files in the temporary directory, so nothing in it is readable through the grant — a file directly in it is as unreadable as before. But it is not a secret as a whole, and it is where sessions (and this library, for its trust bundle) stage directories of their own: it is not denied, and a session may grant a directory inside it with `filesystem.allowRead` or `allowWrite` as usual. Only a grant of the temporary directory itself, or of a directory above it, is refused, because that would cover everything in it. (The browser caches under `Microsoft\Windows` are protected, not merely ungranted: they hold cookie and history databases and pages fetched with your sign-ins, and nothing stages a session directory in them.)

**Links.** A junction or symbolic link is never granted through or written on. Where an excluded name is itself a link — `.ssh` or `.config` pointing into a `dotfiles` directory, say — the exclusion follows it: the link's target, if it is inside the profile, is excluded in its place (or becomes a directory of which only the right children are excluded), and is recorded with the grant at its real location. Links are resolved from the links themselves, one at a time, and only while they stay on this machine's drives; a link that leads to a network share is reported and not followed.

**Objects you may not change.** A real profile holds directories its user does not own (the Windows Installer cache, for one) and directories locked down so far that their own owner is denied reading. The grant works around them and says what it did — in its result, on the command line, and in `srt-win profile status` / `getWindowsProfileReadStatus()` — and none of them makes it fail or leaves it incomplete:

- **`notGranted`** — was to be made readable and its access list cannot be written. It stays unreadable to sandboxed commands; where it is a directory whose children are granted one by one, nothing beneath it is granted either.
- **`selfClosed`** — an exclusion whose deny cannot be written, and whose own access list gives the sandbox account no read: neither on the object itself nor, for a directory, in what it hands down to objects created or already inheriting beneath it. Closed without the deny. This is established for the directory and for what it hands down, not for every object already inside it — one of those may carry an allow of its own, and an excluded store is not walked.
- **`unverifiable`** — an exclusion whose deny cannot be written and which could not be examined, so nobody established whether the sandbox account is kept out. Each item says why (`cause`: the access list may not be read by you, the sandbox account is not known, the path is not on a local drive, or the look failed) and whether **you** can read its content (`callerReads`). One you can read without being able to see its access list is treated as readable to sandboxed commands — what admits you there is as a rule a group the sandbox account is in too — and is reported with the `unprotected` ones. For the others the warning states what is known (for instance that you cannot read them either) and promises nothing. A session starts either way; `getWindowsProfileReadWarnings()` returns `profile_exclusion_unverifiable` for them.
- **`staleAllow`** — a path that has left the grant (it was granted by an earlier run and is no longer part of it) and still carries the allow of that run, which could not be removed. It is readable through that entry; the warning is `profile_stale_allow`. It is not on the exclusion list. Nothing else is taken off an object that cannot be written — a deny that is still wanted is never touched.

**A protected path that is readable through an entry this product wrote** is the one case here that calls for action. It arises when a path carries an allow from an earlier run, is on the exclusion list now — the built-in list grew, or you added an exclusion — and its access list can no longer be written; or when a directory was granted whole, something beneath it became an exclusion, and the directory cannot be rewritten. It is reported among `unprotected` (the `profile_exclusion_unprotected` warning names these first), with `protectedExclusion: true` and `entry` on the item: `explicit` when the entry is on the object itself, `inherited` when it is a copy handed down from a directory above that could not be taken off the object. The session still starts — refusing every session over an object you cannot change would cost the sandbox and close nothing — and no per-command deny can help, since that would have to be written to the same access list. Where the entry is inherited the grant has already rewritten the directory it came from; what is left is the copy on the object. The item's `reason` gives the command that removes it, to be run as the object's owner or from an elevated prompt — `icacls "<path>" /remove:g "*<sandbox group SID>"` for an explicit entry, `icacls "<path>" /inheritance:e` for an inherited copy — followed by `srt-win profile grant` again. A `staleAllow` item carries the same two fields, with `protectedExclusion: false`.
- **`unprotected`** — an exclusion whose deny cannot be written and whose own access list lets the sandbox account read it. It was readable to that account before the grant, and would be without it: the sandbox account can open any path whose own access list admits it, whatever the directories above say, so leaving its parents ungranted would close nothing. The grant did not open it and cannot close it; its owner or an administrator can. A session on such a grant starts, and `SandboxManager.getWindowsProfileReadWarnings()` returns a `profile_exclusion_unprotected` warning naming the paths — show it.

The last three are what the access lists say when they are read, not what they said when the grant ran: `srt-win profile status` looks at each such exclusion again, so one that has been opened up since is reported as `unprotected` at the next session start, and one that can be denied by now is denied by the next run of the grant.

A grant reads as incomplete only when a run was cut short.

The list covers known stores. `AppData` holds the data of every application you run, and an application this list does not know is readable until you exclude its directory.

#### When the grant changes

The grant is written, refreshed and removed only while no sandbox session or command of yours is running, so that **a session's view of your profile is fixed from its start to its end**. `grantWindowsProfileRead()` (`srt-win profile grant`), `srt-win profile forget` and uninstall write nothing and fail — `profile_grant_blocked_by_session`, `kept_grants_in_use` — while one is; close the running sessions and run it again. A write root kept from an earlier session that is, lies inside, or lies above an exclusion is forgotten by the grant, and named in its output and result (`forgottenRoots`): its inheriting allow would otherwise reach the excluded store, and a session that asks for such a root is refused anyway. That is the price of a refresh: a new top-level item in your profile becomes readable at the next refresh, and a refresh needs the sessions closed. While a grant or a forget runs (half a minute to many minutes on a large profile), a session or command that tries to start fails with `profile_operation_in_progress` — at once where it asks for the grant's status, after about three seconds where it waits for the lock — rather than waiting it out. Every session counts, whatever it was given: `initialize()` registers it with `srt-win`, and a command wrapped with no session behind it registers itself for as long as it runs (one more acquisition of `srt-win`'s lock per such command). A sandboxed command does not outlive its session: `srt-win exec` watches the process that started it, and if that process ends while the command runs — it is killed, or crashes — the command and everything it started are terminated at once and `srt-win exec` exits **26** (`session_ended` from `parseWindowsSandboxError`). So "no session is running" means no sandboxed process is. The refusals name the processes: `kept_grants_in_use` and `profile_grant_blocked_by_session` say for each whether it is a session or command, holds a session grant or deny, or runs on a kept write root.

#### Shared machines

The sandbox account and the sandbox group exist once per machine, not once per user. The read grant on your profile is a grant to that group. So once ANY user's profile is granted, sandboxed commands started by ANY local user who can use the sandbox can read that profile (minus the exclusions) — not only commands you start. A person at another account on the same computer can read your documents, source trees and the configuration files listed above by running a sandboxed command.

On a computer that more than one person has an account on, do not apply the grant: install with `--skip-profile-grant` (`skipProfileGrant: true`), or run `srt-win profile forget` if it is already there. The sandbox works without it.

The same holds for the write grants kept on project roots (see [The child token and kept write grants](#the-child-token-and-kept-write-grants)): another user's sandboxed session can read a kept root, though not write it.

#### Restricting it

- **For a session:** `filesystem.denyRead` and `credentials.files` entries (`mode: "mask"` included — on Windows a masked file is unreadable) apply on top of the grant. They are the session's own: written for it on every granted path they cover — by `srt-win`, from its record, when it is handed the deny — and released when it ends; they are not recorded with the grant, and a read-denied file inside an `allowWrite` root is fine. `denyRead: ['~']` makes the whole profile unreadable for that session; the next session without it reads again. (Because `srt-win` does this and the library relies on it, a session refuses to start, with `srt_win_outdated`, on an `srt-win` that does not report the capabilities the library needs — whether or not a grant is recorded at that moment. The two can be different builds when a program embeds its own.)
- **For every session — persistent exclusions:** pass paths inside the profile (absolute, or relative to it) as `profileExclude` to the install, as `exclude` to `grantWindowsProfileRead()`, or as `srt-win profile grant --exclude <path>` (repeatable): for example the embedding program's own configuration directory. They are recorded with the grant and stay excluded on later runs that do not name them; `replaceExclusions: true` (`--replace-excludes`) makes the given list the whole added list. Nothing removes a built-in exclusion. These are lasting choices, for stores: a recorded exclusion is protected in every session, and no session can then use a directory above it as a write root. Do not record a session's own `denyRead` or `credentials.files` paths this way. If an earlier setup did (a project's `.env`, for instance) and a session is now refused its project directory, run the grant once more with the list you do want and `replaceExclusions: true`.
- **A session cannot grant its way to an exclusion.** `initialize()` rejects with `profile_exclusion_read_grant`, before granting anything, when a path the session would grant reaches an excluded one — compared with the exclusions recorded with the grant (built-in and added), after resolving links, junctions, short names and case; `srt-win acl grant` makes the same check itself:

  | The path is … | a protected path | the temporary directory |
  | --- | --- | --- |
  | the excluded path itself | refused | refused |
  | inside it | refused | allowed |
  | above it | refused | refused |

  This holds for `filesystem.allowRead` and for write roots (`allowWrite`, and so the working directory) alike: a write root grants read too, and its grant is kept between sessions. Above counts because a grant inherits: an excluded store created again beneath it would carry the grant. For the two wildcard entries (`EBWebView` under any directory of `%LOCALAPPDATA%` or `%LOCALAPPDATA%\Microsoft`) "above" means that such a directory exists beneath the path now: a tool's own directory there is grantable until one appears in it. A directory is checked for such stores when a session starts — every session, kept write roots included — not continuously; a path that exists and cannot be listed is refused like one that holds a store. So a session cannot use your profile directory, `AppData`, or another directory that contains an excluded path as its working directory — choose a narrower one, such as the project's own directory. An embedding program that means to open a protected store to its sessions for READING passes the path to `initialize()` itself — `SandboxManager.initialize(config, askCallback, false, { dangerouslyAllowReadOfProfileExclusions: [path] })`; this is not a configuration key. It admits an `allowRead` path that is a protected path or lies inside one. It never admits a write root, or any path above an exclusion. When no grant is recorded none of this applies: nothing in the profile is readable by default then.

#### Removing it

`forgetWindowsProfileRead({ srtWin })` or `srt-win profile forget` takes the sandbox group's entry off every recorded path, leaving each access list as it was, and removes the empty directories the grant created. `windows-uninstall` does the same. While a sandbox session or command is running nothing is removed and the call fails with `kept_grants_in_use`, naming the process. `forgetWindowsProfileReadAsync()` is the same removal without blocking the event loop. `srt-win profile status` shows what is recorded. After a removal sessions keep running; they no longer read the profile.

A kept write grant on a volume that cannot be reached — a disk that is not attached, a drive with no media, a locked BitLocker volume, a share that does not answer — cannot be taken off, and does not have to be for `srt-win acl forget` to succeed: it is listed as pending and is removed — by the next session start, `forget` or uninstall — once the volume is back, wherever the directory has been moved to on it. For a volume that will not come back, `srt-win acl forget --drop-pending <path>` gives the record up and says what it leaves behind; nothing else drops one.

### TLS termination on Windows

`network.tlsTerminate` does not need the MITM CA in the sandbox user's certificate store. Only Schannel clients read that store, and they do not run inside the sandbox ([above](#the-child-token-and-kept-write-grants)); `windowsTrustCa()` / `srt-win user trust-ca` remain available but `initialize()` no longer checks for them.

Clients with their own TLS stack (msys2 `curl`, git on its OpenSSL backend, Node, Python) are covered by the env-var trust layer: the same trust bundle used on macOS/Linux is passed into the sandbox via `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `CARGO_HTTP_CAINFO`, etc., and the bundle path is added to the session's `allowRead` grant so the sandbox account can open it.

### Windows-specific configuration

The cross-platform `filesystem` and `network` blocks apply as described above. Windows-only settings live under `windows`:

- `windows.proxyPortRange` — `[low, high]` inclusive port range the JS proxies bind inside. **Must match** the range passed to `windows-install --proxy-port-range` (default `[60080, 60089]`) — the WFP loopback PERMIT only covers that range.
- `windows.sublayerGuid` — WFP sublayer GUID under which the filters were installed. Omit to use the compile-time default; set only when enterprise tooling installed the filters under a custom sublayer.
- `windows.srtWin.path` — path to the `srt-win` binary. Omit to resolve the packaged `vendor/srt-win/<arch>/srt-win.exe`. Set when embedding `srt-win`'s CLI into a multicall binary; spawns then pass `--srt-win` as `argv[1]` so the embedder's dispatcher can route to `srt_win::run_from_args`.

### Local servers on Windows

By default a sandboxed command cannot connect to anything on `localhost` except the sandbox's own proxies: not a development server, not a database, not a server another sandboxed command started. `network.allowLocalBinding` — the same setting that opens local ports on macOS — opens loopback on Windows. It is off by default, and it is a property of the install:

```powershell
npx @anthropic-ai/sandbox-runtime windows-install --allow-loopback
```

```json
{ "network": { "allowLocalBinding": true } }
```

**What it opens.** Any service listening on the machine's loopback (`127.0.0.0/8` and `::1`, every TCP and UDP port) becomes reachable by sandboxed commands, whoever started it and whenever — including a local proxy or forwarder that carries traffic off the machine, which the domain allowlist does not cover. This is the same as on macOS with the setting on; Linux gives the sandbox its own loopback instead. Connections to any non-loopback address, the machine's own LAN address included, stay blocked. One loopback port, `1`, stays blocked as well, so that the sandbox can check its own fence.

**Set at install time, machine-wide.** The filters need an administrator, so the mode changes only by running `windows-install` again, elevated — with `--force`, as for any other change to an existing install (omit `--allow-loopback` to close loopback again). `srt-win status` reports it as `wfp.allow_loopback`, with a `loopback_notice` when it is open, and the fence probe and the dependency check say so in their warnings (`WINDOWS_ALLOW_LOOPBACK_EFFECT`).

**One mode per machine, not per session.** The key is written per session, but the mode it names belongs to the machine: every session on the machine, of every application that uses this install, must ask for the installed mode. A session that asks for the other one — in either direction — does not start: `initialize()` rejects with a `WindowsSandboxError` whose code is `wfp_loopback_mismatch`, `srt-win exec` exits 19 with the same code on its error line and launches nothing, and the dependency check reports it as an error when it is given the configuration, each naming the one install command to run. The mode cannot change for one command or through `updateConfig()`: those are refused the same way, and `reset()` then `initialize()` re-checks. Two applications that need different values therefore cannot share a machine; an embedder that offers the setting should say so where it offers it, and treat this error as "the machine is installed the other way", not as a broken install.

**Where the setting may come from.** Because it decides what sandboxed code can reach, an application embedding this library should take `network.allowLocalBinding` — and decide whether to install with `--allow-loopback` — only from a source the machine's user or administrator controls, never from a project's own files. The library cannot tell where its configuration came from; that is the embedder's duty.

**`no_proxy`.** With loopback closed the sandbox sets no `no_proxy`, so HTTP clients send `localhost` requests to the proxy like any other, where the domain allowlist decides them. With loopback open, the sandbox sets `no_proxy=localhost,127.0.0.1,::1` (in lower case only, like the other proxy variables) so that proxy-aware clients connect to local servers directly: those requests bypass the filtering proxy.

### Known limitations

- **Machines shared by several Windows users.** The sandbox account and group are one per machine, and a kept write grant names that group; `srt-win`'s refusal to run a command without the write-restricted token while kept grants exist is per Windows user. The library always uses that token, but another Windows user who runs `srt-win exec` directly without `--write-restricted-token`, or who runs an older release that does not use the token, can write into your kept project folders. `srt-win acl forget --all` removes the kept grants of the user who runs it.
- **Schannel-based clients do not work inside the sandbox** — see [The child token and kept write grants](#the-child-token-and-kept-write-grants) for the list.
- **Per-user tool installs are not reachable without the profile read grant** (see [Reading your user profile](#reading-your-user-profile)). Then the sandboxed process runs as `srt-sandbox`, not as you, so tools installed under your profile (nvm/fnm-managed Node, per-user `winget`/Scoop packages, `pip install --user`, `%LOCALAPPDATA%\Programs\…`) resolve on the inherited `PATH` but cannot be opened by the sandbox account. Prefer machine-wide installs (`Program Files`, `choco`/`winget --scope machine`), or add the specific profile paths to `filesystem.allowRead`.
- **Per-exec `filesystem.allowRead` / `filesystem.allowWrite` overrides are not supported.** Session-level `allowRead`/`allowWrite` (in the config passed to `initialize()`) work as described above; passing them per-command in `wrapWithSandbox`'s `customConfig` throws — grants are applied session-wide via `srt-win acl grant` at `initialize()`, and `srt-win exec` only exposes per-exec denies.
- **`proxyAuthToken` lives in the sandboxed child's environment.** Token-bearing proxy env entries (`http_proxy`, `https_proxy`, `all_proxy` and the others whose value is a proxy URL with the token in it, each under its one spelling) never ride a command line: `wrapWithSandboxArgv` returns them as a `stdinPayload` the caller writes to `srt-win exec`'s stdin (`--env-stdin`), and the broker forwards them to the runner over the existing spec pipe. The token still ends up in the child's environment block — that is how the sandboxed process authenticates to the loopback proxy, so it is not a secret from the sandbox itself. A process's environment is readable by principals that can open it for `PROCESS_VM_READ`, which includes other processes running as `srt-sandbox`; on a shared host treat the proxy allowlist as reachable by other same-session principals.

  **Spawning the wrapped argv:** prefer `spawnWrappedCommandWindows(wrapped)` (exported from the package root) — it owns the stdin contract. If you spawn by hand, spawn with stdin piped and write `stdinPayload` immediately whenever it is set; a caller that passes the argv through but never writes the frame does not hang — `srt-win exec` rejects a console stdin outright and otherwise gives up after 5 seconds with an error naming this contract, before any per-exec ACL side effects. Version skew: an older pinned `srt-win.exe` that predates `--env-stdin` exits with clap's unknown-argument error when driven by a newer host — rebuild it from `vendor/srt-win-src` (prebuilt `vendor/srt-win` binaries are produced from that source at release time, so skew only affects user-pinned executables).
- **Traffic carried by system services is not matched by the fence.** The WFP filters match connects made by processes running as `srt-sandbox`. File access over SMB (a `\\server\share` path, `net use`) is connected by the kernel's redirector rather than by the sandboxed process, and the logon-right denials on the sandbox account govern logons to this machine only. A sandboxed command has been observed to read and write a share on this machine's own SMB server, by loopback and by the machine's network address, with its own identity and with explicit credentials; whether a separate server accepts it is that server's decision. `wsl.exe` and the WSL service also answer a sandboxed process; nothing here establishes whether it can start a distribution, whose traffic would not leave as the sandbox account. Do not rely on `network.allowedDomains` / `deniedDomains` to cover SMB shares or WSL.
- **A sandboxed process that puts the anonymous token on a thread before creating a socket is not fenced.** The filtering engine attributes a connect to the token that was in effect when its socket was created, and the anonymous token (`ANONYMOUS LOGON`) is not the sandbox account. A sandboxed thread that impersonates it and then creates its socket can connect directly, without the proxies: to other machines and the internet, and to any listener on `127.0.0.0/8` or `::1`, not only the proxy port range — including local services that trust loopback callers. The only filter that could refuse this is one keyed on the anonymous token itself, which would apply to every process on the machine that uses that token, sandboxed or not; the filter set does not include one. Treat the network filter as stopping commands that connect directly, not code written to defeat it. `initialize()` probes the loopback destination each session and, where the connect goes through, reports it as the `anonymous-loopback` residual on the result of `verifyWindowsWfpEgress()` and as a warning in the debug log — it does not fail the session. The off-machine probe (`anonymous-egress`) cannot change the result and can take seconds, so it runs only when asked for: `verifyWindowsWfpEgress({ anonymousEgress: true })`, or `srt-win wfp verify --anonymous-egress`.
- **A token derived from the sandboxed process's own token is not fenced either.** The sandbox-account BLOCK matches a token that is granted the match right through an allow entry for the account's SID. A sandboxed process can derive a copy of its own token that no such entry matches (`CreateRestrictedToken`): one whose user SID is deny-only — an allow entry never matches a deny-only SID — or one whose restricting-SID list no longer contains the account's SID, so the second pass a restricted token needs is not satisfied. If it impersonates that copy and connects on a socket created under it, the BLOCK does not match and the connect is not fenced at all — off-machine and loopback destinations alike. This holds under the write-restricted token every sandboxed command runs with. No change to the filter descriptors closes it; it needs the policy inverted (block by default, permit what is named), which would apply to every account on the machine. `initialize()` probes the deny-only variant each session and, where the connect goes through, reports it as the `deny-only-user-sid` residual on the result of `verifyWindowsWfpEgress()` and as a warning in the debug log — it does not fail the session.
- **DNS resolution via the system resolver is not fenced.** `getaddrinfo()` is serviced by the `Dnscache` service running as `NETWORK SERVICE`, so name resolution succeeds even though the subsequent `connect()` from the sandboxed process is blocked. Tools that do their own UDP/53 (`nslookup`, `dig`) are fenced. This mirrors the macOS behaviour.

### Uninstall

```powershell
npx @anthropic-ai/sandbox-runtime windows-uninstall
```

Removes the WFP filter set, the `srt-sandbox` account and its profile, the `sandbox-runtime-users` group, the write grants kept on `allowWrite` roots by sessions of the user running it, that user's profile read grant, and removes the `HKLM\SOFTWARE\sandbox-runtime` key (credential, marker, CA record) — one UAC prompt. It refuses up front, with `kept_grants_in_use`, while a sandbox session or command of yours is running. That is checked once, before the prompt: a session started between the check and the elevated step is not kept out, loses its account under it, and is named when the uninstall finishes. Nothing is removed before the prompt is accepted: declining it leaves the sandbox and every grant as they were. The elevated step removes the install; the grants are then taken off by the process that asked, as the user who asked, whenever the account is gone. If one cannot be, the uninstall says which, exits non-zero, and `srt-win acl forget --all` / `srt-win profile forget` finish it later — also after a reinstall, which gives the group a new identifier: the old one is remembered with the grants. A grant on a disk that is not attached is listed rather than reported as removed. `%ProgramData%\sandbox-runtime` (the CA key material) is left in place; delete it (and `%LOCALAPPDATA%\sandbox-runtime` per user) manually for a full sweep.

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

- **Windows**: WFP `ALE_AUTH_CONNECT` filters block outbound connects made by a process running as the `srt-sandbox` account except loopback to the configured proxy port range (a sandboxed process that puts the anonymous token, or another token derived from its own, on a thread before creating a socket is not fenced, and neither is traffic a system service carries for it — see the Windows [Known limitations](#known-limitations)). The proxies bind inside that range. Environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, …) point tools at the proxies, but the WFP filter is the boundary — a process that ignores or unsets them is still fenced. Each proxy variable is in the sandboxed command's environment under one name only (two spellings of one name break every process start made through .NET): `http_proxy`, `https_proxy`, `ftp_proxy`, `all_proxy`, `no_proxy` and `grpc_proxy` in lower case and `RSYNC_PROXY` in upper case, the spellings the case-sensitive Cygwin/MSYS2 tools read. Native Windows programs look names up ignoring case and find them under either spelling. A case-sensitive reader of the upper-case name does not: in Git Bash `$HTTPS_PROXY` expands to nothing (`$https_proxy` has the value), and code that reads the upper-case key from a copy of the environment (`{...process.env}.HTTPS_PROXY` in Node) gets `undefined`. Any other `*_PROXY` variable keeps the one spelling it arrives with.

**git over SSH (macOS/Linux):** `ssh` reads no proxy variable, so srt sets `GIT_SSH_COMMAND` to an `ssh` whose `ProxyCommand` opens an HTTP CONNECT through the proxy and presents its token: `socat` on Linux, and on macOS a `/bin/sh` script around `/usr/bin/nc`, carried in `SRT_SSH_PROXY_COMMAND`, which keeps the token out of the arguments of `ssh` and of what it starts. (On macOS, a `socksProxyPort` or `httpProxyPort` of your own keeps `nc -X 5` to the SOCKS port.) The destination is held to `allowedDomains` / `deniedDomains` like any other: `github.com` admits port 22, `github.com:443` does not. On macOS a refusal is one line on stderr before ssh's own, with the proxy's reason: `sandbox proxy: github.com:22: 403 host is not on the allow list`. On Linux it is up to `socat`: 1.8.1 prints the reason, 1.8.0 nothing. What ssh needs to authenticate is a separate matter: its agent's socket has to be in `allowUnixSockets`, and its keys readable. An `ssh` that git does not start is not covered.

**Node.js (Windows):** Node's built-in `fetch`, `http` and `https` clients read `HTTP_PROXY`/`HTTPS_PROXY` only when asked to, so on Windows srt sets `NODE_USE_ENV_PROXY=1` alongside them (read by Node 22.21+ and 24.5+; on older releases those clients still connect directly and are refused). The two do not use the proxy the same way: `http.get` to an `http://` URL sends the request to the proxy, while `fetch` opens a CONNECT tunnel even for an `http://` URL, so for `fetch` the proxy sees and filters the host and port and nothing of the request inside the tunnel. With the variable set, Node's default agent proxies every request, so a library that already does its own proxying through that agent (it is handed the proxy's address and sends its requests there) has those requests proxied a second time and fails. To opt out, clear the variable in the command (in `cmd`, `set "NODE_USE_ENV_PROXY=" & set "node_use_env_proxy=" & node app.js`: a `*_PROXY` name is in the environment in both cases, and `set` removes one entry at a time), or give it a value of your own in the environment variables you pass for the sandboxed command: a caller's value replaces the generated one. On macOS and Linux srt does not set it.

**JVM tools (macOS/Linux):** the JVM ignores `HTTPS_PROXY`/`NO_PROXY` and has no environment variable for proxy credentials — proxy selection comes from the `https.proxyHost` system properties and the credential can only be supplied through `java.net.Authenticator`. So JVM-based tools (Bazel's gRPC remote cache, Gradle, Maven, …) would otherwise dial the target directly and fail, or reach the proxy without its token and get a 407. To close that gap srt injects a small `-javaagent` via `JAVA_TOOL_OPTIONS` (the env var carries only the jar path, the credential stays in `HTTPS_PROXY`). At JVM start the agent sets `http[s].proxyHost`/`Port` and `http.nonProxyHosts` from the proxy env vars, re-enables Basic auth for CONNECT tunnels, and installs an Authenticator for the proxy endpoint. Explicit `-D` proxy properties on the JVM command line still win, and any inherited `JAVA_TOOL_OPTIONS` is preserved (unless it is a denied credential env var). Every JVM prints a `Picked up JAVA_TOOL_OPTIONS: …` line to stderr as a result; a jlink'd runtime built without the `java.instrument` module cannot load agents and will refuse to start under the sandbox — unset `JAVA_TOOL_OPTIONS` in the command for such a tool. The jar ships in the npm package as `vendor/java-proxy-agent/srt-proxy-agent.jar` (source: `vendor/java-proxy-agent-src/`; built by the release workflow, or locally with `npm run build:java-agent` — needs a JDK ≥ 17). If it is not found, `JAVA_TOOL_OPTIONS` is left alone and JVMs behave as before; bundlers can point at their own copy with `javaAgentJarPath`.

### TLS Termination

With `network.tlsTerminate`, a CONNECT to an allowed host that is not in `excludeDomains` is answered `200`, and the client's first bytes are read. If they are a TLS ClientHello, the TLS is terminated in the SRT process, on the tunnel's own socket: the leaf certificate is minted for the server name read from the ClientHello (for the CONNECT target when there is none, and always with `requireHostMatch`), and the decrypted connection is handed to an HTTP server that never listens. Each request on it goes through `filterRequest` and the credential hooks and is forwarded upstream over a separate, certificate-verified TLS connection. The decrypted traffic, and the credentials injected into it, stay inside the SRT process and leave it only re-encrypted, to that verified upstream. Nothing is opened that another process could connect to: there is no per-tunnel listener and no per-tunnel socket file. A CONNECT whose first bytes are not TLS is tunnelled opaquely, as before (or refused, with `refuseOpaqueTunnels`).

**Runtime requirement.** Handing a decrypted connection to an HTTP server needs an `http.Server` that serves a connection passed to it with `emit('connection')`. Node's does, and Bun's does from 1.4. On an older Bun, `SandboxManager.initialize` with `network.tlsTerminate` set throws before it starts anything, with an error that names the runtime found:

```
tlsTerminate needs Node, or Bun 1.4 or later (this is Bun 1.3.13)
```

A program built with `bun build --compile` runs on the Bun that built it, so build it with Bun 1.4 or later. Without `tlsTerminate`, nothing changes on any runtime. Should a tunnel still reach the proxy on such a runtime, it is closed rather than left hanging.

**Limits.** At most `maxTunnels` tunnels (default 256) are terminated at once, and each must finish its handshake within `handshakeTimeoutMs` (default 10 s) of its CONNECT; see [Network Configuration](#network-configuration). Past its handshake, an idle tunnel (no request on it, nothing queued for its client) is closed and its slot freed: 10 s after its ClientHello if no whole request head has come, and 6 s after a response if none has followed, which is 1 s later than the `Keep-Alive: timeout=5` that responses carry; a client that does not answer the close is cut off as long again later. A tunnel whose request is not all in or is held back for an upstream that takes no more of it, or whose client does not take what is queued for it, is closed 300 to 360 s after anything last moved. A client that goes on reading, slowly or in bursts, loses nothing; that it reads shows as the kernel's send buffer frees up, up to a megabyte or two at a time, so one that takes less than about 5 KB/s of a response larger than the kernel's buffers hold counts as one that has stopped. A whole request may wait for its response without limit. Leaf certificates share one key per CA, and the proxy keeps those of the 256 most recently used host names.

**Memory held for slow peers.** A response to a client that is not reading waits once about 1 MiB is queued for that client, or once all tunnels together have 256 MiB queued, on Node and Bun alike. A request body to an upstream that is not reading is held back by the runtime under Node. Under Bun, the proxy does it itself (it pauses a tunnel once 4 MiB of its request body is buffered, or once the shared 256 MiB is used), but that only works on a connection the proxy is handed by its host. The proxy `SandboxManager` runs accepts its own connections, and Bun keeps reading such a tunnel while it is paused. So under Bun an upload to an upstream that has stopped reading is buffered in the SRT process without bound. This is a limitation of the runtime. Use Node where a sandboxed process may upload more than the host can hold.

**Changes a `tlsTerminate` user can observe.** On a supported runtime, compared with the per-tunnel listener:

- The tunnel cap: past `maxTunnels`, a CONNECT is answered `503` (`X-Proxy-Error: too-many-tunnels`), whether or not it would have carried TLS.
- The handshake deadline: a tunnel that has not finished its TLS handshake within `handshakeTimeoutMs` of its CONNECT is closed.
- Idle tunnels are closed 6 s after a response, as before, and 10 s after a ClientHello that no request follows (before: about 12 s under Bun, 90 s under Node). An upload is cut once it has not moved for 300 to 360 s, no longer 300 s after it began; so is a response of which the client takes nothing (before: never).
- The server name passed to `filterRequest` (`sni`) is lower-cased.
- With `requireHostMatch`, the leaf certificate is always the CONNECT target's, whatever server name the client asks for (a name that does not match gets `421`, as before).
- A ClientHello whose server name cannot be read as a plain DNS name (letters, digits and inner hyphens in dot-separated labels, with no trailing dot; for example one with an underscore) gets the CONNECT target's leaf certificate instead of one minted for that name. With `requireHostMatch`, its requests are answered `421`.
- Under Bun, an HTTP/1.1 request without a `Host` header inside a tunnel is answered `400`, as Node's parser already does.

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

**Precedence is intentionally opposite for reads vs writes:** `allowRead` overrides `denyRead`, while `denyWrite` overrides `allowWrite`. This lets you carve out readable regions within denied areas, and carve out protected regions within writable areas. On Linux and Windows that also holds when the `denyWrite` entry is at or above the `allowWrite` one — `allowWrite: ["/", "/work"]` with `denyWrite: ["/"]` leaves `/work` read-only rather than writable — and with debug logging on (`SRT_DEBUG`) a warning names both paths.

**Writes through links (Linux and macOS):** a write is judged by where it lands, after symbolic links are followed. A link inside an allowed write path that leads out of it gives a command nothing: the write is refused. A link that leads into an allowed write path works like any other name for that place. A hard link is a second name for the file itself: on Linux a file outside the allowed write paths that already has a hard link inside one can be written through it, and a sandboxed command cannot create such a link. On macOS nothing is promised for such a file.

**Read-side rules (Linux):** an entry is matched by the name it is, not by what it points at.

- An `allowRead` entry re-allows the name it names, so a link planted at an allowed path cannot re-open a denied one. One that is itself a symlink is bound back at its own name, from the target it was checked against: the target's own path stays hidden, and the target's contents are reachable only through the name. A `denyRead` entry or a credential mask that overlaps that target — at it, inside it, or covering it — wins over the carve-out, which is then not restored at all: the name is absent inside the sandbox rather than serving what the deny hides. The denied directory the carve-out is being restored into is not such an overlap, nor is anything above it: those are what the carve-out is an exception to. Neither is an entry that denies nothing — one naming a path that is not there, or a file an `allowRead` entry lifts.
- A `denyRead` of `/` together with an `allowRead` of `/` denies nothing: the root deny is expanded into the root's children, and the allow covers every one of them.
- A `denyRead` entry naming a FILE is lifted only by an `allowRead` entry naming that same file. An `allowRead` entry that is a symlink to it names the link, so it does not cancel the deny of its target.
- A `denyRead` entry that cannot be inspected (a parent made unsearchable, a dead network mount) hides the deepest directory above it that can be — never `/`, so when `/` is the only one left the entry mounts nothing and that deny is not enforced (the wrap logs which entry, and why, under `SRT_DEBUG`). Such a stand-in hides more than was written: nothing beneath it is readable, carve-outs named there included, and a carve-out elsewhere that resolves beneath it is not restored either.

**Write denies on paths that do not exist yet (Linux):** bubblewrap can only deny a path by mounting over it, so for a `denyWrite` path that is absent under a writable directory it first creates a mount point there: an empty, read-only file (or an empty directory for a missing intermediate component) that is visible on the host for as long as a sandbox is alive and is removed afterwards. Host tools therefore see such a path as existing while a sandboxed command runs, which matters for paths whose existence is their meaning (a lockfile such as `.git/config.lock` makes `git config` report "could not lock config file"). A process that dies without an exit event (`SIGKILL`, OOM) cannot remove its mount points, and nothing removes them later: they cannot be told from an empty file or directory of your own, or from the mount points of another process's sandbox that is still running. A later command finds a path that exists, binds it read-only like any other, and leaves it on the host until you remove it. Where a file lies above the path (`denyWrite: ["f/x"]`, and `f` is a file), no mount point can be made below it: the file itself is bound read-only, which keeps it there.

- No mount point is made where none can be: in a directory that refuses this user, when the refusal is not this user's to lift (another user's directory it may not write, a read-only file system, an immutable directory). bubblewrap could not create the path there, and would stop every command from starting; the sandboxed command cannot create it either, so the deny holds without a mount. The directories above the path are kept from being moved aside as for any other deny. A directory of your own that only its mode closes keeps its mount point, because the command could open it with `chmod`. Should somebody else lift the refusal while a command runs (the owner, an administrator, a remount), that command can create the path; the next one gets its mount point.
- On a Windows drive under WSL 2 (`/mnt/c`, a 9p mount) the Windows ACL decides what can be created, and Linux is told nothing of it: every folder looks like yours and writable. The only way to know is to try, so there, and only there, the library makes the mount point itself while it wraps the command, instead of leaving it to bubblewrap when the command runs: the same empty file or directory, at the same path, removed by the same clean-up. It is on the drive from the wrap on, also for a command that is never run, until `cleanupAfterCommand()` or `reset()`. A file deny in a folder that takes subfolders but no files (`C:\`) is covered by an empty directory. If nothing can be made and the folder refuses even to be given the mode it has, no mount point is made, as above.

**Note (Linux, large profiles):** The wrapped string runs as one argument of `sh -c`, which Linux caps at 32 pages (128 KiB with 4 KiB pages). A profile that would not fit, with 4 KiB to spare for a prefix of the caller's own, has its mounts written to an unnamed file (`O_TMPFILE`) that the wrapping process holds open and bubblewrap reads through `--args`. The string then reads `/bin/sh -c '…' srt-args /proc/<wrapping pid>/fd/<n> bwrap … --args 9 …`: still a simple command, which opens the profile on fd 9 and runs bubblewrap. The environment and the command stay on the command line; the file holds mount paths only.

- The profile is never given a name, so nothing can be put in its place between the wrap and the execution — not a command the process sandboxed, not a sandbox another process of the same user started with tmpdir writable, not a rename of a directory above `TMPDIR`. Every sandbox this library starts has its own PID namespace and a fresh `/proc`, so none of them can reach `/proc/<wrapping pid>` either.
- Not covered: another process of the same user running outside a sandbox can read a pending profile through `/proc`. It can already read the wrapping process's memory, so this gives it nothing new.
- The string must be run while the process that produced it is alive, and before the runtime cleans up after that command (`cleanupAfterCommand()`), which is when the profile is released.
- The profile needs a directory that takes an `O_TMPFILE` file — `os.tmpdir()`, else `/dev/shm` — and a readable `/proc/self/fd`. Without them an over-long profile is refused at wrap time with the reason; there is no fallback to a named file. Profiles that fit the command line do not use any of this.
- bubblewrap parses at most 9000 arguments (about 3000 mounts). A profile past that, or a command too long for one argument by itself, fails at wrap time with an error. The [mandatory deny paths](#mandatory-deny-paths-auto-protected-files) count too, and no list in the configuration holds them: a git repository directly inside a writable working directory takes four mounts (its hooks, its config, and the two directories above them), so some 730 repositories reach the limit by themselves. The error says how many of the arguments are theirs. There are fewer when the command runs from a directory with fewer repositories in it, or when `allowWrite` names fewer of them; a lower `mandatoryDenySearchDepth` leaves the deeper ones unprotected.
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
- Git hooks and config: `.git/hooks/`, `.git/config`. Where the working directory is a worktree or a submodule, its `.git` is a file: on Linux that file is blocked, so it can be read but not changed, moved or removed.

These paths are blocked automatically - you don't need to add them to `denyWrite`. For example, even with `allowWrite: ["."]`, writing to `.bashrc` or `.git/hooks/pre-commit` will fail:

```bash
$ srt 'echo "malicious" >> .bashrc'
/bin/bash: .bashrc: Operation not permitted

$ srt 'echo "bad" > .git/hooks/pre-commit'
/bin/bash: .git/hooks/pre-commit: Operation not permitted
```

**Note (Linux):** A mandatory deny path that does not exist yet is blocked as well. bubblewrap covers it with a read-only `/dev/null`, or mounts an empty read-only directory at the first missing intermediate component, and those host mount points are removed by `cleanupAfterCommand()` — see "Write denies on paths that do not exist yet (Linux)" above. macOS uses glob patterns, which cover existing and new files alike.

**Pinned directories (Linux):** Every existing ancestor of a protected path (a write-denied path, a read-denied file or directory, a masked credential file) up to the allowed write root covering it is made a mountpoint — "pinned" — and cannot be renamed or removed from inside the sandbox: `mv` or `rmdir` of such a directory (for example a nested repository's parent) fails with `EBUSY` ("Device or resource busy"), and `rm -rf` of a nested repository leaves the pinned directories and the protected files behind (as with `.git/hooks`). A pin is buried under the mounts above it, so it never appears on a lookup path: reads, writes, creation, renames and hard links inside or across a pinned directory are unaffected.

With `allowWrite: ["/"]` the pins reach every ancestor, including any other allowed write root that is one (`mv /work /work.bak` fails with `EBUSY` given `allowWrite: ["/", "/work"]` and a protected path inside `/work`). They stop below the top-level directory, which is bound writable over them, and that directory is the one new filesystem boundary: `mv` or `ln` between two top-level directories — say `/tmp` and `/home` — fails with `EXDEV` ("Invalid cross-device link"), as it does on any host where they are separate filesystems. `mv` falls back to a copy; `ln` and a raw `rename(2)` do not.

A wrap that carries no write restrictions at all — `filesystem.disabled` with credential masks still in force, or a library caller passing no write config while a `denyRead` entry or a mask still seeds a pin — is the same shape: the whole tree is bound writable, so it gets the same pins and the same top-level covers, and the same `EXDEV` boundary applies there too.

**Linux search depth:** On Linux, the sandbox uses `ripgrep` to scan for dangerous files in subdirectories within allowed write paths. By default, it searches up to 3 levels deep for performance: a dangerous file is found down to `a/b/.bashrc`, and a dangerous directory, or the hooks and config of a repository, one level higher up (`a/.vscode`, `a/.claude/commands`, `a/.git/hooks`). Ignore files (`.gitignore`, `.ignore`) do not hide anything from it, and a directory of the user's own that it cannot read is denied whole. A dangerous directory other than a repository's hooks is only seen if it holds a file directly: below the working directory, one that is empty or does not exist yet can be filled. A repository that has no `hooks` directory has an empty file in its place while a command runs, which stops `git init` from being run again there and a hook from being installed. You can configure this with `mandatoryDenySearchDepth`:

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
   - Network bridging processes (socat) start inside the sandbox (need Unix sockets), and the wrapper waits until both listen
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
- Where This Package Is Installed: Install it outside every allowed write path (a global prefix outside them, or `npx` run from outside the project). A copy in `<project>/node_modules/` with the project writable can be rewritten by a sandboxed command, and the next `srt` there runs the result unsandboxed. `checkDependencies()` returns a warning for a copy placed like that, also logged under `SRT_DEBUG`. A copy compiled into an application is unaffected.
- Linux Sandbox Strength: The Linux implementation provides strong filesystem and network isolation but includes an `enableWeakerNestedSandbox` mode that enables it to work inside of Docker environments without privileged namespaces. This option considerably weakens security and should only be used in cases where additional isolation is otherwise enforced.
- Weaker Network Isolation (macOS): The `enableWeakerNetworkIsolation` option re-enables access to `com.apple.trustd.agent`, which is needed for Go programs to verify TLS certificates via the macOS Security framework. This opens a potential data exfiltration vector through the trustd service and should only be enabled when Go TLS verification is required (e.g., when using `httpProxyPort` with a MITM proxy and custom CA).
- Apple Events (macOS): The `allowAppleEvents` option re-enables sending Apple Events and Launch Services open requests (`(allow appleevent-send)`, `(allow lsopen)`, and mach-lookups for `com.apple.coreservices.appleevents`, `com.apple.CoreServices.coreservicesd`, and `com.apple.coreservices.quarantine-resolver`), which `open`, `osascript`, and URL-opening helpers require. With these allowed, a sandboxed command can launch arbitrary applications with no user prompt, and launched applications run outside the sandbox entirely — so this option removes code-execution isolation, not just weakens it. Scripting already-running applications via Apple Events is additionally gated by macOS TCC automation consent, but launching via `open` is not. Only enable this when commands inside the sandbox genuinely need to open URLs or applications.

### Known Limitations and Future Work

**Linux proxy bypass**: Currently uses environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) to direct traffic through proxies. This works for most applications but may be ignored by programs that don't respect these variables, leading to them being unable to connect to the internet.

**Future improvements:**

- **Proxychains support**: Add support for `proxychains` with `LD_PRELOAD` on Linux to intercept network calls at a lower level, making bypass more difficult
