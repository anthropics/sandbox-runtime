# srt-proxy: SRT's HTTP proxy with an external decider

`srt-proxy` (also `srt proxy`) runs SRT's HTTP proxy on its own, with no
sandboxed child. An embedding host runs the workload elsewhere (a VM, a
container, another sandbox) and points the workload's traffic at the proxy.
Every request the proxy would forward is first decided by a separate
process, the **decider**, which the host also runs. The proxy holds no
policy of its own: a request goes out only when the decider allows it.

This document covers the command line, the decider protocol (version 1),
and the security model.

## Command line

The host starts the proxy with every resource it needs already open, as
inherited file descriptors:

| Flag                                      | What it is                                                                                                                                                                                                                                                                                                                                                                               |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--listen-fd <fd>`                        | A listening socket the host bound (a unix socket in a directory only the host can reach, or a TCP socket). The proxy accepts on it.                                                                                                                                                                                                                                                      |
| `--decider-fd <fd>`                       | A bidirectional stream (a socket) to the decider.                                                                                                                                                                                                                                                                                                                                        |
| `--decider-in <fd>`, `--decider-out <fd>` | The same as a pair of pipes, decider-to-proxy and proxy-to-decider.                                                                                                                                                                                                                                                                                                                      |
| `--lifeline-fd <fd>`                      | The read end of a pipe the host holds. When it ends, the proxy shuts down.                                                                                                                                                                                                                                                                                                               |
| `--ca-fd <fd>`                            | The TLS-termination CA (PEM private key and certificate), read to EOF. Without it, every CONNECT is refused.                                                                                                                                                                                                                                                                             |
| `--strip-response-header <names...>`      | Response headers never passed back to the client (for example `set-cookie`).                                                                                                                                                                                                                                                                                                             |
| `--plaintext-header-set`                  | Let allow verdicts set headers on plain-HTTP requests. Off by default, so that a credential never travels in cleartext.                                                                                                                                                                                                                                                                  |
| `--listen <host:port>`                    | Bind a loopback address (`127.0.0.0/8`, `[::1]` or `localhost`) instead of `--listen-fd` (development and tests). Any other address, including an empty host (`:PORT`), is refused at start-up unless `--listen-any-interface` is also given; the listener has no authentication, so with that flag anything that can reach the port can use the proxy, and a warning says so on stderr. |
| `--listen-any-interface`                  | Let `--listen` bind a non-loopback address. No effect on `--listen-fd`: the host owns that socket.                                                                                                                                                                                                                                                                                       |
| `--debug`                                 | Log to stderr.                                                                                                                                                                                                                                                                                                                                                                           |

A typical host:

```sh
# fd 3: lifeline, fd 4: listening socket, fd 5: decider socket, fd 6: CA pipe
srt-proxy --lifeline-fd 3 --listen-fd 4 --decider-fd 5 --ca-fd 6 \
  --strip-response-header set-cookie set-cookie2
```

`bun run build:srt-proxy` compiles a single executable (with `.env`,
`bunfig.toml`, `tsconfig.json` and `package.json` autoloading off), and
`bun run build:srt-proxy-node` a single-file Node bundle. The proxy needs
Node 22.12 or later (the package's `engines` floor), or Bun 1.4 or
later: an older Bun cannot take a handed listening socket
and cannot terminate TLS in-process. Given `--ca-fd`, the proxy refuses to
start there, with
`srt proxy: tlsTerminate needs Node, or Bun 1.4 or later (this is Bun <version>)`
on stderr and exit code 2. Without `--ca-fd`, on a loopback `--listen`, it
serves plain HTTP only and refuses every CONNECT.
Under Node, the two-stream form (`--decider-in`/`--decider-out`) fails at
start on pipes, anonymous or named, with
`decider unavailable: write error: read ENOTCONN` and exit code 2; hand Node
a socket pair, or use the single-descriptor `--decider-fd` form. Bun and the
compiled binary take pipes in either form.

The proxy serves the listener only after the decider's hello has arrived.
It exits when the lifeline ends, when the decider's stream ends or breaks
the protocol, or when the listener fails.

For diagnostics, setting `SRT_PROXY_REPORT_RSS_MS` to a positive integer
N makes the proxy write a line `srt-proxy rss <bytes>`, its resident set
size, to stderr every N milliseconds, for hosts that cannot read another
process's memory use.

The proxy refuses `TRACE` and `TRACK` requests itself with `405` (deny code `method_refused`), on plain HTTP and inside a terminated tunnel, without asking the decider: their response echoes the request, which would return a decider-supplied credential to the client. In practice a `TRACK` request does not get that far: the HTTP parser of Node and of Bun 1.4 rejects it as an unknown method and answers `400` with no deny code before any proxy code runs (under Bun 1.3 the connection is closed without an answer), so the `405` is what a `TRACE` gets, and what a `TRACK` would get on a runtime whose parser let it through. A `need_body` for a `GET`, `HEAD` or `OPTIONS` request that carries a body (a non-zero `Content-Length`, or any chunked content) is refused with `403` (deny code `bodyless_method_body`) and nothing is sent upstream: those methods are judged without their body, so the proxy will not show the decider an empty one and then forward the real one.

## Decider protocol, version 1

### Framing

Each message is a **frame**: a 4-byte big-endian length, then exactly that
many bytes of one UTF-8 JSON object. The object's `t` field names the
message. Every frame is at most 1 MiB except `body`: it carries up to 32 MiB
of request body as base64 in one frame, so it can reach 44 739 302 bytes
(about 42.7 MiB).

Frames are read strictly. Any of these breaks the protocol:

- bytes that are not UTF-8, or a string with a lone surrogate;
- anything but a single JSON object;
- a `null` anywhere, or a duplicate key;
- a field the message does not have;
- an optional field sent empty (`false`, `""`, `{}` or `[]`): optional
  fields are left out instead;
- a header name that is not a lower-case token;
- a control character (other than tab, and including C1 controls) in a
  header value or a reason.

### Hello

The proxy speaks first, with exactly:

```json
{ "t": "hello", "proto": 1 }
```

The decider answers with the same version and the egress lists the proxy
holds requests to:

```json
{
  "t": "hello",
  "proto": 1,
  "allowedDomains": ["api.example.com", "*.example.org"],
  "deniedDomains": []
}
```

List entries are lower-case DNS names, `*.` wildcards of two labels or
more, or IP literals, each with an optional `:port`. A CONNECT to a host
outside the lists (or on the denied list) is refused with 403 without asking
the decider. The hello carries nothing else.

### Requests and verdicts

For each request the proxy sends a `req` and waits for a verdict. Request
ids start at 1 and strictly increase.

```json
{
  "t": "req",
  "id": 7,
  "method": "POST",
  "host": "api.example.com",
  "port": 443,
  "hostHeader": "api.example.com",
  "sni": "api.example.com",
  "path": "/v1/things",
  "query": "limit=10",
  "headers": { "content-type": ["application/json"], "accept": ["*/*"] }
}
```

- An allow that sets headers on a plain-HTTP request (one not read inside a
  TLS-terminated tunnel) is refused: the client gets 403 with
  `X-Deny-Reason: plaintext_header_set` and nothing is sent upstream, so a
  credential never travels in cleartext and a request never goes out without
  a header its allow relied on. Allow such a request without sets, or start
  the proxy with `--plaintext-header-set`. A request frame carries `sni`
  only for a request inside a terminated tunnel whose client sent a server
  name; the field is left out, never sent empty. A frame without `sni` is
  either a plain-HTTP request or a TLS request whose client sent no server
  name (one that connected by IP address, for example). The frame has no
  scheme field, so only `port` can tell the two apart: a missing `sni` is
  not proof of plain HTTP.
- `host` and `port` are the CONNECT target (or the absolute URI's, on the
  plain path). They are canonical: lower-case, with no trailing dot.
- `hostHeader` and `sni` are present when the client sent them.
- `path` and `query` are the request target **as the client spelled it**:
  dot segments and percent escapes are not resolved. A decider that matches
  paths exactly therefore refuses an unusual spelling of an allowed path.
  `query` is left out when there is none.
- `headers` maps each lower-case header name to its values, in order, with
  `Host` apart.

The decider answers with one of:

```json
{"t":"verdict","id":7,"action":"allow",
 "setHeaders":{"x-tenant":["a"]},"removeHeaders":["x-api-key"],
 "cred":"api","credential":"<1-8 KiB of printable ASCII, no spaces>"}
{"t":"verdict","id":7,"action":"deny","status":451,"reason":"not here"}
{"t":"verdict","id":7,"action":"need_body","max":1048576}
```

- **allow**: forward the request, after removing `removeHeaders` and setting
  `setHeaders`. Names match case-insensitively, with `-`, `_` and `.` as one
  character, so every spelling the client sent is removed. An allow may not
  set or remove a framing header (`host`, `content-length`,
  `transfer-encoding`, `connection`, `upgrade`, `te`, `trailer`,
  `keep-alive`, `proxy-connection`), and may not set a credential header
  except through `cred` and `credential`.
- **cred / credential**: a credential for this one request. `cred` names its
  class and `credential` carries the value; both or neither. Every
  credential header the client sent (`authorization`, `proxy-authorization`,
  `cookie`, `x-api-key`, in any spelling) is removed first. The value then
  goes as `Authorization: Bearer <value>`, or where the host has configured
  that class to go (for example HTTP Basic for a git transport).
- **deny**: answer the client with `status` (400 to 599) and the optional
  `reason`. Nothing is dialled.
- **need_body**: the decider wants the request body before deciding. The
  proxy sends up to `max` bytes (1 byte to 32 MiB):

  ```json
  { "t": "body", "id": 7, "data": "<base64>", "cut": true }
  ```

  `cut` is present when the body was longer than `max`. The decider then
  answers with an allow or a deny. A request gets one `need_body`; a second
  breaks the protocol. While the proxy is reading the body, the decider may
  end the request with a deny, and nothing else.

### Limits

The proxy never sends a request the decider could not read. A request past
these limits is answered 400 (`X-Deny-Reason: bad_request`) without asking:

| Item                                                           | Limit  |
| -------------------------------------------------------------- | ------ |
| Header values (Host apart; a name with no value counts as one) | 190    |
| Header names and values                                        | 64 KiB |
| `host`, `hostHeader`, `sni`, `path`, each                      | 8 KiB  |
| The whole `req` frame                                          | 1 MiB  |

The same limits apply to an allow's `setHeaders`. An allow's
`removeHeaders` is at most 190 names and 64 KiB, and a reason is at most
1 KiB. A verdict past any limit breaks the protocol. Sizes are counted in
UTF-8 bytes.

### Timeouts and failure

**Fail closed.** A request is forwarded only if a well-formed allow for its
id arrives in time. Everything else refuses it.

- **One timer, the proxy's.** The proxy waits 5 seconds for each verdict,
  then answers the client 503 (`X-Deny-Reason: decider_unavailable`). A late
  verdict for that id is dropped without effect.
- **A protocol violation, in either direction, kills the link.** That covers
  a malformed frame, a verdict for an id nothing waits on, and a second
  `need_body`. Every pending and later request is answered 503, and the
  proxy shuts down.
- **The decider dying** (its stream ends) is handled the same way: pending
  requests get 503, and the proxy exits. It never forwards a request with
  no decider.
- Ids more than 4096 below the newest are forgotten, and late messages for
  them are dropped.

### Refusal codes

After a refusal it generates itself the proxy closes the client connection
once the response is written, although that response still carries
`Connection: keep-alive`. A client should not reuse the connection after a
response with `X-Deny-Reason`.

In proxy-only mode, every refusal the proxy answers itself carries
`X-Deny-Reason`:

| Code                   | Status        | When                                                                                                                               |
| ---------------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `host_not_allowed`     | 403           | A CONNECT or request to a host outside the decider's lists.                                                                        |
| `decider`              | the decider's | The decider denied the request.                                                                                                    |
| `decider_unavailable`  | 503           | No verdict in time, or the decider is gone.                                                                                        |
| `bad_request`          | 400           | A request the decider cannot be asked about, a malformed request target, an HTTP/1.1 request without Host, or a head past 2 MiB.   |
| `misdirected`          | 421           | The Host header, the TLS server name or an absolute-form authority does not name the target, or the server name could not be read. |
| `opaque_tunnel`        | 403           | A CONNECT that would not be TLS-terminated (proxy-only mode refuses opaque tunnels).                                               |
| `plaintext_header_set` | 403           | The decider allowed a plain-HTTP request with header sets and `--plaintext-header-set` is off.                                     |
| `bodyless_method_body` | 403           | The decider asked for the body of a `GET`, `HEAD` or `OPTIONS` request that has one.                                               |
| `address_not_allowed`  | 403           | The target resolves only to addresses the proxy may not dial.                                                                      |
| `too_many_tunnels`     | 503           | More TLS-terminated tunnels than the limit are open.                                                                               |
| `method_refused`       | 405           | A `TRACE` or `TRACK` request, on plain HTTP or inside a terminated tunnel. The decider is not asked.                               |

## Security model

### Nothing another local process can reach

The proxy accepts only on the socket the host handed in. TLS termination
opens nothing else: a CONNECT tunnel's TLS runs in this process, on the
tunnel's own socket, and the decrypted connection goes to an HTTP server
that never listens. No other process on the host can connect to a tunnel
or reach its decider, credentials or TLS state.

### Nothing is dialled before a verdict

The proxy resolves and connects to an upstream only after an allow. A
denied, refused, timed-out or malformed request leaves the host with no DNS
query and no connection. Before dialling an allowed hostname, the proxy
resolves it once and drops loopback, link-local, metadata, this host's own
addresses and the private ranges (`10/8`, `172.16/12`, `192.168/16`,
`100.64/10`, `fc00::/7`). It then dials the address that passed the check.

### What the client cannot do

- **No opaque tunnels**: every CONNECT is TLS-terminated, so the decider
  sees every request.
- **Names are pinned**: the Host header and the TLS server name must name
  the CONNECT target.
- **Spellings are refused, not normalized**: non-ASCII hosts and unusual
  request targets are refused before the decider is asked.
- **Clean requests upstream**: hop-by-hop headers (in any spelling) and
  request trailers never reach the upstream.
- **Credential headers are replaced**: when the decider places a credential,
  the client's own credential headers are removed first.

### Limits and backpressure

The memory and CPU a client can make the proxy spend are bounded by the
limits below. Slots are not: there is no request-head deadline and no idle
deadline, so once its TLS handshake is done a client can hold a tunnel open
indefinitely by sending nothing or half a request head, and it can do the
same on a plain connection; plain connections are not capped in number. The
proxy serves a single sandboxed client, so a client that exhausts its slots
denies service only to itself.

| Resource                                                           | Limit                                                                                                       |
| ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| TLS-terminated tunnels at once                                     | 256; past it, 503 before the 200                                                                            |
| Time to finish a tunnel's TLS handshake                            | 10 s after the CONNECT; then the tunnel is closed and its slot freed                                        |
| Request head                                                       | 2 MiB                                                                                                       |
| Request body the decider sees (`need_body`)                        | `max`, at most 32 MiB                                                                                       |
| Request bodies held for the decider at once                        | 64 MiB, counting each at its Content-Length or else at `max`; past it, 503 `decider_unavailable`            |
| Frames written to the decider and not yet read by it               | About 117 MiB; past it the decider counts as dead                                                           |
| Buffered request bodies and response queues across all connections | 256 MiB together                                                                                            |
| Per connection                                                     | 1 MiB queued for the client; under Bun, 4 MiB of request body (Node's own backpressure bounds it otherwise) |
| Leaf certificates                                                  | the 256 most recently used names; all share one key, so a new name costs a signature, not a key generation  |

The tunnel cap and the handshake deadline are fixed in srt-proxy. SRT's full
sandbox mode sets them with `network.tlsTerminate.maxTunnels` and
`handshakeTimeoutMs` (see the [README](../README.md#tls-termination)).

A slow upstream holds back the client's upload, and a slow client holds back
the upstream's response, rather than the proxy buffering either. Under Bun,
whose HTTP server for a handed-in connection keeps reading a paused request
and reports room to write while its socket's queue grows, the proxy pauses
the socket and watches the queue itself.

Known limitation: a `body` frame is not chunked. One frame carries the whole
body, up to the largest `max` of 32 MiB (about 43 MiB as base64), and the
proxy holds the body and its frame until the decider has read it, which is
why the bodies held at once are bounded. A `need_body` that would take them
past that budget is refused (`503`, `decider_unavailable`), not queued.

### When the decider dies

Pending requests get 503, and the proxy exits. The host notices through the
proxy's exit, and through its own end of the lifeline and decider streams.
