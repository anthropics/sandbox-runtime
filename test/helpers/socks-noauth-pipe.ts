/**
 * Minimal no-auth SOCKS5 CONNECT pipe for tests: connects to the proxy,
 * offers ONLY the no-auth method (like BSD `nc -X 5`), issues CONNECT for
 * the given destination, then pipes stdin/stdout to the socket. Used as an
 * ssh ProxyCommand so the ssh-refusal end-to-end tests do not depend on
 * which netcat flavor the host ships (GNU/nmap variants lack `-X`).
 *
 * Usage: bun socks-noauth-pipe.ts <proxyPort> <destHost> <destPort>
 */
import { connect } from 'node:net'

const [proxyPort, destHost, destPort] = process.argv.slice(2)
const sock = connect(Number(proxyPort), '127.0.0.1')
sock.on('connect', () => {
  sock.write(Buffer.from([0x05, 0x01, 0x00]))
})
let stage: 'method' | 'reply' | 'pipe' = 'method'
let buf = Buffer.alloc(0)
sock.on('data', chunk => {
  if (stage === 'pipe') {
    process.stdout.write(chunk)
    return
  }
  buf = Buffer.concat([buf, chunk])
  if (stage === 'method' && buf.length >= 2) {
    if (buf[0] !== 0x05 || buf[1] !== 0x00) {
      process.exit(1)
    }
    buf = buf.subarray(2)
    const host = Buffer.from(destHost!, 'utf8')
    sock.write(
      Buffer.concat([
        Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]),
        host,
        Buffer.from([(Number(destPort) >> 8) & 0xff, Number(destPort) & 0xff]),
      ]),
    )
    stage = 'reply'
  }
  if (stage === 'reply' && buf.length >= 10) {
    if (buf[1] !== 0x00) {
      process.exit(1)
    }
    const rest = buf.subarray(10)
    stage = 'pipe'
    if (rest.length > 0) process.stdout.write(rest)
    process.stdin.pipe(sock)
  }
})
/**
 * The proxy refuses by writing banner + DISCONNECT and closing straight
 * away, but ssh only reads that DISCONNECT after it has written its own
 * identification/KEXINIT into our stdin. Exiting as soon as the socket
 * closes therefore races ssh's write: when ssh loses (busy CI runner) it
 * gets EPIPE and dies with "Broken pipe" instead of reporting the reason.
 * So on socket close, signal EOF to ssh once everything forwarded has been
 * flushed, then keep draining stdin and exit only when ssh closes it — with
 * a fallback timer so a client that never closes cannot wedge the test.
 */
sock.on('close', () => {
  process.stdout.end()
  process.stdin.unpipe(sock)
  process.stdin.on('end', () => process.exit(0))
  process.stdin.on('close', () => process.exit(0))
  process.stdin.on('error', () => process.exit(0))
  process.stdin.resume()
  setTimeout(() => process.exit(0), 5000).unref()
})
process.stdout.on('error', () => process.exit(0))
sock.on('error', () => process.exit(1))
