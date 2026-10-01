import { connect, type Socket } from 'node:net'

const [proxyPortArg, username, password, destinationHost, destinationPortArg] =
  process.argv.slice(2)

function fail(message: string): never {
  throw new Error(message)
}

function required(value: string | undefined, name: string): string {
  if (value === undefined || value.length === 0) fail(`missing ${name}`)
  return value
}

const proxyPort = Number(required(proxyPortArg, 'proxy port'))
const destinationPort = Number(required(destinationPortArg, 'destination port'))
const proxyUsername = required(username, 'proxy username')
const proxyPassword = required(password, 'proxy password')
const host = required(destinationHost, 'destination host')

if (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535) {
  fail('invalid proxy port')
}
if (
  !Number.isInteger(destinationPort) ||
  destinationPort < 1 ||
  destinationPort > 65535
) {
  fail('invalid destination port')
}
if (Buffer.byteLength(proxyUsername) > 255) fail('proxy username is too long')
if (Buffer.byteLength(proxyPassword) > 255) fail('proxy password is too long')
if (Buffer.byteLength(host) > 255) fail('destination host is too long')

type ParsedReply = { consumed: number; value: boolean }

function readReply(
  socket: Socket,
  parse: (buffer: Buffer) => ParsedReply | undefined,
): Promise<boolean> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0)

    const cleanup = (): void => {
      socket.off('data', onData)
      socket.off('error', onError)
      socket.off('close', onClose)
    }
    const onError = (error: Error): void => {
      cleanup()
      reject(error)
    }
    const onClose = (): void => {
      cleanup()
      reject(new Error('SOCKS proxy closed during handshake'))
    }
    const onData = (chunk: Buffer): void => {
      buffer = Buffer.concat([buffer, chunk])
      const reply = parse(buffer)
      if (reply === undefined) return
      cleanup()
      const remainder = buffer.subarray(reply.consumed)
      if (remainder.length > 0) socket.unshift(remainder)
      resolve(reply.value)
    }

    socket.on('data', onData)
    socket.once('error', onError)
    socket.once('close', onClose)
  })
}

function parseMethodReply(buffer: Buffer): ParsedReply | undefined {
  if (buffer.length < 2) return undefined
  if (buffer[0] !== 0x05) fail('invalid SOCKS version')
  return { consumed: 2, value: buffer[1] === 0x02 }
}

function parseAuthReply(buffer: Buffer): ParsedReply | undefined {
  if (buffer.length < 2) return undefined
  if (buffer[0] !== 0x01) fail('invalid SOCKS auth version')
  return { consumed: 2, value: buffer[1] === 0x00 }
}

function parseConnectReply(buffer: Buffer): ParsedReply | undefined {
  if (buffer.length < 5) return undefined
  if (buffer[0] !== 0x05) fail('invalid SOCKS version')

  let addressLength: number
  switch (buffer[3]) {
    case 0x01:
      addressLength = 4
      break
    case 0x03:
      if (buffer.length < 5) return undefined
      addressLength = 1 + buffer[4]!
      break
    case 0x04:
      addressLength = 16
      break
    default:
      fail('invalid SOCKS address type')
  }

  const consumed = 4 + addressLength + 2
  if (buffer.length < consumed) return undefined
  return { consumed, value: buffer[1] === 0x00 }
}

async function main(): Promise<void> {
  const socket = connect(proxyPort, '127.0.0.1')
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', resolve)
    socket.once('error', reject)
  })

  socket.write(Buffer.from([0x05, 0x01, 0x02]))
  if (!(await readReply(socket, parseMethodReply))) {
    fail('SOCKS proxy does not support username/password authentication')
  }

  const user = Buffer.from(proxyUsername)
  const pass = Buffer.from(proxyPassword)
  socket.write(
    Buffer.concat([
      Buffer.from([0x01, user.length]),
      user,
      Buffer.from([pass.length]),
      pass,
    ]),
  )
  if (!(await readReply(socket, parseAuthReply))) {
    fail('SOCKS proxy authentication failed')
  }

  const hostBytes = Buffer.from(host)
  socket.write(
    Buffer.concat([
      Buffer.from([0x05, 0x01, 0x00, 0x03, hostBytes.length]),
      hostBytes,
      Buffer.from([(destinationPort >> 8) & 0xff, destinationPort & 0xff]),
    ]),
  )
  if (!(await readReply(socket, parseConnectReply))) {
    fail('SOCKS proxy CONNECT failed')
  }

  process.stdin.pipe(socket)
  socket.pipe(process.stdout)
}

main().catch(error => {
  process.stderr.write(
    `${error instanceof Error ? error.message : String(error)}\n`,
  )
  process.exitCode = 1
})
