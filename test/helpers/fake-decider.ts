import { PassThrough } from 'node:stream'

/** A frame: the 4-byte big-endian length, then the JSON text as given. */
export function frameOf(json: string): Buffer {
  const b = Buffer.from(json)
  const n = Buffer.alloc(4)
  n.writeUInt32BE(b.length)
  return Buffer.concat([n, b])
}

export type Frame = Record<string, unknown>

/** An in-test decider on a pair of streams, driven by a verdict function. */
export function fakeDecider(
  allowedDomains: string[],
  decide: (f: Frame) => Frame | Promise<Frame> | 'hang' | 'garbage' | 'end',
  deniedDomains: string[] = [],
) {
  const toProxy = new PassThrough()
  const fromProxy = new PassThrough()
  const seen: Frame[] = []
  let buf = Buffer.alloc(0)
  let hello = false
  const send = (m: Frame) => {
    const b = Buffer.from(JSON.stringify(m))
    const n = Buffer.alloc(4)
    n.writeUInt32BE(b.length)
    toProxy.write(Buffer.concat([n, b]))
  }
  fromProxy.on('data', (c: Buffer) => {
    buf = Buffer.concat([buf, c])
    while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
      const n = buf.readUInt32BE(0)
      const f = JSON.parse(buf.subarray(4, 4 + n).toString()) as Frame
      buf = buf.subarray(4 + n)
      if (!hello) {
        hello = true
        send({ t: 'hello', proto: 1, allowedDomains, deniedDomains })
        continue
      }
      seen.push(f)
      const v = decide(f)
      if (v instanceof Promise) {
        void v.then(late => send({ t: 'verdict', id: f.id, ...late }))
        continue
      }
      if (v === 'hang') continue
      if (v === 'garbage')
        toProxy.write(Buffer.from([0, 0, 0, 3, 120, 121, 122]))
      else if (v === 'end') toProxy.end()
      else send({ t: 'verdict', id: f.id, ...v })
    }
  })
  return { streams: { input: toProxy, output: fromProxy }, seen }
}
