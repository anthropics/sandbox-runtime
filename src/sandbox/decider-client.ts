/**
 * External request decider: a FilterRequestCallback answered by another
 * process over a byte stream (an inherited socket, or a pair of pipes).
 *
 * Framing: a 4-byte big-endian length, then exactly that many bytes of one
 * UTF-8 JSON object whose `t` names the message. The proxy speaks first:
 *
 *   proxy   → decider  {"t":"hello","proto":1}
 *   decider → proxy    {"t":"hello","proto":1,"allowedDomains":[...],"deniedDomains":[...]}
 *   proxy   → decider  {"t":"req","id","method","host","port","hostHeader"?,"sni"?,
 *                       "path","query"?,"headers"?:{name:[values]}}
 *   decider → proxy    {"t":"verdict","id","action":"allow","setHeaders"?:{name:[values]},
 *                       "removeHeaders"?:[names],"cred"?,"credential"?}
 *                    | {"t":"verdict","id","action":"deny","status":400..599,"reason"?}
 *                    | {"t":"verdict","id","action":"need_body","max":1..32MiB}
 *   proxy   → decider  {"t":"body","id","data":"<base64>","cut"?:true}   (after need_body)
 *
 * The rules this end keeps:
 * - proto is the integer 1, and a hello states nothing else.
 * - Request ids start at 1 and strictly increase.
 * - Optional fields are left out rather than sent empty: an optional field
 *   that is false, "", {} or [] is refused, as is a null, a duplicate key, a
 *   field the message does not have, a header name that is not lower-case,
 *   and a header or reason value with a control character (tab aside, C1
 *   controls included).
 * - A request gets verdicts until a deny or an allow ends it; a need_body
 *   asks for the body once (a second one is a violation). While this end
 *   reads a body, the decider may end the request with a deny.
 * - This end's timer is the only one: it waits `timeoutMs` for each
 *   verdict, then answers the client itself and drops, silently, whatever
 *   comes later for that id. A message for any other id nothing waits on is
 *   a violation, except that ids more than 4096 below the newest are
 *   forgotten and their late messages dropped.
 * - It reads frames of at most 1 MiB, and sends no req over 1 MiB. In a
 *   req, headers are at most 190 values and 64 KiB of names and values;
 *   host, Host header, server name and path at most 8 KiB each; all counted
 *   in UTF-8 bytes. A request that doesn't fit is answered 400 here,
 *   without asking.
 *
 * An allow's removeHeaders and setHeaders are applied exactly, matched
 * case-insensitively with `-`, `_` and `.` as one character (see
 * applyHeaderEdits). A credential (`cred` names its class, `credential`
 * carries the value for this one request) first removes every credential
 * header the client sent, then goes where its placement says.
 *
 * Fail-closed: a request is refused unless a well-formed allow for its id
 * arrives in time. Any violation, in either direction, kills the link:
 * every pending and later request is refused and `onDead` fires once.
 */

import { isIP } from 'node:net'
import type { Readable, Writable } from 'node:stream'
import { z } from 'zod/v3'
import {
  foldHeaderName,
  type FilterRequestCallback,
  type RequestDecision,
  type RequestInfo,
} from './request-filter.js'

export const DECIDER_PROTO = 1
const MAX_READ_FRAME = 1 << 20
const MAX_BODY = 32 << 20
/**
 * Request-body bytes that may be held for the decider at once, across all
 * requests. Each held byte costs about two and a third in this process (the
 * body, then its base64 in the frame), so two full-size bodies keep what
 * this budget covers near 150 MiB. The reservation ends at the verdict,
 * before anything is sent upstream: the copy of an allowed body that then
 * waits to go upstream is not counted here, and is paced by the proxy's
 * relay limits. A need_body that would pass the budget is refused, not
 * queued: a queue of held bodies is the same memory.
 */
const MAX_BODY_BYTES_HELD = 2 * MAX_BODY
/**
 * Bytes written to the decider and not yet taken by it before it counts as
 * gone. It has to clear every body frame the budget above allows at once
 * (base64, so four thirds of it) with room for request frames besides; past
 * that the decider is not reading, and one that is not reading cannot answer.
 */
const QUEUED_REQUEST_FRAME_ROOM = 32 << 20
export const MAX_QUEUED_BYTES =
  Math.ceil((MAX_BODY_BYTES_HELD * 4) / 3) + QUEUED_REQUEST_FRAME_ROOM
// A multiple of three, so slices of base64 join with no padding between.
const BASE64_SLICE = 3 << 16
// The protocol's limits (docs/srt-proxy.md, "Limits"), which both ends keep:
// header values and bytes, and an allow's removeHeaders names and bytes.
const MAX_HEADER_ENTRIES = 190
const MAX_HEADER_BYTES = 64 << 10
const MAX_REMOVE_NAMES = 190
const MAX_REMOVE_BYTES = 64 << 10
const MAX_HOST_PATH = 8 << 10
const MAX_REASON_BYTES = 1 << 10
const MAX_ID = 2 ** 53 - 1
const ID_WINDOW = 4096

/** Headers a credential travels in; removed (in any spelling) before one is placed. */
const CREDENTIAL_HEADERS = [
  'authorization',
  'proxy-authorization',
  'cookie',
  'x-api-key',
]
/** Headers an allow may not set: framing, and credentials (which only `cred` places). */
const NEVER_SET = new Set(
  [
    ...CREDENTIAL_HEADERS,
    'host',
    'content-length',
    'transfer-encoding',
    'connection',
    'upgrade',
    'te',
    'trailer',
    'keep-alive',
    'proxy-connection',
  ].map(foldHeaderName),
)
/** Headers an allow may not remove: framing. */
const NEVER_REMOVED = new Set(
  [
    'host',
    'content-length',
    'transfer-encoding',
    'connection',
    'upgrade',
    'te',
    'trailer',
    'keep-alive',
    'proxy-connection',
  ].map(foldHeaderName),
)

const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/
const LONE_SURROGATE =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/
const wellFormed = (s: string): boolean => !LONE_SURROGATE.test(s)
/** A C0 control other than tab, DEL, or a C1 control. */
function hasControl(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if ((c < 0x20 && c !== 0x09) || (c >= 0x7f && c <= 0x9f)) return true
  }
  return false
}
const lowerName = z.string().refine(n => TOKEN.test(n) && n === n.toLowerCase())
const headerValue = z.string().refine(v => !hasControl(v))
const nonEmptyHeaderObject = z
  .record(lowerName, z.array(headerValue))
  .refine(o => Object.keys(o).length > 0)
const id = z.number().int().min(1).max(MAX_ID)
const uniqueList = <T extends z.ZodTypeAny>(item: T) =>
  z.array(item).refine(l => new Set(l).size === l.length)

const helloSchema = z
  .object({
    t: z.literal('hello'),
    proto: z.literal(DECIDER_PROTO),
    allowedDomains: uniqueList(z.string().refine(isEgressEntry)),
    deniedDomains: uniqueList(z.string().refine(isEgressEntry)),
  })
  .strict()

const allowSchema = z
  .object({
    t: z.literal('verdict'),
    id,
    action: z.literal('allow'),
    setHeaders: nonEmptyHeaderObject.optional(),
    removeHeaders: uniqueList(lowerName)
      .refine(l => l.length > 0)
      .optional(),
    cred: z.string().min(1).optional(),
    // 1 to 8 KiB of printable ASCII, no space: placed in a header as is,
    // never trimmed or cleaned.
    credential: z
      .string()
      .refine(v => /^[\x21-\x7e]{1,8192}$/.test(v))
      .optional(),
  })
  .strict()
  .refine(a => (a.cred === undefined) === (a.credential === undefined))
  .refine(a =>
    Object.keys(a.setHeaders ?? {}).every(
      n => !NEVER_SET.has(foldHeaderName(n)),
    ),
  )
  .refine(a =>
    (a.removeHeaders ?? []).every(n => !NEVER_REMOVED.has(foldHeaderName(n))),
  )
  // A verdict past the protocol's limits breaks the protocol.
  .refine(a => headersFit(a.setHeaders ?? {}))
  .refine(
    a =>
      (a.removeHeaders ?? []).length <= MAX_REMOVE_NAMES &&
      (a.removeHeaders ?? []).reduce((n, h) => n + utf8Bytes(h), 0) <=
        MAX_REMOVE_BYTES,
  )

const denySchema = z
  .object({
    t: z.literal('verdict'),
    id,
    action: z.literal('deny'),
    status: z.number().int().min(400).max(599),
    reason: z
      .string()
      .min(1)
      .refine(r => Buffer.byteLength(r) <= MAX_REASON_BYTES && !hasControl(r))
      .optional(),
  })
  .strict()

const needBodySchema = z
  .object({
    t: z.literal('verdict'),
    id,
    action: z.literal('need_body'),
    max: z.number().int().min(1).max(MAX_BODY),
  })
  .strict()

type Allow = z.infer<typeof allowSchema>
type Deny = z.infer<typeof denySchema>
type NeedBody = z.infer<typeof needBodySchema>
type Verdict = Allow | Deny | NeedBody
export type DeciderHello = z.infer<typeof helloSchema>

/**
 * Where a credential class's value goes. The first rule whose class and
 * host (when given) match wins; with none, the value goes as
 * `Authorization: Bearer <value>`.
 */
export type CredentialPlacement = {
  class?: string
  host?: string
} & ({ scheme: 'bearer' } | { scheme: 'basic'; user: string })

export type DeciderOptions = {
  input: Readable
  output: Writable
  /** How long to wait for each verdict. */
  timeoutMs?: number
  credentialPlacements?: CredentialPlacement[]
  onDead?: (why: string) => void
  /** Overrides MAX_BODY_BYTES_HELD. */
  maxBodyBytesHeld?: number
  /** Overrides MAX_QUEUED_BYTES. */
  maxQueuedBytes?: number
}

export type Decider = {
  /** Resolves with the decider's hello, or rejects when it never comes. */
  hello: Promise<DeciderHello>
  filterRequest: FilterRequestCallback
  close(): void
  /** Request-body bytes reserved for need_body reads still in flight. */
  bodyBytesHeld(): number
}

type Waiter = (v: Verdict | { dead: string }) => void

class Violation extends Error {}

export function createDecider(opts: DeciderOptions): Decider {
  const timeoutMs = opts.timeoutMs ?? 5000
  const waiters = new Map<number, Waiter>()
  // Ids this end gave up on (timed out), with whether a need_body had
  // already been answered for them; late verdicts for them are dropped.
  const late = new Map<number, 'verdict' | 'verdict_shown'>()
  let lastId = 0
  let dead: string | undefined
  let gotHello = false
  let helloResolve!: (h: DeciderHello) => void
  let helloReject!: (e: Error) => void
  const hello = new Promise<DeciderHello>((res, rej) => {
    helloResolve = res
    helloReject = rej
  })
  hello.catch(() => {})

  const die = (why: string): void => {
    if (dead !== undefined) return
    dead = why
    helloReject(new Error(`decider unavailable: ${why}`))
    for (const w of waiters.values()) w({ dead: why })
    waiters.clear()
    opts.onDead?.(why)
  }

  const maxHeld = opts.maxBodyBytesHeld ?? MAX_BODY_BYTES_HELD
  const maxQueued =
    opts.maxQueuedBytes ??
    (opts.maxBodyBytesHeld === undefined
      ? MAX_QUEUED_BYTES
      : Math.ceil((maxHeld * 4) / 3) + QUEUED_REQUEST_FRAME_ROOM)
  let held = 0
  let queued = 0

  const sendFrame = (frame: Buffer): void => {
    if (dead !== undefined) return
    queued += frame.length
    opts.output.write(frame, () => {
      queued -= frame.length
    })
    if (queued > maxQueued) die(`not reading: ${queued} bytes queued`)
  }
  const send = (msg: Record<string, unknown>): void => {
    if (dead !== undefined) return
    sendFrame(encodeFrame(msg))
  }

  const onFrame = (frame: Buffer): void => {
    let parsed: unknown
    try {
      parsed = parseStrictJson(frame)
    } catch (e) {
      return die((e as Error).message)
    }
    if (!gotHello) {
      const h = helloSchema.safeParse(parsed)
      if (!h.success) return die('bad hello')
      gotHello = true
      helloResolve(h.data)
      return
    }
    const v = verdictOf(parsed)
    if (v === undefined) return die('bad verdict frame')
    const waiter = waiters.get(v.id)
    if (waiter) {
      waiters.delete(v.id)
      waiter(v)
      return
    }
    const state = late.get(v.id)
    if (state !== undefined) {
      if (v.action === 'need_body' && state !== 'verdict') {
        return die('need_body where none may come')
      }
      if (v.action !== 'need_body') late.delete(v.id)
      return
    }
    if (v.id < lastId && lastId - v.id >= ID_WINDOW) return
    die(`verdict for id ${v.id}, which nothing waits on`)
  }

  let buf: Buffer = Buffer.alloc(0)
  opts.input.on('data', (chunk: Buffer) => {
    buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk])
    while (buf.length >= 4 && dead === undefined) {
      const n = buf.readUInt32BE(0)
      if (n > MAX_READ_FRAME) return die('oversized frame')
      if (buf.length < 4 + n) break
      const frame = buf.subarray(4, 4 + n)
      buf = buf.subarray(4 + n)
      onFrame(frame)
    }
  })
  opts.input.on('end', () => die('decider closed the stream'))
  opts.input.on('error', err => die(`read error: ${err.message}`))
  opts.output.on('error', err => die(`write error: ${err.message}`))
  // A stream destroyed without an error (Node's socket on a descriptor whose
  // peer closed) drops later writes without reporting one.
  opts.output.on('close', () => die('decider closed the output stream'))

  send({ t: 'hello', proto: DECIDER_PROTO })

  /**
   * Wait for id's next verdict. With a timeout, running out records the id
   * as late; `cancel` stops waiting without that.
   */
  const awaitVerdict = (
    reqId: number,
    lateState: 'verdict' | 'verdict_shown' | undefined,
  ): { promise: Promise<Verdict>; cancel: () => void } => {
    let cancel = (): void => {}
    const promise = new Promise<Verdict>((resolve, reject) => {
      if (dead !== undefined) return reject(new Error(dead))
      let timer: ReturnType<typeof setTimeout> | undefined
      const w: Waiter = v => {
        if (timer) clearTimeout(timer)
        if ('dead' in v) reject(new Error(v.dead))
        else resolve(v)
      }
      if (lateState !== undefined) {
        timer = setTimeout(() => {
          if (waiters.get(reqId) === w) waiters.delete(reqId)
          late.set(reqId, lateState)
          pruneLate()
          reject(new Error('decider timed out'))
        }, timeoutMs)
      }
      waiters.set(reqId, w)
      cancel = () => {
        if (timer) clearTimeout(timer)
        if (waiters.get(reqId) === w) waiters.delete(reqId)
      }
    })
    promise.catch(() => {})
    return { promise, cancel }
  }

  const pruneLate = (): void => {
    for (const k of late.keys()) {
      if (lastId - k >= ID_WINDOW) late.delete(k)
    }
  }

  const placements = opts.credentialPlacements ?? []
  const placeCredential = (
    cls: string,
    value: string,
    host: string,
  ): [string, string] => {
    const rule = placements.find(
      p =>
        (p.class === undefined || p.class === cls) &&
        (p.host === undefined || p.host === host),
    )
    if (rule?.scheme === 'basic') {
      return [
        'authorization',
        'Basic ' + Buffer.from(`${rule.user}:${value}`).toString('base64'),
      ]
    }
    return ['authorization', `Bearer ${value}`]
  }

  const toDecision = (v: Allow | Deny, host: string): RequestDecision => {
    if (v.action === 'deny') {
      return {
        action: 'deny',
        status: v.status,
        reason: v.reason,
        mark: 'decider',
      }
    }
    const setHeaders: Array<[string, string]> = []
    for (const [name, values] of Object.entries(v.setHeaders ?? {})) {
      for (const value of values) setHeaders.push([name, value])
    }
    const removeHeaders = [...(v.removeHeaders ?? [])]
    if (v.cred !== undefined && v.credential !== undefined) {
      removeHeaders.push(...CREDENTIAL_HEADERS)
      setHeaders.push(placeCredential(v.cred, v.credential, host))
    }
    return { action: 'allow', setHeaders, removeHeaders }
  }

  const filterRequest: FilterRequestCallback = async (request, info) => {
    if (dead !== undefined) {
      return {
        action: 'deny',
        status: 503,
        mark: 'decider_unavailable',
        reason: 'request decider unavailable',
      }
    }
    if (!gotHello) {
      return {
        action: 'deny',
        status: 503,
        mark: 'decider_unavailable',
        reason: 'request decider not ready',
      }
    }
    const req = reqFrameFields(request, info)
    if (typeof req === 'string') {
      return { action: 'deny', status: 400, reason: req, mark: 'bad_request' }
    }
    const reqId = lastId + 1
    if (reqId > MAX_ID) {
      die('request ids exhausted')
      return {
        action: 'deny',
        status: 503,
        mark: 'decider_unavailable',
        reason: 'request decider unavailable',
      }
    }
    lastId = reqId
    const host = String(req.host)
    let reserved = 0
    try {
      const first = awaitVerdict(reqId, 'verdict')
      send({ t: 'req', id: reqId, ...req })
      let v = await first.promise
      if (v.action === 'need_body') {
        // While the body is read the decider may end the request with a
        // deny; nothing else may come, and no timer runs here.
        if (!request.body && info?.unshownBody) {
          // A GET, HEAD or OPTIONS whose Request carries no body may still
          // have one on the wire. Showing the decider an empty body and
          // forwarding the real one on its allow would send upstream what
          // it never saw, so such a request is refused. The decider still
          // waits for a body; whatever it says next for this id is for a
          // request already refused, or (when the body turns out empty)
          // ends a request that can no longer be decided.
          late.set(reqId, 'verdict_shown')
          if (await info.unshownBody()) {
            return {
              action: 'deny',
              reason: BODYLESS_METHOD_BODY_REASON,
              mark: 'bodyless_method_body',
            }
          }
          if (!late.delete(reqId)) {
            throw new Error('the decider answered before it was sent the body')
          }
        }
        const length = Number(request.headers.get('content-length') ?? NaN)
        const want = !request.body
          ? 0
          : Number.isInteger(length) && length >= 0
            ? Math.min(length, v.max)
            : v.max
        if (held + want > maxHeld) {
          // The decider still waits for this body; whatever it says next
          // for this id is for a request already refused.
          late.set(reqId, 'verdict_shown')
          throw new Error('too many request bodies held for inspection')
        }
        held += reserved = want
        const whileReading = awaitVerdict(reqId, undefined)
        const body = await Promise.race([
          readUpTo(request, v.max),
          whileReading.promise.then(d => ({ verdict: d })),
        ])
        if ('verdict' in body) {
          if (body.verdict.action !== 'deny') {
            die('a verdict other than deny while the body was read')
            throw new Violation('decider broke the protocol')
          }
          return toDecision(body.verdict, host)
        }
        whileReading.cancel()
        const next = awaitVerdict(reqId, 'verdict_shown')
        sendFrame(encodeBodyFrame(reqId, body.data, body.cut))
        v = await next.promise
        if (v.action === 'need_body') {
          die('a second need_body')
          throw new Violation('decider broke the protocol')
        }
      }
      return toDecision(v, host)
    } catch (err) {
      return {
        action: 'deny',
        status: 503,
        mark: 'decider_unavailable',
        reason: `request decider: ${(err as Error).message}`,
      }
    } finally {
      held -= reserved
    }
  }

  return {
    hello,
    filterRequest,
    close: () => die('closed'),
    bodyBytesHeld: () => held,
  }
}

const BODYLESS_METHOD_BODY_REASON =
  'the decider asked to see the body of a request whose method normally has none, and it has one'

/** One frame: the 4-byte big-endian length, then the JSON object. */
export function encodeFrame(msg: Record<string, unknown>): Buffer {
  const body = Buffer.from(JSON.stringify(msg), 'utf8')
  const len = Buffer.alloc(4)
  len.writeUInt32BE(body.length)
  return Buffer.concat([len, body])
}

/**
 * The frame `encodeFrame({t:'body',id,data:<base64>,cut?})` gives, byte for
 * byte, built in place: the base64 goes into the frame a slice at a time, so
 * no base64 string, JSON string or second buffer of the whole body exists.
 */
export function encodeBodyFrame(
  id: number,
  data: Buffer,
  cut: boolean,
): Buffer {
  const head = Buffer.from(`{"t":"body","id":${id},"data":"`, 'latin1')
  const tail = Buffer.from(cut ? '","cut":true}' : '"}', 'latin1')
  const frame = Buffer.allocUnsafe(
    4 + head.length + Math.ceil(data.length / 3) * 4 + tail.length,
  )
  frame.writeUInt32BE(frame.length - 4)
  let at = 4 + head.copy(frame, 4)
  for (let i = 0; i < data.length; i += BASE64_SLICE) {
    at += frame.write(
      data.toString('base64', i, Math.min(i + BASE64_SLICE, data.length)),
      at,
      'latin1',
    )
  }
  tail.copy(frame, at)
  return frame
}

const utf8Bytes = (v: string): number => Buffer.byteLength(v, 'utf8')

/**
 * Whether headers (lower-case name -> values) are within the protocol's
 * caps, counted as the protocol counts them: values (a name with no
 * value counts as one) and UTF-8 bytes of each name once plus its values.
 */
function headersFit(headers: Record<string, string[]>): boolean {
  let entries = 0
  let bytes = 0
  for (const [name, values] of Object.entries(headers)) {
    entries += Math.max(1, values.length)
    bytes += utf8Bytes(name)
    for (const v of values) bytes += utf8Bytes(v)
    if (entries > MAX_HEADER_ENTRIES || bytes > MAX_HEADER_BYTES) return false
  }
  return true
}

const validHeaderValue = (v: string): boolean => !hasControl(v) && wellFormed(v)

/**
 * The req frame's fields (all but t and id), or why the request can't be
 * asked about: a req the protocol cannot carry (past its limits, or with a
 * value it refuses) would break the protocol, so the proxy answers such a
 * request 400 itself and sends nothing.
 */
export function reqFrameFields(
  request: Request,
  info: RequestInfo | undefined,
): Record<string, unknown> | string {
  const url = new URL(request.url)
  const host = info?.target?.host ?? url.hostname.replace(/^\[|\]$/g, '')
  const port =
    info?.target?.port ??
    Number(url.port || (url.protocol === 'https:' ? 443 : 80))
  const target = info?.requestTarget ?? url.pathname + url.search
  const q = target.indexOf('?')
  const path = q >= 0 ? target.slice(0, q) : target
  const query = q >= 0 ? target.slice(q + 1) : ''
  const raw = info?.rawHeaders ?? []
  const headers: Record<string, string[]> = {}
  let hostHeader: string | undefined
  let hostHeaders = 0
  for (let i = 0; i + 1 < raw.length; i += 2) {
    const name = raw[i]!.toLowerCase()
    const value = raw[i + 1]!
    if (!TOKEN.test(name) || !validHeaderValue(value)) {
      return 'request header the decider cannot be asked about'
    }
    if (name === 'host') {
      hostHeaders++
      hostHeader = value
      continue
    }
    ;(headers[name] ??= []).push(value)
  }
  if (hostHeaders > 1) return 'more than one Host header'
  if (!headersFit(headers)) return 'request headers too large'
  if (
    request.method === '' ||
    host === '' ||
    path === '' ||
    !(port >= 1 && port <= 65535)
  ) {
    return 'request the decider cannot be asked about'
  }
  for (const v of [host, hostHeader ?? '', info?.sni ?? '', path]) {
    if (utf8Bytes(v) > MAX_HOST_PATH) return 'request target too large'
  }
  for (const v of [
    request.method,
    host,
    hostHeader ?? '',
    info?.sni ?? '',
    path,
    query,
  ]) {
    if (!wellFormed(v)) return 'request the decider cannot be asked about'
  }
  const fields = {
    method: request.method,
    host,
    port,
    ...(hostHeader !== undefined ? { hostHeader } : {}),
    ...(info?.sni ? { sni: info.sni } : {}),
    path,
    ...(query !== '' ? { query } : {}),
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
  }
  // The whole frame, at the largest id, within what the decider reads.
  if (
    utf8Bytes(JSON.stringify({ t: 'req', id: MAX_ID, ...fields })) >
    MAX_READ_FRAME
  ) {
    return 'request too large for the decider'
  }
  return fields
}

/**
 * Whether s is an entry of the decider's egress lists: a lower-case DNS
 * name, the same after `*.` (with two labels or more), or an IP literal,
 * then an optional `:port` (after `[...]` for an IPv6 literal). No scheme,
 * path, user or space.
 */
export function isEgressEntry(s: string): boolean {
  if (isIP(s) !== 0) return true
  let host = s
  let port: string | undefined
  if (s.startsWith('[')) {
    const end = s.indexOf(']')
    if (end < 0) return false
    host = s.slice(1, end)
    const rest = s.slice(end + 1)
    if (rest !== '') {
      if (!rest.startsWith(':')) return false
      port = rest.slice(1)
    }
    return isIP(host) === 6 && (port === undefined || isPort(port))
  }
  const i = s.lastIndexOf(':')
  if (i >= 0) {
    host = s.slice(0, i)
    port = s.slice(i + 1)
    if (!isPort(port)) return false
  }
  if (isIP(host) !== 0) return isIP(host) === 4
  const wild = host.startsWith('*.')
  const base = wild ? host.slice(2) : host
  const labels = base.split('.')
  if (base === '' || base.length > 253 || (wild && labels.length < 2)) {
    return false
  }
  for (const l of labels) {
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l)) return false
  }
  // A name's last label starts with a letter, which keeps every spelling of
  // an IP address out of the names.
  return /^[a-z]/.test(labels[labels.length - 1]!)
}

function isPort(s: string): boolean {
  return /^[1-9][0-9]{0,4}$/.test(s) && Number(s) <= 65535
}

function verdictOf(parsed: unknown): Verdict | undefined {
  const action = (parsed as { action?: unknown } | null)?.action
  const schema =
    action === 'allow'
      ? allowSchema
      : action === 'deny'
        ? denySchema
        : action === 'need_body'
          ? needBodySchema
          : undefined
  const r = schema?.safeParse(parsed)
  return r?.success ? (r.data as Verdict) : undefined
}

/**
 * One JSON object from a frame, refusing what a lenient parser would let
 * through: invalid UTF-8, a lone surrogate, a duplicate key, anything but
 * one object, and a null anywhere.
 */
function parseStrictJson(frame: Buffer): unknown {
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(frame)
  } catch {
    throw new Error('frame is not UTF-8')
  }
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    throw new Error('frame is not valid JSON')
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('frame is not one JSON object')
  }
  const check = (v: unknown): void => {
    if (v === null) throw new Error('null in frame')
    if (typeof v === 'string' && !wellFormed(v)) {
      throw new Error('lone surrogate in frame')
    }
    if (typeof v === 'object') {
      for (const x of Object.values(v as object)) check(x)
    }
  }
  check(value)
  if (hasDuplicateKey(text)) throw new Error('duplicate key in frame')
  return value
}

/** Whether a (valid) JSON text has an object with the same key twice. */
function hasDuplicateKey(text: string): boolean {
  const stack: Array<Set<string> | null> = []
  let expectKey = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (c === '"') {
      let j = i + 1
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1
      if (expectKey) {
        const key = JSON.parse(text.slice(i, j + 1)) as string
        const keys = stack[stack.length - 1]!
        if (keys.has(key)) return true
        keys.add(key)
        expectKey = false
      }
      i = j
    } else if (c === '{') {
      stack.push(new Set())
      expectKey = true
    } else if (c === '[') {
      stack.push(null)
    } else if (c === '}' || c === ']') {
      stack.pop()
    } else if (c === ',') {
      expectKey = stack[stack.length - 1] instanceof Set
    }
  }
  return false
}

/** Up to `max` bytes of the request body, and whether there was more. */
async function readUpTo(
  request: Request,
  max: number,
): Promise<{ data: Buffer; cut: boolean }> {
  if (!request.body) return { data: Buffer.alloc(0), cut: false }
  const reader = request.body.getReader()
  const chunks: Buffer[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    // A view, not a copy: the chunk is this reader's own.
    const b = Buffer.from(value.buffer, value.byteOffset, value.byteLength)
    if (total + b.length > max) {
      chunks.push(b.subarray(0, max - total))
      total = max
      // Not awaited: the body is one branch of a tee, and a branch's cancel
      // settles only once the other branch (the one going upstream) is done
      // too, so awaiting it would hold a body past max until the request
      // ended.
      reader.cancel().catch(() => {})
      return { data: Buffer.concat(chunks), cut: true }
    }
    chunks.push(b)
    total += b.length
  }
  return { data: Buffer.concat(chunks), cut: false }
}
