import { describe, it, expect, afterEach } from 'bun:test'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

// Argument-level checks; nothing here executes bwrap.
describe.if(isLinux)('Linux sandbox — mount-plan record and ordering', () => {
  const baseParams = {
    command: 'true',
    needsNetworkRestriction: false,
    allowAllUnixSockets: true,
  }

  const created: string[] = []
  afterEach(() => {
    for (const dir of created.splice(0)) {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  /** Occurrences of one whole `<flag> <source> <dest>` argv triple. */
  function countBinds(
    command: string,
    flag: string,
    source: string,
    dest: string,
  ): number {
    const argv = command.split(/\s+/)
    let found = 0
    for (let i = 0; i + 2 < argv.length; i++) {
      if (argv[i] === flag && argv[i + 1] === source && argv[i + 2] === dest) {
        found++
      }
    }
    return found
  }

  function tempTree(files: Record<string, string>): string {
    const proj = realpathSync(mkdtempSync(join(tmpdir(), 'mount-plan-')))
    created.push(proj)
    for (const [rel, content] of Object.entries(files)) {
      mkdirSync(dirname(join(proj, rel)), { recursive: true })
      writeFileSync(join(proj, rel), content)
    }
    return proj
  }

  it('preserves a carve-out under a denyRead dir when the inner deny mounts later', async () => {
    const proj = tempTree({ 'data/build/logs/keep.txt': 'x' })
    const data = join(proj, 'data')
    const build = join(proj, 'data', 'build')
    const logs = join(proj, 'data', 'build', 'logs')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [data, logs], allowWithinDeny: [] },
      writeConfig: { allowOnly: [build], denyWithinAllow: [] },
    })
    // The restore is a second occurrence of the allowWrite bind, after the
    // outer tmpfs; the deeper tmpfs mounts after the restore and on top.
    const bind = `--bind ${build} ${build}`
    const restoreIdx = wrapped.lastIndexOf(bind)
    // Space-terminated: data is a string prefix of logs.
    expect(restoreIdx).toBeGreaterThan(wrapped.indexOf(`--tmpfs ${data} `))
    expect(wrapped.indexOf(`--tmpfs ${logs}`)).toBeGreaterThan(restoreIdx)
  })

  it('restores a write root under a denyRead directory in whichever order a symlink-spelled entry inside it is listed', async () => {
    const proj = tempTree({
      'a/t/w/secret-dir/s.txt': 'x',
      'a/t/w/deep/file.txt': 'x',
    })
    // s is spelled shallow but lands deep inside the write root w.
    const s = join(proj, 's')
    symlinkSync(join(proj, 'a/t/w/secret-dir'), s)
    const t = join(proj, 'a/t')
    const w = join(proj, 'a/t/w')
    const file = join(proj, 'a/t/w/deep/file.txt')
    const plan = (denyOnly: string[]) =>
      wrapCommandWithSandboxLinux({
        ...baseParams,
        readConfig: { denyOnly, allowWithinDeny: [] },
        writeConfig: { allowOnly: [w], denyWithinAllow: [file] },
      })
    const wrapped = await plan([s, t])
    expect(await plan([t, s])).toBe(wrapped)

    // t is hidden, w comes back writable on top of it, and the tmpfs on the
    // secret directory and the deny bind land on top of w.
    const wBind = `--bind ${w} ${w}`
    const tTmpfs = wrapped.indexOf(`--tmpfs ${t} `)
    expect(tTmpfs).toBeGreaterThan(-1)
    expect(wrapped.lastIndexOf(wBind)).toBeGreaterThan(tTmpfs)
    expect(wrapped.indexOf(`--tmpfs ${s} `)).toBeGreaterThan(
      wrapped.lastIndexOf(wBind),
    )
    expect(wrapped.indexOf(`--ro-bind ${file} ${file}`)).toBeGreaterThan(
      wrapped.lastIndexOf(wBind),
    )
    // The deny bind's parent is pinned beneath w's first bind.
    const deepPin = `--ro-bind ${join(w, 'deep')} ${join(w, 'deep')}`
    expect(wrapped.indexOf(deepPin)).toBeGreaterThan(-1)
    expect(wrapped.indexOf(deepPin)).toBeLessThan(wrapped.indexOf(wBind))
  })

  it('emits a deny bind whose region a later unit re-exposed', async () => {
    const proj = tempTree({ 'p/q/w/.git/config': 'x' })
    const W = join(proj, 'p/q/w')
    const cfg = join(proj, 'p/q/w/.git/config')
    // p/q hides W and restores it; s and W each mount a tmpfs at W and
    // restore it again, so W's host content is on top and the deny bind is
    // still needed.
    symlinkSync(W, join(proj, 's'))
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: {
        denyOnly: [join(proj, 's'), join(proj, 'p/q'), W],
        allowWithinDeny: [],
      },
      writeConfig: { allowOnly: [W], denyWithinAllow: [cfg] },
    })
    const wBind = `--bind ${W} ${W}`
    expect(wrapped.lastIndexOf(wBind)).toBeGreaterThan(
      wrapped.indexOf(`--tmpfs ${W}`),
    )
    expect(wrapped).toContain(`--ro-bind ${cfg} ${cfg}`)
    const gitPin = `--ro-bind ${join(proj, 'p/q/w/.git')} ${join(proj, 'p/q/w/.git')}`
    expect(wrapped).toContain(gitPin)
    // The pin sits beneath W's first (allow) bind and every tmpfs.
    expect(wrapped.indexOf(gitPin)).toBeLessThan(wrapped.indexOf(wBind))
    expect(wrapped.indexOf(gitPin)).toBeLessThan(
      wrapped.indexOf(`--tmpfs ${join(proj, 's')}`),
    )
  })

  it('resolves a symlink-spelled denyRead directory after the mandatory-deny scan, not before it', async () => {
    // link points at old/ when the wrap starts and at now/ once the scan (a
    // stand-in for ripgrep that retargets it) has run. bwrap mounts the tmpfs
    // where the link points at spawn time, so the write path beneath that
    // target is the one the tmpfs wipes and the one to restore.
    const proj = tempTree({ 'old/w/f': 'x', 'now/w/f': 'x' })
    const link = join(proj, 'link')
    symlinkSync(join(proj, 'old'), link)
    const retarget = join(proj, 'retarget.sh')
    writeFileSync(
      retarget,
      `#!/bin/sh\nln -sfn ${join(proj, 'now')} ${link}\nexit 1\n`,
      { mode: 0o755 },
    )
    const nowW = join(proj, 'now/w')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      ripgrepConfig: { command: retarget },
      readConfig: { denyOnly: [link], allowWithinDeny: [] },
      writeConfig: { allowOnly: [nowW], denyWithinAllow: [] },
    })
    const bind = `--bind ${nowW} ${nowW}`
    expect(wrapped.lastIndexOf(bind)).toBeGreaterThan(
      wrapped.indexOf(`--tmpfs ${link}`),
    )
  })

  it('keeps a symlink-spelled file mask when a denyWrite names its canonical location', async () => {
    const proj = tempTree({ 'data/secrets/key.pem': 'SECRET' })
    symlinkSync(join(proj, 'data/secrets'), join(proj, 'secrets'))
    const rawSpelling = join(proj, 'secrets', 'key.pem')
    const canonical = join(proj, 'data', 'secrets', 'key.pem')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [rawSpelling], allowWithinDeny: [] },
      writeConfig: { allowOnly: [proj], denyWithinAllow: [canonical] },
    })
    expect(wrapped).toContain(`--ro-bind /dev/null ${rawSpelling}`)
    expect(wrapped).not.toContain(`--ro-bind ${canonical} ${canonical}`)
  })

  it('emits a deny bind whose raw route is buried but whose canonical location is exposed', async () => {
    const proj = tempTree({ 'x/W/secret': 'SECRET', 'z/foo': 'host-content' })
    // The deny is spelled through link2, inside x, but its bind mounts at
    // the canonical dest under z, which no tmpfs covers.
    symlinkSync(join(proj, 'x/W/secret'), join(proj, 's'))
    symlinkSync(join(proj, 'z'), join(proj, 'x/W/link2'))
    const canonicalFoo = join(proj, 'z', 'foo')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: {
        denyOnly: [join(proj, 's'), join(proj, 'x')],
        allowWithinDeny: [],
      },
      writeConfig: {
        allowOnly: [proj, join(proj, 'x/W')],
        denyWithinAllow: [join(proj, 'x/W/link2/foo')],
      },
    })
    expect(wrapped).toContain(`--ro-bind /dev/null ${join(proj, 'x/W/secret')}`)
    expect(wrapped).toContain(`--ro-bind ${canonicalFoo} ${canonicalFoo}`)
  })

  it('pins the canonical parents of a symlink-spelled denyRead file mask beneath the mask, which is emitted once', async () => {
    const proj = tempTree({
      'data/secrets/key.pem': 'SECRET',
      'data/other/thing.txt': 'x',
    })
    symlinkSync(join(proj, 'data/secrets'), join(proj, 'secrets'))
    const rawSpelling = join(proj, 'secrets', 'key.pem')
    const canonicalParent = join(proj, 'data', 'secrets')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [rawSpelling], allowWithinDeny: [] },
      writeConfig: {
        allowOnly: [proj],
        denyWithinAllow: [join(proj, 'data/other/thing.txt')],
      },
    })
    const parentPin = `--ro-bind ${canonicalParent} ${canonicalParent}`
    const dataPin = `--ro-bind ${join(proj, 'data')} ${join(proj, 'data')}`
    expect(wrapped).toContain(parentPin)
    expect(wrapped).toContain(dataPin)
    const maskBind = `--ro-bind /dev/null ${rawSpelling}`
    const first = wrapped.indexOf(maskBind)
    expect(first).toBeGreaterThan(-1)
    // No pin lands over the mask, so it is never re-applied.
    expect(wrapped.lastIndexOf(maskBind)).toBe(first)
    expect(wrapped.indexOf(parentPin)).toBeLessThan(first)
    expect(wrapped.indexOf(dataPin)).toBeLessThan(
      wrapped.indexOf(`--bind ${proj} ${proj}`),
    )
  })

  it('restores an allowRead carve-out spelled through a symlink whose target lies inside the denied directory', async () => {
    // The merged-/usr shape: lib -> usr/lib, denyRead lib, allowRead lib/x.
    const proj = tempTree({ 'usr/lib/x/lib.so': 'so', 'usr/lib/y/other': 'o' })
    const lib = join(proj, 'lib')
    symlinkSync(join(proj, 'usr/lib'), lib)
    const carveOut = join(lib, 'x')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [lib], allowWithinDeny: [carveOut] },
      writeConfig: { allowOnly: [], denyWithinAllow: [] },
    })
    // Bound where it resolves: after the tmpfs, lib/x is a plain path on it.
    const resolved = join(proj, 'usr/lib/x')
    const restore = `--ro-bind ${resolved} ${resolved}`
    expect(wrapped.indexOf(restore)).toBeGreaterThan(
      wrapped.indexOf(`--tmpfs ${lib} `),
    )
  })

  it('spells a read-deny mount by where it lands once an earlier tmpfs has hidden its symlink target', async () => {
    // The merged-/usr root expansion: bin -> usr/bin, both denied. After the
    // tmpfs on usr, bin dangles in the new root and bwrap cannot mount on it.
    const proj = tempTree({ 'usr/bin/tool': 't', 'usr/share/doc': 'd' })
    const bin = join(proj, 'bin')
    symlinkSync('usr/bin', bin)
    const usr = join(proj, 'usr')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [bin, usr], allowWithinDeny: [] },
      writeConfig: { allowOnly: [], denyWithinAllow: [] },
    })
    const usrTmpfs = wrapped.indexOf(`--tmpfs ${usr} `)
    expect(usrTmpfs).toBeGreaterThan(-1)
    expect(wrapped.indexOf(`--tmpfs ${join(usr, 'bin')} `)).toBeGreaterThan(
      usrTmpfs,
    )
    expect(wrapped).not.toContain(`--tmpfs ${bin} `)
  })

  it('restores an allowRead carve-out under a denied directory reached through a symlinked parent', async () => {
    const proj = tempTree({
      'var/home/u/work/f': 'x',
      'var/home/u/secret': 's',
    })
    symlinkSync(join(proj, 'var/home'), join(proj, 'home'))
    const denied = join(proj, 'home/u')
    const carveOut = join(proj, 'home/u/work')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [denied], allowWithinDeny: [carveOut] },
      writeConfig: { allowOnly: [], denyWithinAllow: [] },
    })
    const restore = wrapped.match(/--ro-bind (\S+\/u\/work) \1/)
    expect(restore).not.toBeNull()
    expect(wrapped.indexOf(restore![0])).toBeGreaterThan(
      wrapped.indexOf('--tmpfs '),
    )
  })

  it('does not bind an allowRead symlink whose target lies outside the denied directory', async () => {
    const proj = tempTree({ 'd/keep': 'x', 'elsewhere/secret': 's' })
    const link = join(proj, 'd/link')
    symlinkSync(join(proj, 'elsewhere'), link)
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [join(proj, 'd')], allowWithinDeny: [link] },
      writeConfig: { allowOnly: [], denyWithinAllow: [] },
    })
    expect(wrapped).toContain(`--tmpfs ${join(proj, 'd')} `)
    expect(wrapped).not.toContain(`--ro-bind ${link} ${link}`)
  })

  it('does not restore an allowRead entry that is a symlink into a read-denied directory', async () => {
    // A command run earlier (or the repository) plants docs -> home/.ssh at
    // an allowed path: the entry names the link, not what it points at.
    const proj = tempTree({ 'home/.ssh/id_rsa': 'KEY', 'proj/src.ts': 'x' })
    const ssh = join(proj, 'home/.ssh')
    const docs = join(proj, 'proj/docs')
    symlinkSync(ssh, docs)
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [ssh], allowWithinDeny: [docs] },
      writeConfig: { allowOnly: [join(proj, 'proj')], denyWithinAllow: [] },
    })
    expect(wrapped).toContain(`--tmpfs ${ssh} `)
    expect(wrapped).not.toContain(`--ro-bind ${ssh} ${ssh}`)
    expect(wrapped).not.toContain(`--ro-bind ${docs} `)
  })

  it('does not restore a file inside a read-denied directory through a symlink planted outside it', async () => {
    const proj = tempTree({ 'home/.aws/credentials': 'SECRET', 'proj/a': 'x' })
    const aws = join(proj, 'home/.aws')
    const credentials = join(aws, 'credentials')
    const cfg = join(proj, 'proj/cfg.json')
    symlinkSync(credentials, cfg)
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [aws], allowWithinDeny: [cfg] },
      writeConfig: { allowOnly: [join(proj, 'proj')], denyWithinAllow: [] },
    })
    expect(wrapped).toContain(`--tmpfs ${aws} `)
    expect(wrapped).not.toContain(`--ro-bind ${credentials} ${credentials}`)
  })

  it('keeps a file mask when the allowRead entry is a symlink to the file, even one the deny list names too', async () => {
    // sub/.env.example -> ../.env, matched by an allowRead glob and by a
    // denyRead glob: the deny lands on .env (bwrap cannot bind onto a link),
    // and the allow names the link, so nothing lifts it.
    const proj = tempTree({ '.env': 'SECRET', 'sub/keep': 'x' })
    const env = join(proj, '.env')
    const planted = join(proj, 'sub/.env.example')
    symlinkSync('../.env', planted)
    const viaLink = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [planted], allowWithinDeny: [planted] },
      writeConfig: { allowOnly: [proj], denyWithinAllow: [] },
    })
    expect(viaLink).toContain(`--ro-bind /dev/null ${env}`)
    const direct = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [env], allowWithinDeny: [planted] },
      writeConfig: { allowOnly: [proj], denyWithinAllow: [] },
    })
    expect(direct).toContain(`--ro-bind /dev/null ${env}`)
  })

  it('still lifts a file mask for an allowRead entry naming that file through a symlinked directory', async () => {
    const proj = tempTree({ 'real/.env.example': 'ok' })
    symlinkSync(join(proj, 'real'), join(proj, 'link'))
    const file = join(proj, 'real/.env.example')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: {
        denyOnly: [file],
        allowWithinDeny: [join(proj, 'link/.env.example')],
      },
      writeConfig: { allowOnly: [proj], denyWithinAllow: [] },
    })
    expect(wrapped).not.toContain(`--ro-bind /dev/null ${file}`)
  })

  it('still hides a root child under a root deny when an allowRead entry is a symlink to it', async () => {
    const proj = tempTree({ 'proj/a': 'x' })
    const docs = join(proj, 'proj/docs')
    symlinkSync('/etc', docs)
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: ['/'], allowWithinDeny: [docs] },
      writeConfig: { allowOnly: [join(proj, 'proj')], denyWithinAllow: [] },
    })
    expect(wrapped).toContain('--tmpfs /etc ')
    expect(wrapped).not.toContain('--ro-bind /etc /etc')
  })

  it('keeps a deny bind under the target of a denyRead symlink that an earlier tmpfs already hid', async () => {
    // home/u/sec -> work/proj/secrets, but home/u is hidden first, so the
    // second tmpfs is created on the first and never reaches work/proj.
    const proj = tempTree({
      'work/proj/secrets/token': 'T',
      'work/proj/src.ts': 'x',
      'home/u/other': 'o',
    })
    symlinkSync(join(proj, 'work/proj/secrets'), join(proj, 'home/u/sec'))
    const token = join(proj, 'work/proj/secrets/token')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: {
        denyOnly: [join(proj, 'home/u'), join(proj, 'home/u/sec')],
        allowWithinDeny: [],
      },
      writeConfig: {
        allowOnly: [join(proj, 'work/proj')],
        denyWithinAllow: [token],
      },
    })
    expect(wrapped).toContain(`--ro-bind ${token} ${token}`)
  })

  it('keeps a deny bind on the target of a denyRead file symlink route that an earlier tmpfs already hid', async () => {
    const proj = tempTree({ 'data/key': 'K', 'home/u/x': 'x' })
    symlinkSync(join(proj, 'data'), join(proj, 'home/u/lnk'))
    const key = join(proj, 'data/key')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: {
        denyOnly: [join(proj, 'home/u'), join(proj, 'home/u/lnk/key')],
        allowWithinDeny: [],
      },
      writeConfig: { allowOnly: [join(proj, 'data')], denyWithinAllow: [key] },
    })
    expect(wrapped).toContain(`--ro-bind ${key} ${key}`)
  })

  it('seeds pins from a read-denied directory', async () => {
    const proj = tempTree({ 'other/secrets/key.pem': 'K', 'other/readme': 'r' })
    const secrets = join(proj, 'other/secrets')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [secrets], allowWithinDeny: [] },
      writeConfig: { allowOnly: [proj], denyWithinAllow: [] },
    })
    const pin = `--ro-bind ${join(proj, 'other')} ${join(proj, 'other')}`
    expect(wrapped.indexOf(pin)).toBeGreaterThan(-1)
    expect(wrapped.indexOf(pin)).toBeLessThan(
      wrapped.indexOf(`--bind ${proj} ${proj}`),
    )
    expect(wrapped).toContain(`--tmpfs ${secrets} `)
  })

  it('re-applies an allowRead carve-out that contains a deeper read-deny, then the deeper deny', async () => {
    const proj = tempTree({
      'cfg/private/pub/readme': 'r',
      'cfg/private/pub/sec/k': 'k',
    })
    const cfg = join(proj, 'cfg')
    const priv = join(proj, 'cfg/private')
    const pub = join(proj, 'cfg/private/pub')
    const sec = join(proj, 'cfg/private/pub/sec')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [priv, sec], allowWithinDeny: [pub] },
      writeConfig: { allowOnly: [proj], denyWithinAllow: [cfg] },
    })
    // cfg is pinned as well as denied; the deny bind is the later of the two.
    const afterDeny = wrapped.slice(
      wrapped.lastIndexOf(`--ro-bind ${cfg} ${cfg}`),
    )
    const privIdx = afterDeny.indexOf(`--tmpfs ${priv} `)
    const pubIdx = afterDeny.indexOf(`--ro-bind ${pub} ${pub}`)
    const secIdx = afterDeny.indexOf(`--tmpfs ${sec} `)
    expect(privIdx).toBeGreaterThan(-1)
    expect(pubIdx).toBeGreaterThan(privIdx)
    expect(secIdx).toBeGreaterThan(pubIdx)
  })

  it('denies beneath a writable root, and pins nothing under it', async () => {
    // '/' is a legal allowOnly entry, and the allow loop binds it writable,
    // so the denies inside it apply: a `root + '/'` prefix test spells '//'
    // and matches nothing, which silently dropped every deny and every
    // mandatory deny over a root already bound read-write.
    //
    // The pins are the one consumer that cannot follow. They are spliced in
    // beneath every other mount, and this root's own recursive --bind / / is
    // one of them, landing on top: a directory pinned under it is not a
    // mountpoint and renames as if unpinned. They are skipped instead of
    // emitted as arguments that promise an EBUSY that does not happen.
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      writeConfig: { allowOnly: ['/'], denyWithinAllow: [] },
    })
    const cwd = process.cwd()
    expect(wrapped).toContain('--bind / /')
    expect(wrapped).toContain(` ${join(cwd, '.bashrc')}`)
    expect(wrapped).not.toContain(`--ro-bind ${dirname(cwd)} ${dirname(cwd)}`)
    expect(wrapped).not.toContain(`--ro-bind ${cwd} ${cwd}`)
  })

  it('stubs no absent path after a read-only root when the root is both allowed and denied', async () => {
    // bwrap cannot create a stub's mount point on a read-only '/', so one
    // emitted here stops the sandbox from starting. Now that a '/' write
    // root contains the paths beneath it, the deny of '/' is emitted as a
    // second, read-only bind after the allow's writable one, and that is
    // what makes the whole tree uncreatable: the absent cwd dotfiles are
    // covered by it and need no stub of their own. The read-denied directory
    // is the exception the guard keeps — its tmpfs is writable inside.
    const proj = tempTree({ 'hidden/x': 'x' })
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [join(proj, 'hidden')], allowWithinDeny: [] },
      writeConfig: { allowOnly: ['/'], denyWithinAllow: ['/'] },
    })
    // Two: the base root mount, then the deny bind that holds it read-only.
    expect(countBinds(wrapped, '--ro-bind', '/', '/')).toBe(2)
    expect(wrapped).toContain(`--tmpfs ${join(proj, 'hidden')} `)
    expect(wrapped).not.toContain(`/dev/null ${join(process.cwd(), '.bashrc')}`)
    expect(wrapped).not.toContain(`--ro-bind ${process.cwd()} ${process.cwd()}`)
  })
})
