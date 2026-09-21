import { afterEach, beforeEach, describe, expect, it, spyOn } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  cleanupBwrapMountPoints,
  LinuxSandboxProfileError,
  linuxGetCwdMandatoryDenyPaths,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { withCapturedWarnings } from '../helpers/captured-warnings.js'
import { isLinux } from '../helpers/platform.js'

/**
 * A deny path is bound where it LANDS: bubblewrap resolves a destination, so
 * a git directory entry that is itself a link to the checkout
 * (`hooks -> ../..`) binds the checkout, however the entry is spelled. The
 * guard that keeps a whole-directory deny off the work tree has to judge every
 * deny path that way, and not only the ones a producer spelled by landing:
 * otherwise the landing is dropped and the entry's own path puts the same bind
 * back.
 */
describe.if(isLinux)('a git entry that is a link to the work tree', () => {
  const LIVE = bwrapCanNamespace()
  let dir: string
  const savedCwd = process.cwd()

  beforeEach(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'work-tree-guard-')))
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(dir, { recursive: true, force: true })
  })

  /** A checkout whose `.git` git would accept. */
  function makeCheckout(name: string): string {
    const checkout = join(dir, name)
    mkdirSync(join(checkout, '.git', 'hooks'), { recursive: true })
    mkdirSync(join(checkout, 'src'))
    writeFileSync(join(checkout, '.git', 'HEAD'), 'ref: refs/heads/main')
    writeFileSync(join(checkout, '.git', 'config'), '[core]\n')
    writeFileSync(join(checkout, 'src', 'file.c'), 'int x;\n')
    return checkout
  }

  /** What a few ordinary writes leave: a nested git directory, found by the
   *  scan, whose `hooks` is a link to `target`. */
  function plantNestedRepository(checkout: string, target: string): string {
    const nestedGitDir = join(checkout, 'nested', '.git')
    mkdirSync(nestedGitDir, { recursive: true })
    writeFileSync(join(nestedGitDir, 'HEAD'), 'ref: refs/heads/main\n')
    symlinkSync(target, join(nestedGitDir, 'hooks'))
    return nestedGitDir
  }

  function wrapIn(
    checkout: string,
    command = 'true',
    allowOnly: string[] = [checkout],
  ): Promise<string> {
    process.chdir(checkout)
    return wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      readConfig: undefined,
      writeConfig: { allowOnly, denyWithinAllow: [] },
    })
  }

  /** Every `--ro-bind X X` of the wrapped command, by what it binds. */
  function readOnlyBinds(command: string): string[] {
    return [...command.matchAll(/--ro-bind (\S+) (\S+)/g)]
      .filter(([, source, dest]) => source === dest)
      .map(([, source]) => source!)
  }

  function landing(denyPath: string): string {
    try {
      return realpathSync(denyPath)
    } catch {
      return denyPath
    }
  }

  it('does not deny the checkout for its own hooks linked at it', () => {
    const checkout = makeCheckout('repo')
    rmSync(join(checkout, '.git', 'hooks'), { recursive: true })
    symlinkSync('..', join(checkout, '.git', 'hooks'))

    process.chdir(checkout)
    const denyPaths = linuxGetCwdMandatoryDenyPaths(false, [checkout])

    expect(denyPaths.map(landing)).not.toContain(checkout)
    // The link is held by the directory around it, which is what holds any
    // symlinked entry.
    expect(denyPaths).toContain(join(checkout, '.git'))
  })

  it('does not bind the checkout for a nested entry linked at it', async () => {
    const checkout = makeCheckout('repo')
    const nestedGitDir = plantNestedRepository(checkout, '../..')

    const { result: command, warnings } = await withCapturedWarnings(() =>
      wrapIn(checkout),
    )

    const binds = readOnlyBinds(command)
    expect(binds).not.toContain(checkout)
    expect(binds).toContain(nestedGitDir)
    expect(binds).toContain(join(checkout, '.git', 'hooks'))
    // Said once, since no bind is there to say it.
    expect(
      warnings.filter(w => w.includes('would have been denied whole')),
    ).toHaveLength(1)
  })

  it('does not bind a second write root an entry is linked at', async () => {
    const checkout = makeCheckout('repo')
    const other = join(dir, 'other-root')
    mkdirSync(other)
    writeFileSync(join(other, 'existing.txt'), 'kept\n')
    const nestedGitDir = plantNestedRepository(checkout, other)

    const binds = readOnlyBinds(
      await wrapIn(checkout, 'true', [checkout, other]),
    )

    expect(binds).not.toContain(other)
    expect(binds).toContain(nestedGitDir)
  })

  it('does not bind a directory that holds the checkout', async () => {
    const checkout = makeCheckout('repo')
    // `dir` holds the checkout and is not itself writable here.
    plantNestedRepository(checkout, dir)

    const binds = readOnlyBinds(await wrapIn(checkout))

    expect(binds).not.toContain(dir)
    expect(binds).not.toContain(checkout)
  })

  it('still binds an ordinary directory an entry is linked at', async () => {
    const checkout = makeCheckout('repo')
    mkdirSync(join(checkout, 'shared-hooks'))
    plantNestedRepository(checkout, '../../shared-hooks')

    const binds = readOnlyBinds(await wrapIn(checkout))

    expect(binds).toContain(join(checkout, 'shared-hooks'))
    expect(binds).not.toContain(checkout)
  })

  it('does not bind the checkout where a collapse folds a linked modules entry', async () => {
    // Past the argument cap a submodule's git directory is bound whole, as
    // the walk spelled it. One the walk reached through `modules/zz -> ../..`
    // is the checkout, which has an entry named `hooks` and so passes for a
    // git directory. The collapse adds its bind after the plan was guarded,
    // so what it adds is guarded again.
    const checkout = makeCheckout('repo')
    const gitDir = join(checkout, '.git')
    for (let i = 0; i < 3000; i++) {
      const submodule = join(
        gitDir,
        'modules',
        `s${String(i).padStart(5, '0')}`,
      )
      mkdirSync(join(submodule, 'hooks'), { recursive: true })
      writeFileSync(join(submodule, 'HEAD'), 'ref: refs/heads/main')
    }
    symlinkSync('nowhere', join(checkout, 'hooks'))
    symlinkSync('../..', join(gitDir, 'modules', 'zz-linked'))

    const binds = readOnlyBinds(await wrapIn(checkout))

    // The submodules are behind one bind, of `modules` or of what holds it.
    expect(
      binds.includes(join(gitDir, 'modules')) || binds.includes(gitDir),
    ).toBe(true)
    expect(binds).not.toContain(checkout)
  }, 120000)

  it('says which link a directory is bound read-only to hold', async () => {
    // A link chain through `src` makes `src` the only handle on the link in
    // it, so `src` is bound read-only: a directory nothing asked to deny. The
    // debug log is where that can be traced back to the link.
    const checkout = makeCheckout('repo')
    mkdirSync(join(checkout, 'tgt'))
    symlinkSync('../tgt', join(checkout, 'src', 'a'))
    plantNestedRepository(checkout, '../../src/a')

    const lines: string[] = []
    const savedDebug = process.env.SRT_DEBUG
    process.env.SRT_DEBUG = '1'
    const spies = [
      spyOn(console, 'error').mockImplementation((...parts: unknown[]) => {
        lines.push(parts.map(String).join(' '))
      }),
      spyOn(console, 'warn').mockImplementation(() => {}),
    ]
    let command: string
    try {
      command = await wrapIn(checkout)
    } finally {
      for (const spy of spies) spy.mockRestore()
      if (savedDebug === undefined) delete process.env.SRT_DEBUG
      else process.env.SRT_DEBUG = savedDebug
    }

    expect(readOnlyBinds(command)).toContain(join(checkout, 'src'))
    const told = lines.filter(l => l.includes('Bound read-only to hold a link'))
    expect(told).toHaveLength(1)
    expect(told[0]).toContain(
      `${join(checkout, 'src')} holds ${join(checkout, 'src', 'a')}`,
    )
    expect(told[0]).toContain(join(checkout, 'nested', '.git', 'hooks'))
  })

  it.if(LIVE)(
    'leaves the project writable for the command after the one that made the link',
    async () => {
      const checkout = makeCheckout('repo')
      const run = (command: string) =>
        spawnSync(command, { shell: true, encoding: 'utf8', timeout: 20000 })

      const planted = run(
        await wrapIn(
          checkout,
          "mkdir -p nested/.git && printf 'ref: refs/heads/main\\n' > nested/.git/HEAD && ln -s ../.. nested/.git/hooks && echo PLANTED",
        ),
      )
      expect(planted.stdout).toContain('PLANTED')
      expect(planted.status).toBe(0)
      cleanupBwrapMountPoints({ force: true })

      const next = run(
        await wrapIn(
          checkout,
          'echo BOOTED; echo w > work.txt && echo edit >> src/file.c && echo WROTE; rm -f nested/.git/hooks; echo "rm=$?"',
        ),
      )

      expect(next.stdout).toContain('BOOTED')
      expect(next.stdout).toContain('WROTE')
      expect(readFileSync(join(checkout, 'work.txt'), 'utf8')).toBe('w\n')
      expect(readFileSync(join(checkout, 'src', 'file.c'), 'utf8')).toBe(
        'int x;\nedit\n',
      )
      // The link itself is still held, by the git directory around it.
      expect(next.stdout).toContain('rm=1')
      expect(
        lstatSync(join(checkout, 'nested', '.git', 'hooks')).isSymbolicLink(),
      ).toBe(true)
      expect(existsSync(join(checkout, 'nested', '.git', 'HEAD'))).toBe(true)
    },
    60000,
  )
})

/**
 * A git directory entry whose link chain reaches nothing (a loop) and goes
 * through a link the working directory holds has no bind that holds it and no
 * far end to deny. For an entry of the working directory's own repository that
 * is the user's layout, and the command is refused. For anything a command may
 * have made - a nested repository, a `modules` that was not there - refusing
 * would let a few ordinary writes lock every later command out, so the wrap
 * warns and runs.
 */
describe.if(isLinux)('a git entry whose link chain is a loop', () => {
  const LIVE = bwrapCanNamespace()
  let dir: string
  const savedCwd = process.cwd()

  beforeEach(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'loop-guard-')))
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(dir, { recursive: true, force: true })
  })

  function makeCheckout(name: string): string {
    const checkout = join(dir, name)
    mkdirSync(join(checkout, '.git', 'hooks'), { recursive: true })
    writeFileSync(join(checkout, '.git', 'HEAD'), 'ref: refs/heads/main')
    writeFileSync(join(checkout, '.git', 'config'), '[core]\n')
    return checkout
  }

  /** `a -> b -> a` in the checkout's root. */
  function makeLoop(checkout: string): void {
    symlinkSync('b', join(checkout, 'a'))
    symlinkSync('a', join(checkout, 'b'))
  }

  function wrapIn(checkout: string, command = 'true'): Promise<string> {
    process.chdir(checkout)
    return wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      readConfig: undefined,
      writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
    })
  }

  function readOnlyBinds(command: string): string[] {
    return [...command.matchAll(/--ro-bind (\S+) (\S+)/g)]
      .filter(([, source, dest]) => source === dest)
      .map(([, source]) => source!)
  }

  it('refuses for an entry of the working directory own repository', async () => {
    const checkout = makeCheckout('repo')
    makeLoop(checkout)
    rmSync(join(checkout, '.git', 'hooks'), { recursive: true })
    symlinkSync('../a', join(checkout, '.git', 'hooks'))

    const refusal = await wrapIn(checkout).then(
      () => undefined,
      (error: unknown) => error,
    )

    expect(refusal).toBeInstanceOf(LinuxSandboxProfileError)
    expect((refusal as LinuxSandboxProfileError).code).toBe(
      'deny_unresolvable_git_entry',
    )
  })

  it('warns and wraps for a nested repository', async () => {
    const checkout = makeCheckout('repo')
    makeLoop(checkout)
    const nestedGitDir = join(checkout, 'nested', '.git')
    mkdirSync(nestedGitDir, { recursive: true })
    writeFileSync(join(nestedGitDir, 'HEAD'), 'ref: refs/heads/main\n')
    symlinkSync('../../a', join(nestedGitDir, 'hooks'))

    const { result: command, warnings } = await withCapturedWarnings(() =>
      wrapIn(checkout),
    )

    // The link itself is held by the git directory around it.
    expect(readOnlyBinds(command)).toContain(nestedGitDir)
    expect(readOnlyBinds(command)).not.toContain(checkout)
    expect(
      warnings.filter(
        w =>
          w.includes(join(nestedGitDir, 'hooks')) &&
          w.includes(join(checkout, 'a')),
      ).length,
    ).toBeGreaterThan(0)
  })

  it('warns and wraps for a modules that was not there', async () => {
    const checkout = makeCheckout('repo')
    makeLoop(checkout)
    symlinkSync('../a', join(checkout, '.git', 'modules'))

    const { result: command, warnings } = await withCapturedWarnings(() =>
      wrapIn(checkout),
    )

    expect(readOnlyBinds(command)).toContain(join(checkout, '.git'))
    expect(readOnlyBinds(command)).not.toContain(checkout)
    expect(
      warnings.filter(w => w.includes(join(checkout, '.git', 'modules')))
        .length,
    ).toBeGreaterThan(0)
  })

  it.if(LIVE)(
    'runs the command after one that left a loop behind a nested repository',
    async () => {
      const checkout = makeCheckout('repo')
      const run = (command: string) =>
        spawnSync(command, { shell: true, encoding: 'utf8', timeout: 20000 })

      const planted = run(
        await wrapIn(
          checkout,
          "ln -s b a && ln -s a b && mkdir -p nested/.git && printf 'ref: refs/heads/main\\n' > nested/.git/HEAD && ln -s ../../a nested/.git/hooks && echo PLANTED",
        ),
      )
      expect(planted.stdout).toContain('PLANTED')
      cleanupBwrapMountPoints({ force: true })

      const next = run(
        await wrapIn(checkout, 'echo BOOTED; echo w > work.txt && echo WROTE'),
      )

      expect(next.stdout).toContain('BOOTED')
      expect(next.stdout).toContain('WROTE')
      expect(readFileSync(join(checkout, 'work.txt'), 'utf8')).toBe('w\n')
    },
    60000,
  )
})
