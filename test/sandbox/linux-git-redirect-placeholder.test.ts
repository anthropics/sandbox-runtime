import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as fs from 'fs'
import { spawn, spawnSync } from 'node:child_process'
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import {
  indexOfMount,
  lastIndexOfMount,
  lastMountAt,
} from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import {
  type Process,
  processAt,
  refusal,
  sleep,
  waitFor,
  writeManifest,
  writeScript,
} from '../helpers/mount-point-fixtures.js'
import { isLinux } from '../helpers/platform.js'
import { usePrivateManifestDirectory } from '../helpers/private-manifest-directory.js'

/**
 * Denying a path that is not there means mounting something at it, and two of
 * these the host's git reads back: it refuses to run at all against a
 * `commondir` it cannot read, and neither a bound /dev/null nor an empty file
 * is one. So the wrap makes these mount points itself, holding what git
 * concludes with no file there, and binds each read-only onto itself.
 *
 * It makes them on the host, in a git directory a command already running may
 * be writing: one that made the directory after its own wrap has nothing of it
 * mounted. So nothing that is there is ever written over, and nothing is made
 * anywhere but in the directory the plan looked at.
 */
describe.if(isLinux)('The mount point of a file git reads back', () => {
  const VICTIM = 'a file outside every write root\n'
  /** Echoed by a command that runs for real, so nothing concludes anything
   *  from a sandbox that never started. */
  const BOOTED = 'BOOTED'
  const LIBRARY = join(import.meta.dir, '../helpers/isolated/library.ts')
  /** One that outlives every test here. */
  const initProcess = (): Process => processAt(1)
  const runtime = usePrivateManifestDirectory()
  let dir: string
  const savedCwd = process.cwd()

  beforeEach(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'git-redirect-')))
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(dir, { recursive: true, force: true })
  })

  /** A checkout whose `.git` git would accept, wrapped with it as the cwd. */
  function makeCheckout(name: string): string {
    const checkout = join(dir, name)
    mkdirSync(join(checkout, '.git', 'hooks'), { recursive: true })
    writeFileSync(join(checkout, '.git', 'HEAD'), 'ref: refs/heads/main')
    writeFileSync(join(checkout, '.git', 'config'), '[core]\n')
    return checkout
  }

  function wrapIn(
    checkout: string,
    command = 'true',
    denyWithinAllow: string[] = [],
    denyRead: string[] = [],
  ): Promise<string> {
    process.chdir(checkout)
    return wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      readConfig: { denyOnly: denyRead },
      writeConfig: { allowOnly: [checkout], denyWithinAllow },
    })
  }

  /** Whether `gitDir` is bound read-only above the bind that makes `checkout`
   *  writable. A pin spells the same words beneath that one. */
  function isDeniedWhole(
    command: string,
    checkout: string,
    gitDir: string,
  ): boolean {
    const madeWritable = indexOfMount(command, '--bind', checkout, checkout)
    expect(madeWritable).toBeGreaterThan(-1)
    return lastIndexOfMount(command, '--ro-bind', gitDir, gitDir) > madeWritable
  }

  /**
   * Wraps in `checkout`, and runs `swap` once: as the wrapper is about to open
   * `gitDir` to make a `commondir` in it, or about to make the file. Those are
   * the last moments a command writing the directory has to change what the
   * plan saw. Returns the command, and where each `commondir` made really was:
   * one made in the wrong place may be gone again by the end of the wrap.
   */
  async function wrapSwappingBefore(
    call: 'openSync' | 'writeFileSync',
    checkout: string,
    gitDir: string,
    swap: () => void,
  ): Promise<{ command: string; made: string[] }> {
    type Fn = (...args: unknown[]) => unknown
    const [open, write] = [fs.openSync as Fn, fs.writeFileSync as Fn]
    const made: string[] = []
    let swapped = false
    const swapOnce = (): void => {
      if (!swapped) swap()
      swapped = true
    }
    const spies = [
      spyOn(fs, 'openSync').mockImplementation(((...args: unknown[]) => {
        // Nothing is made before a manifest names it, so an open of the
        // directory before one is published is for something else.
        const isPublished = readdirSync(runtime.manifestDir()).some(name =>
          name.endsWith('.json'),
        )
        if (call === 'openSync' && args[0] === gitDir && isPublished) swapOnce()
        return open(...args)
      }) as never),
      spyOn(fs, 'writeFileSync').mockImplementation(((...args: unknown[]) => {
        const makesCommondir =
          String(args[0]).endsWith('/commondir') &&
          (args[2] as { flag?: string } | undefined)?.flag === 'wx'
        if (call === 'writeFileSync' && makesCommondir) swapOnce()
        write(...args)
        if (makesCommondir) made.push(realpathSync(String(args[0])))
      }) as never),
    ]
    try {
      return { command: await wrapIn(checkout), made }
    } finally {
      for (const spy of spies) spy.mockRestore()
      expect(swapped).toBe(true)
    }
  }

  /**
   * What each file of the git directory holds before the wrap, what the host
   * finds there while the command runs, and whether the clean-up takes it away.
   * `named` by the manifest a killed wrap left, which alone makes it a mount
   * point: anything else that is there is somebody's file.
   */
  it.each<{
    name: string
    file: 'commondir' | 'config.worktree'
    before?: { contents: string; mode: number; named?: true }
    during?: { contents: string; mode: number }
  }>([
    {
      name: 'an absent commondir',
      file: 'commondir',
      during: { contents: '.\n', mode: 0o444 },
    },
    {
      name: 'an absent config.worktree',
      file: 'config.worktree',
      during: { contents: '', mode: 0o444 },
    },
    {
      name: 'the commondir a killed wrap left',
      file: 'commondir',
      before: { contents: '.\n', mode: 0o444, named: true },
    },
    {
      name: 'the config.worktree a killed wrap left',
      file: 'config.worktree',
      before: { contents: '', mode: 0o444, named: true },
    },
    {
      name: 'a commondir naming a directory',
      file: 'commondir',
      before: { contents: '../..\n', mode: 0o644 },
    },
    {
      name: 'a commondir as long as what is written, holding something else',
      file: 'commondir',
      before: { contents: '..', mode: 0o444 },
    },
    {
      name: 'a commondir holding what is written, that no manifest names',
      file: 'commondir',
      before: { contents: '.\n', mode: 0o444 },
    },
    {
      name: 'an empty commondir that no manifest names, a host git mid-write',
      file: 'commondir',
      before: { contents: '', mode: 0o644 },
    },
    {
      name: 'a config.worktree with settings in it',
      file: 'config.worktree',
      before: { contents: '[core]\n', mode: 0o644 },
    },
    {
      name: 'an empty read-only config.worktree that no manifest names',
      file: 'config.worktree',
      before: { contents: '', mode: 0o444 },
    },
  ])('binds $name from itself', async ({ file, before, during = before }) => {
    const checkout = makeCheckout('repo')
    const dest = join(checkout, '.git', file)
    if (before !== undefined) {
      writeFileSync(dest, before.contents)
      chmodSync(dest, before.mode)
    }
    if (before?.named) writeManifest(runtime.manifestDir(), [dest])

    const command = await wrapIn(checkout)

    expect(lastMountAt(command, dest)).toBe(`--ro-bind ${dest} ${dest}`)
    expect(readFileSync(dest, 'utf8')).toBe(during!.contents)
    expect(statSync(dest).mode & 0o777).toBe(during!.mode)

    cleanupBwrapMountPoints({ force: true })
    const isSomebodys = before !== undefined && !before.named
    expect(existsSync(dest)).toBe(isSomebodys)
    if (isSomebodys) expect(readFileSync(dest, 'utf8')).toBe(before.contents)
  })

  // What bubblewrap's own ensure_file() makes where the file has gone from under
  // a command that then starts. It is no use to git, and is never written over.
  it('makes anew the empty commondir a killed wrap left', async () => {
    // It goes as any mount point does once no running process's manifest names
    // it, which is when the plan that found it lets go of its own.
    const checkout = makeCheckout('repo')
    const commondir = join(checkout, '.git', 'commondir')
    writeFileSync(commondir, '', { mode: 0o444 })
    writeManifest(runtime.manifestDir(), [commondir])

    const command = await wrapIn(checkout)

    expect(lastMountAt(command, commondir)).toBe(
      `--ro-bind ${commondir} ${commondir}`,
    )
    expect(readFileSync(commondir, 'utf8')).toBe('.\n')
    cleanupBwrapMountPoints({ force: true })
    expect(existsSync(commondir)).toBe(false)
  })

  it('denies the git directory whole where the empty commondir stays', async () => {
    const checkout = makeCheckout('repo')
    const gitDir = join(checkout, '.git')
    const commondir = join(gitDir, 'commondir')
    writeFileSync(commondir, '', { mode: 0o444 })
    writeManifest(runtime.manifestDir(), [commondir], initProcess())

    const command = await wrapIn(checkout)

    expect(isDeniedWhole(command, checkout, gitDir)).toBe(true)
    expect(lastMountAt(command, commondir)).toBeUndefined()
    cleanupBwrapMountPoints({ force: true })
    expect(readFileSync(commondir, 'utf8')).toBe('')
    expect(existsSync(join(gitDir, 'config.worktree'))).toBe(false)
  })

  it('takes a commondir another wrap is about to write for no leftover', async () => {
    // Made and written are two steps. Found between them, it is empty.
    const checkout = makeCheckout('repo')
    const gitDir = join(checkout, '.git')
    const commondir = join(gitDir, 'commondir')
    let manifest: string | undefined

    const { command } = await wrapSwappingBefore(
      'writeFileSync',
      checkout,
      gitDir,
      () => {
        manifest = writeManifest(
          runtime.manifestDir(),
          [commondir],
          initProcess(),
        )
        writeFileSync(commondir, '', { mode: 0o444 })
        // By the time this wrap has planned again the other has written it.
        setImmediate(() => {
          chmodSync(commondir, 0o644)
          writeFileSync(commondir, '.\n')
          chmodSync(commondir, 0o444)
        })
      },
    )

    expect(manifest).toBeDefined()
    expect(isDeniedWhole(command, checkout, gitDir)).toBe(false)
    expect(lastMountAt(command, commondir)).toBe(
      `--ro-bind ${commondir} ${commondir}`,
    )
  })

  it('goes by the file, not by the spelling of the deny entry', async () => {
    // A caller's own deny for the same file comes first and wins the dedup. Its
    // spelling does not name the file, and /dev/null there would cost the
    // repository every git command for as long as the command runs.
    const checkout = makeCheckout('repo')
    const commondir = join(checkout, '.git', 'commondir')

    const command = await wrapIn(checkout, 'true', ['./.git/commondir/'])

    expect(lastMountAt(command, commondir)).toBe(
      `--ro-bind ${commondir} ${commondir}`,
    )
    expect(readFileSync(commondir, 'utf8')).toBe('.\n')
  })

  it('leaves every other absent deny on /dev/null', async () => {
    const checkout = makeCheckout('repo')
    const bashrc = join(checkout, '.bashrc')

    expect(lastMountAt(await wrapIn(checkout), bashrc)).toBe(
      `--ro-bind /dev/null ${bashrc}`,
    )
  })

  it('makes none where the deny takes no bind', async () => {
    // A git directory denied for reading is hidden whole, and what is written
    // in there never reaches the host.
    const checkout = makeCheckout('repo')
    const gitDir = join(checkout, '.git')

    const command = await wrapIn(checkout, 'true', [], [gitDir])

    expect(lastMountAt(command, gitDir)).toBe(`--tmpfs ${gitDir}`)
    expect(readdirSync(gitDir).sort()).toEqual(['HEAD', 'config', 'hooks'])
  })

  it('leaves no mount point behind when the wrap itself throws', async () => {
    // The caller does not clean up after a wrap that threw.
    const checkout = makeCheckout('repo')

    expect(
      await refusal(
        wrapIn(
          checkout,
          'true',
          Array.from({ length: 4000 }, (_unused, n) =>
            join(checkout, `deny-${n}`),
          ),
        ),
      ),
    ).toBe('too_many_arguments')

    expect(existsSync(join(checkout, '.git', 'commondir'))).toBe(false)
  })

  it('does not remove a mount point that became something else', async () => {
    // One was written to, as many bytes as it held. The others were swapped for
    // links to files that hold what the mount points did: a check that looks
    // through a link would pass them, and the unlink does not look through it.
    const written = join(makeCheckout('written'), '.git', 'commondir')
    const linked = makeCheckout('linked')
    const links = { commondir: '.\n', 'config.worktree': '' }
    await wrapIn(join(dir, 'written'))
    await wrapIn(linked)

    chmodSync(written, 0o644)
    writeFileSync(written, '..')
    for (const [name, contents] of Object.entries(links)) {
      expect(readFileSync(join(linked, '.git', name), 'utf8')).toBe(contents)
      writeFileSync(join(dir, name), contents)
      rmSync(join(linked, '.git', name))
      symlinkSync(join(dir, name), join(linked, '.git', name))
    }
    cleanupBwrapMountPoints({ force: true })

    expect(readFileSync(written, 'utf8')).toBe('..')
    for (const name of Object.keys(links)) {
      expect(lstatSync(join(linked, '.git', name)).isSymbolicLink()).toBe(true)
      expect(existsSync(join(dir, name))).toBe(true)
    }
  })

  it.each<{
    what: string
    plant: (victim: string, name: string) => void
    isStillThere: (name: string) => boolean
    deniedWhole: boolean
  }>([
    {
      what: 'a link to a file outside every write root',
      plant: symlinkSync,
      isStillThere: name => lstatSync(name).isSymbolicLink(),
      deniedWhole: true,
    },
    {
      what: 'a hard link to one',
      plant: linkSync,
      isStillThere: name => lstatSync(name).nlink === 2,
      deniedWhole: false,
    },
    {
      what: 'a FIFO',
      plant: (_victim, name) =>
        expect(spawnSync('mkfifo', [name]).status).toBe(0),
      isStillThere: name => lstatSync(name).isFIFO(),
      deniedWhole: false,
    },
  ])(
    'writes to nothing where the name is taken by $what as it is made',
    async ({ plant, isStillThere, deniedWhole }) => {
      const checkout = makeCheckout('repo')
      const gitDir = join(checkout, '.git')
      const commondir = join(gitDir, 'commondir')
      const victim = join(dir, 'victim')
      writeFileSync(victim, VICTIM)

      const { command, made } = await wrapSwappingBefore(
        'writeFileSync',
        checkout,
        gitDir,
        () => plant(victim, commondir),
      )

      expect(made).toEqual([])
      // It plans again, and denies what it finds: somebody's file from itself,
      // and the whole directory where the entry is a link.
      expect(isDeniedWhole(command, checkout, gitDir)).toBe(deniedWhole)
      expect(lastMountAt(command, commondir)).toBe(
        deniedWhole ? undefined : `--ro-bind ${commondir} ${commondir}`,
      )
      cleanupBwrapMountPoints({ force: true })
      expect(isStillThere(commondir)).toBe(true)
      expect(readFileSync(victim, 'utf8')).toBe(VICTIM)
      expect(statSync(victim).mode & 0o777).toBe(0o644)
    },
  )

  describe.each(['x/.git', 'x'])('where %s becomes a link', swapped => {
    // The plan resolved the path, and the name of the file alone would be
    // followed wherever the path leads by now.
    it.each(['openSync', 'writeFileSync'] as const)(
      'makes nothing elsewhere (ahead of its %s)',
      async call => {
        const project = join(dir, 'project')
        mkdirSync(project)
        const gitDir = join(makeCheckout('project/x'), '.git')
        const elsewhere = join(dir, 'elsewhere')
        mkdirSync(join(elsewhere, 'x', '.git'), { recursive: true })

        const { made } = await wrapSwappingBefore(call, project, gitDir, () => {
          renameSync(join(project, swapped), join(dir, 'aside'))
          symlinkSync(join(elsewhere, swapped), join(project, swapped))
        })

        // In the directory it opened, wherever that has been moved to.
        expect(made).toEqual(
          call === 'openSync'
            ? []
            : [join(dir, 'aside', swapped === 'x' ? '.git' : '', 'commondir')],
        )
        expect(readdirSync(join(elsewhere, 'x', '.git'))).toEqual([])
        cleanupBwrapMountPoints({ force: true })
        expect(lstatSync(join(project, swapped)).isSymbolicLink()).toBe(true)
      },
    )
  })

  it('does not wait on a FIFO that is there', () => {
    // Opening one to read waits for a writer, and none comes. In a process of
    // its own, which can be given up on.
    const checkout = makeCheckout('repo')
    const commondir = join(checkout, '.git', 'commondir')
    expect(spawnSync('mkfifo', [commondir]).status).toBe(0)

    const wrapped = spawnSync(
      process.execPath,
      [
        writeScript(dir, 'wrap.ts', [
          `import { wrapCommandWithSandboxLinux } from ${JSON.stringify(LIBRARY)}`,
          `process.chdir(${JSON.stringify(checkout)})`,
          `console.log(await wrapCommandWithSandboxLinux(${JSON.stringify({
            command: 'true',
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })}))`,
        ]),
      ],
      { encoding: 'utf8', timeout: 30000 },
    )

    expect(`${wrapped.signal} ${wrapped.stderr}`).toBe('null ')
    expect(lastMountAt(wrapped.stdout.trim(), commondir)).toBe(
      `--ro-bind ${commondir} ${commondir}`,
    )
  }, 60000)

  describe.if(bwrapCanNamespace() && Bun.which('git') !== null)(
    'with git',
    () => {
      /** Enough to commit without a hook, an identity or a signature. */
      const IDENT = [
        '-c',
        'user.name=t',
        '-c',
        'user.email=t@t',
        '-c',
        'commit.gpgsign=false',
        '-c',
        'core.hooksPath=/dev/null',
      ]

      function git(
        cwd: string,
        args: string[],
      ): { status: number | null; said: string } {
        const result = spawnSync('git', args, {
          cwd,
          encoding: 'utf8',
          timeout: 30000,
          env: { ...process.env, LC_ALL: 'C' },
        })
        return {
          status: result.status,
          said: `${result.stdout}${result.stderr}`,
        }
      }

      /** A repository with one commit, made by git itself. */
      function gitRepo(name: string): string {
        const repo = join(dir, name)
        mkdirSync(repo, { recursive: true })
        writeFileSync(join(repo, 'index.js'), 'console.log(1)\n')
        for (const args of [
          ['-c', 'init.defaultBranch=main', 'init', '-q', '.'],
          ['add', 'index.js'],
          [...IDENT, 'commit', '-q', '-m', 'one'],
        ]) {
          expect(git(repo, args)).toMatchObject({ status: 0 })
        }
        return repo
      }

      /**
       * Wraps a command with `checkout` as the cwd in a process of its own,
       * which is then killed: nothing of that wrap's clean-up runs. What it
       * leaves is its mount points and the manifest that names them.
       */
      async function wrapAndBeKilled(checkout: string): Promise<void> {
        const killed = spawnSync(
          process.execPath,
          [
            writeScript(dir, 'killed-wrap.ts', [
              `import { wrapCommandWithSandboxLinux } from ${JSON.stringify(LIBRARY)}`,
              `process.chdir(${JSON.stringify(checkout)})`,
              `await wrapCommandWithSandboxLinux(${JSON.stringify({
                command: 'true',
                needsNetworkRestriction: false,
                allowAllUnixSockets: true,
                writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
              })})`,
              "process.kill(process.pid, 'SIGKILL')",
            ]),
          ],
          { encoding: 'utf8', timeout: 60000 },
        )
        expect(`${killed.signal} ${killed.stderr}`).toBe('SIGKILL ')
        // A manifest this young counts as live with no command on its record.
        await sleep(600)
      }

      it("keeps the host's git working while a wrapped command runs", async () => {
        const sub = gitRepo('sub')
        const repo = gitRepo('repo')
        for (const args of [
          [
            '-c',
            'protocol.file.allow=always',
            ...IDENT,
            'submodule',
            'add',
            '-q',
            sub,
            'lib',
          ],
          [...IDENT, 'commit', '-q', '-m', 'lib'],
          ['worktree', 'add', '-q', join(dir, 'wt')],
        ]) {
          expect(git(repo, args)).toMatchObject({ status: 0 })
        }
        const commondirs = [
          join(repo, '.git', 'commondir'),
          join(repo, '.git', 'modules', 'lib', 'commondir'),
        ]

        // Runs until the host releases it, so the host's git is exercised with
        // the sandbox up and the mount points in place.
        const child = spawn(
          await wrapIn(
            repo,
            'echo > up; i=0; while [ ! -f release ] && [ $i -lt 200 ]; do sleep 0.1; i=$((i+1)); done',
          ),
          { shell: true, cwd: repo, stdio: 'ignore' },
        )
        try {
          await waitFor(join(repo, 'up'))

          for (const commondir of commondirs) {
            expect(readFileSync(commondir, 'utf8')).toBe('.\n')
          }
          for (const args of [
            ['status', '--porcelain'],
            ['log', '--oneline'],
            ['worktree', 'list'],
            ['rev-parse', '--git-common-dir'],
            [...IDENT, 'commit', '--allow-empty', '-q', '-m', 'during'],
          ]) {
            expect({ args, ...git(repo, args) }).toMatchObject({ status: 0 })
          }
          expect(
            git(join(repo, 'lib'), ['status', '--porcelain']),
          ).toMatchObject({ status: 0 })
        } finally {
          writeFileSync(join(repo, 'release'), '')
          await new Promise(resolve => child.on('close', resolve))
        }
        expect(child.exitCode).toBe(0)

        cleanupBwrapMountPoints()
        expect(commondirs.filter(existsSync)).toEqual([])
        expect(git(repo, ['status', '--porcelain'])).toMatchObject({
          status: 0,
        })
      })

      it('leaves behind a killed wrap a commondir git reads, and takes an empty one away', async () => {
        const repo = gitRepo('repo')
        const commondir = join(repo, '.git', 'commondir')
        const status = (): number | null =>
          git(repo, ['status', '--porcelain']).status

        await wrapAndBeKilled(repo)
        expect(readFileSync(commondir, 'utf8')).toBe('.\n')
        expect(status()).toBe(0)
        await wrapIn(repo)
        cleanupBwrapMountPoints()
        expect(existsSync(commondir)).toBe(false)

        // What bubblewrap makes where the file has gone from under it: git
        // refuses every command in the repository until the next clean-up.
        await wrapAndBeKilled(repo)
        chmodSync(commondir, 0o644)
        writeFileSync(commondir, '')
        chmodSync(commondir, 0o444)
        expect(git(repo, ['status', '--porcelain']).said).toContain('commondir')

        await wrapIn(repo)
        cleanupBwrapMountPoints()
        expect(existsSync(commondir)).toBe(false)
        expect(status()).toBe(0)
      })

      it('leaves git working across wraps, and the commondir unwritable', async () => {
        const repo = gitRepo('repo')
        const commondir = join(repo, '.git', 'commondir')
        const run = (command: string): string =>
          spawnSync(command, {
            shell: true,
            encoding: 'utf8',
            timeout: 30000,
            cwd: repo,
            env: { ...process.env, LC_ALL: 'C' },
          }).stdout

        // No clean-up in between: the first wrap's mount point is still in the
        // git directory, and the second wrap's scan finds it there. By name:
        // the mount points of the dotfile denies are not files to stage.
        for (const file of ['one.js', 'two.js']) {
          writeFileSync(join(repo, file), 'console.log(1)\n')
          expect(
            run(
              await wrapIn(
                repo,
                `echo ${BOOTED} && git add ${file} && git ${IDENT.join(' ')} commit -q -m ${file} && echo COMMIT_OK`,
              ),
            ),
          ).toBe(`${BOOTED}\nCOMMIT_OK\n`)
        }

        expect(
          run(
            await wrapIn(
              repo,
              `echo ${BOOTED}; echo ../decoy > .git/commondir || chmod 666 .git/commondir || echo DENIED`,
            ),
          ),
        ).toBe(`${BOOTED}\nDENIED\n`)
        expect(readFileSync(commondir, 'utf8')).toBe('.\n')
        cleanupBwrapMountPoints({ force: true })
        expect(existsSync(commondir)).toBe(false)
      })
    },
  )
})
