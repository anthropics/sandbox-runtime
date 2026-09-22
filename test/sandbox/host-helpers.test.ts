import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as childProcess from 'node:child_process'
import { EventEmitter } from 'node:events'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { isAbsolute, join } from 'node:path'
import {
  getGlobalNpmPathsAsync,
  resetGlobalNpmPathsForTesting,
} from '../../src/sandbox/generate-seccomp-filter.js'
import {
  describeUnavailableHostHelper,
  findHostHelper,
  hostSearchPath,
} from '../../src/sandbox/host-helpers.js'
import {
  LinuxSandboxProfileError,
  checkLinuxDependencies,
  cleanupBwrapMountPoints,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import {
  startMacOSSandboxLogMonitor,
  wrapCommandWithSandboxMacOS,
} from '../../src/sandbox/macos-sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { whichSync } from '../../src/utils/which.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux, isWindows } from '../helpers/platform.js'

/**
 * The programs the library itself runs on the host are never taken from a
 * place the sandboxed command may write. The fixture is the usual way that
 * goes wrong: a project directory that is in `allowWrite` and whose
 * `node_modules/.bin` leads PATH (as under `npx` and `npm run`), holding files
 * named like the helpers. Each of them leaves a marker behind if it is ever
 * run, and no test may find that marker.
 */
describe('programs run on the host are found outside the allowed write paths', () => {
  const savedPath = process.env.PATH ?? ''
  const savedCwd = process.cwd()
  // A made-up helper name for the cases that are about the search alone.
  const HELPER = 'srt-test-helper'

  let base: string
  let project: string
  let projectBin: string
  let safe: string
  let marker: string

  // An executable that leaves the marker behind if anything ever runs it.
  function plant(file: string): string {
    writeFileSync(file, `#!/bin/sh\necho "$0" >> '${marker}'\nexit 0\n`)
    chmodSync(file, 0o755)
    return file
  }

  function dir(...parts: string[]): string {
    const made = join(base, ...parts)
    mkdirSync(made, { recursive: true })
    return made
  }

  beforeEach(() => {
    // Other suites wrap without cleaning up, and the active count is shared.
    cleanupBwrapMountPoints({ force: true })
    base = realpathSync(mkdtempSync(join(tmpdir(), 'host-helpers-')))
    marker = join(base, 'a-planted-file-was-run')
    project = dir('project')
    projectBin = dir('project', 'node_modules', '.bin')
    safe = dir('safe')
  })

  afterEach(() => {
    process.env.PATH = savedPath
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(base, { recursive: true, force: true })
  })

  describe('findHostHelper', () => {
    it('passes over a copy in the writable directory, however early on PATH', () => {
      plant(join(projectBin, HELPER))
      plant(join(safe, HELPER))
      process.env.PATH = `${projectBin}:${safe}`

      // The plain search, for what runs inside the sandbox, takes the first.
      expect(whichSync(HELPER)).toBe(join(projectBin, HELPER))

      const search = findHostHelper(HELPER, [project])

      expect(search.path).toBe(join(safe, HELPER))
      expect(search.skipped).toEqual([
        {
          candidate: join(projectBin, HELPER),
          reason: `inside the allowed write path ${project}`,
        },
      ])
      expect(existsSync(marker)).toBe(false)
    })

    it.if(isLinux)(
      'finds the real bwrap, socat and rg behind planted ones',
      () => {
        for (const helper of ['bwrap', 'socat', 'rg']) {
          const real = whichSync(helper)
          expect(real).not.toBeNull()
          plant(join(projectBin, helper))
          process.env.PATH = `${projectBin}:${savedPath}`

          expect(whichSync(helper)).toBe(join(projectBin, helper))
          expect(findHostHelper(helper, [project]).path).toBe(real)

          process.env.PATH = savedPath
        }
        expect(existsSync(marker)).toBe(false)
      },
    )

    it('finds nothing when the only copies are writable, and says which and why', () => {
      const empty = dir('empty')
      plant(join(projectBin, 'bwrap'))
      process.env.PATH = `${projectBin}:${empty}`

      const search = findHostHelper('bwrap', [project])

      expect(search.path).toBeNull()
      expect(search.skipped.map(s => s.candidate)).toEqual([
        join(projectBin, 'bwrap'),
      ])
      const refusal = describeUnavailableHostHelper('bwrap', search)
      expect(refusal).toContain('bwrap runs on the host')
      expect(refusal).toContain(join(projectBin, 'bwrap'))
      expect(refusal).toContain(`inside the allowed write path ${project}`)
      expect(refusal).toContain('bwrapPath')
      expect(describeUnavailableHostHelper('socat', search)).toContain(
        'socatPath',
      )
      expect(describeUnavailableHostHelper('rg', search)).toContain(
        'ripgrep.command',
      )
      expect(existsSync(marker)).toBe(false)
    })

    it('never uses a relative PATH entry, the empty one included', () => {
      const cwd = dir('cwd')
      plant(join(cwd, HELPER))
      plant(join(dir('cwd', 'bin'), HELPER))
      plant(join(safe, HELPER))
      process.chdir(cwd)
      process.env.PATH = `:.:bin:${safe}`

      // The plain search reads the empty entry as the current directory.
      expect(whichSync(HELPER)).toBe(join(cwd, HELPER))

      const search = findHostHelper(HELPER, [project])

      expect(search.path).toBe(join(safe, HELPER))
      expect(search.skipped).toEqual([
        {
          candidate: join(cwd, HELPER),
          reason: 'an empty PATH entry means the current directory',
        },
        {
          candidate: join(cwd, HELPER),
          reason: 'the PATH entry . is relative',
        },
        {
          candidate: join(cwd, 'bin', HELPER),
          reason: 'the PATH entry bin is relative',
        },
      ])
    })

    it('passes over a link in a safe directory that leads to a writable file', () => {
      const linked = dir('linked')
      const target = plant(join(project, 'built-helper'))
      symlinkSync(target, join(linked, HELPER))
      plant(join(safe, HELPER))
      process.env.PATH = `${linked}:${safe}`

      expect(whichSync(HELPER)).toBe(join(linked, HELPER))

      const search = findHostHelper(HELPER, [project])

      expect(search.path).toBe(join(safe, HELPER))
      expect(search.skipped).toEqual([
        {
          candidate: join(linked, HELPER),
          reason: `resolves to ${target}, inside the allowed write path ${project}`,
        },
      ])
    })

    it('passes over a PATH entry that is a link kept in the writable directory', () => {
      // The link leads to a safe directory today; whoever may write the
      // directory it sits in decides where it leads tomorrow.
      plant(join(safe, HELPER))
      const elsewhere = dir('elsewhere')
      plant(join(elsewhere, HELPER))
      symlinkSync(safe, join(project, 'tools'))
      process.env.PATH = `${join(project, 'tools')}:${elsewhere}`

      const search = findHostHelper(HELPER, [project])

      expect(search.path).toBe(join(elsewhere, HELPER))
      expect(search.skipped).toEqual([
        {
          candidate: join(project, 'tools', HELPER),
          reason: `inside the allowed write path ${project}`,
        },
      ])
    })

    it('passes over that link when PATH reaches it through an alias of the directory', () => {
      // Neither the spelling nor the file it resolves to is inside the
      // project; the link followed on the way is.
      plant(join(safe, HELPER))
      const elsewhere = dir('elsewhere')
      plant(join(elsewhere, HELPER))
      symlinkSync(safe, join(project, 'tools'))
      symlinkSync(project, join(base, 'alias'))
      process.env.PATH = `${join(base, 'alias', 'tools')}:${elsewhere}`

      const search = findHostHelper(HELPER, [project])

      expect(search.path).toBe(join(elsewhere, HELPER))
      expect(search.skipped).toEqual([
        {
          candidate: join(base, 'alias', 'tools', HELPER),
          reason: `reached through the link ${join(project, 'tools')}, inside the allowed write path ${project}`,
        },
      ])
    })

    it('compares against a write path in the form it resolves to as well', () => {
      // The write path is given through a link; the copy is inside the
      // directory that link leads to, and PATH names it there.
      const real = dir('real-project')
      plant(join(dir('real-project', 'bin'), HELPER))
      plant(join(safe, HELPER))
      symlinkSync(real, join(base, 'project-link'))
      process.env.PATH = `${join(real, 'bin')}:${safe}`

      const search = findHostHelper(HELPER, [join(base, 'project-link')])

      expect(search.path).toBe(join(safe, HELPER))
      expect(search.skipped.map(s => s.candidate)).toEqual([
        join(real, 'bin', HELPER),
      ])
    })

    it('passes over nothing when no writes are restricted', () => {
      plant(join(projectBin, HELPER))
      plant(join(safe, HELPER))
      process.env.PATH = `${projectBin}:${safe}`

      expect(findHostHelper(HELPER, undefined)).toEqual({
        path: join(projectBin, HELPER),
        skipped: [],
      })
      // No allowed write path at all is a restriction: nothing is writable,
      // so nothing is passed over either.
      expect(findHostHelper(HELPER, [])).toEqual({
        path: join(projectBin, HELPER),
        skipped: [],
      })
    })

    it('passes over nothing when the policy lets the command write everywhere', () => {
      // With '/' allowed there is no place outside the write paths to prefer.
      // The helper is still found in this process, from the whole PATH, by an
      // absolute path.
      plant(join(projectBin, HELPER))
      plant(join(safe, HELPER))
      const cwd = dir('cwd')
      plant(join(cwd, HELPER))
      process.chdir(cwd)

      process.env.PATH = `${projectBin}:${safe}`
      expect(findHostHelper(HELPER, ['/', project])).toEqual({
        path: join(projectBin, HELPER),
        skipped: [],
      })

      process.env.PATH = `:${safe}`
      const fromEmptyEntry = findHostHelper(HELPER, ['/'])
      expect(fromEmptyEntry.path).toBe(join(cwd, HELPER))
      expect(isAbsolute(fromEmptyEntry.path!)).toBe(true)
      expect(existsSync(marker)).toBe(false)
    })

    it('looks again at a remembered result under the write paths of each call', () => {
      const first = dir('first')
      const second = dir('second')
      plant(join(first, HELPER))
      plant(join(second, HELPER))
      process.env.PATH = `${first}:${second}`

      expect(findHostHelper(HELPER, [project]).path).toBe(join(first, HELPER))
      expect(findHostHelper(HELPER, [project]).path).toBe(join(first, HELPER))

      // The write paths now cover what was found: it is not returned again.
      const widened = findHostHelper(HELPER, [project, first])
      expect(widened.path).toBe(join(second, HELPER))
      expect(widened.skipped.map(s => s.candidate)).toEqual([
        join(first, HELPER),
      ])

      // And narrowed back, either copy will do; the one in hand is kept.
      expect(findHostHelper(HELPER, [project]).path).toBe(join(second, HELPER))

      // A remembered file that is gone is searched for again.
      rmSync(join(second, HELPER))
      expect(findHostHelper(HELPER, [project]).path).toBe(join(first, HELPER))
    })
  })

  describe.if(isLinux)('wrapCommandWithSandboxLinux', () => {
    const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()
    let realBwrap: string
    let realSocat: string
    let realRg: string

    beforeEach(() => {
      realBwrap = whichSync('bwrap')!
      realSocat = whichSync('socat')!
      realRg = whichSync('rg')!
      expect(realBwrap).not.toBeNull()
      expect(realSocat).not.toBeNull()
      expect(realRg).not.toBeNull()
      for (const helper of ['bwrap', 'socat', 'rg']) {
        plant(join(projectBin, helper))
      }
      // Something only the scan finds: a shell startup file below the cwd.
      mkdirSync(join(project, 'nested'))
      writeFileSync(join(project, 'nested', '.bashrc'), '')
      process.chdir(project)
    })

    const firstWord = (wrapped: string): string => wrapped.split(' ')[0]!

    it('names the real bubblewrap by its absolute path and scans with the real ripgrep', async () => {
      process.env.PATH = `${projectBin}:${savedPath}`

      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'echo wrapped-ok',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [project], denyWithinAllow: [] },
      })

      expect(firstWord(wrapped)).toBe(realBwrap)
      expect(isAbsolute(firstWord(wrapped))).toBe(true)
      expect(wrapped).not.toContain(projectBin)
      // The scan ran, with the real ripgrep: the nested file it alone finds
      // is made read-only, and the planted rg was not run to find it.
      expect(wrapped).toContain(join(project, 'nested', '.bashrc'))
      expect(existsSync(marker)).toBe(false)

      if (BWRAP_CAN_NAMESPACE) {
        const run = childProcess.spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 10000,
        })
        expect(run.stdout).toBe('wrapped-ok\n')
        expect(run.status).toBe(0)
        expect(existsSync(marker)).toBe(false)
      }
    })

    it('starts the listeners inside the sandbox with the real socat', async () => {
      process.env.PATH = `${projectBin}:${savedPath}`
      const httpSocket = join(base, 'http.sock')
      const socksSocket = join(base, 'socks.sock')
      writeFileSync(httpSocket, '')
      writeFileSync(socksSocket, '')

      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'echo wrapped-ok',
        needsNetworkRestriction: true,
        httpSocketPath: httpSocket,
        socksSocketPath: socksSocket,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [project], denyWithinAllow: [] },
      })

      expect(wrapped).toContain(`${realSocat} TCP-LISTEN:3128`)
      expect(wrapped).toContain(`${realSocat} TCP-LISTEN:1080`)
      expect(wrapped).not.toContain(projectBin)
      expect(wrapped).not.toMatch(/(^|[\s'"])socat TCP-LISTEN/)
      expect(existsSync(marker)).toBe(false)
    })

    it('refuses, by a typed error, when bubblewrap is only to be had from the writable directory', async () => {
      // Everything else the wrap needs, and no bwrap, outside the project.
      const tools = dir('tools')
      for (const needed of ['rg', 'socat', 'bash']) {
        symlinkSync(whichSync(needed)!, join(tools, needed))
      }
      process.env.PATH = `${projectBin}:${tools}`

      let thrown: unknown
      try {
        await wrapCommandWithSandboxLinux({
          command: 'echo never-run',
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [] },
          writeConfig: { allowOnly: [project], denyWithinAllow: [] },
        })
      } catch (error) {
        thrown = error
      }

      expect(thrown).toBeInstanceOf(LinuxSandboxProfileError)
      const refusal = thrown as LinuxSandboxProfileError
      expect(refusal.code).toBe('host_helper_unavailable')
      expect(refusal.message).toContain('bwrap runs on the host')
      expect(refusal.message).toContain(join(projectBin, 'bwrap'))
      expect(refusal.message).toContain('bwrapPath')
      expect(existsSync(marker)).toBe(false)

      // The same for the scan's ripgrep.
      rmSync(join(tools, 'rg'))
      symlinkSync(realBwrap, join(tools, 'bwrap'))
      // eslint-disable-next-line @typescript-eslint/await-thenable
      await expect(
        wrapCommandWithSandboxLinux({
          command: 'echo never-run',
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [] },
          writeConfig: { allowOnly: [project], denyWithinAllow: [] },
        }),
      ).rejects.toMatchObject({
        name: 'LinuxSandboxProfileError',
        code: 'host_helper_unavailable',
        message: expect.stringContaining(join(projectBin, 'rg')),
      })
      expect(existsSync(marker)).toBe(false)
    })

    it('uses bwrapPath, socatPath and a ripgrep command with a directory part as given', async () => {
      // Named outright, even inside the write path: a directive. Nothing is
      // looked up, so a PATH that holds none of them does not matter.
      const tools = dir('tools')
      symlinkSync(whichSync('bash')!, join(tools, 'bash'))
      process.env.PATH = tools
      const httpSocket = join(base, 'http.sock')
      const socksSocket = join(base, 'socks.sock')
      writeFileSync(httpSocket, '')
      writeFileSync(socksSocket, '')

      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'echo wrapped-ok',
        needsNetworkRestriction: true,
        httpSocketPath: httpSocket,
        socksSocketPath: socksSocket,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [project], denyWithinAllow: [] },
        bwrapPath: join(projectBin, 'bwrap'),
        socatPath: join(projectBin, 'socat'),
        ripgrepConfig: { command: realRg },
      })

      expect(firstWord(wrapped)).toBe(join(projectBin, 'bwrap'))
      expect(wrapped).toContain(`${join(projectBin, 'socat')} TCP-LISTEN:3128`)
      expect(existsSync(marker)).toBe(false)
    })

    it('resolves from the whole PATH when the policy lets the command write everywhere', async () => {
      process.env.PATH = `${safe}:${savedPath}`
      symlinkSync(realBwrap, join(safe, 'bwrap'))

      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'echo wrapped-ok',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: ['/'], denyWithinAllow: ['/'] },
      })

      expect(firstWord(wrapped)).toBe(join(safe, 'bwrap'))
    })
  })

  describe.if(isLinux)('the dependency check', () => {
    it('reports a required helper found only inside a writable path as an error naming it', () => {
      const tools = dir('tools')
      symlinkSync(whichSync('socat')!, join(tools, 'socat'))
      plant(join(projectBin, 'bwrap'))
      process.env.PATH = `${projectBin}:${tools}`

      const restricted = checkLinuxDependencies({
        allowedWritePaths: [project],
      })

      expect(restricted.errors).toHaveLength(1)
      expect(restricted.errors[0]).toContain('bwrap runs on the host')
      expect(restricted.errors[0]).toContain(join(projectBin, 'bwrap'))
      // The same PATH with nothing restricted: that copy is the one to run.
      expect(checkLinuxDependencies().errors).toEqual([])
      // One that is nowhere keeps the message it always had.
      process.env.PATH = tools
      expect(
        checkLinuxDependencies({ allowedWritePaths: [project] }).errors,
      ).toEqual(['bubblewrap (bwrap) not installed'])
      expect(existsSync(marker)).toBe(false)
    })

    it('warns about a helper named outright that the sandboxed command may write', () => {
      const bwrapPath = plant(join(projectBin, 'bwrap'))
      const socatPath = plant(join(projectBin, 'socat'))
      const applyPath = plant(join(projectBin, 'apply-seccomp'))

      const named = checkLinuxDependencies({
        bwrapPath,
        socatPath,
        seccompConfig: { applyPath },
        allowedWritePaths: [project],
      })

      expect(named.errors).toEqual([])
      expect(named.warnings).toEqual([
        `bwrapPath ${bwrapPath} is inside the allowed write path ${project}: the sandboxed command can replace that file`,
        `socatPath ${socatPath} is inside the allowed write path ${project}: the sandboxed command can replace that file`,
        `seccomp.applyPath ${applyPath} is inside the allowed write path ${project}: the sandboxed command can replace that file`,
      ])
      // Outside the write paths, or with nothing restricted: no warning.
      expect(
        checkLinuxDependencies({
          bwrapPath,
          socatPath,
          seccompConfig: { applyPath },
          allowedWritePaths: [safe],
        }).warnings,
      ).toEqual([])
      expect(
        checkLinuxDependencies({
          bwrapPath,
          socatPath,
          seccompConfig: { applyPath },
        }).warnings,
      ).toEqual([])
      expect(existsSync(marker)).toBe(false)
    })

    it('SandboxManager judges by the configuration it is initialized with', async () => {
      const tools = dir('tools')
      for (const needed of ['bwrap', 'socat']) {
        symlinkSync(whichSync(needed)!, join(tools, needed))
      }
      plant(join(projectBin, 'rg'))
      process.env.PATH = `${projectBin}:${tools}`

      const config = {
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [project], denyWrite: [] },
      }
      // initialize() runs the check under the configuration it is given, and
      // refuses to start with a required helper it would never run.
      // eslint-disable-next-line @typescript-eslint/await-thenable
      await expect(SandboxManager.initialize(config)).rejects.toThrow(
        /Sandbox dependencies not available: rg runs on the host and was not found on PATH outside the paths the sandboxed command may write\. Passed over: .*node_modules\/\.bin\/rg/,
      )
      await SandboxManager.reset()

      // A ripgrep named outright is used as given, and warned about.
      await SandboxManager.initialize({
        ...config,
        ripgrep: { command: join(projectBin, 'rg') },
      })
      try {
        const named = SandboxManager.checkDependencies()
        expect(named.errors).toEqual([])
        expect(named.warnings).toEqual([
          `ripgrep.command ${join(projectBin, 'rg')} is inside the allowed write path ${project}: the sandboxed command can replace that file`,
        ])
      } finally {
        await SandboxManager.reset()
      }
      expect(existsSync(marker)).toBe(false)
    })
  })

  // `npm root -g` finds a global install of this package where the helper or
  // the JVM agent's jar is not beside the library. npm is a script and looks
  // `node` up by name, so it is a PATH, not a file, that the rule is put to.
  describe.if(!isWindows)(
    'the PATH given to a program that searches it itself',
    () => {
      afterEach(() => {
        resetGlobalNpmPathsForTesting()
      })

      it('leaves out what a host helper would not be taken from', () => {
        const linked = join(safe, 'into-the-project')
        symlinkSync(projectBin, linked)
        process.env.PATH = [
          projectBin,
          'relative',
          '',
          linked,
          safe,
          '/usr/bin',
        ].join(':')

        expect(hostSearchPath([project])).toBe([safe, '/usr/bin'].join(':'))
        // Nothing the policy keeps the command from writing: nothing left out,
        // and the program inherits the PATH as it is.
        expect(hostSearchPath(undefined)).toBeUndefined()
        expect(hostSearchPath(['/'])).toBeUndefined()
      })

      it('keeps an npm the sandboxed command could have written from being run', async () => {
        plant(join(projectBin, 'npm'))
        plant(join(projectBin, 'node'))
        process.env.PATH = `${projectBin}:${savedPath}`

        resetGlobalNpmPathsForTesting()
        await getGlobalNpmPathsAsync(hostSearchPath([project]))
        expect(existsSync(marker)).toBe(false)

        // The control: asked with the PATH as it is, the planted one answers,
        // which is what the marker is there to show.
        resetGlobalNpmPathsForTesting()
        await getGlobalNpmPathsAsync()
        expect(existsSync(marker)).toBe(true)
      })
    },
  )

  describe('macOS: fixed locations, no search', () => {
    it('starts the wrapped command with /usr/bin/env', () => {
      const wrapped = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
        unsetEnvVars: ['GH_TOKEN'],
      })

      expect(wrapped.startsWith('/usr/bin/env -u GH_TOKEN ')).toBe(true)
      expect(wrapped).toContain(' /usr/bin/sandbox-exec -p ')
    })

    it('spawns the log monitor as /usr/bin/log', () => {
      const child = Object.assign(new EventEmitter(), {
        stdout: new EventEmitter(),
        stderr: new EventEmitter(),
        kill: () => true,
      })
      const spawnSpy = spyOn(childProcess, 'spawn').mockReturnValue(
        child as never,
      )
      try {
        const stop = startMacOSSandboxLogMonitor(
          () => {},
          undefined,
          key => key,
        )
        stop()

        expect(spawnSpy).toHaveBeenCalledTimes(1)
        expect(spawnSpy.mock.calls[0]?.[0]).toBe('/usr/bin/log')
        expect(spawnSpy.mock.calls[0]?.[1]?.[0]).toBe('stream')
      } finally {
        spawnSpy.mockRestore()
      }
    })
  })
})
