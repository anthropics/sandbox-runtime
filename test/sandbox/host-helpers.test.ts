import { afterEach, beforeEach, expect, it, mock, spyOn } from 'bun:test'
import type { Mock } from 'bun:test'
import * as childProcess from 'node:child_process'
import { EventEmitter } from 'node:events'
import * as fs from 'node:fs'
import * as os from 'node:os'
import { dirname, join } from 'node:path'
import * as seccomp from '../../src/sandbox/generate-seccomp-filter.js'
import * as hostHelpers from '../../src/sandbox/host-helpers.js'
import * as javaAgent from '../../src/sandbox/java-proxy-agent.js'
import * as linux from '../../src/sandbox/linux-sandbox-utils.js'
import * as macos from '../../src/sandbox/macos-sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import * as platformUtils from '../../src/utils/platform.js'
import { whichSync } from '../../src/utils/which.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { withCapturedWarnings } from '../helpers/captured-warnings.js'
import { isLinux, isWindows } from '../helpers/platform.js'

/**
 * The programs the library itself runs on the host are never taken from a
 * place the sandboxed command may write. The fixture: a project directory in
 * `allowWrite` whose `node_modules/.bin` leads PATH, holding files named like
 * the helpers. Each leaves a marker behind if run; no test may find it.
 */
const { findHostHelper, hostSearchPath, writablePlaces } = hostHelpers
const unavailable = hostHelpers.describeUnavailableHostHelper
const warning = hostHelpers.writableNamedHelperWarning
const posix = it.if(!isWindows)
const onLinux = it.if(isLinux)
const BWRAP_CAN_NAMESPACE = isLinux && bwrapCanNamespace()
const savedPath = process.env.PATH ?? ''
const savedCwd = process.cwd()
const platform = Object.getOwnPropertyDescriptor(process, 'platform')!
const base = fs.realpathSync(fs.mkdtempSync(join(os.tmpdir(), 'host-helpers-')))
const marker = `${base}/a-planted-file-was-run`
const project = `${base}/project`
const projectBin = `${project}/node_modules/.bin`
const safe = `${base}/safe`
const elsewhere = `${base}/elsewhere`
// A made-up helper name for the cases that are about the search alone.
const HELPER = 'srt-test-helper'
const planted = `${projectBin}/${HELPER}`
const outside = `${safe}/${HELPER}`
const writable = [project]
const inProject = `inside the allowed write path ${project}`
const replaceable = 'the sandboxed command can replace that file'

// An executable that leaves the marker behind if anything ever runs it.
function plant(file: string): string {
  fs.mkdirSync(dirname(file), { recursive: true })
  const script = `#!/bin/sh\necho "$0" >> '${marker}'\n`
  fs.writeFileSync(file, script, { mode: 0o755 })
  return file
}

function link(target: string, file: string): void {
  fs.mkdirSync(dirname(file), { recursive: true })
  fs.symlinkSync(target, file)
}

// What the search passes over when a helper's only copy is the planted one,
// and what is then said.
const skipped = (helper: string): hostHelpers.SkippedHostHelper[] => [
  { path: `${projectBin}/${helper}`, reason: inProject, writePath: project },
]
const refusal = (helper: string, option: string): string =>
  unavailable(helper, option, { path: null, skipped: skipped(helper) })

beforeEach(async () => {
  // Other suites leave a configuration, and wraps they did not clean up.
  await SandboxManager.reset()
  for (const name of [HELPER, 'bwrap', 'socat', 'rg', 'bash', 'npm', 'node'])
    plant(`${projectBin}/${name}`)
  plant(outside)
  plant(`${elsewhere}/${HELPER}`)
  link(planted, `${base}/linked/${HELPER}`)
  link(elsewhere, `${project}/tools`)
  link(project, `${base}/alias`)
  link(`${project}/node_modules/../../safe/${HELPER}`, `${base}/up/${HELPER}`)
  link('/', `${project}/dist`)
  // Something only the scan finds: a shell startup file below the cwd.
  fs.mkdirSync(`${project}/nested`)
  fs.writeFileSync(`${project}/nested/.bashrc`, '')
})

afterEach(async () => {
  mock.restore()
  Object.defineProperty(process, 'platform', platform)
  process.env.PATH = savedPath
  process.chdir(savedCwd)
  seccomp.resetGlobalNpmPathsForTesting()
  // The manager keeps its configuration: one that names nothing of this file's.
  SandboxManager.updateConfig({
    ...config,
    filesystem: { ...config.filesystem, allowWrite: [] },
  })
  await SandboxManager.reset()
  const ran = fs.existsSync(marker) && fs.readFileSync(marker, 'utf8')
  fs.rmSync(base, { recursive: true, force: true })
  expect(ran).toBe(false)
})

posix.each<[string, Parameters<typeof writablePlaces>[0], string[]]>([
  ['writes anywhere', 'anywhere', []],
  ['the root among them', [project, '/'], []],
  ['a trailing slash', [`${project}/`], [project]],
  ['an entry that is not there', [`${base}/absent`], [`${base}/absent`]],
  ['a home directory with no name', ['~', project], [project]],
  // The command can make such a link wherever one entry lies inside another,
  // and the wrap binds nothing for it: it switches nothing off, widens nothing.
  ['a link to the root', [`${project}/dist`], [`${project}/dist`]],
  ['a link out of its place', [`${project}/tools`], [`${project}/tools`]],
])('writablePlaces: %s', (_, allowed, places) => {
  spyOn(os, 'homedir').mockReturnValue('')
  expect(writablePlaces(allowed)).toEqual(places)
})

posix('writablePlaces: what reads as a pattern is a name on Linux', () => {
  const names = [`${project}/src/**/*.ts`, `${safe}/w[1]`, '/x[1]']
  const entries = names.map(name => `${name}/`)
  const on = spyOn(platformUtils, 'getPlatform').mockReturnValue('linux')
  expect(writablePlaces(entries)).toEqual(names)
  on.mockReturnValue('macos')
  expect(writablePlaces(entries.slice(0, 2))).toEqual([`${project}/src`, safe])
  // It starts from the root.
  expect(writablePlaces(entries)).toEqual([])
})

posix('writablePlaces: no policy known yet', () => {
  process.chdir(elsewhere)
  fs.rmSync(elsewhere, { recursive: true })
  const defaults = writablePlaces(undefined)
  expect(defaults).toContain('/dev/null')
  process.chdir(safe)
  expect(writablePlaces(undefined)).toEqual([safe, ...defaults])
})

// What, the PATH entry it is found through, the place that rules it out.
posix.each([
  ['a copy in it', projectBin, undefined],
  ['a link to a file in it', `${base}/linked`, planted],
  // It leads out today; whoever may write the directory it is kept in decides
  // where it leads tomorrow.
  ['a PATH entry that is a link kept in it', `${project}/tools`, undefined],
  ['that link through an alias', `${base}/alias/tools`, `${project}/tools`],
  ['a link that goes up from it', `${base}/up`, `${project}/node_modules`],
])('the search passes over %s', (_, entry, through) => {
  const path = `${entry}/${HELPER}`
  const reason = (through ? `leads through ${through}, ` : '') + inProject
  const skipped = [{ path, reason, writePath: project }]
  process.env.PATH = `${entry}:${safe}`
  // The plain search, for what runs inside the sandbox, takes the first.
  expect(whichSync(HELPER)).toBe(path)
  expect(findHostHelper(HELPER, writable)).toEqual({ path: outside, skipped })
  expect(hostSearchPath(writable, [HELPER])).toBe(safe)
  // With writes allowed everywhere no place is better than another.
  expect(findHostHelper(HELPER, [])).toEqual({ path, skipped: [] })
  process.env.PATH = entry
  expect(findHostHelper(HELPER, writable)).toEqual({ path: null, skipped })
  // Named outright it is used as given, and warned about.
  expect(findHostHelper(path, writable)).toEqual({ path, skipped: [] })
  expect(warning('o', path, writable)).toBe(
    `o ${path} ${through ? '' : 'is '}${reason}: ${replaceable}`,
  )
})

posix('the search never uses a relative PATH entry, nor the empty one', () => {
  plant(`${elsewhere}/bin/${HELPER}`)
  process.chdir(elsewhere)
  process.env.PATH = `:.:bin:${safe}`
  const skipped = ['', '.', 'bin'].map(entry => ({
    path: `${entry || '.'}/${HELPER}`,
    reason: `the PATH entry '${entry}' is relative`,
  }))
  for (const places of [writable, []]) {
    expect(findHostHelper(HELPER, places)).toEqual({ path: outside, skipped })
    expect(hostSearchPath(places, [])).toBe(safe)
  }
})

posix('the search takes the first program outside', () => {
  fs.mkdirSync(`${project}/no-program/${HELPER}`, { recursive: true })
  // By path segment: this one is beside the project, not in it.
  const path = plant(`${project}-tools/${HELPER}`)
  process.env.PATH = `${project}/no-program:${project}-tools:${safe}`
  expect(findHostHelper(HELPER, writable)).toEqual({ path, skipped: [] })
  expect(findHostHelper(project, writable)).toEqual({ path: null, skipped: [] })
  // `..` in an entry is the file system's to read: after a link, this one's
  // copy is another directory's.
  link(elsewhere, `${safe}/jump`)
  link(planted, `${base}/${HELPER}`)
  process.env.PATH = `${safe}/jump/..:${safe}`
  expect(findHostHelper(HELPER, writable).skipped).toHaveLength(1)
  expect(hostSearchPath(writable, [HELPER])).toBe(safe)
})

posix('hostSearchPath leaves out what no helper would be taken from', () => {
  // Whatever bears the name is judged: the command could supply the rest.
  link(`${project}/not-there-yet`, `${base}/dangling-in/${HELPER}`)
  link(`${base}/nowhere`, `${base}/dangling-out/${HELPER}`)
  link(HELPER, `${base}/loop/${HELPER}`)
  const copies = ['dangling-in', 'dangling-out', 'loop'].map(d => join(base, d))
  const all = [projectBin, `${base}/absent`, ...copies, safe, '/usr/bin']
  process.env.PATH = all.join(':')
  expect(hostSearchPath(writable, []).split(':')).toEqual(all.slice(2))
  expect(hostSearchPath(writable, ['x', HELPER])).toBe(`${safe}:/usr/bin`)
  expect(hostSearchPath([], [HELPER]).split(':')).toEqual(all)
  // An empty PATH would mean the current directory to a shell.
  process.env.PATH = projectBin
  expect(hostSearchPath(writable, [])).toBe('/dev/null')
  delete process.env.PATH
  expect(hostSearchPath(writable, [])).toBe('/dev/null')
})

posix('what is said of a helper that may not be used', () => {
  const none = { path: null, skipped: [] }
  expect(unavailable('rg', 'o', none)).toBe('rg was not found on PATH')
  expect(unavailable('/rg', 'o', none)).toBe('/rg is not an executable file')
  expect(unavailable('rg', 'o', none, 'not installed')).toBe('not installed')
  const two = ['/w/rg', './rg'].map(path => ({ path, reason: 'why' }))
  expect(unavailable('rg', 'o', { path: null, skipped: two }, 'unused')).toBe(
    'rg was not found on PATH outside the paths the sandboxed command may write. ' +
      'Passed over: /w/rg (why); ./rg (why). Install it outside those paths, ' +
      'put the directory that holds it on PATH, or name it by its path with o.',
  )
  process.chdir(projectBin)
  expect(warning('o', `./${HELPER}`, writable)).toBe(
    `o ./${HELPER} is ${inProject}: ${replaceable}`,
  )
  // A bare name names no file: argv0 mode's applyPath.
  for (const file of [HELPER, undefined, outside, `${base}/absent`])
    expect(warning('o', file, writable)).toBeUndefined()
})

const NAMES = ['rg', 'bwrap', 'socat', 'bash']
const real = Object.fromEntries(NAMES.map(name => [name, whichSync(name)!]))
const config = {
  network: { allowedDomains: [], deniedDomains: [] },
  filesystem: { denyRead: [], allowWrite: [project], denyWrite: [] },
}
// Never run: for a socket any path that is there will do.
const RELAYED = {
  needsNetworkRestriction: true,
  httpSocketPath: safe,
  socksSocketPath: elsewhere,
}
const NAMED = {
  bwrapPath: `${projectBin}/bwrap`,
  socatPath: `${projectBin}/socat`,
  binShell: `${projectBin}/bash`,
  ripgrepConfig: { command: real.rg },
}

// A directory of links to the real programs named, and to no other.
function tools(names: string[], dir = `${base}/real`): string {
  fs.mkdirSync(dir, { recursive: true })
  for (const name of names) link(real[name], `${dir}/${name}`)
  return dir
}

// The project is marked literal, which counts like any other entry, and the
// link to the root is among the write paths.
function wrap(
  params: Partial<linux.LinuxSandboxParams> = {},
  allowOnly = [`${project}/dist`],
): Promise<string> {
  return linux.wrapCommandWithSandboxLinux({
    command: 'echo wrapped-ok',
    needsNetworkRestriction: false,
    writeConfig: {
      allowOnly,
      literalAllowOnly: [project],
      denyWithinAllow: [],
    },
    ...params,
  })
}

onLinux.each<[string, Partial<linux.LinuxSandboxParams>]>([
  ['the real ones', {}],
  // It may ask bubblewrap about itself: the copy it runs, never PATH's.
  ['the real ones, relayed', { ...RELAYED, allowAllUnixSockets: true }],
  ['the ones named outright, as given', { ...RELAYED, ...NAMED }],
])('a wrap names its programs by their paths: %s', async (_, params) => {
  const { bwrapPath = real.bwrap, binShell = real.bash } = params
  process.chdir(project)
  process.env.PATH = `${projectBin}:${savedPath}`
  const wrapped = await wrap(params)
  expect(wrapped).toStartWith(`${bwrapPath} `)
  expect(wrapped).toContain(` -- ${binShell} -c `)
  // Each relay names socat twice: for both families, and for IPv4 alone.
  expect([...(wrapped.match(/[^\s'"]*socat(?= TCP\d-LISTEN)/g) ?? [])]).toEqual(
    Array(params.httpSocketPath ? 4 : 0).fill(params.socatPath ?? real.socat),
  )
  // Its own binds agree about the link.
  expect(wrapped).toContain(`--bind ${project} ${project}`)
  expect(wrapped).not.toContain(`--bind ${project}/dist`)
  // Only the scan finds the nested file: the real ripgrep ran.
  expect(wrapped).toContain(`${project}/nested/.bashrc`)
  if (BWRAP_CAN_NAMESPACE && !params.httpSocketPath) {
    const options = { shell: true, encoding: 'utf8' } as const
    expect(childProcess.spawnSync(wrapped, options).stdout).toBe('wrapped-ok\n')
  }
})

onLinux.each([
  ['bwrap', 'bwrapPath', undefined],
  ['socat', 'socatPath', undefined],
  ['bash', 'binShell', undefined],
  [HELPER, 'binShell', HELPER],
])('a wrap refuses for want of %s', async (helper, option, binShell) => {
  // Everything else it needs is there, outside the project.
  process.env.PATH = `${projectBin}:${tools(NAMES.filter(n => n !== helper))}`
  const error: unknown = await wrap({ ...RELAYED, binShell }).catch(
    (thrown: unknown) => thrown,
  )
  expect(error).toBeInstanceOf(linux.LinuxSandboxProfileError)
  expect(error).toMatchObject({
    code: 'host_helper_unavailable',
    message: refusal(helper, option),
    // The same as fields, for a caller that words its own message.
    cause: { helper, skipped: skipped(helper) },
  })
})

onLinux('a wrap goes on without a ripgrep, and says so', async () => {
  // The policy counts, not the working directory.
  process.chdir(safe)
  process.env.PATH = `${projectBin}:${tools(['bwrap', 'bash'])}`
  const { result, warnings } = await withCapturedWarnings(() =>
    wrap({}, [safe]),
  )
  expect(warnings.join()).toContain(
    `ripgrep scan failed: LinuxSandboxProfileError: ${refusal('rg', 'ripgrep.command')}`,
  )
  // What needs no scan is still denied.
  expect(result).toContain(`--ro-bind /dev/null ${safe}/.bashrc`)
})

onLinux('a wrap that restricts no write searches the whole PATH', async () => {
  process.chdir(project)
  process.env.PATH = `${tools(['bwrap'], `${project}/real`)}:${savedPath}`
  const unrestricted = { writeConfig: undefined, unsetEnvVars: ['X'] }
  expect(await wrap(unrestricted)).toStartWith(`${project}/real/bwrap `)
  // But for where the session's earlier commands could write.
  expect(await wrap({ ...unrestricted, alsoWritable: writable })).toStartWith(
    `${real.bwrap} `,
  )
})

const refusals = [
  refusal('rg', 'ripgrep.command'),
  refusal('bwrap', 'bwrapPath'),
  refusal('socat', 'socatPath'),
]

// In a process of its own: nothing takes a configuration out of the manager.
onLinux('with no configuration the checks judge by the cwd', () => {
  const { stdout } = childProcess.spawnSync(
    process.execPath,
    [
      '-e',
      `const { SandboxManager: s } = await import('${import.meta.dir}/../../src/index.ts')
       const checks = [s.checkDependencies(), await s.checkDependenciesAsync()]
       console.log(JSON.stringify(checks.map(check => check.errors)))`,
    ],
    { cwd: project, encoding: 'utf8', env: { PATH: projectBin } },
  )
  expect(JSON.parse(stdout)).toEqual([refusals, refusals])
})

onLinux.each([
  ['checkDependencies', SandboxManager.checkDependencies],
  ['checkDependenciesAsync', SandboxManager.checkDependenciesAsync],
])('%s takes a configuration it cannot read for none', async (_, check) => {
  SandboxManager.updateConfig({
    ...config,
    filesystem: { allowWrite: [{}] },
  } as never)
  process.chdir(project)
  process.env.PATH = `${projectBin}:${tools([])}`
  expect((await check()).errors).toEqual(refusals)
  expect(linux.checkLinuxDependencies().errors).toEqual(refusals.slice(1))
  expect(linux.getLinuxDependencyStatus().hasBwrap).toBe(false)
  // Of a helper that is nowhere it says what it always said.
  process.env.PATH = `${base}/real`
  expect((await check()).errors).toEqual([
    'ripgrep (rg) not found',
    'bubblewrap (bwrap) not installed',
    'socat not installed',
  ])
})

onLinux(
  'the manager judges by its configuration, and hands it on',
  async () => {
    process.env.PATH = `${projectBin}:${tools(['bwrap', 'socat'])}`
    expect(await SandboxManager.initialize(config).catch(String)).toBe(
      `Error: Sandbox dependencies not available: ${refusal('rg', 'ripgrep.command')}`,
    )
    const lookups = [
      spyOn(seccomp, 'getApplySeccompBinaryPath'),
      spyOn(seccomp, 'getApplySeccompBinaryPathAsync'),
      spyOn(javaAgent, 'getJavaProxyAgentJarPathAsync'),
    ]
    // The bridges run on the host: not the planted socat.
    process.env.PATH = `${projectBin}:${savedPath}`
    await SandboxManager.initialize(config)
    await wrap()
    linux.getLinuxDependencyStatus({ writable })
    // A call's own, narrower write paths do not clear the session's.
    const own = { ...config.filesystem, allowWrite: [elsewhere] }
    expect(
      await SandboxManager.wrapWithSandbox('true', undefined, {
        filesystem: own,
      }),
    ).toStartWith(`${real.bwrap} `)
    expect(lookups.map(lookup => lookup.mock.calls.length)).toEqual([4, 1, 1])
    for (const call of lookups.flatMap(lookup => lookup.mock.calls))
      expect(call[1]).toContain(project)
  },
)

onLinux('the dependency check warns of a helper named outright', () => {
  const { bwrapPath, socatPath, binShell: applyPath } = NAMED
  const command = `${projectBin}/rg`
  SandboxManager.updateConfig({
    ...config,
    ...{ bwrapPath, socatPath, ripgrep: { command }, seccomp: { applyPath } },
  })
  expect(SandboxManager.checkDependencies()).toEqual({
    errors: [],
    warnings: [
      `ripgrep.command ${command} is ${inProject}: ${replaceable}`,
      `bwrapPath ${bwrapPath} is ${inProject}: ${replaceable}`,
      `socatPath ${socatPath} is ${inProject}: ${replaceable}`,
      `seccomp.applyPath ${applyPath} is ${inProject}: ${replaceable}`,
    ],
  })
  // The bwrap it names is asked its version. The check runs nothing else.
  expect(fs.readFileSync(marker, 'utf8').split(`${bwrapPath}\n`).join('')).toBe(
    '',
  )
  fs.rmSync(marker)
})

// `npm root -g` is asked for a global install of this package. npm is a script
// and looks `node` up by name, so the rule is put to a PATH. Here neither file
// is in one of the package's own locations, and an npm outside the project
// answers.
function npmAnswers(): Mock<typeof hostSearchPath> {
  const script = `#!/bin/sh\necho '${base}/global'\n`
  fs.writeFileSync(`${safe}/npm`, script, { mode: 0o755 })
  link(`${projectBin}/node`, `${base}/linked/node`)
  process.env.PATH = `${projectBin}:${base}/linked:${safe}:${savedPath}`
  const existed = fs.existsSync
  spyOn(fs, 'existsSync').mockImplementation(
    file =>
      (String(file).startsWith(base) ||
        !/(apply-seccomp|\.jar)$/.test(String(file))) &&
      existed(file),
  )
  return spyOn(hostHelpers, 'hostSearchPath')
}

// Lookups are remembered by the path named: an absent one, each time another.
let lookups = 0
const absent = (): string => `${base}/absent-${lookups++}`

posix.each<(places?: string[]) => unknown>([
  seccomp.getGlobalNpmPaths,
  seccomp.getGlobalNpmPathsAsync,
  places => seccomp.getApplySeccompBinaryPath(absent(), places),
  places => seccomp.getApplySeccompBinaryPathAsync(absent(), places),
  places => javaAgent.getJavaProxyAgentJarPathAsync(absent(), places),
])('npm is looked up outside the write paths, and once: %#', async ask => {
  const searchPath = npmAnswers()
  // With no policy known the working directory counts.
  for (const places of [writable, undefined]) {
    if (!places) process.chdir(project)
    seccomp.resetGlobalNpmPathsForTesting()
    await ask(places)
    await ask(places)
  }
  expect(
    searchPath.mock.results.map(({ value }) => String(value).split(':')[0]),
  ).toEqual([safe, safe])
})

posix.each([
  seccomp.getApplySeccompBinaryPath,
  seccomp.getApplySeccompBinaryPathAsync,
])('a global install the command may write is passed over: %#', async find => {
  const helper = plant(
    `${base}/global/@anthropic-ai/sandbox-runtime/vendor/seccomp/${process.arch}/apply-seccomp`,
  )
  npmAnswers()
  const named = absent()
  expect(await find(named, [project, `${base}/global`])).toBeNull()
  // Remembered by the places it was judged by, too.
  expect(await find(named, writable)).toBe(helper)
})

posix('on Windows npm is given the environment as it is', () => {
  const execSync = spyOn(childProcess, 'execSync').mockReturnValue('')
  Object.defineProperty(process, 'platform', { value: 'win32' })
  seccomp.getGlobalNpmPaths(writable)
  expect(execSync.mock.calls[0]?.[1]?.env).toBe(process.env)
})

posix(
  'macOS: the shell, under sandbox-exec, is found on the whole PATH',
  () => {
    process.env.PATH = `${projectBin}:${savedPath}`
    const wrapped = macos.wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: [project], denyWithinAllow: [] },
    })
    expect(wrapped).toMatch(/^\/usr\/bin\/env .* \/usr\/bin\/sandbox-exec -p /s)
    expect(wrapped).toContain(` ${projectBin}/bash -c `)
  },
)

posix('macOS: the log monitor is spawned as /usr/bin/log', () => {
  const child = new EventEmitter() as never
  const spawn = spyOn(childProcess, 'spawn').mockReturnValue(child)
  macos.startMacOSSandboxLogMonitor(mock(), undefined, String)
  expect(spawn.mock.calls[0]?.[0]).toBe('/usr/bin/log')
})
