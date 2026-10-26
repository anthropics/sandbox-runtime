#!/usr/bin/env python3
"""Mutation runner for PR 594's source. Works on a scratch copy of the repo.

usage: mutate.py [--repo DIR] [--only ID,ID] [--shard I/N] [--list]
Each mutation is (id, what, file, [(old, new), ...], extra test files).
`old` must occur exactly once. After each run: git checkout -- src.
"""
import argparse, os, re, subprocess, sys

HH = 'src/sandbox/host-helpers.ts'
WH = 'src/utils/which.ts'
LX = 'src/sandbox/linux-sandbox-utils.ts'
SM = 'src/sandbox/sandbox-manager.ts'
GS = 'src/sandbox/generate-seccomp-filter.ts'
JA = 'src/sandbox/java-proxy-agent.ts'
MC = 'src/sandbox/macos-sandbox-utils.ts'
RP = 'src/utils/real-path.ts'

TESTS = [
    'test/sandbox/host-helpers.test.ts',
    'test/utils/which.test.ts',
    'test/sandbox/check-dependencies.test.ts',
    'test/sandbox/linux-dependency-error.test.ts',
    'test/sandbox/own-files.test.ts',
    'test/sandbox/java-proxy-agent.test.ts',
    'test/sandbox/credential-deny.test.ts',
]
REAL_PATH = ['test/utils/real-path.test.ts']
NODE = 'NODE'  # also run test/utils/which-node-test.mjs

M = []


def m(id, what, file, pairs, extra=()):
    if isinstance(pairs, tuple):
        pairs = [pairs]
    M.append((id, what, file, pairs, list(extra)))


# ---------------------------------------------------------------- host-helpers
m('HH01', "'anywhere' no longer gives the empty list", HH,
  ("  if (allowedWritePaths === 'anywhere') return []\n", ''))
m('HH02', 'policy unknown: the working directory is left out', HH,
  ('    ...(cwd === undefined ? [] : [cwd]),\n', ''))
m('HH03', 'policy unknown: the default write paths are left out', HH,
  ('    ...getDefaultWritePaths(),\n', ''))
m('HH04', 'policy unknown: process.cwd() asked outright (throws when gone)', HH,
  ('const cwd = workingDirectory()', 'const cwd = process.cwd()'))
m('HH05', 'a pattern is not cut to the directory it starts from', HH,
  ('containsGlobChars(normalized)\n      ? globPatternBaseDir(normalized)\n      : normalized', 'normalized'))
m('HH08', 'a spelling that is not absolute is kept', HH,
  ('    if (!path.isAbsolute(normalized)) continue\n', ''))
m('HH09', "a list naming '/' does not give the empty list", HH,
  ("    if (globBaseDirIsRoot(place)) return []\n", ''))
m('HH10', "only '/' itself gives the empty list, not a pattern from the root", HH,
  ("if (globBaseDirIsRoot(place)) return []", "if (place === '/') return []"))
m('HH13', 'no short cut for the empty list', HH,
  ('  if (writable.length === 0) return undefined\n', ''))
m('HH14', 'the file as spelled is not judged', HH,
  ('const places = [file]', 'const places: string[] = []'))
m('HH15', 'links followed are not judged', HH,
  ('{ link: note, left: note }', '{ left: note }'))
m('HH16', 'directories gone up from are not judged', HH,
  ('{ link: note, left: note }', '{ link: note }'))
m('HH17', 'the real file is not judged', HH,
  ('    places.push(real)\n', ''))
m('HH18', 'a way that ends at a missing name counts as followed', HH,
  ('followed = notThere === undefined', 'followed = true'))
m('HH19', 'a way that throws counts as followed', HH,
  ('let followed = false', 'let followed = true'))
m('HH20', 'compared by prefix of the text, not by segment', HH,
  ('writable.find(w => isAtOrUnder(place, w))', 'writable.find(w => place.startsWith(w))'))
m('HH21', "the reason never says 'leads through'", HH,
  ("${place === file ? '' : `leads through ${place}, `}inside", 'inside'))
m('HH22', 'the refusal carries no writePath', HH,
  ('inside the allowed write path ${writePath}`,\n        writePath,\n', 'inside the allowed write path ${writePath}`,\n'))
m('HH23', 'what cannot be followed is accepted', HH,
  ("return followed ? undefined : { reason: 'it could not be followed to a file' }", 'return undefined'))
m('HH24', "other words for 'it could not be followed to a file'", HH,
  ("{ reason: 'it could not be followed to a file' }", "{ reason: 'not followed' }"))
m('HH25', 'a path-qualified name is searched for', HH,
  ('  if (isPathQualified(name)) return { path: whichSync(name), skipped: [] }\n', ''))
m('HH26', 'a path-qualified name is judged like a found one', HH,
  ('if (isPathQualified(name)) return { path: whichSync(name), skipped: [] }',
   'if (isPathQualified(name)) return { path: isOutside(name, writable) ? whichSync(name) : null, skipped: [] }'))
m('HH27', 'what is no executable file is a candidate', HH,
  ('    if (!isExecutableFile(file)) continue\n', ''))
m('HH28', 'a relative PATH entry is judged like any other', HH,
  ('const refusal = path.isAbsolute(entry)\n      ? refusalFor(file, writable)\n      : { reason: `the PATH entry \'${entry}\' is relative` }',
   'const refusal = refusalFor(file, writable)'))
m('HH29', 'what was passed over is not recorded', HH,
  ('    skipped.push({ path: file, ...refusal })\n', ''))
m('HH30', 'none left: falls back to the bare name', HH,
  ('  return { path: null, skipped }\n', '  return { path: name, skipped }\n'))
m('HH31', 'hostSearchPath keeps relative entries', HH,
  ('    path.isAbsolute(entry) &&\n', ''))
m('HH32', 'hostSearchPath does not judge the entry as a directory', HH,
  ('    isOutside(entry, writable) &&\n', ''))
m('HH33', 'hostSearchPath does not judge the copies of the programs', HH,
  ('      return isOutside(file, writable)\n', '      return true\n'))
m('HH34', 'hostSearchPath: a dangling link is not judged (stat for lstat)', HH,
  ('fs.lstatSync(file)', 'fs.statSync(file)'))
m('HH35', 'hostSearchPath: an entry without the program is left out', HH,
  ('      } catch {\n        return true\n      }', '      } catch {\n        return false\n      }'))
m('HH36', 'hostSearchPath folds `..` in text', HH,
  ('const file = `${entry}/${program}`', 'const file = path.join(entry, program)'))
m('HH37', 'hostSearchPath may be empty', HH,
  (" ||\n    '/dev/null'\n", '\n'))
m('HH38', 'hostSearchPath throws on an unset PATH', HH,
  ("(process.env.PATH ?? '')", 'process.env.PATH!'))
m('HH39', 'the refusal: nothing skipped is not told apart', HH,
  ('  if (skipped.length === 0) return nowhere\n', ''))
m('HH40', 'the refusal: a path gets the words of a name', HH,
  ('nowhere = isPathQualified(helper)\n    ? `${helper} is not an executable file`\n    : `${helper} was not found on PATH`',
   'nowhere = `${helper} was not found on PATH`'))
m('HH41', 'the refusal: other opening words', HH,
  ('`${helper} was not found on PATH outside the paths', '`${helper} is not on PATH outside the paths'))
m('HH42', 'the refusal: reasons left out', HH,
  ('`${s.path} (${s.reason})`', '`${s.path}`'))
m('HH43', 'the refusal: does not name the option', HH,
  ('or name it by its path with ${option}.', 'or name it by its path.'))
m('HH44', 'the warning is given for a bare name', HH,
  ('file && isPathQualified(file) && refusalFor', 'file && refusalFor'))
m('HH45', 'the warning is given for what could not be followed', HH,
  ('return refusal && refusal.writePath !== undefined', 'return refusal'))
m('HH46', 'the warning: a relative name is not resolved', HH,
  ('refusalFor(path.resolve(file), writable)', 'refusalFor(file, writable)'))
m('HH47', "the warning: 'inside' not made 'is inside'", HH,
  (".replace(/^inside/, 'is inside')", ''))

# ----------------------------------------------------------------------- which
m('WH01', 'no name is path-qualified', WH,
  ("return bin.includes('/') || bin.includes(path.sep)", 'return false'), [NODE])
m('WH02', 'the execute bit is not asked for', WH,
  ('    fs.accessSync(file, fs.constants.X_OK)\n', ''), [NODE])
m('WH03', 'a directory is an executable file', WH,
  ('return fs.statSync(file).isFile()', 'return fs.statSync(file) !== undefined'), [NODE])
m('WH04', 'the empty entry is the root', WH,
  ("`${entry || '.'}${path.sep}${bin}`", '`${entry}${path.sep}${bin}`'), [NODE])
m('WH05', 'an empty PATH is one empty entry', WH,
  ('(process.env.PATH || undefined)?.split', "(process.env.PATH ?? '').split"), [NODE])
m('WH06', 'candidates are path.resolve()d', WH,
  ("file: `${entry || '.'}${path.sep}${bin}`", 'file: path.resolve(entry, bin)'), [NODE])
m('WH07', 'candidates are path.join()ed', WH,
  ("file: `${entry || '.'}${path.sep}${bin}`", "file: path.join(entry || '.', bin)"), [NODE])
m('WH08', 'a path-qualified name is not checked', WH,
  ('if (isPathQualified(bin)) return isExecutableFile(bin) ? bin : null', 'if (isPathQualified(bin)) return bin'), [NODE])
m('WH09', 'Bun.which again (the PATH the process started with)', WH,
  ('  if (isPathQualified(bin)) return isExecutableFile(bin) ? bin : null\n',
   "  if (typeof globalThis.Bun !== 'undefined') return globalThis.Bun.which(bin)\n  if (isPathQualified(bin)) return isExecutableFile(bin) ? bin : null\n"), [NODE])
m('WH10', 'under Node a `which` program is run again', WH,
  [("import * as path from 'node:path'\n", "import * as path from 'node:path'\nimport { spawnSync } from 'node:child_process'\n"),
   ('  if (isPathQualified(bin)) return isExecutableFile(bin) ? bin : null\n',
    "  if (typeof globalThis.Bun === 'undefined') {\n    const r = spawnSync('which', [bin], { encoding: 'utf8' })\n    return r.status === 0 && r.stdout ? r.stdout.trim() : null\n  }\n  if (isPathQualified(bin)) return isExecutableFile(bin) ? bin : null\n")], [NODE])
m('WH11', 'the last candidate wins', WH,
  ('pathCandidates(bin).find(', 'pathCandidates(bin).reverse().find('), [NODE])

# ----------------------------------------------------------------------- linux
m('LX01', "the wrap's bwrap: the bare name", LX,
  ("bwrapPath ?? requireHostHelper('bwrap', 'bwrapPath', writable)", "bwrapPath ?? 'bwrap'"))
m('LX02', "the wrap's shell: the plain search", LX,
  ("const shell = requireHostHelper(binShell || 'bash', 'binShell', writable)",
   "const shell = requireHostHelper(binShell || 'bash', 'binShell', [])"))
m('LX03', "the wrap's shell: binShell ignored", LX,
  ("requireHostHelper(binShell || 'bash', 'binShell', writable)", "requireHostHelper('bash', 'binShell', writable)"))
m('LX04', "the wrap's socat: the bare name", LX,
  ("        socatPath ?? requireHostHelper('socat', 'socatPath', writable),\n      )", "        socatPath ?? 'socat',\n      )"))
m('LX05', "the wrap's write paths: allowOnly as handed in, literal entries not counted", LX,
  ("writeConfig ? writeRootsOf(writeConfig) : 'anywhere',", "writeConfig ? (params.writeConfig?.allowOnly ?? []) : 'anywhere',"))
m('LX06', 'no write restriction: judged as a policy not known', LX,
  ("writeConfig ? writeRootsOf(writeConfig) : 'anywhere',", 'writeConfig ? writeRootsOf(writeConfig) : undefined,'))
m('LX09', 'a ripgrep not to be had is hard: the wrap throws', LX,
  ('    signal.throwIfAborted()\n    // INVARIANT: what ripgrep listed counts',
   '    signal.throwIfAborted()\n    if (error instanceof LinuxSandboxProfileError) throw error\n    // INVARIANT: what ripgrep listed counts'))
m('LX10', 'the scan spawns ripgrep by the name given', LX,
  ("        command: requireHostHelper(\n          ripgrepConfig.command,\n          'ripgrep.command',\n          writable,\n        ),\n",
   '        command: ripgrepConfig.command,\n'))
m('LX11', "the scan judges by the default places, not the wrap's", LX,
  ('        abortSignal,\n        writablePlaces(writeRootsOf(writeConfig)),\n', '        abortSignal,\n'))
m('LX12', 'a failed scan loses the cwd-level denies', LX,
  ("    logForDebugging(`[Sandbox] ripgrep scan failed: ${error}`, {\n      level: 'warn',\n    })\n",
   "    logForDebugging(`[Sandbox] ripgrep scan failed: ${error}`, {\n      level: 'warn',\n    })\n    if (error instanceof LinuxSandboxProfileError) return []\n"))
m('LX13', 'a failed scan is not warned about', LX,
  ("    logForDebugging(`[Sandbox] ripgrep scan failed: ${error}`, {\n      level: 'warn',\n    })\n", ''))
m('LX14', 'checkLinuxDependencies, places omitted: nothing passed over', LX,
  ("  const { seccompConfig, bwrapPath, socatPath } = opts ?? {}\n  const writable = opts?.writable ?? writablePlaces(undefined)\n  const errors",
   "  const { seccompConfig, bwrapPath, socatPath } = opts ?? {}\n  const writable = opts?.writable ?? []\n  const errors"))
m('LX15', 'getLinuxDependencyStatus, places omitted: nothing passed over', LX,
  ("  const writable = opts?.writable ?? writablePlaces(undefined)\n  const onPath = (helper: string): boolean", "  const writable = opts?.writable ?? []\n  const onPath = (helper: string): boolean"))
m('LX16', 'getLinuxDependencyStatus: the plain search', LX,
  ('    findHostHelper(helper, writable).path !== null\n', '    findHostHelper(helper, []).path !== null\n'))
m('LX17', 'checkLinuxDependencies: the plain search', LX,
  ('    const search = findHostHelper(helper, writable)\n    if (search.path === null) {\n      errors.push(',
   '    const search = findHostHelper(helper, [])\n    if (search.path === null) {\n      errors.push('))
m('LX18', "checkLinuxDependencies: main's words for a helper that is nowhere are lost", LX,
  ('describeUnavailableHostHelper(helper, option, search, notInstalled),', 'describeUnavailableHostHelper(helper, option, search),'))
m('LX19', 'checkLinuxDependencies: no warning about a named helper', LX,
  ('    if (warning !== undefined) warnings.push(warning)\n  }\n\n  const uid0Error', '    void warning\n  }\n\n  const uid0Error'))
m('LX20', 'checkLinuxDependencies: seccomp.applyPath is not warned about', LX,
  ("    ['seccomp.applyPath', seccompConfig?.applyPath],\n", ''))
m('LX21', 'checkLinuxDependencies: apply-seccomp looked up without the places', LX,
  ("    !seccompConfig?.argv0 &&\n    getApplySeccompBinaryPath(seccompConfig?.applyPath, writable) === null",
   "    !seccompConfig?.argv0 &&\n    getApplySeccompBinaryPath(seccompConfig?.applyPath) === null"))
m('LX22', 'getLinuxDependencyStatus: apply-seccomp looked up without the places', LX,
  ('      : getApplySeccompBinaryPath(seccompConfig?.applyPath, writable) !== null,',
   '      : getApplySeccompBinaryPath(seccompConfig?.applyPath) !== null,'))
m('LX23', 'the wrap: apply-seccomp looked up without the places', LX,
  ('  const binary = getApplySeccompBinaryPath(applyPath, writable)\n', '  const binary = getApplySeccompBinaryPath(applyPath)\n'))
m('LX24', 'the bridges: socat by the bare name', LX,
  ("const socat = socatPath ?? requireHostHelper('socat', 'socatPath', writable)", "const socat = socatPath ?? 'socat'"))
m('LX25', "--disable-userns is asked of PATH's bwrap", LX,
  [("import { realPathOf, wayTo } from '../utils/real-path.js'\n", "import { realPathOf, wayTo } from '../utils/real-path.js'\nimport { whichSync } from '../utils/which.js'\n"),
   ('bwrapCanDisableUserns(bwrapBinary)', "bwrapCanDisableUserns(whichSync('bwrap') ?? '')")])
m('LX26', "the uid-0 probe runs a bare 'true' inside", LX,
  ("['--unshare-user', '--dev-bind', '/', '/', bwrap, '--version'],", "['--unshare-user', '--dev-bind', '/', '/', 'true'],"))
m('LX27', 'the typed refusal has another code', LX,
  ("    throw new LinuxSandboxProfileError(\n      'host_helper_unavailable',", "    throw new LinuxSandboxProfileError(\n      'too_many_arguments',"))
m('LX28', 'the typed refusal has no cause', LX,
  ('      { helper, skipped: search.skipped },\n', ''))
m('LX29', 'the relays name socat by the bare name', LX,
  ('const socat = quote([socatPath])', "const socat = 'socat'"))
m('LX30', 'the wrapped string names bwrap by the bare name', LX,
  ('renderBwrapInvocation(bwrapBinary, bwrapArgs, mounts)', "renderBwrapInvocation(bwrapPath ?? 'bwrap', bwrapArgs, mounts)"))
m('LX31', 'the wrapped string names the shell by the bare name', LX,
  ("bwrapArgs.push('--', shell, '-c')", "bwrapArgs.push('--', binShell || 'bash', '-c')"))
m('LX32', 'the bridges, places omitted: nothing passed over', LX,
  ('  socatPath?: string,\n  writable: WritablePlaces = writablePlaces(undefined),\n): Promise<LinuxNetworkBridgeContext>',
   '  socatPath?: string,\n  writable: WritablePlaces = [],\n): Promise<LinuxNetworkBridgeContext>'))
m('LX33', 'the refusal of the wrap names another option for the shell', LX,
  ("requireHostHelper(binShell || 'bash', 'binShell', writable)", "requireHostHelper(binShell || 'bash', 'shell', writable)"))

# --------------------------------------------------------------------- manager
m('SM02', 'Windows is not asked by hostWritablePlaces', SM,
  ("  if (getPlatform() === 'windows') return writablePlaces('anywhere')\n", ''))
m('SM03', "no configuration counts as 'anywhere'", SM,
  ('return writablePlaces(config && writeRootsOf(getFsWriteConfig()))', "return writablePlaces(config ? writeRootsOf(getFsWriteConfig()) : 'anywhere')"))
m('SM04', 'no configuration: the default write paths alone (no working directory)', SM,
  ('return writablePlaces(config && writeRootsOf(getFsWriteConfig()))', 'return writablePlaces(writeRootsOf(getFsWriteConfig()))'))
m('SM05', 'a configuration that cannot be read makes the check throw', SM,
  ('  } catch {\n    return writablePlaces(undefined)\n  }', '  } catch (e) {\n    throw e\n  }'))
m('SM06', "a configuration that cannot be read counts as 'anywhere'", SM,
  ('  } catch {\n    return writablePlaces(undefined)\n  }', "  } catch {\n    return writablePlaces('anywhere')\n  }"))
m('SM07', "the manager's ripgrep: the plain search", SM,
  ('const search = findHostHelper(rgToCheck.command, writable)', 'const search = findHostHelper(rgToCheck.command, [])'))
m('SM08', "the manager's ripgrep: main's words are lost", SM,
  ('          search,\n          `ripgrep (${rgToCheck.command}) not found`,\n', '          search,\n'))
m('SM09', "the manager's ripgrep: no warning about a named one", SM,
  ("    if (warning !== undefined) warnings.push(warning)\n\n    const linuxDeps", '    void warning\n\n    const linuxDeps'))
m('SM10', 'the manager does not hand its places to checkLinuxDependencies', SM,
  ('      socatPath: config?.socatPath,\n      writable,\n', '      socatPath: config?.socatPath,\n'))
m('SM11', 'checkDependenciesAsync looks apply-seccomp up without the places', SM,
  ('      config?.seccomp?.applyPath,\n      hostWritablePlaces(),\n', '      config?.seccomp?.applyPath,\n'))
m('SM12', 'initialize() looks the jar up without the places', SM,
  ('          config.javaAgentJarPath,\n          hostWritablePlaces(),\n', '          config.javaAgentJarPath,\n'))
m('SM13', 'initialize() starts the bridges without the places', SM,
  ('          config.socatPath,\n          hostWritablePlaces(),\n', '          config.socatPath,\n'))

# --------------------------------------------------------------------- seccomp
m('GS01', 'win32: the environment is filtered too', GS,
  ("  return process.platform === 'win32'\n    ? process.env\n    : { ...process.env, PATH: hostSearchPath(writable, ['npm', 'node']) }",
   "  return { ...process.env, PATH: hostSearchPath(writable, ['npm', 'node']) }"))
m('GS02', 'sync: npm runs with the PATH as it is', GS,
  ("      stdio: ['pipe', 'pipe', 'ignore'],\n      env: npmEnvironment(writable),\n", "      stdio: ['pipe', 'pipe', 'ignore'],\n"))
m('GS03', 'async: npm runs with the PATH as it is', GS,
  ('          timeout: NPM_ROOT_TIMEOUT_MS,\n          env: npmEnvironment(writable),\n', '          timeout: NPM_ROOT_TIMEOUT_MS,\n'))
m('GS04', "an entry's copy of node is not judged", GS,
  ("hostSearchPath(writable, ['npm', 'node'])", "hostSearchPath(writable, ['npm'])"))
m('GS05', 'sync: the PATH is computed whether or not npm is run', GS,
  [('): string[] {\n  if (cachedGlobalNpmPaths) return cachedGlobalNpmPaths\n', '): string[] {\n  const env = npmEnvironment(writable)\n  if (cachedGlobalNpmPaths) return cachedGlobalNpmPaths\n'),
   ("      stdio: ['pipe', 'pipe', 'ignore'],\n      env: npmEnvironment(writable),\n", "      stdio: ['pipe', 'pipe', 'ignore'],\n      env,\n")])
m('GS06', 'async: the PATH is computed whether or not npm is run', GS,
  [('): Promise<string[]> {\n  if (cachedGlobalNpmPaths) return Promise.resolve(cachedGlobalNpmPaths)\n', '): Promise<string[]> {\n  const env = npmEnvironment(writable)\n  if (cachedGlobalNpmPaths) return Promise.resolve(cachedGlobalNpmPaths)\n'),
   ('          timeout: NPM_ROOT_TIMEOUT_MS,\n          env: npmEnvironment(writable),\n', '          timeout: NPM_ROOT_TIMEOUT_MS,\n          env,\n')])
m('GS07', 'sync: remembered by applyPath alone', GS,
  ("): string | null {\n  const cacheKey = [seccompBinaryPath, ...writable].join('\\0')", "): string | null {\n  const cacheKey = seccompBinaryPath ?? ''"))
m('GS08', 'async: remembered by applyPath alone', GS,
  ("): Promise<string | null> {\n  const cacheKey = [seccompBinaryPath, ...writable].join('\\0')", "): Promise<string | null> {\n  const cacheKey = seccompBinaryPath ?? ''"))
m('GS09', 'a global install the command may write is taken', GS,
  ('if (fs.existsSync(binaryPath) && isOutside(binaryPath, writable)) {', 'if (fs.existsSync(binaryPath)) {'))
m('GS10', 'sync: npm is asked without the places', GS,
  ('findGlobalApplySeccompPath(getGlobalNpmPaths(writable), writable)', 'findGlobalApplySeccompPath(getGlobalNpmPaths(), writable)'))
m('GS11', 'async: npm is asked without the places', GS,
  ('          await getGlobalNpmPathsAsync(writable),\n', '          await getGlobalNpmPathsAsync(),\n'))
m('GS12', 'getGlobalNpmPaths, places omitted: the PATH as it is', GS,
  ('export function getGlobalNpmPaths(\n  writable: WritablePlaces = writablePlaces(undefined),', 'export function getGlobalNpmPaths(\n  writable: WritablePlaces = [],'))
m('GS13', 'getGlobalNpmPathsAsync, places omitted: the PATH as it is', GS,
  ('export function getGlobalNpmPathsAsync(\n  writable: WritablePlaces = writablePlaces(undefined),', 'export function getGlobalNpmPathsAsync(\n  writable: WritablePlaces = [],'))
m('GS14', 'getApplySeccompBinaryPath, places omitted: nothing passed over', GS,
  ('  seccompBinaryPath?: string,\n  writable: WritablePlaces = writablePlaces(undefined),\n): string | null {', '  seccompBinaryPath?: string,\n  writable: WritablePlaces = [],\n): string | null {'))
m('GS15', 'getApplySeccompBinaryPathAsync, places omitted: nothing passed over', GS,
  ('  seccompBinaryPath?: string,\n  writable: WritablePlaces = writablePlaces(undefined),\n): Promise<string | null> {', '  seccompBinaryPath?: string,\n  writable: WritablePlaces = [],\n): Promise<string | null> {'))

# ------------------------------------------------------------------ java, macOS
m('JA01', 'the jar: npm is asked without the places', JA,
  ('findGlobalJar(await getGlobalNpmPathsAsync(writable))', 'findGlobalJar(await getGlobalNpmPathsAsync())'))
m('JA02', 'the jar, places omitted: the PATH as it is', JA,
  ('  writable: WritablePlaces = writablePlaces(undefined),', '  writable: WritablePlaces = [],'))
m('MC01', "macOS: a bare 'env'", MC, ("    '/usr/bin/env',\n", "    'env',\n"))
m('MC02', "macOS: a bare 'log'", MC, ("spawn('/usr/bin/log', [", "spawn('log', ["))
m('MC03', 'macOS: the shell is found like a host helper', MC,
  [("import { whichSync } from '../utils/which.js'\n", "import { whichSync } from '../utils/which.js'\nimport { findHostHelper, writablePlaces } from './host-helpers.js'\n"),
   ('const shell = whichSync(shellName)', "const shell = findHostHelper(shellName, writablePlaces(writeConfig?.allowOnly ?? 'anywhere')).path ?? (whichSync('') as null)")])

# ------------------------------------------------------------------- real-path
m('RP01', 'wayTo tells of no link', RP, ('    watcher.link?.(next, target)\n', ''), REAL_PATH)
m('RP02', 'wayTo tells of no directory left', RP, ('        watcher.left?.(real)\n', ''), REAL_PATH)
m('RP03', "wayTo: `..` at the root is told of ('' left)", RP, ("if (name === '..' && real !== '') {", "if (name === '..') {"), REAL_PATH)
m('RP04', 'EILSEQ carries no path', RP, ("      code: 'EILSEQ',\n      path: at,\n", "      code: 'EILSEQ',\n"), REAL_PATH)
m('RP05', 'wayPastMissingNames always throws', RP,
  ('  const passed: string[] = []\n  let onward = folded\n', "  const passed: string[] = []\n  let onward = folded\n  if (onward) throw new Error('mutant')\n"), REAL_PATH)


def run(cmd, cwd, env, timeout=300):
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired as e:
        return 124, 'TIMEOUT ' + str(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', default='/tmp/claude-1000/tests594')
    ap.add_argument('--only')
    ap.add_argument('--shard')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--verbose', action='store_true')
    ap.add_argument('--check', action='store_true')
    a = ap.parse_args()
    todo = M
    if a.only:
        want = a.only.split(',')
        todo = [x for x in M if any(x[0].startswith(w) for w in want)]
    if a.shard:
        i, n = map(int, a.shard.split('/'))
        todo = [x for k, x in enumerate(todo) if k % n == i]
    if a.list:
        for x in todo:
            print(x[0], x[1])
        print(len(todo))
        return
    if a.check:
        for id, what, file, pairs, extra in todo:
            text = open(os.path.join(a.repo, file)).read()
            for old, _ in pairs:
                if text.count(old) != 1:
                    print(id, text.count(old), repr(old[:70]))
        print('checked', len(todo))
        return
    env = dict(os.environ)
    env['PATH'] = '/opt/srt-stubs:' + env['PATH']
    dirty = subprocess.run(['git', 'status', '--porcelain', '--', 'src'], cwd=a.repo, capture_output=True, text=True).stdout
    if dirty.strip():
        sys.exit('src is dirty:\n' + dirty)
    survivors = []
    for id, what, file, pairs, extra in todo:
        p = os.path.join(a.repo, file)
        text = open(p).read()
        bad = [old for old, _ in pairs if text.count(old) != 1]
        if bad:
            print(f'{id} | CANNOT APPLY ({text.count(bad[0])} matches): {bad[0][:60]!r}', flush=True)
            continue
        for old, new in pairs:
            text = text.replace(old, new)
        open(p, 'w').write(text)
        try:
            tests = TESTS + [t for t in extra if t != NODE]
            code, out = run(['bun', 'test', *tests], a.repo, env)
            fails = {}
            current = '?'
            for line in out.splitlines():
                h = re.match(r'^(test/\S+):$', line)
                if h:
                    current = os.path.basename(h.group(1)).replace('.test.ts', '')
                if line.startswith('(fail)'):
                    fails[current] = fails.get(current, 0) + 1
            if code != 0 and not fails:
                fails['(run failed)'] = 1
            node = ''
            if NODE in extra:
                ncode, nout = run(['node', 'test/utils/which-node-test.mjs'], a.repo, env)
                built = 'Build failed' not in nout
                node = f' | node: {"caught" if ncode != 0 and built else "BUILD FAILED" if not built else "passes"}'
                if ncode != 0 and built:
                    fails['which-node'] = 1
            total = sum(fails.values())
            by = ', '.join(f'{k} {v}' for k, v in fails.items())
            print(f'{id} | {what} | {total if total else "SURVIVES"} | {by}{node}', flush=True)
            if a.verbose:
                print('\n'.join(l for l in out.splitlines() if l.startswith('(fail)')))
            if not total:
                survivors.append(id)
        finally:
            subprocess.run(['git', 'checkout', '--', 'src'], cwd=a.repo, check=True)
    print(f'{len(todo)} mutations, {len(survivors)} survive: {" ".join(survivors)}')


main()
