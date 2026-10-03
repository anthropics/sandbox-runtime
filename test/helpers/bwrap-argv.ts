import { existsSync, realpathSync } from 'node:fs'
import { basename } from 'node:path'
import { quote } from '../../src/utils/shell-quote.js'

/** The $0 renderBwrapInvocation gives the shell that opens an over-long
 * profile's argument file. Its presence means the mount words are in that
 * file and not in the command. */
const ARGS_FILE_ARGV0 = 'srt-args'

/**
 * How a wrapped command that takes steps of its own before bubblewrap begins, on
 * this host: bash where it is at one of its two usual places, else /bin/sh.
 */
export const STEP_SHELL = ((): string => {
  const bash =
    ['/bin/bash', '/usr/bin/bash'].find(shell => existsSync(shell)) ??
    ['/bin/sh'].find(shell => basename(realpathSync(shell)) === 'bash')
  return bash === undefined ? '/bin/sh -c' : `${bash} -p -c`
})()

/** The step that puts the command on its manifest's started record. */
export const RECORD_STEP =
  'read -r s </proc/self/stat && printf "%s\\n" "$s" >>"$1" && shift'

/** The mount flags this generator emits with a source and a destination. */
const MOUNT_FLAGS = ['--bind', '--ro-bind']

/** How many words follow each mount flag this generator emits. */
const MOUNT_ARITY: Record<string, number> = {
  '--bind': 2,
  '--ro-bind': 2,
  '--dev-bind': 2,
  '--tmpfs': 1,
  '--dev': 1,
  '--proc': 1,
}

/**
 * A whole mount, in the two shapes bwrap is given here: a destination-only
 * `--tmpfs`, or a flag with a source and a destination. Spelling them out is
 * what keeps an absence assertion honest — a run of any length would let a
 * typo'd flag, or a transposed source and destination, match nothing and
 * report 0 for free.
 */
type MountWords = ['--tmpfs', string] | ['--bind' | '--ro-bind', string, string]

/**
 * The wrapped command as argv words. Refused when the mounts went to the
 * argument file, where nothing below can see them: every absence assertion
 * would otherwise pass for free.
 */
function argvOf(command: string): string[] {
  const argv = command.split(/\s+/)
  if (argv.includes(ARGS_FILE_ARGV0)) {
    throw new Error(
      'bwrap-argv cannot read this command: the profile was too long for the command line, so its mount words are in the argument file',
    )
  }
  return argv
}

/**
 * The command is a shell-quoted string, so this can only see a token the
 * wrapper emitted verbatim. A path that needs quoting is silently absent
 * from the split, which would make every absence assertion pass for free —
 * so such a token is refused outright rather than reported as 0 matches.
 */
function assertLiteralToken(token: string): void {
  if (quote([token]) !== token) {
    throw new Error(
      `bwrap-argv cannot match ${JSON.stringify(token)}: the wrapper shell-quotes it, so it is not one whitespace-separated argv token`,
    )
  }
}

/**
 * Argv indices of every run of adjacent words equal to `words`. Matching a
 * run, not a substring, is what keeps a '/' assertion honest: the base
 * `--ro-bind / /` root mount spells the deny-side bind of '/' exactly, so
 * `lastIndexOf('--ro-bind / /')` finds the root mount and passes even when
 * the deny-side bind was never emitted.
 */
function runIndices(command: string, words: readonly string[]): number[] {
  for (const token of words) assertLiteralToken(token)
  const argv = argvOf(command)
  const found: number[] = []
  for (let i = 0; i + words.length <= argv.length; i++) {
    if (words.every((word, offset) => argv[i + offset] === word)) found.push(i)
  }
  return found
}

/**
 * The manifest the wrap recorded its mount points in, by the started record
 * the command's own shell is given, or `undefined` for a wrap that recorded
 * none.
 */
export function manifestOf(command: string): string | undefined {
  const id = / srt(?:-args)? (\S+)\.started /.exec(command)?.[1]
  return id === undefined ? undefined : `${id}.json`
}

/**
 * The bubblewrap the command runs, as the wrap spelled it: the first word, or
 * the word after the steps the command's own shell takes first.
 */
export function bwrapOf(command: string): string | undefined {
  return command.split(' ').find(word => /(^|\/)bwrap$/.test(word))
}

/** How many times that whole mount appears. */
export function countMounts(command: string, ...words: MountWords): number {
  return runIndices(command, words).length
}

/**
 * Argv index of the first occurrence of that whole mount, or -1. Comparable
 * with another mount's index to assert mount order — but never with a
 * character offset from `String.indexOf`.
 */
export function indexOfMount(command: string, ...words: MountWords): number {
  return runIndices(command, words)[0] ?? -1
}

/**
 * Every mount the command carries, in emission order, each as the words
 * bwrap is given for it. Compare as a MULTISET: the mandatory-deny scan
 * takes ripgrep's hits in thread order, so that order varies run to run.
 */
export function mountsOf(command: string): string[] {
  const argv = argvOf(command)
  const mounts: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i]
    if (flag === undefined) continue
    const arity = MOUNT_ARITY[flag]
    if (arity === undefined) continue
    const words = argv.slice(i, i + 1 + arity)
    if (words.length === 1 + arity) mounts.push(words.join(' '))
  }
  return mounts
}

/** Argv index of the last occurrence of that whole mount, or -1. */
export function lastIndexOfMount(
  command: string,
  ...words: MountWords
): number {
  return runIndices(command, words).at(-1) ?? -1
}

/**
 * The last mount whose destination is exactly `dest`, as the words it was
 * emitted with. That is what the sandbox sees there only if nothing later
 * mounts over an ANCESTOR of it, which this does not look for. Scanning argv
 * words rather than `lastIndexOf` keeps a path that appears as a mount
 * SOURCE from passing for a mount at that destination; `--tmpfs` takes a
 * destination alone and needs its own arm.
 */
export function lastMountAt(command: string, dest: string): string | undefined {
  assertLiteralToken(dest)
  const argv = argvOf(command)
  let last: string | undefined
  for (let i = 0; i + 1 < argv.length; i++) {
    if (argv[i] === '--tmpfs' && argv[i + 1] === dest) {
      last = `--tmpfs ${dest}`
    } else if (MOUNT_FLAGS.includes(argv[i]) && argv[i + 2] === dest) {
      last = `${argv[i]} ${argv[i + 1]} ${argv[i + 2]}`
    }
  }
  return last
}
