import { quote } from '../../src/utils/shell-quote.js'

/**
 * Argv indices of every whole `<flag> <source> <dest>` triple in a wrapped
 * command. Matching triples, not substrings, is what keeps a '/' assertion
 * honest: the base `--ro-bind / /` root mount spells the deny-side bind of
 * '/' exactly, so `lastIndexOf('--ro-bind / /')` finds the root mount and
 * passes even when the deny-side bind was never emitted.
 *
 * The command is a shell-quoted string, so this can only see a token the
 * wrapper emitted verbatim. A path that needs quoting is silently absent
 * from the split, which would make every absence assertion pass for free —
 * so such a token is refused outright rather than reported as 0 matches.
 */
function tripleIndices(
  command: string,
  flag: string,
  source: string,
  dest: string,
): number[] {
  for (const token of [flag, source, dest]) {
    if (quote([token]) !== token) {
      throw new Error(
        `bwrap-argv cannot match ${JSON.stringify(token)}: the wrapper shell-quotes it, so it is not one whitespace-separated argv token`,
      )
    }
  }
  const argv = command.split(/\s+/)
  const found: number[] = []
  for (let i = 0; i + 2 < argv.length; i++) {
    if (argv[i] === flag && argv[i + 1] === source && argv[i + 2] === dest) {
      found.push(i)
    }
  }
  return found
}

/** How many times that whole triple appears. */
export function countBinds(
  command: string,
  flag: string,
  source: string,
  dest: string,
): number {
  return tripleIndices(command, flag, source, dest).length
}

/**
 * Argv index of the first occurrence of that whole triple, or -1. Comparable
 * with another triple's index to assert mount order — but never with a
 * character offset from `String.indexOf`.
 */
export function indexOfTriple(
  command: string,
  flag: string,
  source: string,
  dest: string,
): number {
  return tripleIndices(command, flag, source, dest)[0] ?? -1
}

/** Argv index of the last occurrence of that whole triple, or -1. */
export function lastIndexOfTriple(
  command: string,
  flag: string,
  source: string,
  dest: string,
): number {
  return tripleIndices(command, flag, source, dest).at(-1) ?? -1
}
