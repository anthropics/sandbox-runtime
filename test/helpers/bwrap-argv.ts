/**
 * Occurrences of one whole `<flag> <source> <dest>` argv triple in a wrapped
 * command. Counting triples, not substrings, is what keeps a '/' assertion
 * honest: the base `--ro-bind / /` root mount spells the deny-side bind of
 * '/' exactly, so `lastIndexOf('--ro-bind / /')` finds the root mount and
 * passes even when the deny-side bind was never emitted.
 */
export function countBinds(
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
