import * as fs from 'node:fs'
import * as path from 'node:path'

/** As many links as the kernel follows on the way to one path. */
const MAX_LINKS = 40

/**
 * `p` with every symbolic link on the way to it resolved, as
 * `fs.realpathSync` gives it, whatever characters its names hold.
 *
 * Off Windows a backslash is a character of a name like any other, and
 * runtimes differ in what `realpathSync` does with one. So the real path of a
 * name is asked of the file system component by component, split at `/`
 * alone, where the name holds a backslash. Every other name goes to
 * `realpathSync` as it is.
 *
 * A `.`, `..` or `//` in `p` itself is folded in text before anything is
 * looked at, which is what `realpathSync` does with them: `link/..` is the
 * directory that holds the link. In a link's target they are read as the
 * kernel reads them, `..` being the parent of the real directory reached.
 *
 * An error carries the `code` the kernel gave the call that failed, and
 * ELOOP past the number of links the kernel follows.
 */
export function realPathOf(p: string): string {
  // What a relative `p` is resolved against is part of the name.
  const from = path.isAbsolute(p) ? '' : process.cwd()
  if (process.platform === 'win32' || !(from + p).includes('\\')) {
    return fs.realpathSync(p)
  }
  let real = ''
  let links = 0
  const rest = path.resolve(from, p).split('/')
  for (let name = rest.shift(); name !== undefined; name = rest.shift()) {
    if (name === '' || name === '.' || name === '..') {
      // Only a directory that can be searched has them: ENOTDIR, EACCES.
      fs.lstatSync(`${real}/.`)
      if (name === '..') real = real.slice(0, real.lastIndexOf('/'))
      continue
    }
    const next = `${real}/${name}`
    if (!fs.lstatSync(next).isSymbolicLink()) {
      real = next
      continue
    }
    if (++links > MAX_LINKS) {
      throw Object.assign(
        new Error(
          `ELOOP: too many symbolic links encountered, realpath '${p}'`,
        ),
        { code: 'ELOOP', syscall: 'realpath', path: p },
      )
    }
    const target = fs.readlinkSync(next)
    if (target.startsWith('/')) real = ''
    rest.unshift(...target.split('/'))
  }
  return real || '/'
}
