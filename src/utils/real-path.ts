import * as fs from 'node:fs'
import * as path from 'node:path'

/** As many links as the kernel follows on the way to one path. */
const MAX_LINKS = 40

function noText(at: string): Error {
  return Object.assign(new Error(`EILSEQ: illegal byte sequence, '${at}'`), {
    code: 'EILSEQ',
  })
}

/**
 * What `ask` says of `at`. U+FFFD in it stands for itself, or for bytes that
 * are no text: the string made of those names another file or none, so it is
 * refused.
 */
function textOf(ask: typeof fs.realpathSync.native, at: string): string {
  const text = ask(at)
  if (text.includes('\uFFFD') && !ask(at, 'buffer').equals(Buffer.from(text))) {
    throw noText(at)
  }
  return text
}

/**
 * A path as its bytes, one to a character. A name can hold bytes that are no
 * text, and so can a link's target, and no string spells those. As bytes a
 * path still splits at `/`, and joins with it, like any string.
 */
export type PathBytes = string

export function bytesOf(text: string): PathBytes {
  return Buffer.from(text).toString('latin1')
}

/** The text that `bytes` spell, or undefined where they spell none. */
export function spelledBy(bytes: PathBytes): string | undefined {
  const buffer = Buffer.from(bytes, 'latin1')
  const text = buffer.toString()
  return buffer.equals(Buffer.from(text)) ? text : undefined
}

/** `bytes` as `fs` is asked about them. */
function asked(bytes: PathBytes): string | Buffer {
  return spelledBy(bytes) ?? Buffer.from(bytes, 'latin1')
}

/**
 * `p` with every symbolic link on the way to it resolved. The real path is
 * the kernel's on every runtime, whatever characters its names hold.
 *
 * Off Windows a backslash is a character of a name like any other, and
 * runtimes differ in what `realpathSync` does with one. So the real path of a
 * name is asked of the file system component by component, split at `/`
 * alone, where the name holds a backslash. Every other name is asked of
 * `realpathSync.native`, since runtimes differ in how they read a link's
 * target too. On Windows `realpathSync` is asked, of `p` as it is.
 *
 * A `.`, `..` or `//` in `p` itself, and a `/` at its end, is folded in text
 * before anything is looked at: `link/..` is the directory that holds the
 * link. In a link's target they are read as the kernel reads them, `..` being
 * the parent of the real directory reached.
 *
 * An error carries the `code` the kernel gave the call that failed, ELOOP
 * past the number of links the kernel follows, and EILSEQ where the real path
 * holds a name that is no text.
 */
export function realPathOf(p: string): string {
  if (process.platform === 'win32') return fs.realpathSync(p)
  // What a relative `p` is resolved against is part of the name.
  const from = path.isAbsolute(p) ? '' : process.cwd()
  const folded = path.resolve(from, p)
  if (!(from + p).includes('\\')) return textOf(fs.realpathSync.native, folded)
  const { real, notThere } = wayTo(bytesOf(folded))
  if (notThere !== undefined) throw notThere
  const text = spelledBy(real)
  if (text === undefined) throw noText(folded)
  return text || '/'
}

/**
 * The kernel's way to `folded`, an absolute path with no `.`, `..` or `//` of
 * its own: name by name, split at `/` alone, every link followed. `real` is
 * as far as it leads, '' being the root. `rest` is what it has not come to:
 * nothing, or first the name that is not there, or that `real` lets nobody
 * look for (EACCES), with what the kernel said of it. Whatever else stops the
 * way is thrown. POSIX only.
 */
export function wayTo(folded: PathBytes): {
  real: PathBytes
  rest: PathBytes[]
  notThere?: unknown
} {
  let real = ''
  let links = 0
  const rest = folded.split('/')
  for (let name = rest.shift(); name !== undefined; name = rest.shift()) {
    if (name === '' || name === '.' || name === '..') {
      // Only a directory that can be searched has them: ENOTDIR, EACCES.
      try {
        fs.lstatSync(asked(`${real}/.`))
      } catch (notThere) {
        if ((notThere as NodeJS.ErrnoException).code !== 'EACCES') {
          throw notThere
        }
        return { real, rest: [name, ...rest], notThere }
      }
      if (name === '..') real = real.slice(0, real.lastIndexOf('/'))
      continue
    }
    const next = `${real}/${name}`
    let isLink: boolean
    try {
      isLink = fs.lstatSync(asked(next)).isSymbolicLink()
    } catch (notThere) {
      const { code } = notThere as NodeJS.ErrnoException
      if (code !== 'ENOENT' && code !== 'ENOTDIR' && code !== 'EACCES') {
        throw notThere
      }
      return { real, rest: [name, ...rest], notThere }
    }
    if (!isLink) {
      real = next
      continue
    }
    if (++links > MAX_LINKS) {
      const given = Buffer.from(folded, 'latin1').toString()
      throw Object.assign(
        new Error(
          `ELOOP: too many symbolic links encountered, realpath '${given}'`,
        ),
        { code: 'ELOOP', syscall: 'realpath', path: given },
      )
    }
    const target = fs.readlinkSync(asked(next), 'buffer').toString('latin1')
    if (target.startsWith('/')) real = ''
    rest.unshift(...target.split('/'))
  }
  return { real, rest }
}
