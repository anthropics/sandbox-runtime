import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join } from 'node:path'
import { isLinux } from '../helpers/platform.js'

/**
 * vendor/seccomp/build.ts compiles the filter generator
 * (vendor/seccomp-src/seccomp-unix-block.c), runs it and deletes it, so it is
 * compiled here once more where there is a compiler and a libseccomp to link
 * against (elsewhere these tests skip). It must never write a `namespaces`
 * filter with one of its calls left out.
 */

type Arch = 'x86_64' | 'aarch64'

// The fifteen calls the filter answers itself, by their numbers. The old ones
// have a number of their own on each architecture; every call added since
// Linux 5.1 has the same one everywhere.
const SINCE_5_1 = {
  clone3: 435,
  open_tree: 428,
  move_mount: 429,
  fsopen: 430,
  fsconfig: 431,
  fsmount: 432,
  fspick: 433,
  mount_setattr: 442,
  open_tree_attr: 467,
}
const REFUSED: Record<Arch, Record<string, number>> = {
  x86_64: {
    clone: 56,
    unshare: 272,
    setns: 308,
    mount: 165,
    umount2: 166,
    pivot_root: 155,
    ...SINCE_5_1,
  },
  aarch64: {
    clone: 220,
    unshare: 97,
    setns: 268,
    mount: 40,
    umount2: 39,
    pivot_root: 41,
    ...SINCE_5_1,
  },
}

const NATIVE: Arch | undefined = ({ x64: 'x86_64', arm64: 'aarch64' } as const)[
  process.arch as string
]
const OTHER: Arch = NATIVE === 'x86_64' ? 'aarch64' : 'x86_64'

// Asked when the file is loaded, and leaves nothing behind: under a name
// filter that matches no test here, no hook would run to remove a build.
function canBuildGenerator(): boolean {
  if (!isLinux || NATIVE === undefined) return false
  const header = spawnSync('gcc', ['-E', '-x', 'c', '-'], {
    input: '#include <seccomp.h>\n',
    stdio: ['pipe', 'ignore', 'ignore'],
    timeout: 30000,
  })
  // The path it would link, or the bare name where it has found none.
  const library = spawnSync('gcc', ['-print-file-name=libseccomp.a'], {
    encoding: 'utf8',
    timeout: 30000,
  })
  return (
    header.status === 0 &&
    library.status === 0 &&
    isAbsolute(library.stdout.trim())
  )
}
const CAN_BUILD = canBuildGenerator()

// The generator, compiled with the flags build.ts gives it.
let GENERATOR: string | undefined
function compileGenerator(): void {
  const work = mkdtempSync(join(tmpdir(), 'seccomp-generator-'))
  GENERATOR = join(work, 'seccomp-unix-block')
  const source = join(import.meta.dir, '../../vendor/seccomp-src')
  const gcc = spawnSync(
    'gcc',
    [
      '-static',
      '-O2',
      '-Wall',
      '-Wextra',
      '-o',
      GENERATOR,
      join(source, 'seccomp-unix-block.c'),
      '-lseccomp',
    ],
    { stdio: ['ignore', 'ignore', 'pipe'], encoding: 'utf8', timeout: 60000 },
  )
  if (gcc.status !== 0) {
    rmSync(work, { recursive: true, force: true })
    throw new Error(`the generator did not compile: ${gcc.stderr}`)
  }
}

// A classic BPF instruction is eight bytes: the operation in two, two jump
// offsets of one each, and an operand of four. A filter from libseccomp tells
// system calls apart with one "jump if equal to this number" each.
const JUMP_IF_EQUAL = 0x15
function numbersComparedWith(filter: Buffer): Set<number> {
  expect(filter.length % 8).toBe(0)
  const numbers = new Set<number>()
  for (let at = 0; at < filter.length; at += 8) {
    if (filter.readUInt16LE(at) === JUMP_IF_EQUAL) {
      numbers.add(filter.readUInt32LE(at + 4))
    }
  }
  return numbers
}

function generate(arch: Arch) {
  const out = join(dirname(GENERATOR!), `${arch}.namespaces.bpf`)
  rmSync(out, { force: true })
  const run = spawnSync(GENERATOR!, [out, arch, 'namespaces'], {
    encoding: 'utf8',
    timeout: 30000,
  })
  return { status: run.status, stderr: run.stderr, out }
}

function expectEveryCall(arch: Arch, out: string): void {
  const compared = numbersComparedWith(readFileSync(out))
  for (const [call, number] of Object.entries(REFUSED[arch])) {
    // Named, so that a failure says which call is missing.
    expect([call, compared.has(number)]).toEqual([call, true])
  }
}

describe.if(isLinux)('the generator of the seccomp filters', () => {
  beforeAll(() => {
    if (CAN_BUILD) compileGenerator()
  })

  afterAll(() => {
    if (GENERATOR !== undefined) {
      rmSync(dirname(GENERATOR), { recursive: true, force: true })
    }
  })

  it.if(CAN_BUILD)(
    "the namespaces filter for the builder's own architecture has every one of its calls",
    () => {
      const made = generate(NATIVE!)
      expect(made.stderr).toBe('')
      expect(made.status).toBe(0)
      expect(Object.keys(REFUSED[NATIVE!])).toHaveLength(15)
      expectEveryCall(NATIVE!, made.out)
    },
  )

  it.if(CAN_BUILD)(
    'for another architecture it writes the whole filter or none, and says which call it could not put in',
    () => {
      // Which of the two depends on the libseccomp it was linked with: one
      // that names every call can carry them all to another architecture.
      const made = generate(OTHER)
      if (made.status === 0) {
        expectEveryCall(OTHER, made.out)
      } else {
        expect(made.stderr).toMatch(
          new RegExp(`cannot name (${Object.keys(REFUSED[OTHER]).join('|')})`),
        )
        expect(existsSync(made.out)).toBe(false)
      }
    },
  )
})
