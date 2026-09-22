import { readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { run, setup } from '../build-common.js'

const { SRC, OUT } = setup({
  importMetaUrl: import.meta.url,
  requirePlatform: 'linux',
  srcDirName: 'seccomp-src',
})

function toCArray(bytes: Buffer): string {
  const hex = Array.from(bytes, b => '0x' + b.toString(16).padStart(2, '0'))
  const lines: string[] = []
  for (let i = 0; i < hex.length; i += 8) {
    lines.push('    ' + hex.slice(i, i + 8).join(', ') + ',')
  }
  return lines.join('\n')
}

const cflags = ['-static', '-O2', '-Wall', '-Wextra']

const gen = join(OUT, 'seccomp-unix-block')
run([
  'gcc',
  ...cflags,
  '-o',
  gen,
  join(SRC, 'seccomp-unix-block.c'),
  '-lseccomp',
])

// Two filters, which apply-seccomp stacks: `unix` refuses Unix-socket
// creation, `namespaces` keeps the command in the namespaces the sandbox made
// for it (see seccomp-unix-block.c). Separate arrays so that a command opted
// out of the second still gets the first.
//
// For this builder's own architecture only. The helper compiled below takes
// the arrays of its own architecture and no other, and the generator can put
// a call its libseccomp cannot name into a filter by number only for the
// architecture it runs on, and refuses for another one rather than leave the
// call out. A build that does emit for another architecture (it can: the
// generator takes the architecture as an argument) needs a libseccomp that
// names every call.
const NATIVE_TARGET = { x64: 'x86_64', arm64: 'aarch64' }[
  process.arch as string
]
if (NATIVE_TARGET === undefined) {
  throw new Error(`no seccomp filters for ${process.arch}`)
}
const RULE_SETS = ['unix', 'namespaces'] as const
const bpf: Record<string, Record<string, Buffer>> = {}
for (const target of [NATIVE_TARGET]) {
  bpf[target] = {}
  for (const rules of RULE_SETS) {
    const tmp = join(OUT, `${target}.${rules}.bpf`)
    run([gen, tmp, target, rules])
    bpf[target][rules] = readFileSync(tmp)
    rmSync(tmp)
  }
}
rmSync(gen)

function arrays(target: string): string {
  return (
    'static const unsigned char unix_block_bpf[] = {\n' +
    toCArray(bpf[target].unix) +
    '\n};\n' +
    'static const unsigned char namespace_block_bpf[] = {\n' +
    toCArray(bpf[target].namespaces) +
    '\n};\n'
  )
}

const header = join(OUT, 'unix-block-bpf.h')
writeFileSync(
  header,
  `#if defined(${NATIVE_TARGET === 'x86_64' ? '__x86_64__' : '__aarch64__'})\n` +
    arrays(NATIVE_TARGET) +
    '#else\n' +
    '#error "these filters were generated for another architecture"\n' +
    '#endif\n',
)

run([
  'gcc',
  ...cflags,
  '-I',
  OUT,
  '-o',
  join(OUT, 'apply-seccomp'),
  join(SRC, 'apply-seccomp.c'),
])
run(['strip', join(OUT, 'apply-seccomp')])
rmSync(header)

console.log('built ' + join(OUT, 'apply-seccomp'))
