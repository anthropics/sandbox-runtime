import { readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { run, setup } from '../build-common.js'

const { SRC, OUT, arch } = setup({
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

// The two filters apply-seccomp stacks (see seccomp-unix-block.c), as separate
// arrays so that a command opted out of `namespaces` keeps `unix`. For the
// builder's own architecture only: the generator can put a call its libseccomp
// cannot name into a filter by number for that architecture alone.
const target = arch === 'x64' ? 'x86_64' : 'aarch64'
const bpf: Record<string, Buffer> = {}
for (const rules of ['unix', 'namespaces']) {
  const tmp = join(OUT, `${target}.${rules}.bpf`)
  run([gen, tmp, target, rules])
  bpf[rules] = readFileSync(tmp)
  rmSync(tmp)
}
rmSync(gen)

const header = join(OUT, 'unix-block-bpf.h')
writeFileSync(
  header,
  `#if defined(__${target}__)\n` +
    'static const unsigned char unix_block_bpf[] = {\n' +
    toCArray(bpf.unix) +
    '\n};\n' +
    'static const unsigned char namespace_block_bpf[] = {\n' +
    toCArray(bpf.namespaces) +
    '\n};\n' +
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
