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

// Two filters per architecture, which apply-seccomp stacks: `unix` refuses
// Unix-socket creation, `namespaces` keeps the command in the namespaces the
// sandbox made for it (see seccomp-unix-block.c). Separate arrays so that a
// command opted out of the second still gets the first.
const RULE_SETS = ['unix', 'namespaces'] as const
const bpf: Record<string, Record<string, Buffer>> = {}
for (const target of ['x86_64', 'aarch64']) {
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
  '#if defined(__x86_64__)\n' +
    arrays('x86_64') +
    '#elif defined(__aarch64__)\n' +
    arrays('aarch64') +
    '#else\n' +
    '#error "unsupported architecture for unix-block BPF filter"\n' +
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
