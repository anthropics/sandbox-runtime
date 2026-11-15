import { copyFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { run, setup } from '../build-common.js'

const { SRC, OUT } = setup({
  importMetaUrl: import.meta.url,
  requirePlatform: 'win32',
  srcDirName: 'srt-win-src',
})

run([
  'cargo',
  'build',
  '--release',
  '--locked',
  '--manifest-path',
  join(SRC, 'Cargo.toml'),
])

const built = join(SRC, 'target', 'release', 'srt-win.exe')
if (!existsSync(built)) {
  console.error('srt-win build: expected output not found at ' + built)
  process.exit(1)
}

const dest = join(OUT, 'srt-win.exe')
copyFileSync(built, dest)
console.log('built ' + dest)
