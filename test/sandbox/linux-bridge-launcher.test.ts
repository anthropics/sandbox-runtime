import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { spawnSync, type SpawnSyncReturns } from 'node:child_process'
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'
import { isLinux } from '../helpers/platform.js'

const binary = isLinux ? getApplySeccompBinaryPath() : null

describe.skipIf(!isLinux || !binary)('Linux host bridge launcher', () => {
  let dir: string

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'bridge-launcher-'))
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  function launch(...args: string[]): SpawnSyncReturns<string> {
    return spawnSync(
      binary!,
      ['--bridge-launcher', String(process.pid), ...args],
      { encoding: 'utf8', timeout: 5000 },
    )
  }

  it('supports an expected-parent capability probe', () => {
    const result = launch()
    expect(result.error).toBeUndefined()
    expect(result.status).toBe(0)
    expect(result.stderr).toBe('')
  })

  it('rejects a different parent before executing the command', () => {
    const marker = join(dir, 'executed')
    const result = spawnSync(
      binary!,
      [
        '--bridge-launcher',
        String(process.pid === 1 ? 2 : 1),
        join(dir, 'socket'),
        'touch',
        marker,
      ],
      { encoding: 'utf8', timeout: 5000 },
    )
    expect(result.status).toBe(1)
    expect(existsSync(marker)).toBe(false)
  })

  it.each(['0', '-1', 'invalid', '999999999999999999999999'])(
    'rejects invalid parent %s',
    parent => {
      const result = spawnSync(binary!, ['--bridge-launcher', parent], {
        encoding: 'utf8',
        timeout: 5000,
      })
      expect(result.status).toBe(1)
      expect(result.stderr).toContain('expected --bridge-launcher')
    },
  )

  it('removes a socket the child leaves behind and preserves its exit status', () => {
    const socket = join(dir, 'socket')
    const result = launch(
      socket,
      'python3',
      '-c',
      'import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.close(); sys.exit(7)',
      socket,
    )
    expect(result.error).toBeUndefined()
    expect(result.status).toBe(7)
    expect(result.stderr).toBe('')
    expect(existsSync(socket)).toBe(false)
  })

  it('reports signal death as 128 plus the signal', () => {
    const result = launch(join(dir, 'socket'), '/bin/sh', '-c', 'kill -TERM $$')
    expect(result.error).toBeUndefined()
    expect(result.status).toBe(143)
  })

  it('terminates a child that ignores graceful shutdown and cleans its socket', () => {
    const socket = join(dir, 'socket')
    const result = launch(
      socket,
      'python3',
      '-c',
      'import os,signal,socket,sys,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); ' +
        's=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); ' +
        'os.kill(os.getppid(),signal.SIGTERM); time.sleep(3)',
      socket,
    )
    expect(result.error).toBeUndefined()
    expect(result.status).toBe(137)
    expect(existsSync(socket)).toBe(false)
  })

  it('leaves a regular file at the cleanup path intact', () => {
    const file = join(dir, 'socket')
    writeFileSync(file, 'keep this file')
    const result = launch(file, 'true')
    expect(result.status).toBe(1)
    expect(result.stderr).toContain('not an owned socket')
    expect(readFileSync(file, 'utf8')).toBe('keep this file')
  })
})
