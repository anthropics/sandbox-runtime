import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'

describe('Linux sandbox relay exit trap', () => {
  let tempDir: string
  let httpSock: string
  let socksSock: string

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'linux-relay-test-'))
    httpSock = join(tempDir, 'http.sock')
    socksSock = join(tempDir, 'socks.sock')
    writeFileSync(httpSock, '')
    writeFileSync(socksSock, '')
  })

  afterAll(() => {
    rmSync(tempDir, { recursive: true, force: true })
  })

  it('generates an EXIT trap that signals process groups directly and avoids job specifiers', async () => {
    const result = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: true,
      httpSocketPath: httpSock,
      socksSocketPath: socksSock,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly: [tempDir], denyWithinAllow: [] },
      bwrapPath: '/usr/bin/bwrap',
      binShell: 'bash',
      socatPath: '/usr/bin/socat',
    })

    // The wrapped bwrap invocation should set up monitor mode, capture relay PIDs,
    // and install a trap that signals the relay process groups and PIDs.
    expect(result).toContain('set -m 2>/dev/null || true')
    expect(result).toContain(
      'trap "rc=\\$?; kill -TERM -$_srt_http -$_srt_socks $_srt_http $_srt_socks 2>/dev/null; exit \\$rc" EXIT',
    )
    expect(result).toContain('set +m 2>/dev/null || true')
    expect(result).not.toContain('kill %1 %2')
  })
})
