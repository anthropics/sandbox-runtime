import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { generateProxyEnvVars } from '../../src/sandbox/sandbox-utils.js'

describe('generateProxyEnvVars: TMPDIR', () => {
  const saved = {
    CLAUDE_CODE_TMPDIR: process.env.CLAUDE_CODE_TMPDIR,
    CLAUDE_TMPDIR: process.env.CLAUDE_TMPDIR,
  }

  beforeEach(() => {
    delete process.env.CLAUDE_CODE_TMPDIR
    delete process.env.CLAUDE_TMPDIR
  })

  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  })

  it('reads CLAUDE_CODE_TMPDIR for TMPDIR', () => {
    process.env.CLAUDE_CODE_TMPDIR = '/tmp/claude-1001'
    expect(generateProxyEnvVars()).toContain('TMPDIR=/tmp/claude-1001')
  })

  it('falls back to CLAUDE_TMPDIR when CLAUDE_CODE_TMPDIR is unset', () => {
    process.env.CLAUDE_TMPDIR = '/tmp/legacy'
    expect(generateProxyEnvVars()).toContain('TMPDIR=/tmp/legacy')
  })

  it('prefers CLAUDE_CODE_TMPDIR over CLAUDE_TMPDIR when both set', () => {
    process.env.CLAUDE_CODE_TMPDIR = '/tmp/claude-1001'
    process.env.CLAUDE_TMPDIR = '/tmp/legacy'
    expect(generateProxyEnvVars()).toContain('TMPDIR=/tmp/claude-1001')
  })

  it('falls back to /tmp/agents when neither is set', () => {
    expect(generateProxyEnvVars()).toContain('TMPDIR=/tmp/agents')
  })

  it('omits TMPDIR when skipTmpdir is true', () => {
    process.env.CLAUDE_CODE_TMPDIR = '/tmp/claude-1001'
    const vars = generateProxyEnvVars(
      undefined,
      undefined,
      undefined,
      undefined,
      true,
    )
    expect(vars.some(v => v.startsWith('TMPDIR='))).toBe(false)
    expect(vars).toContain('SANDBOX_RUNTIME=1')
  })
})
