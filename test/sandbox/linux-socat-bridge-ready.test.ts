import { describe, test, expect } from 'bun:test'
import { buildSandboxCommand } from '../../src/sandbox/linux-sandbox-utils.js'

describe('linux socat bridge command building', () => {
  test('quotes socket paths containing spaces and special characters', () => {
    const httpSocket = '/tmp/claude test path/http.sock'
    const socksSocket = '/tmp/claude test path/socks.sock'
    const cmd = buildSandboxCommand(
      httpSocket,
      socksSocket,
      'echo hello',
      undefined,
      'bash',
    )

    // Verify unix socket paths are properly quoted
    expect(cmd).toContain("UNIX-CONNECT:'/tmp/claude test path/http.sock'")
    expect(cmd).toContain("UNIX-CONNECT:'/tmp/claude test path/socks.sock'")
  })

  test('includes readiness probe loop before user command execution', () => {
    const cmd = buildSandboxCommand(
      '/tmp/http.sock',
      '/tmp/socks.sock',
      'echo hello',
      undefined,
      'bash',
    )

    // Verify socat readiness probe loop is present
    expect(cmd).toContain('TCP:127.0.0.1:3128')
    expect(cmd).toContain('break')
  })
})
