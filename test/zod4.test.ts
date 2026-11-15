import { expect, test } from 'bun:test'
import { z } from 'zod'
import { SandboxRuntimeConfigSchema } from '../src/sandbox/sandbox-config.js'

test('configuration schemas use Zod 4 and retain path-entry diagnostics', () => {
  expect(SandboxRuntimeConfigSchema).toBeInstanceOf(z.ZodObject)
  const config = {
    network: { allowedDomains: [], deniedDomains: [] },
    filesystem: {
      denyRead: [],
      allowWrite: [{ path: '/tmp/output', literal: true as const }],
      denyWrite: [],
    },
  }
  expect(SandboxRuntimeConfigSchema.parse(config)).toEqual(config)
  const invalid = SandboxRuntimeConfigSchema.safeParse({
    ...config,
    filesystem: {
      ...config.filesystem,
      allowWrite: [{ path: '/tmp', literal: false }],
    },
  })
  expect(invalid.success).toBe(false)
  if (!invalid.success) {
    expect(invalid.error.issues).toContainEqual(
      expect.objectContaining({
        path: ['filesystem', 'allowWrite', 0],
        message: 'Expected a path, or { "path": "<path>", "literal": true }',
      }),
    )
  }
})
