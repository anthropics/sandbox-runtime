import { spyOn } from 'bun:test'

/**
 * Run `fn` with debug logging on and console.warn/error captured, and return
 * what it produced beside the warnings it logged. The library routes its
 * warnings through the debug logger, so SRT_DEBUG has to be set for any of
 * them to be emitted at all; it is restored to whatever it was, unset
 * included.
 */
export async function withCapturedWarnings<T>(
  fn: () => Promise<T>,
): Promise<{ result: T; warnings: string[] }> {
  const warnings: string[] = []
  const savedDebug = process.env.SRT_DEBUG
  process.env.SRT_DEBUG = '1'
  const spies = [
    spyOn(console, 'warn').mockImplementation((...parts: unknown[]) => {
      warnings.push(parts.map(String).join(' '))
    }),
    spyOn(console, 'error').mockImplementation(() => {}),
  ]
  try {
    return { result: await fn(), warnings }
  } finally {
    for (const spy of spies) spy.mockRestore()
    if (savedDebug === undefined) delete process.env.SRT_DEBUG
    else process.env.SRT_DEBUG = savedDebug
  }
}
