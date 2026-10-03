import { lstatSync, mkdirSync } from 'node:fs'

export const DEFAULT_SANDBOX_TMPDIR = '/tmp/agents'

export function ensureSandboxTempDirectory(directory: string): void {
  mkdirSync(directory, { recursive: true, mode: 0o700 })
  const stat = lstatSync(directory)

  if (!stat.isDirectory() || stat.uid !== process.getuid?.()) {
    throw new Error(
      `Sandbox temporary path must be a real directory owned by the current user: ${directory}`,
    )
  }

  if ((stat.mode & 0o022) !== 0) {
    throw new Error(
      `Sandbox temporary directory must not be writable by other users: ${directory}`,
    )
  }
}
