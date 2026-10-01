import { describe, it, expect } from 'bun:test'
import * as srt from '../src/index.js'

/**
 * Every value src/index.ts re-exports, sorted. src/index.ts is what
 * package.json points `main` and `types` at, and almost all of it is reached
 * only by embedders: the test tree imports two of these names through the
 * barrel and everything else straight from its implementation module, so a
 * removal here breaks the published surface without reddening anything.
 * Pinning the list makes a removal edit this array in the same commit, which
 * is the signal a review wants.
 *
 * Runtime values only. `export type` is erased before this can see it, so a
 * removed type still passes; catching that needs a declaration snapshot or an
 * API report, neither of which the package builds.
 */
const PUBLIC_VALUE_EXPORTS = [
  'CredentialsConfigSchema',
  'DEFAULT_WINDOWS_PROXY_PORT_RANGE',
  'FilesystemConfigSchema',
  'GitConfigSchema',
  'IgnoreViolationsConfigSchema',
  'LinuxSandboxProfileError',
  'NetworkConfigSchema',
  'RipgrepConfigSchema',
  'SRT_WIN_DISPATCH_ARG1',
  'SandboxManager',
  'SandboxRuntimeConfigSchema',
  'SandboxViolationStore',
  'SrtWinConfigSchema',
  'VENDORED_SRT_WIN_EXE',
  'WindowsConfigSchema',
  'WindowsSandboxError',
  'buildGitConfigEnv',
  'certThumbprint',
  'checkWindowsDependenciesAsync',
  'checkWindowsSandboxStatus',
  'checkWindowsSandboxStatusAsync',
  'ensurePersistentWindowsCa',
  'expandWindowsFsPaths',
  'generateCa',
  'getDefaultWritePaths',
  'getSrtWinPath',
  'getWindowsSandboxCaCert',
  'getWindowsSandboxUserStatus',
  'getWindowsSandboxUserStatusAsync',
  'getWindowsWfpStatus',
  'getWindowsWfpStatusAsync',
  'getWslVersion',
  'grantWindowsAcl',
  'installWindowsSandbox',
  'installWindowsSandboxAsync',
  'isUncPath',
  'parseWindowsBinShell',
  'parseWindowsSandboxError',
  'resolveSrtWin',
  'restoreWindowsAcl',
  'revokeWindowsAcl',
  'stampWindowsAcl',
  'uninstallWindowsSandbox',
  'validateCaPair',
  'verifyWindowsWfpEgress',
  'windowsInstallInstructions',
  'windowsStateDir',
  'windowsTrustCa',
  'windowsTrustCaAsync',
]

describe('package entry point', () => {
  it('exports exactly the checked-in list of values', () => {
    expect(Object.keys(srt).sort()).toEqual(PUBLIC_VALUE_EXPORTS)
  })

  it('binds every listed name', () => {
    for (const name of PUBLIC_VALUE_EXPORTS) {
      expect(srt[name as keyof typeof srt]).toBeDefined()
    }
  })
})
