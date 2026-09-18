// Library exports
export { SandboxManager } from './sandbox/sandbox-manager.js'
export type { WrapWithSandboxOptions } from './sandbox/sandbox-manager.js'
export { SandboxViolationStore } from './sandbox/sandbox-violation-store.js'

// Configuration types and schemas
export type {
  SandboxRuntimeConfig,
  NetworkConfig,
  FilesystemConfig,
  CredentialsConfig,
  CredentialFileConfig,
  CredentialEnvVarConfig,
  CredentialMode,
  IgnoreViolationsConfig,
} from './sandbox/sandbox-config.js'

export {
  SandboxRuntimeConfigSchema,
  NetworkConfigSchema,
  FilesystemConfigSchema,
  CredentialsConfigSchema,
  IgnoreViolationsConfigSchema,
  RipgrepConfigSchema,
} from './sandbox/sandbox-config.js'

// Schema types and utilities
export type {
  SandboxAskCallback,
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
  CredentialRestrictionConfig,
  NetworkRestrictionConfig,
  NetworkHostPattern,
} from './sandbox/sandbox-schemas.js'

// Per-request filter
export type {
  FilterRequestCallback,
  RequestDecision,
  MutateForwardedHeaders,
} from './sandbox/request-filter.js'

// Platform-specific utilities
export type { SandboxViolationEvent } from './sandbox/macos-sandbox-utils.js'
export {
  type SandboxDependencyCheck,
  LinuxSandboxProfileError,
  type LinuxSandboxProfileErrorCode,
} from './sandbox/linux-sandbox-utils.js'
// The macOS profile generator's own wrap-time refusal: a `.git` pointer or a
// `commondir` whose target cannot be worked out the way git works it out. On
// Linux the same condition arrives as a LinuxSandboxProfileError carrying
// `deny_git_metadata_unreadable`.
// The other refusal the shared producers raise: the `.git/modules` walk ran
// out of the time it was given, which on Linux arrives as a
// LinuxSandboxProfileError carrying `deny_scan_failed`.
export {
  GitMetadataError,
  SubmoduleWalkBudgetError,
} from './sandbox/mandatory-deny-paths.js'

// Windows install/status API
export {
  WindowsSandboxError,
  getSrtWinPath,
  resolveSrtWin,
  VENDORED_SRT_WIN_EXE,
  checkWindowsSandboxStatus,
  checkWindowsSandboxStatusAsync,
  getWindowsWfpStatus,
  getWindowsWfpStatusAsync,
  verifyWindowsWfpEgress,
  getWindowsSandboxUserStatus,
  getWindowsSandboxUserStatusAsync,
  getWindowsSandboxCaCert,
  windowsTrustCa,
  windowsTrustCaAsync,
  ensurePersistentWindowsCa,
  windowsStateDir,
  installWindowsSandbox,
  installWindowsSandboxAsync,
  checkWindowsDependenciesAsync,
  uninstallWindowsSandbox,
  windowsInstallInstructions,
  stampWindowsAcl,
  restoreWindowsAcl,
  grantWindowsAcl,
  revokeWindowsAcl,
  expandWindowsFsPaths,
  buildGitConfigEnv,
  parseWindowsBinShell,
  parseWindowsSandboxError,
  isUncPath,
  DEFAULT_WINDOWS_PROXY_PORT_RANGE,
  SRT_WIN_DISPATCH_ARG1,
} from './sandbox/windows-sandbox-utils.js'
export type {
  WindowsSandboxErrorCode,
  WindowsSandboxStatus,
  WindowsBinShell,
  MappedDriveCwdError,
  WindowsInstallOptions,
  WindowsInstallResult,
  WindowsWfpStatus,
  WindowsAclStampOptions,
  WindowsAclGrantOptions,
  WindowsAclAceOutcome,
  WindowsWfpStatusResult,
  WindowsWfpVerifyResult,
  WindowsSandboxUserStatus,
  WindowsPersistentCa,
  SrtWinSpawn,
} from './sandbox/windows-sandbox-utils.js'

// TLS-termination CA generation/validation (mitm-ca.ts). Embedders that
// manage CA persistence themselves (rather than relying on the Windows
// persistent-CA default) use these to generate and validate a pair.
export {
  generateCa,
  validateCaPair,
  certThumbprint,
} from './sandbox/mitm-ca.js'
export type { GeneratedCa, CaPairValidation } from './sandbox/mitm-ca.js'
export type {
  WindowsConfig,
  SrtWinConfig,
  GitConfig,
} from './sandbox/sandbox-config.js'
export {
  WindowsConfigSchema,
  SrtWinConfigSchema,
  GitConfigSchema,
} from './sandbox/sandbox-config.js'

// Utility functions
export { getDefaultWritePaths } from './sandbox/sandbox-utils.js'

// Platform utilities
export { getWslVersion } from './utils/platform.js'
export type { Platform } from './utils/platform.js'
