// Library exports
export { SandboxManager } from './sandbox/sandbox-manager.js'
export type { WrapWithSandboxOptions } from './sandbox/sandbox-manager.js'
export { SandboxViolationStore } from './sandbox/sandbox-violation-store.js'

// Sandbox-Agent channel (sandbox side)
export {
  SandboxAgentChannel,
  blockedMessageFromViolation,
  AGENT_CHANNEL_PROTOCOL_VERSION,
  SANDBOX_AGENT_CHANNEL_FD_ENV_VAR,
} from './sandbox/agent-channel.js'
export type {
  AgentChannelResource,
  AgentChannelBlockedMessage,
} from './sandbox/agent-channel.js'

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
export { type SandboxDependencyCheck } from './sandbox/linux-sandbox-utils.js'

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
