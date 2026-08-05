<#
  Best-effort teardown of any state smoke.ps1/smoke-exec.ps1/
  smoke-aces.ps1 may have left behind. Intended for `if: always()`
  in CI; safe to run locally too.

  Targets the same fixed test sublayers as the smoke scripts (NOT
  the production default).

  Usage:
    pwsh vendor/srt-win-src/ci/cleanup.ps1 <path-to-srt-win.exe>
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$Exe,
  # Must match smoke.ps1's default.
  [string]$InstallSublayer = 'b2e8a6c4-1f73-4d09-9e25-c7b0d3a48f61',
  # Must match smoke-exec.ps1's default.
  [string]$ExecSublayer = '5b0e64f4-09f1-4c2e-8c97-4d2c0f4e9b7d',
  # Must match smoke-aces.ps1's default.
  [string]$AcesSublayer = 'd3a85b1c-7e92-4f6a-b1d4-8e0c5f2a9b3e',
  # Must match smoke-kill.ps1's default.
  [string]$KillSublayer = '4c1f7a2e-8b9d-4e3a-9f6c-1d7e5a0b8c4f',
  # Must match test/sandbox/winsrt.test.ts.
  [string]$TsSublayer = '7c1f0e90-3a2b-4f5d-9e8c-1d2e3f4a5b6c'
)

$ErrorActionPreference = 'SilentlyContinue'

if (-not (Test-Path $Exe)) {
  Write-Host "cleanup: $Exe not found; nothing to do"
  exit 0
}

& $Exe wfp uninstall --sublayer-guid $InstallSublayer
& $Exe wfp uninstall --sublayer-guid $ExecSublayer
& $Exe wfp uninstall --sublayer-guid $AcesSublayer
& $Exe wfp uninstall --sublayer-guid $KillSublayer
& $Exe wfp uninstall --sublayer-guid $TsSublayer
# winsrt.test.ts installWindowsSandbox round-trip rows use these
# sublayers; the test tears down via uninstallWindowsSandbox(). This
# is belt-and-braces in case it crashed mid-row.
& $Exe wfp uninstall --sublayer-guid 8d2f1e91-4b3c-5a6e-af9d-2e3f4a5b6c7d
& $Exe wfp uninstall --sublayer-guid 9e3a2fa2-5c4d-6b7f-ba0e-3f4a5b6c7d8e
# winsrt.test.ts verifyWindowsWfpEgress row.
& $Exe wfp uninstall --sublayer-guid 6a1e0f80-2b3c-4d5e-9f8a-1b2c3d4e5f60
# Orphaned sandbox-user ACEs (working_aces rows whose holder PID
# died mid-test). Best-effort — this only matters if a G-row
# (smoke-exec) / A-row (smoke-aces) / H-row (winsrt.test.ts) threw
# mid-section before its `finally` ran.
& $Exe acl recover --force
# Sandbox user + credential/marker rows in state.db — `srt-win
# install` provisions these; `uninstall` (no --keep-user) removes
# them, so this only matters if a smoke script threw mid-section.
& $Exe uninstall --sublayer-guid $InstallSublayer
Remove-LocalUser -Name srt-sandbox -ea SilentlyContinue
Remove-LocalGroup -Name sandbox-runtime-users -ea SilentlyContinue
Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' `
  -Name srt-sandbox -ea SilentlyContinue
exit 0
