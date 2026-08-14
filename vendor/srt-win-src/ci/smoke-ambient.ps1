<#
  Install-time ambient write-deny lifecycle smoke (`ambient.rs`).

  Asserts the v2 install stamps Windows' stock world-writable system
  dirs `(D;OICI;WriteDeny)` for the sandbox SID, that the deny holds
  for a sandboxed child (write denied, read allowed), that a session
  deny stamp + restore on the same path preserves the ambient floor
  (the `ambient_denies` fold-in at the recompose chokepoint), and
  that uninstall removes it all. Also covers the broker-time
  `audit-ww` sweep (WW1): a third-party Everyone-writable dir under
  the system drive is flagged and session-deny-stamped, a junction
  sibling is skipped, and `acl restore` releases the stamp.

  Self-contained: installs under a fixed test-only sublayer GUID
  (distinct from the other smoke scripts). NOTE the ambient stamps
  themselves are machine-global (one state DB), so this script runs
  its uninstall in `finally` — a later smoke script's install
  re-stamps them for itself.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe
)

$ErrorActionPreference = 'Stop'

# Fixed test-only sublayer; referenced by cleanup.ps1.
$Sublayer  = '9e4b2d7a-6c05-4f18-8a3d-2b9e7c1f5a0d'
$PortRange = '60080-60089'

function Run { param([string[]] $argv)
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited $LASTEXITCODE"
  }
}
function J { param([string[]] $argv) Run $argv | ConvertFrom-Json }
function Stdin { param([string[]] $argv, [string] $json)
  $raw = $json | & $Exe @argv 2>&1 | Out-String
  Write-Host -NoNewline $raw
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited ${LASTEXITCODE}: $raw"
  }
}
function RunCapture { param([string[]] $argv)
  $raw = & $Exe @argv 2>&1 | Out-String
  return [pscustomobject]@{ exit = $LASTEXITCODE; raw = $raw }
}
# A sandboxed write to $probe must fail AND leave no file behind.
function Assert-WriteDenied { param([string] $msg)
  & $Exe exec --quiet -- $cmd /c "echo p > `"$probe`"" 2>&1 | Out-Null
  if ($LASTEXITCODE -eq 0 -or (Test-Path $probe)) {
    Remove-Item $probe -Force -ea SilentlyContinue
    throw $msg
  }
}

$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
$env:SANDBOX_RUNTIME_WIN_DEBUG = '1'
Write-Host "smoke-ambient: sublayer=$Sublayer  exe=$Exe"

try { Start-Service seclogon -ea Stop } catch {
  Write-Host "smoke-ambient: WARNING: Start-Service seclogon: $_"
}

try {
  # ── AM1: install stamps the ambient list ─────────────────────────
  $inst = RunCapture @('install','--sublayer-guid',$Sublayer,'--proxy-port-range',$PortRange)
  Write-Host -NoNewline $inst.raw
  if ($inst.exit -ne 0) { throw "install exited $($inst.exit): $($inst.raw)" }
  if ($inst.raw -notmatch 'ambient write-deny stamped on (\d+) system path') {
    throw 'AM1: install output missing the ambient-stamp line'
  }
  $us = J @('user','status')
  $sbSid = $us.marker_user_sid
  if (-not $sbSid) { throw 'setup marker missing user_sid' }

  $st = J @('status','--sublayer-guid',$Sublayer)
  if (-not $st.ambient.paths -or $st.ambient.paths.Count -lt 3) {
    throw "AM1: status.ambient.paths has $($st.ambient.paths.Count) entries (want >= 3)"
  }
  $absent = @($st.ambient.paths | Where-Object { -not $_.present })
  if ($absent.Count -gt 0) {
    throw "AM1: recorded-but-absent ambient ACEs: $($absent.path -join ', ')"
  }
  Write-Host "AM1 ok: $($st.ambient.paths.Count) ambient denies recorded + present"

  # ── AM2: sandboxed write to %ProgramData% denied; read allowed ───
  $probe = Join-Path $env:ProgramData "srt-ambient-smoke-$([guid]::NewGuid().ToString('N')).txt"
  Assert-WriteDenied 'AM2: sandboxed write into %ProgramData% succeeded (must be denied)'
  & $Exe exec --quiet -- $cmd /c "dir `"$env:ProgramData`" > nul" 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'AM2: sandboxed READ of %ProgramData% failed (deny must be write-only)' }
  Write-Host 'AM2 ok: %ProgramData% write denied, read allowed'

  # ── AM3: session stamp + restore preserves the ambient floor ─────
  $json = @{ denyRead = @(); denyWrite = @($env:ProgramData) } | ConvertTo-Json
  Stdin @('acl','stamp','--holder-pid',$PID,'--sandbox-user-sid',$sbSid) $json
  Run @('acl','restore','--holder-pid',$PID,'--sandbox-user-sid',$sbSid,'--json')
  Assert-WriteDenied 'AM3: ambient deny lost after session stamp+restore round-trip'
  Write-Host 'AM3 ok: ambient floor survives session stamp+restore'

  # -- WW1: audit-ww flags + stamps a third-party world-writable dir --
  # Create an Everyone-writable dir directly under the system drive
  # (a scanned root), a junction sibling pointing at it (must be
  # skipped, never followed), run the audit, and assert: the dir is
  # stamped, a sandboxed write into it is denied, the junction is
  # not flagged, and `acl restore` releases the deny (the dir is
  # Everyone-writable again for the sandbox account).
  $wwDir  = Join-Path $env:SystemDrive "srt-ww-smoke-$([guid]::NewGuid().ToString('N'))"
  $wwJunc = "$wwDir-junc"
  New-Item -ItemType Directory -Path $wwDir | Out-Null
  # Everyone: generic write, inheritable - the shape a sloppy
  # third-party installer leaves behind.
  icacls $wwDir /grant '*S-1-1-0:(OI)(CI)(GW)' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "WW1: icacls grant on $wwDir failed" }
  New-Item -ItemType Junction -Path $wwJunc -Value $wwDir | Out-Null
  $auditRaw = & $Exe audit-ww --holder-pid $PID --sandbox-user-sid $sbSid --json 2>&1
  if ($LASTEXITCODE -ne 0) { throw "WW1: audit-ww exited ${LASTEXITCODE}: $auditRaw" }
  Write-Host ($auditRaw | Out-String)
  $audit = ($auditRaw | Where-Object { "$_".StartsWith('{') } | Select-Object -First 1) | ConvertFrom-Json
  $wwLeaf = Split-Path $wwDir -Leaf
  if (-not ($audit.stamped | Where-Object { $_ -like "*$wwLeaf" })) {
    throw "WW1: audit-ww did not stamp ${wwDir}: stamped=$($audit.stamped -join ', ')"
  }
  if ($audit.flagged | Where-Object { $_ -like "*$wwLeaf-junc" }) {
    throw 'WW1: audit-ww flagged the junction (reparse points must be skipped)'
  }
  # Non-vacuous half: a regression that FOLLOWS reparse points would
  # surface the junction under its target's canonical name and dedup
  # away - the flagged-list check above cannot see that. The
  # collection-time skip is counted, so require the counter to have
  # registered our planted junction.
  if (-not $audit.budget.reparseSkipped -or $audit.budget.reparseSkipped -lt 1) {
    throw "WW1: reparseSkipped=$($audit.budget.reparseSkipped) - the planted junction was not skip-counted (reparse handling regressed?)"
  }
  $probe = Join-Path $wwDir 'ww-probe.txt'
  Assert-WriteDenied 'WW1: sandboxed write into audited world-writable dir succeeded (must be denied)'
  # Release: the audit denies are ordinary session holds under this
  # holder PID, so `acl restore` removes them; the dir then accepts
  # sandbox writes again via its own Everyone grant.
  Run @('acl','restore','--holder-pid',$PID,'--sandbox-user-sid',$sbSid,'--json')
  & $Exe exec --quiet -- $cmd /c "echo p > `"$probe`"" 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $probe)) {
    throw 'WW1: sandboxed write still denied after acl restore (audit deny not released)'
  }
  Remove-Item $probe -Force -ea SilentlyContinue
  # Reset $probe for the later ambient sections that reuse it.
  $probe = Join-Path $env:ProgramData "srt-ambient-smoke-$([guid]::NewGuid().ToString('N')).txt"
  Write-Host 'WW1 ok: audit-ww stamped the world-writable dir, skipped the junction, restore released it'

  # ── AM4: --keep-user uninstall keeps the floor ───────────────────
  # Ambient stamps key on the ACCOUNT, not the sublayer: tearing down
  # one sublayer with --keep-user (what test suites do around a
  # possibly-shared machine) must not strip the floor.
  $un = RunCapture @('uninstall','--sublayer-guid',$Sublayer,'--keep-user')
  Write-Host -NoNewline $un.raw
  if ($un.exit -ne 0) { throw "uninstall --keep-user exited $($un.exit): $($un.raw)" }
  if ($un.raw -match 'ambient write-deny removed') {
    throw 'AM4: --keep-user uninstall removed the ambient stamps (must keep them)'
  }
  $st2 = J @('status','--sublayer-guid',$Sublayer)
  if ($st2.ambient.paths.Count -lt 3) {
    throw "AM4: only $($st2.ambient.paths.Count) ambient rows survive --keep-user uninstall"
  }
  Assert-WriteDenied 'AM4: ambient deny lost after --keep-user uninstall'
  Write-Host 'AM4 ok: --keep-user uninstall keeps the ambient floor'

  # ── AM5: full uninstall removes the stamps with the account ──────
  $un2 = RunCapture @('uninstall','--sublayer-guid',$Sublayer)
  Write-Host -NoNewline $un2.raw
  if ($un2.exit -ne 0) { throw "uninstall exited $($un2.exit): $($un2.raw)" }
  if ($un2.raw -notmatch 'ambient write-deny removed') {
    throw 'AM5: full uninstall output missing the ambient-removal line'
  }
  $st3 = J @('status','--sublayer-guid',$Sublayer)
  if ($st3.ambient.paths.Count -ne 0) {
    throw "AM5: $($st3.ambient.paths.Count) ambient rows survive full uninstall"
  }
  # The account is gone, so assert ACE removal via icacls, not exec.
  $pdAcl = icacls $env:ProgramData | Out-String
  if ($pdAcl -match [regex]::Escape($sbSid) -or $pdAcl -match 'srt-sandbox') {
    throw 'AM5: sandbox-SID ACE still on %ProgramData% after full uninstall'
  }
  Write-Host 'AM5 ok: full uninstall removed the ambient denies'
}
finally {
  & $Exe uninstall --sublayer-guid $Sublayer 2>&1 | Out-Null
  # WW1 leftovers: remove the junction FIRST (rmdir on a junction
  # deletes the link, not the target), then the dir.
  if ($wwJunc -and (Test-Path $wwJunc)) {
    # Guarded: a transient AV/indexer handle here must not mask the
    # real test error or skip the wwDir removal below.
    try { (Get-Item $wwJunc).Delete() } catch { }
  }
  if ($wwDir -and (Test-Path $wwDir)) {
    Remove-Item $wwDir -Recurse -Force -ea SilentlyContinue
  }
}

Write-Host 'smoke-ambient: PASS (AM1/AM2/AM3/WW1/AM4/AM5)'
