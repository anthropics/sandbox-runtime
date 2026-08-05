<#
  Additive-DENY-ACE lifecycle smoke (the A-row equivalents from
  the deleted smoke-acl.ps1, re-expressed for the separate-user
  model: trustee = `srt-sandbox`'s SID, mechanism = additive
  explicit DENY ACE, refcount = `ace_holders` table).

  Self-contained: provisions the `srt-sandbox` account + WFP
  filters under a fixed test-only sublayer GUID (distinct from
  smoke.ps1 / smoke-exec.ps1) and grants a scratch tree to the
  sandbox user so the child can read test files at all.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe
)

$ErrorActionPreference = 'Stop'

# Fixed test-only sublayer; distinct from smoke.ps1 and smoke-exec.ps1.
# Referenced verbatim by the workflow's always()-cleanup step.
$Sublayer  = 'd3a85b1c-7e92-4f6a-b1d4-8e0c5f2a9b3e'
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

$cmd  = Join-Path $env:SystemRoot 'System32\cmd.exe'
$pwsh = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$env:SANDBOX_RUNTIME_WIN_DEBUG = '1'
Write-Host "smoke-aces: sublayer=$Sublayer  exe=$Exe"

try { Start-Service seclogon -ea Stop } catch {
  Write-Host "smoke-aces: WARNING: Start-Service seclogon: $_"
}

Run @('install','--sublayer-guid',$Sublayer,'--proxy-port-range',$PortRange)
$us = J @('user','status')
if (-not $us.user.exists) { throw 'srt-sandbox not provisioned' }
$sbSid = $us.marker_user_sid
if (-not $sbSid) { throw 'setup marker missing user_sid' }
Write-Host "smoke-aces: sandbox user sid=$sbSid"

# Exec helper — same as smoke-exec.ps1's RExec.
# Do NOT pass --quiet — A28's assertion depends on the
# `per-exec deny.*holder_pid=\d+` diag line, which is `!quiet`-gated.
function RExec {
  param([string[]] $tail)
  $argv = @('exec',
            '--env', "PATH=$($env:PATH)",
            '--env', "PATHEXT=$($env:PATHEXT)") + $tail
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName               = $Exe
  $psi.UseShellExecute        = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.Environment['SANDBOX_RUNTIME_WIN_DEBUG'] = '1'
  foreach ($a in $argv) { $null = $psi.ArgumentList.Add($a) }
  $p  = [System.Diagnostics.Process]::Start($psi)
  $so = $p.StandardOutput.ReadToEndAsync()
  $se = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit(30000)) {
    try { $p.Kill($true) } catch { }
    $p.WaitForExit()
    throw ("RExec: TIMEOUT after 30s. argv: $($argv -join ' ')`n" +
           "stderr: $($se.Result)`nstdout: $($so.Result)")
  }
  $exit  = $p.ExitCode
  $raw   = $so.Result + $se.Result
  $lines = $raw -split "`r?`n"
  $child = ($lines | Where-Object { $_ -notmatch '^srt-win:' }) -join "`n"
  return [pscustomobject]@{ exit = $exit; raw = $raw; out = $child }
}

# `acl stamp` for a given holder PID. JSON body is positional so
# call sites stay one-liners.
function Stamp { param([hashtable] $body, [int] $HolderPid = $PID)
  $j = (ConvertTo-Json -Compress -Depth 4 $body)
  Stdin @('acl','stamp','--holder-pid',$HolderPid,
          '--sandbox-user-sid',$sbSid) $j
}
# `acl restore` for a given holder. Best-effort (does not throw).
function Restore { param([int] $HolderPid)
  & $Exe acl restore --holder-pid $HolderPid `
         --sandbox-user-sid $sbSid 2>&1 | Out-String | Write-Host -NoNewline
}
# "Is there an explicit DENY ACE for the sandbox user on this path?"
# — the additive-DENY-ACE equivalent of smoke-acl's Get-MarkerHash.
# Filtered to explicit (non-inherited) Deny so the working-tree
# GRANT on $Root that inherits into every test file doesn't count.
$sbAcct = New-Object System.Security.Principal.SecurityIdentifier($sbSid)
function Has-SbAce { param([string] $path)
  $hits = (Get-Acl $path).Access | Where-Object {
    -not $_.IsInherited -and
    $_.AccessControlType -eq 'Deny' -and
    $_.IdentityReference.Translate(
      [System.Security.Principal.SecurityIdentifier]) -eq $sbAcct
  }
  return [bool]$hits
}

# Scratch tree under the broker's TEMP. GetLongPathName: the GHA
# runner's TEMP is an 8.3 short path; canonicalize so srt-win and
# Get-Acl agree on the canonical form.
$Root = New-Item -ItemType Directory `
  -Path (Join-Path $env:TEMP "srt-aces-$([guid]::NewGuid().ToString('N'))")
$k32 = Add-Type -PassThru -Namespace WA -Name K -MemberDefinition `
  '[DllImport("kernel32.dll",CharSet=CharSet.Unicode)] public static extern uint GetLongPathName(string s,System.Text.StringBuilder l,uint n);'
$lp  = [System.Text.StringBuilder]::new(1024)
if ($k32::GetLongPathName($Root.FullName, $lp, 1024) -gt 0) {
  $Root = $lp.ToString()
} else {
  $Root = $Root.FullName
}
Write-Host "smoke-aces: scratch=$Root"

try {
  # The sandbox user has no implicit access to the broker's
  # %TEMP%; grant the scratch root so reads/writes inside it
  # succeed BEFORE the per-row deny ACE is layered on.
  Stdin @('acl','grant','--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"write`":[`"$($Root -replace '\\','\\')`"]}"

  # ── A2: denyWrite — child reads, cannot write; broker can ──────
  # f1 first (denyRead) under $PID; A2's stamp of f2 below is then
  # a SECOND batch under the same holder — A2(reg) re-checks f1.
  $f1 = Join-Path $Root 'a1.txt'
  'A1' | Set-Content -Encoding ASCII $f1
  Stamp @{ denyRead = @($f1) }
  $f2 = Join-Path $Root 'a2.txt'
  'A2-readable' | Set-Content -Encoding ASCII $f2
  Stamp @{ denyWrite = @($f2) }
  $r = RExec @('--', $cmd, '/c', "type `"$f2`"")
  if ($r.exit -ne 0 -or $r.out -notmatch 'A2-readable') {
    throw "A2: child read failed (denyWrite should leave read open). " +
          "exit=$($r.exit) raw: $($r.raw)"
  }
  $r = RExec @('--', $cmd, '/c', "echo nope> `"$f2`"")
  if ($r.exit -eq 0) {
    throw "A2: child WRITE succeeded (should be denied). raw: $($r.raw)"
  }
  'A2-broker-wrote' | Set-Content -Encoding ASCII $f2
  if ((Get-Content -Raw $f2).Trim() -ne 'A2-broker-wrote') {
    throw 'A2: broker write did not stick'
  }
  Write-Host 'A2 ok: denyWrite — child reads, child denied write, broker writes'

  # ── A2(reg): re-stamp by same holder is UPSERT-not-REPLACE ──────
  # A2's stamp of f2 above was a SECOND `apply_aces` batch under
  # $PID after f1's. The earlier hold must survive — `ace_holders`
  # is (path, kind, pid)-keyed; a second batch must not CASCADE-
  # delete the prior batch's rows.
  $r = RExec @('--', $cmd, '/c', "type `"$f1`"")
  if ($r.exit -eq 0 -or $r.out -match '^A1$') {
    throw "A2(reg): earlier deny on f1 was DROPPED by a second " +
          "stamp under the same holder. raw: $($r.raw)"
  }
  Write-Host 'A2(reg) ok: second stamp by same holder kept earlier holds'

  # ── A4: refcount — two live holders, restore only on last ──────
  $f4 = Join-Path $Root 'a4.txt'
  'A4' | Set-Content -Encoding ASCII $f4
  $holderB = Start-Process -FilePath $pwsh -PassThru -WindowStyle Hidden `
    -ArgumentList @('-NoProfile','-Command','Start-Sleep 120')
  try {
    Stamp @{ denyRead = @($f4) } $PID
    Stamp @{ denyRead = @($f4) } $holderB.Id
    Restore $PID
    if (-not (Has-SbAce $f4)) {
      throw 'A4: deny ACE removed after only one of two holders released'
    }
    $r = RExec @('--', $cmd, '/c', "type `"$f4`"")
    if ($r.exit -eq 0) {
      throw "A4: child read succeeded after one of two holders " +
            "released. raw: $($r.raw)"
    }
    Restore $holderB.Id
    if (Has-SbAce $f4) {
      throw 'A4: deny ACE still present after both holders released'
    }
    $r = RExec @('--', $cmd, '/c', "type `"$f4`"")
    if ($r.exit -ne 0 -or $r.out -notmatch 'A4') {
      throw "A4: child still denied after both holders released. " +
            "raw: $($r.raw)"
    }
    Write-Host 'A4 ok: ace_holders refcount — restore only on last release'
  } finally {
    Stop-Process -Id $holderB.Id -Force -ea SilentlyContinue
  }

  # ── A5: acl recover reaps dead-PID holds ────────────────────────
  $f5 = Join-Path $Root 'a5.txt'
  'A5' | Set-Content -Encoding ASCII $f5
  $holderC = Start-Process -FilePath $pwsh -PassThru -WindowStyle Hidden `
    -ArgumentList @('-NoProfile','-Command','Start-Sleep 5')
  Stamp @{ denyRead = @($f5) } $holderC.Id
  $holderC.WaitForExit()
  $r = RExec @('--', $cmd, '/c', "type `"$f5`"")
  if ($r.exit -eq 0) { throw "A5: deny did not take effect. raw: $($r.raw)" }
  Run @('acl','recover')
  if (Has-SbAce $f5) {
    throw 'A5: deny ACE still present after recover (dead holder not reaped)'
  }
  $r = RExec @('--', $cmd, '/c', "type `"$f5`"")
  if ($r.exit -ne 0 -or $r.out -notmatch 'A5') {
    throw "A5: still denied after recover. raw: $($r.raw)"
  }
  Write-Host 'A5 ok: acl recover — orphan from dead holder restored'

  # ── A13: cross-holder mask widening (SbAce::max) ────────────────
  $f13 = Join-Path $Root 'a13.txt'
  'A13' | Set-Content -Encoding ASCII $f13
  $hA = Start-Process -FilePath $cmd -PassThru -WindowStyle Hidden `
        -ArgumentList '/c','timeout','/t','120','/nobreak'
  $hB = Start-Process -FilePath $cmd -PassThru -WindowStyle Hidden `
        -ArgumentList '/c','timeout','/t','120','/nobreak'
  try {
    Stamp @{ denyWrite = @($f13) } $hA.Id
    $r = RExec @('--', $cmd, '/c', "type `"$f13`"")
    if ($r.exit -ne 0 -or $r.out -notmatch 'A13') {
      throw "A13 setup: child read under denyWrite-only failed. raw: $($r.raw)"
    }
    Stamp @{ denyRead = @($f13) } $hB.Id
    $r = RExec @('--', $cmd, '/c', "type `"$f13`"")
    if ($r.exit -eq 0) {
      throw "A13: stricter denyRead NOT applied (mask widening " +
            "ignored). raw: $($r.raw)"
    }
    Write-Host 'A13 ok: denyWrite then denyRead on same path → read denied'
  } finally {
    Stop-Process -Id $hA.Id -Force -ea SilentlyContinue
    Stop-Process -Id $hB.Id -Force -ea SilentlyContinue
    & $Exe acl recover 2>&1 | Out-Null
  }

  # ── A28: per-exec error after stamp → PerExecRestore Drop runs ──
  $f28 = Join-Path $Root 'a28.txt'
  'A28-DATA' | Set-Content -Encoding ASCII $f28
  if (Has-SbAce $f28) { throw 'A28 pre: file already carries a sb-user ACE' }
  $r = RExec @('--deny-read', $f28, '--',
               'C:\__srt_win_nonexistent__.exe')
  if ($r.exit -eq 0) {
    throw 'A28 setup: launch of a nonexistent exe SUCCEEDED?'
  }
  if ($r.raw -notmatch 'per-exec deny.*holder_pid=\d+') {
    throw "A28: per-exec deny diag missing — ACE did not commit " +
          "before the launch error. raw: $($r.raw)"
  }
  if (Has-SbAce $f28) {
    throw "A28: per-exec deny ACE LEAKED — sb-user ACE still " +
          "present after a post-stamp error. raw: $($r.raw)"
  }
  $rR = RExec @('--', $cmd, '/c', "type `"$f28`"")
  if ($rR.out -notmatch 'A28-DATA') {
    throw "A28: child without --deny-read still denied. raw: $($rR.raw)"
  }
  Write-Host 'A28 ok: per-exec error after stamp → Drop ran (no leaked ACE)'

  # ── A29: broker hard-killed mid-exec → recover reaps ────────────
  $f29 = Join-Path $Root 'a29.txt'
  'A29-DATA' | Set-Content -Encoding ASCII $f29
  $exec29 = Start-Process -FilePath $Exe -PassThru -WindowStyle Hidden `
    -ArgumentList @('exec','--deny-read',$f29,'--',
                    $cmd,'/c','ping -n 60 127.0.0.1 >nul')
  try {
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (-not (Has-SbAce $f29)) {
      if ([DateTime]::UtcNow -gt $deadline -or $exec29.HasExited) {
        throw "A29 setup: per-exec deny ACE never landed " +
              "(exec exited=$($exec29.HasExited))"
      }
      Start-Sleep -Milliseconds 100
    }
    Stop-Process -Id $exec29.Id -Force
    $exec29.WaitForExit()
  } finally {
    if (-not $exec29.HasExited) {
      Stop-Process -Id $exec29.Id -Force -ea SilentlyContinue
    }
  }
  if (-not (Has-SbAce $f29)) {
    throw 'A29 setup: ACE gone after kill — Drop ran (kill not hard enough)'
  }
  $rec29 = RunCapture @('acl','recover')
  if ($rec29.raw -notmatch 'pruned [1-9]\d* dead broker') {
    throw "A29: crash-recovery did not report the dead per-exec " +
          "holder. raw: $($rec29.raw)"
  }
  if (Has-SbAce $f29) {
    throw 'A29: per-exec deny ACE NOT reaped by recover after broker kill'
  }
  $rR = RExec @('--', $cmd, '/c', "type `"$f29`"")
  if ($rR.out -notmatch 'A29-DATA') {
    throw "A29: child still denied after reap. raw: $($rR.raw)"
  }
  Write-Host 'A29 ok: per-exec broker hard-killed → recover reaps + restores'

  # ── A30: hardlink guard — refuse any multi-link Deny target ─────
  # NTFS hardlinks share one security descriptor across distinct
  # canonical paths, but `ace_holders` is PATH-keyed. A Deny on
  # one alias is invisible to a holder of another — releasing it
  # would write the SHARED DACL back without the deny while the
  # other holder's child is still running. `ensure_ace` refuses
  # `links > 1` for ALL Deny callers (per-exec and session-level
  # `acl stamp` alike — no `refuse_escalation` distinction under
  # the additive-ACE model).
  $d30  = Join-Path $Root 'a30'
  New-Item -ItemType Directory -Path $d30 | Out-Null
  $f30  = Join-Path $d30 'orig.txt'
  $f30L = Join-Path $d30 'alias.txt'
  'A30-DATA' | Set-Content -Encoding ASCII $f30
  New-Item -ItemType HardLink -Path $f30L -Target $f30 | Out-Null
  # (a) per-exec --deny-read on a hardlinked file → refused.
  $r = RExec @('--deny-read', $f30L, '--', $cmd, '/c', 'exit 0')
  if ($r.exit -eq 0) {
    throw ("A30(a): per-exec --deny-read on a hardlinked file " +
           "SUCCEEDED — links>1 gate did not fire. raw: $($r.raw)")
  }
  if ($r.raw -notmatch '(?i)deny refused.*has 2 hardlink') {
    throw "A30(a): expected hardlink refuse; got: $($r.raw)"
  }
  if (Has-SbAce $f30L) {
    throw 'A30(a): hardlinked file was stamped despite refuse'
  }
  # (b) session-level `acl stamp` on the original → ALSO refused.
  #     (Same chokepoint; under the additive-ACE model session
  #     stamps go through ensure_ace too.)
  $b30 = (ConvertTo-Json -Compress @{ denyWrite = @($f30) }) `
         | & $Exe acl stamp --holder-pid $PID `
                  --sandbox-user-sid $sbSid 2>&1 | Out-String
  if ($LASTEXITCODE -eq 0) {
    throw ("A30(b): session acl stamp on a hardlinked file " +
           "SUCCEEDED — expected refuse. out: $b30")
  }
  if ($b30 -notmatch '(?i)deny refused.*has 2 hardlink') {
    throw "A30(b): expected hardlink refuse; got: $b30"
  }
  if (Has-SbAce $f30) {
    throw 'A30(b): original was stamped despite refuse'
  }
  # The grant on $Root inherits into $d30, so a child without a
  # deny can still read — confirms neither alias was stamped.
  $rR = RExec @('--', $cmd, '/c', "type `"$f30`"")
  if ($rR.out -notmatch 'A30-DATA') {
    throw "A30: child denied read — refuse leaked an ACE. raw: $($rR.raw)"
  }
  Write-Host ('A30 ok: hardlink guard — per-exec AND session ' +
              'acl stamp refuse multi-link Deny targets')

  # ── A31: non-existent deny target → placeholder-create + stamp ──
  # `acl stamp` mkdirs each missing intermediate + creates an empty
  # leaf; leaf gets the full Deny mask, intermediates get an
  # object-only deny-DELETE (so rename/rmdir of an intermediate is
  # blocked too). Placeholders are PERMANENT (leave-in-place):
  # `acl restore` strips the ACEs but never deletes the file/dir.
  $leaf31 = Join-Path $Root 'a31\secrets\token'
  if (Test-Path (Join-Path $Root 'a31')) {
    throw 'A31 pre: a31 subtree already exists'
  }
  Stamp @{ denyRead = @($leaf31) }
  # (a) placeholder chain exists; leaf is an empty file with a
  #     sb-user Deny ACE; child `type` denied.
  if (-not (Test-Path $leaf31 -PathType Leaf)) {
    throw 'A31(a): placeholder leaf not created'
  }
  if (-not (Has-SbAce $leaf31)) {
    throw 'A31(a): placeholder leaf has no sb-user Deny ACE'
  }
  $r = RExec @('--', $cmd, '/c', "type `"$leaf31`"")
  if ($r.exit -eq 0) {
    throw "A31(a): child read placeholder leaf. raw: $($r.raw)"
  }
  # (b) child cannot delete/rename the placeholder chain (full
  #     Deny on leaf, deny-DELETE on intermediates, DenyFdc on
  #     parents).
  $r = RExec @('--', $cmd, '/c', "del /f `"$leaf31`"")
  if (-not (Test-Path $leaf31)) {
    throw "A31(b): child deleted placeholder leaf. raw: $($r.raw)"
  }
  $mid31 = Join-Path $Root 'a31\secrets'
  $r = RExec @('--', $cmd, '/c',
               "ren `"$mid31`" secrets2 && mkdir `"$mid31`"")
  if (Test-Path (Join-Path $Root 'a31\secrets2')) {
    throw ("A31(b): child renamed placeholder intermediate. " +
           "raw: $($r.raw)")
  }
  # (c) restore strips the ACEs; placeholder chain LEFT IN PLACE
  #     (leave-in-place — never delete what the user may have
  #     written into).
  Restore $PID
  if ((Has-SbAce $leaf31) -or (Has-SbAce $mid31)) {
    throw 'A31(c): placeholder chain still has sb-user ACE after restore'
  }
  if (-not (Test-Path $leaf31 -PathType Leaf)) {
    throw ('A31(c): placeholder leaf gone after restore ' +
           '(should be left in place)')
  }
  Write-Host ('A31 ok: non-existent deny target → placeholder ' +
              'chain created+stamped, delete/rename blocked, ' +
              'ACEs stripped and chain left in place on restore')

  # (d) trailing `\` ⇒ leaf materialized as a DIRECTORY.
  $dir31 = Join-Path $Root 'a31d\hooks'
  Stamp @{ denyRead = @($dir31 + '\') }
  if (-not (Test-Path $dir31 -PathType Container)) {
    throw 'A31(d): trailing-\ deny target not created as directory'
  }
  if (-not (Has-SbAce $dir31)) {
    throw 'A31(d): dir placeholder leaf has no sb-user Deny ACE'
  }
  Restore $PID
  Write-Host 'A31(d) ok: trailing-\ ⇒ directory placeholder'

  # (e) broker-unwritable deny target soft-drops (exit 0) — the
  #     sandbox cannot create there either. Constructed: deny the
  #     REAL user create under $Root\a31e so `create_placeholder_
  #     chain` hits PermissionDenied even on the elevated CI
  #     runner. `Stamp` throws on nonzero exit, so reaching the
  #     next line is the assertion.
  $unw = Join-Path $Root 'a31e'
  New-Item -ItemType Directory $unw | Out-Null
  $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $me, 'CreateFiles,CreateDirectories', 'Deny')
  $a = Get-Acl $unw; $a.AddAccessRule($rule); Set-Acl $unw $a
  Stamp @{ denyRead = @((Join-Path $unw 'sub\token')) }
  if (Test-Path (Join-Path $unw 'sub')) {
    throw 'A31(e): placeholder created under broker-unwritable dir'
  }
  $a.RemoveAccessRule($rule) | Out-Null; Set-Acl $unw $a
  Write-Host 'A31(e) ok: broker-unwritable deny target soft-drops'
}
finally {
  & $Exe acl revoke  --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
  & $Exe acl restore --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
  & $Exe acl recover 2>&1 | Out-Null
  if (Test-Path $Root) { Remove-Item -Recurse -Force $Root -ea SilentlyContinue }
  & $Exe uninstall --sublayer-guid $Sublayer 2>&1 | Out-Null
}

Write-Host 'smoke-aces: PASS (A2/A2(reg)/A4/A5/A13/A28/A29/A30/A31)'
