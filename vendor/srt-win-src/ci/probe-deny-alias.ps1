<#
  probe-deny-alias.ps1

  Probes how `srt-win acl stamp` deny targets interact with
  reparse-point (junction) ALIASES. srt-win canonicalizes every deny
  path with GetFinalPathNameByHandleW (junctions are resolved), then
  stamps the DENY ACE on the CANONICAL object plus a
  FILE_DELETE_CHILD deny on the canonical parent. These scenarios
  check what that means when a deny is SPELLED through a junction and
  when the junction is later re-pointed or replaced.

  Scenarios (output lines are labelled "DA[n] PASS|FAIL|INFO ..."):
    DA1  baseline: deny a real dir; child read inside it is denied
    DA2  deny spelled through a junction: covers the junction
         spelling AND the target spelling (object-attached ACL)
    DA3  re-point attack (admin): junction re-pointed to a fresh
         dir after the stamp; does the deny follow the spelling?
    DA3b re-point attack (sandboxed child): child rmdir+recreates a
         junction inside a tree it can write, then reads through it
    DA4  deny on the junction object: can the child delete the
         junction itself?

  Run as admin inside the guest (PowerShell 5.1 is fine):
    powershell -ExecutionPolicy Bypass -File probe-deny-alias.ps1 C:\path\to\srt-win.exe

  Installs srt-win under a fixed TEST sublayer GUID and uninstalls at
  the end. Cleans up everything it creates. Exit code is always 0
  unless setup itself fails; grep the DA[n] lines for verdicts.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe
)

$ErrorActionPreference = 'Continue'

# Test-only sublayer, distinct from the production default.
$Sublayer  = '4c7d9b21-3e58-4a06-9d17-8f2a6c40be93'
$PortRange = '60080-60089'
$script:FailCount = 0

function Verdict([string]$tag, [bool]$ok, [string]$msg) {
  if ($ok) { Write-Host "$tag PASS $msg" }
  else     { Write-Host "$tag FAIL $msg"; $script:FailCount++ }
}
function Info([string]$tag, [string]$msg) { Write-Host "$tag INFO $msg" }

if (-not (Test-Path $Exe)) {
  Write-Host "DA0 FAIL srt-win.exe not found at '$Exe'"
  exit 1
}

# Run srt-win, echo its output, return the exit code.
function Run([string[]]$argv) {
  $raw = & $Exe @argv 2>&1 | Out-String
  if ($raw) { Write-Host -NoNewline $raw }
  return $LASTEXITCODE
}
# Pipe $json to srt-win's stdin (acl stamp / acl grant convention).
function Stdin([string[]]$argv, [string]$json) {
  $raw = $json | & $Exe @argv 2>&1 | Out-String
  if ($raw) { Write-Host -NoNewline $raw }
  return $LASTEXITCODE
}
# Escape a Windows path for embedding in a JSON string.
function JsonPath([string]$p) { return ($p -replace '\\', '\\') }
# Run a command line inside the sandbox via `exec --quiet --`.
# Payloads deliberately avoid spaces/quotes (probe paths have no
# spaces) so PowerShell 5.1 native-arg quoting stays trivial.
function SbExec([string[]]$tail) {
  $argv = @('exec', '--quiet',
            '--env', "PATH=$($env:PATH)",
            '--env', "PATHEXT=$($env:PATHEXT)",
            '--') + $tail
  $out = & $Exe @argv 2>&1 | Out-String
  return [pscustomobject]@{ exit = $LASTEXITCODE; out = $out }
}
# True if the sandboxed child can `type` the file and sees $marker.
function ChildReads([string]$path, [string]$marker) {
  $r = SbExec @($cmd, '/c', "type $path")
  return ($r.exit -eq 0 -and $r.out -match $marker)
}

$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'

# ---- install -------------------------------------------------------
try { Start-Service seclogon -ErrorAction Stop } catch {
  Info 'DA0' "Start-Service seclogon: $_"
}
$ec = Run @('install',
            '--sublayer-guid', $Sublayer,
            '--proxy-port-range', $PortRange,
            '--force')
if ($ec -ne 0) { Write-Host "DA0 FAIL install exited $ec"; exit 1 }
$us = & $Exe user status | ConvertFrom-Json
$sbSid = $us.marker_user_sid
if (-not $sbSid) { Write-Host 'DA0 FAIL user status has no marker_user_sid'; exit 1 }
Info 'DA0' "sandbox sid=$sbSid"

# ---- layout --------------------------------------------------------
# No spaces anywhere in these paths (see SbExec).
$root = "C:\srt-da-$([guid]::NewGuid().ToString('N').Substring(0,8))"
$d1   = Join-Path $root 'd1'        # DA1 plain denied dir
$t2   = Join-Path $root 't2'        # DA2/DA3 junction target
$j2   = Join-Path $root 'j2'        # junction -> t2, later -> t3
$t3   = Join-Path $root 't3'        # DA3 re-point target
$p4   = Join-Path $root 'p4'        # DA3b writable parent
$j4   = Join-Path $p4   'j4'        # junction -> t4, child re-points -> t5
$t4   = Join-Path $root 't4'
$t5   = Join-Path $root 't5'
$t6n  = Join-Path $root 't6nest'    # DA4: keeps t6's FDC-deny off $root
$t6   = Join-Path $t6n  't6'
$j6   = Join-Path $root 'j6'        # junction -> t6

foreach ($d in @($root, $d1, $t2, $t3, $p4, $t4, $t5, $t6n, $t6)) {
  New-Item -ItemType Directory -Path $d -Force | Out-Null
}
'SECRET1' | Set-Content -Encoding ASCII (Join-Path $d1 'secret.txt')
'SECRET2' | Set-Content -Encoding ASCII (Join-Path $t2 'secret2.txt')
'SECRET3' | Set-Content -Encoding ASCII (Join-Path $t3 'secret3.txt')
'SECRET4' | Set-Content -Encoding ASCII (Join-Path $t4 'secret4.txt')
'SECRET5' | Set-Content -Encoding ASCII (Join-Path $t5 'secret5.txt')
'SECRET6' | Set-Content -Encoding ASCII (Join-Path $t6 'secret6.txt')
'SIBLING' | Set-Content -Encoding ASCII (Join-Path $root 'sibling.txt')
& $cmd /c "mklink /J $j2 $t2" | Out-Null
& $cmd /c "mklink /J $j4 $t4" | Out-Null
& $cmd /c "mklink /J $j6 $t6" | Out-Null
if (-not ((Test-Path $j2) -and (Test-Path $j4) -and (Test-Path $j6))) {
  Write-Host 'DA0 FAIL mklink /J failed'
  Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
  exit 1
}
Info 'DA0' "root=$root"

try {
  # Working-tree grant so the child can read/write the probe tree at
  # all (the sandbox user has no inherent rights on real-user files).
  $ec = Stdin @('acl', 'grant', '--holder-pid', $PID,
                '--sandbox-user-sid', $sbSid) `
              "{`"write`":[`"$(JsonPath $root)`"]}"
  if ($ec -ne 0) { throw "acl grant exited $ec" }

  # ---- DA1: baseline deny on a real dir --------------------------
  $ec = Stdin @('acl', 'stamp', '--holder-pid', $PID,
                '--sandbox-user-sid', $sbSid) `
              "{`"denyRead`":[`"$(JsonPath $d1)`"]}"
  if ($ec -ne 0) { throw "acl stamp (DA1) exited $ec" }
  Verdict 'DA1' (ChildReads (Join-Path $root 'sibling.txt') 'SIBLING') `
    'control: child reads an un-denied sibling under the grant'
  Verdict 'DA1' (-not (ChildReads (Join-Path $d1 'secret.txt') 'SECRET1')) `
    'child read of denied dir d1\secret.txt is blocked'

  # ---- DA2: deny spelled THROUGH a junction ----------------------
  # Stamp the junction spelling; srt-win canonicalizes it to t2 and
  # the (OI)(CI) deny ACE lands on the t2 OBJECT.
  $ec = Stdin @('acl', 'stamp', '--holder-pid', $PID,
                '--sandbox-user-sid', $sbSid) `
              "{`"denyRead`":[`"$(JsonPath $j2)`"]}"
  if ($ec -ne 0) { throw "acl stamp (DA2) exited $ec" }
  $t2Sddl = (Get-Acl $t2).Sddl
  Info 'DA2' ("t2 (canonical target) carries sb-SID ACE: " +
              ($t2Sddl -match [regex]::Escape($sbSid)))
  Info 'DA2' "t2 Sddl=$t2Sddl"
  Info 'DA2' "root Sddl=$((Get-Acl $root).Sddl)"
  Verdict 'DA2' (-not (ChildReads (Join-Path $j2 'secret2.txt') 'SECRET2')) `
    'child read via junction spelling j2\secret2.txt is blocked'
  Verdict 'DA2' (-not (ChildReads (Join-Path $t2 'secret2.txt') 'SECRET2')) `
    'child read via canonical spelling t2\secret2.txt is blocked too'

  # ---- DA3: re-point attack (admin re-points the junction) -------
  # The deny is attached to the t2 object. Re-point j2 at a fresh
  # unstamped dir t3: does the denied SPELLING j2\... still deny?
  & $cmd /c "rmdir $j2" | Out-Null
  & $cmd /c "mklink /J $j2 $t3" | Out-Null
  if (-not (Test-Path (Join-Path $j2 'secret3.txt'))) {
    Info 'DA3' 're-point of j2 -> t3 did not take; skipping DA3'
  } else {
    # ADMIN re-points are outside the threat model (the reparse
    # lock denies the SANDBOX SID only), so this is informational:
    # an admin-re-pointed spelling resolves to an unstamped object.
    Info 'DA3' ("admin re-point: child read via re-pointed j2 " +
      $(if (ChildReads (Join-Path $j2 'secret3.txt') 'SECRET3') { 'succeeds (accepted: admins are trusted)' } else { 'is denied' }))
    Verdict 'DA3' (-not (ChildReads (Join-Path $t2 'secret2.txt') 'SECRET2')) `
      'original target t2 stays denied after the re-point'
  }

  # ---- DA3b: re-point attack by the SANDBOXED CHILD --------------
  # p4 sits inside the granted-writable tree; j4 -> t4 was created
  # above; deny is stamped via the p4\j4 spelling (canonical: t4).
  $ec = Stdin @('acl', 'stamp', '--holder-pid', $PID,
                '--sandbox-user-sid', $sbSid) `
              "{`"denyRead`":[`"$(JsonPath $j4)`"]}"
  if ($ec -ne 0) { throw "acl stamp (DA3b) exited $ec" }
  Verdict 'DA3b' (-not (ChildReads (Join-Path $j4 'secret4.txt') 'SECRET4')) `
    'pre-attack: child read via p4\j4\secret4.txt is blocked'
  $rm = SbExec @($cmd, '/c', "rmdir $j4")
  Info 'DA3b' "child rmdir of the denied-spelling junction exit=$($rm.exit)"
  $mk = SbExec @($cmd, '/c', "mklink /J $j4 $t5")
  Info 'DA3b' "child mklink /J p4\j4 -> t5 exit=$($mk.exit)"
  if (Test-Path (Join-Path $j4 'secret5.txt')) {
    Verdict 'DA3b' (-not (ChildReads (Join-Path $j4 'secret5.txt') 'SECRET5')) `
      'deny still applies after child replaced the junction (FAIL = child re-point bypassed the denied spelling)'
  } else {
    Verdict 'DA3b' $true `
      'child could not replace the junction (rmdir/mklink refused); denied spelling not re-pointable by the child'
  }
  Verdict 'DA3b' (-not (ChildReads (Join-Path $t4 'secret4.txt') 'SECRET4')) `
    'original target t4 stays denied'

  # ---- DA4: is the denied junction OBJECT protected? -------------
  # Deny stamped via the j6 spelling; canonical is t6 (whose parent
  # t6nest gets the FILE_DELETE_CHILD deny). The child holds
  # inherited MODIFY_NO_FDC (includes DELETE) on j6 from the root
  # grant, so object-DELETE is the path to watch: RemoveDirectory on
  # a junction deletes the reparse object itself, access-checked
  # against the junction object's own DACL.
  $ec = Stdin @('acl', 'stamp', '--holder-pid', $PID,
                '--sandbox-user-sid', $sbSid) `
              "{`"denyRead`":[`"$(JsonPath $j6)`"]}"
  if ($ec -ne 0) { throw "acl stamp (DA4) exited $ec" }
  Verdict 'DA4' (-not (ChildReads (Join-Path $j6 'secret6.txt') 'SECRET6')) `
    'pre-attack: child read via j6\secret6.txt is blocked'
  $rm6 = SbExec @($cmd, '/c', "rmdir $j6")
  Info 'DA4' "child rmdir j6 exit=$($rm6.exit)"
  Verdict 'DA4' (Test-Path $j6) `
    'the junction object itself survives a child delete attempt (FAIL = denied junction is deletable/replaceable)'
  Verdict 'DA4' (-not (ChildReads (Join-Path $t6 'secret6.txt') 'SECRET6')) `
    'canonical target t6 stays denied regardless'
} catch {
  Write-Host "DA0 FAIL setup/stamp error: $_"
  $script:FailCount++
} finally {
  # ---- cleanup ---------------------------------------------------
  & $Exe acl revoke  --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
  & $Exe acl restore --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
  # Remove junctions first so Remove-Item -Recurse never walks
  # through a reparse point.
  foreach ($j in @($j2, $j4, $j6)) {
    if (Test-Path $j) { & $cmd /c "rmdir $j" | Out-Null }
  }
  Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
  $null = Run @('uninstall', '--sublayer-guid', $Sublayer)
}

Write-Host "probe-deny-alias: done ($($script:FailCount) FAIL)"
exit 0
