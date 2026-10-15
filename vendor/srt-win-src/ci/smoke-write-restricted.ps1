<#
  Smoke test for the write-restricted child token
  (`srt-win exec --write-restricted-token`, `token.rs`).

  `srt-win exec` builds that token only when given the flag; the
  library passes the flag unless its `windows.writeRestrictedToken`
  option is `false`. Every row here names its token on the command
  line: "option ON" is with the flag, "option OFF" / "ordinary token"
  is without it.

  The sandbox account is a member of BUILTIN\Users and Authenticated
  Users, so with the ordinary token it can write wherever those groups
  hold write access. The flag adds WRITE_RESTRICTED and the
  restricting SIDs [<sandbox user>, Everyone, RESTRICTED] to the child
  token. Rows (option ON unless noted):

    A  write / create / delete in a directory that grants Modify only
       to Authenticated Users, and in one that grants it only to
       BUILTIN\Users: DENIED with the option, ALLOWED without it (the
       OFF half proves the option is what closes it).
    B  inside an `acl grant` root: write succeeds; a deny-stamped file
       inside it is still denied.
    C  the egress fence holds for this token (`wfp verify
       --write-restricted-token`, and a direct connect from a
       sandboxed process), and the permitted loopback range is still
       reachable.
    D  cmd, Windows PowerShell, node and git-bash each start; a
       process can create and open a named mutex and event; two
       sandboxed processes talk over a named pipe created with the
       default security descriptor.
    E  the child cannot open the runner process, or any of its
       threads, with a write / code-execution / impersonation right.
    F  OBSERVATION ONLY: whether a Schannel client handshake fails
       under the option; prints the error. Never fails the run.
    G  the child token itself: write-restricted, restricting SIDs
       exactly the three above.

  Then the write grants that are kept between sessions (`acl grant
  --persistent`, `exec --write-root`, `persist.rs`), roots PA and PB:

    P0  on an install whose setup marker is the previous version's —
        one a broker of the previous release, which knows only the
        ordinary token, would still launch on — `acl grant
        --persistent` is refused and leaves nothing behind, and `exec`
        does not run.
    P1  a session given only PA writes, creates and deletes in PA and
        can do none of them in PB, although PB carries the persistent
        sandbox-group ACE; it can read PB. With the test-hooks build:
        its token's restricting SIDs are the three plus one capability
        SID.
    P2  a session on PB creates a file and a directory there; a
        session given only PA can then neither change their DACL
        (icacls, and SetAccessControl on a handle) nor write the file
        nor create inside the directory.
    P3  a repeat session start on PA performs zero DACL writes.
    P4  a deny target inside PA — one the real user owns and one the
        sandbox user owns — stays denied during a session and after
        it, and the owner cannot take the deny off.
    P5  the real user can still change the ACL of a file of their own
        under a persistent root.
    P6  the fence probe reports blocked for a session's token; cmd,
        Windows PowerShell, node and git-bash start under it and
        git-bash forks.
    P7  `acl forget <root>` removes a root's ACEs and its denies.
    P8  while a persistent grant exists, `exec` without the token
        flag is refused, also after the state database is deleted;
        a restricted exec whose root has no capability SID recorded
        does not run; a per-session `acl grant` is refused.
    P9  turning the option off (`acl forget --all`) removes the
        persistent ACEs and leaves each root's DACL as it was before
        its grant; then the ordinary token runs again, and cannot
        write a root that gives the sandbox account nothing itself.
    P10 a per-session `acl grant` finds and removes a persistent grant
        that neither the marker nor the database records.
    P11 `uninstall` removes persistent grants.

  A failing row is recorded and the script keeps going, so one run
  reports every row; it throws at the end if any row failed.

  Self-contained: installs under a fixed test-only sublayer GUID
  (referenced by cleanup.ps1) and uninstalls in `finally`.

  Two binaries. `$Exe` is the default-feature build: it is the broker
  and runner of EVERY row, so the token, the fence and the
  self-protection under test are always the shipped ones. `$HooksExe`
  is a second build with `--features test-hooks`, which adds the
  `probe token` and `probe parent-access` subcommands; rows G and E
  run it as the sandboxed command (launched by `$Exe`) and nothing
  else uses it. Without `$HooksExe` rows G and E are SKIPPED, with a
  message, and the rest still run.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe,
  [Parameter(Position = 1)]
  [string] $HooksExe
)

$ErrorActionPreference = 'Stop'

# Fixed test-only sublayer; referenced by cleanup.ps1.
$Sublayer  = 'c8f3a1d5-2e6b-4a97-b0c4-5d1e7f9a3b62'
$PortRange = '60080-60089'
$PortLo    = 60080
$PortHi    = 60089

# Absolute: sandboxed children run these binaries for the probe rows
# (`srt-win probe …`), and they do not share our cwd semantics.
$ExeAbs = (Resolve-Path $Exe).Path
$HooksAbs = $null
if ($HooksExe) {
  if (-not (Test-Path $HooksExe)) { throw "test-hooks binary not found: $HooksExe" }
  $HooksAbs = (Resolve-Path $HooksExe).Path
}
$cmd    = Join-Path $env:SystemRoot 'System32\cmd.exe'
$pwsh   = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$curl   = Join-Path $env:SystemRoot 'System32\curl.exe'
$env:SANDBOX_RUNTIME_WIN_DEBUG = '1'
Write-Host "smoke-write-restricted: sublayer=$Sublayer  exe=$ExeAbs  test-hooks exe=$HooksAbs"

$script:Failures = [System.Collections.Generic.List[string]]::new()
$script:Skipped  = [System.Collections.Generic.List[string]]::new()
function Fail { param([string] $m) Write-Host "FAIL $m"; $script:Failures.Add($m) }
function Ok   { param([string] $m) Write-Host "ok   $m" }
function Skip { param([string] $row)
  Write-Host "SKIP ${row}: needs the test-hooks build of srt-win (cargo build --features test-hooks) as this script's second argument; none was given"
  $script:Skipped.Add($row)
}

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
function JsonPath { param([string] $p) $p -replace '\\', '\\' }

function Bind-Listener { param([int[]] $Candidates)
  foreach ($p in $Candidates) {
    try {
      $l = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback, $p)
      $l.Start()
      return $l
    } catch {
      # port in use — try next
    }
  }
  throw "no free port among: $($Candidates -join ',')"
}
# An ephemeral loopback listener OUTSIDE the WFP permit range.
function Bind-OutOfRange {
  do {
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $l.Start()
    $p = $l.LocalEndpoint.Port
    $inPermit = $p -ge $PortLo -and $p -le $PortHi
    if ($inPermit) { $l.Stop() }
  } while ($inPermit)
  return $l
}

# Start `srt-win exec <tail>` without waiting. The broker forwards
# only what it is told via --env, so pass PATH/PATHEXT — the same
# overlay the TS wrapper builds.
function Start-Sb { param([string[]] $tail)
  $argv = @('exec',
            '--env', "PATH=$($env:PATH)",
            '--env', "PATHEXT=$($env:PATHEXT)") + $tail
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName               = $ExeAbs
  $psi.UseShellExecute        = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.Environment['SANDBOX_RUNTIME_WIN_DEBUG'] = '1'
  foreach ($a in $argv) { $null = $psi.ArgumentList.Add($a) }
  $p = [System.Diagnostics.Process]::Start($psi)
  # Drain both pipes concurrently so a full pipe buffer can't wedge
  # WaitForExit.
  return [pscustomobject]@{
    p = $p; so = $p.StandardOutput.ReadToEndAsync()
    se = $p.StandardError.ReadToEndAsync(); tail = $tail
  }
}
# Wait for a Start-Sb process. A timeout is reported as exit -1 with
# the captured output, not thrown: the caller records the row.
function Wait-Sb { param($h, [int] $TimeoutSec = 180)
  if (-not $h.p.WaitForExit($TimeoutSec * 1000)) {
    try { $h.p.Kill($true) } catch { }
    $h.p.WaitForExit()
    Write-Host "Wait-Sb: TIMEOUT after ${TimeoutSec}s: $($h.tail -join ' ')"
    $raw = "TIMEOUT`n" + $h.so.Result + $h.se.Result
    return [pscustomobject]@{ exit = -1; raw = $raw; out = $raw }
  }
  $raw   = $h.so.Result + $h.se.Result
  $child = (($raw -split "`r?`n") | Where-Object { $_ -notmatch '^srt-win:' }) -join "`n"
  return [pscustomobject]@{ exit = $h.p.ExitCode; raw = $raw; out = $child }
}
# Sandboxed exec, ordinary token (no flag).
function SbOff { param([string[]] $tail, [int] $TimeoutSec = 180)
  Wait-Sb (Start-Sb (@('--') + $tail)) $TimeoutSec
}
# Sandboxed exec, write-restricted token.
function SbOn { param([string[]] $tail, [int] $TimeoutSec = 180)
  Wait-Sb (Start-Sb (@('--write-restricted-token', '--') + $tail)) $TimeoutSec
}
# Sandboxed exec, write-restricted token, with the session's write
# roots (`--write-root` each): the token of a session that was given
# those roots.
function SbRoots { param([string[]] $roots, [string[]] $tail, [int] $TimeoutSec = 180)
  $pre = @('--write-restricted-token')
  foreach ($r in $roots) { $pre += @('--write-root', $r) }
  Wait-Sb (Start-Sb ($pre + @('--') + $tail)) $TimeoutSec
}
# Session start with the option on: `acl grant --persistent`. Returns
# the exit code, the output, and how many DACLs it wrote (-1 if the
# summary line is missing).
function Grant-P { param([string[]] $write, [string[]] $denyWrite = @(), [string[]] $denyRead = @())
  $json = @{ read = @(); write = @($write); denyRead = @($denyRead); denyWrite = @($denyWrite) } |
    ConvertTo-Json -Compress
  $raw = $json | & $Exe acl grant --holder-pid $PID --sandbox-user-sid $sbSid --persistent 2>&1 |
    Out-String
  $code = $LASTEXITCODE
  Write-Host -NoNewline $raw
  $writes = -1
  if ($raw -match '(\d+) DACL write\(s\)') { $writes = [int]$Matches[1] }
  return [pscustomobject]@{ exit = $code; raw = $raw; writes = $writes }
}
# What the session teardown runs: the per-session release. It must
# leave persistent grants alone.
function End-Session {
  & $Exe acl revoke  --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
  & $Exe acl restore --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
}
function Sddl { param([string] $p) (Get-Acl -LiteralPath $p).Sddl }
# Whether a path's DACL names a capability SID or the sandbox group.
$CapPrefix = 'S-1-0-1936880739-'
function Has-Persistent { param([string] $p)
  $sd = Sddl $p
  return ($sd -match [regex]::Escape($CapPrefix)) -or ($sd -match [regex]::Escape($script:grpSid))
}
function Persist-Status { (J @('user', 'status')).persistent_grants }
# First line of a result that parses as a JSON object, or $null.
function JsonLine { param($r)
  $line = ($r.out -split "`r?`n") | Where-Object { $_.TrimStart().StartsWith('{') } |
    Select-Object -First 1
  if (-not $line) { return $null }
  try { return $line | ConvertFrom-Json } catch { return $null }
}

try { Start-Service seclogon -ea Stop } catch {
  Write-Host "smoke-write-restricted: WARNING: Start-Service seclogon: $_"
}

# Scratch tree at the system-drive root. The root and every test
# directory get a protected DACL that is written whole, so the ACEs
# listed for a directory are the only ones that apply to it: nothing
# is inherited from the drive root, where Authenticated Users hold
# Modify and BUILTIN\Users read, and the sandbox account is a member
# of both.
#
# Every test directory carries full control for Administrators and
# SYSTEM, and what its row adds. This script and the broker run
# elevated as a member of Administrators, which is what lets them
# seed, grant and clean up; the sandbox account is in neither, so it
# gains nothing from the two entries.
$root = Join-Path "$env:SystemDrive\" "srt-wr-smoke-$([guid]::NewGuid().ToString('N'))"
$adm  = @('(A;OICI;FA;;;BA)', '(A;OICI;FA;;;SY)')
# The root itself: the same two, and read for BUILTIN\Users on the
# root only (no inheritance flags), so a sandboxed process can still
# look a child up by name. No entry lets the sandbox account write.
$rootAces = $adm + @('(A;;0x1200a9;;;BU)')
# Modify, inherited by files and directories, as an ACE for `$who`
# (an SDDL SID alias).
function ModifyAce { param([string] $who) "(A;OICI;0x1301bf;;;$who)" }
# The DACL of the SDDL string `$sd` in a form two of them can be
# compared in: whether it is protected, then its ACEs, sorted so that
# the comparison is of which ACEs are there and not of their order.
function DaclOf { param([string] $sd)
  $prot = if ($sd -match 'D:[A-Z]*P[A-Z]*\(') { 'protected' } else { 'inheriting' }
  $aces = @([regex]::Matches($sd, '\([^)]*\)') | ForEach-Object Value | Sort-Object)
  return "$prot $($aces -join '')"
}
function Dacl { param([string] $p) DaclOf (Sddl $p) }
# Give directory `$d` a protected DACL holding exactly `$aces` (SDDL
# ACE strings, spelled the way a DACL is reported back).
#
# The DACL is built here and written in one call. icacls is not used:
# what `/inheritance:r` leaves of the inherited ACEs differs between
# Windows versions (removed on one, kept as explicit ACEs on another),
# and a directory that keeps them is writable to the sandbox account
# whatever its row meant to grant. The DACL is then read back, and a
# directory that does not carry exactly `$aces` is a failed row.
function Set-OnlyAces { param([string] $d, [string[]] $aces)
  $want = "D:PAI$($aces -join '')"
  $sec = [System.Security.AccessControl.DirectorySecurity]::new()
  $sec.SetSecurityDescriptorSddlForm(
    $want, [System.Security.AccessControl.AccessControlSections]::Access)
  # Protected, and nothing inherited kept.
  $sec.SetAccessRuleProtection($true, $false)
  [System.IO.FileSystemAclExtensions]::SetAccessControl(
    [System.IO.DirectoryInfo]::new($d), $sec)
  $got = Dacl $d
  if ($got -ne (DaclOf $want)) {
    Fail "setup: the DACL of $d is not the one set on it; rows that use it prove less. want: $(DaclOf $want)  got: $got  Sddl=$(Sddl $d)"
  }
}
function New-AclDir { param([string] $name, [string[]] $extraAces)
  $d = Join-Path $root $name
  New-Item -ItemType Directory -Path $d -Force | Out-Null
  Set-OnlyAces $d ($adm + $extraAces)
  return $d
}
# Seed the three files an A-row acts on. Created AFTER the directory
# ACL is set so they inherit it.
function Seed-Dir { param([string] $d)
  'KEEP' | Set-Content -Encoding ASCII (Join-Path $d 'keep.txt')
  'DEL'  | Set-Content -Encoding ASCII (Join-Path $d 'del.txt')
  Remove-Item (Join-Path $d 'new.txt') -Force -ea SilentlyContinue
}
# One sandboxed cmd that appends to keep.txt, creates new.txt and
# deletes del.txt. cmd's `del` exits 0 even when refused, so the
# verdict is read from the files, not the exit code.
function Mutate { param([string] $d, [bool] $restricted)
  $line = "echo APPENDED>> `"$d\keep.txt`" & echo NEW> `"$d\new.txt`" & del /q `"$d\del.txt`""
  if ($restricted) { return SbOn @($cmd, '/d', '/s', '/c', $line) }
  return SbOff @($cmd, '/d', '/s', '/c', $line)
}
function State { param([string] $d)
  [pscustomobject]@{
    appended = ((Get-Content -Raw (Join-Path $d 'keep.txt')) -match 'APPENDED')
    created  = (Test-Path (Join-Path $d 'new.txt'))
    deleted  = (-not (Test-Path (Join-Path $d 'del.txt')))
  }
}

$sbSid = $null
$script:grpSid = $null
try {
  Run @('install', '--sublayer-guid', $Sublayer, '--proxy-port-range', $PortRange)
  $us = J @('user', 'status')
  $sbSid = $us.marker_user_sid
  if (-not $sbSid) { throw 'setup marker missing user_sid' }
  $script:grpSid = $us.user.group_sid
  if (-not $script:grpSid) { throw 'user status missing group_sid' }
  Write-Host "sandbox user provisioned (sid=$sbSid group=$($script:grpSid))"
  # A persistent grant left by an earlier, interrupted run would make
  # every option-off row below be refused.
  & $Exe acl forget --all 2>&1 | Out-Null
  New-Item -ItemType Directory -Path $root -Force | Out-Null
  Set-OnlyAces $root $rootAces

  # ── G: the token itself ──────────────────────────────────────────
  # First, so every later row is read knowing what token it ran under.
  # `probe token` exists only in the test-hooks build; it runs here as
  # the sandboxed command, under a token the default build created.
  if (-not $HooksAbs) { Skip 'G (the child token''s restricting SIDs)' } else {
    $want = @($sbSid, 'S-1-1-0', 'S-1-5-12') | Sort-Object
    $r = SbOn @($HooksAbs, 'probe', 'token')
    $t = JsonLine $r
    Write-Host "G: child token (option ON): $($r.out.Trim())"
    if ($r.exit -ne 0 -or -not $t) {
      Fail "G: could not read the child token with the option on (exit=$($r.exit)). raw: $($r.raw)"
    } else {
      $got = @($t.restricted_sids) | Sort-Object
      if (-not $t.write_restricted) { Fail 'G: child token is not write-restricted with the option on' }
      elseif (($got -join ',') -ne ($want -join ',')) {
        Fail "G: restricting SIDs are [$($got -join ', ')], want exactly [$($want -join ', ')]"
      } else { Ok "G: child token is write-restricted with exactly [$($want -join ', ')]" }
    }
    $r = SbOff @($HooksAbs, 'probe', 'token')
    $t = JsonLine $r
    Write-Host "G: child token (option OFF): $($r.out.Trim())"
    if ($r.exit -ne 0 -or -not $t) {
      Fail "G: could not read the child token with the option off (exit=$($r.exit)). raw: $($r.raw)"
    } elseif ($t.write_restricted -or @($t.restricted_sids).Count -ne 0) {
      Fail 'G: the ordinary child token carries restricting SIDs (option off must be unchanged)'
    } else { Ok 'G: default child token has no restricting SIDs' }
  }
  # For the log: the group view of the same token.
  $r = SbOn @($cmd, '/c', 'whoami /user /groups /fo csv /nh')
  Write-Host "G: whoami under the option (exit=$($r.exit)):`n$($r.out.Trim())"

  # ── A: ambient group-held write access ───────────────────────────
  foreach ($case in @(
      @{ tag = 'Authenticated Users'; name = 'au';    ace = (ModifyAce 'AU') },
      @{ tag = 'BUILTIN\Users';       name = 'users'; ace = (ModifyAce 'BU') })) {
    $d = New-AclDir $case.name @($case.ace)
    Seed-Dir $d
    # ON first: nothing in the directory is owned by the sandbox
    # account yet.
    $r = Mutate $d $true
    $s = State $d
    Write-Host "A[$($case.tag)] ON : appended=$($s.appended) created=$($s.created) deleted=$($s.deleted)  out: $($r.out.Trim())"
    if ($s.appended) { Fail "A[$($case.tag)]: WRITE to an existing file succeeded with the option on" }
    if ($s.created)  { Fail "A[$($case.tag)]: CREATE succeeded with the option on" }
    if ($s.deleted)  { Fail "A[$($case.tag)]: DELETE succeeded with the option on" }
    if (-not ($s.appended -or $s.created -or $s.deleted)) {
      Ok "A[$($case.tag)]: write, create and delete denied with the option on"
    }
    # Reads must be untouched.
    $r = SbOn @($cmd, '/c', "type `"$d\keep.txt`"")
    if ($r.out -notmatch 'KEEP') { Fail "A[$($case.tag)]: READ failed with the option on. raw: $($r.raw)" }
    else { Ok "A[$($case.tag)]: read still allowed with the option on" }

    # OFF: the same three operations succeed — the baseline that makes
    # the ON half mean something.
    Seed-Dir $d
    $r = Mutate $d $false
    $s = State $d
    Write-Host "A[$($case.tag)] OFF: appended=$($s.appended) created=$($s.created) deleted=$($s.deleted)  out: $($r.out.Trim())"
    if ($s.appended -and $s.created -and $s.deleted) {
      Ok "A[$($case.tag)]: write, create and delete allowed with the option off (baseline)"
    } else {
      Fail "A[$($case.tag)]: baseline broken — with the option off expected all three to succeed. raw: $($r.raw)"
    }
  }

  # A (observations, never failed): what stays writable by design.
  # (1) A directory that grants Modify to Everyone — Everyone is in
  #     the restricting list.
  $d = New-AclDir 'everyone' @(ModifyAce 'WD')
  Seed-Dir $d
  $null = Mutate $d $true
  $s = State $d
  Write-Host "A-obs[Everyone] ON : appended=$($s.appended) created=$($s.created) deleted=$($s.deleted) (Everyone is a restricting SID; writable is expected)"
  # (2) A file the sandbox account OWNS (created by the option-off run
  #     above) in the Authenticated Users directory: can it re-grant
  #     itself through the owner's implicit WRITE_DAC and then write?
  $owned = Join-Path (Join-Path $root 'au') 'new.txt'
  if (Test-Path $owned) {
    $r = SbOn @($cmd, '/d', '/s', '/c',
      "icacls `"$owned`" /grant *${sbSid}:(M) & echo OWNED>> `"$owned`"")
    $hit = (Get-Content -Raw $owned) -match 'OWNED'
    Write-Host "A-obs[owned file] ON : sandbox-owned file rewritten after self-grant=$hit  out: $($r.out.Trim())"
  }

  # ── B: granted root, and a deny stamp inside it ──────────────────
  $granted = New-AclDir 'granted' @()
  $denied  = Join-Path $granted 'deny.txt'
  'DENY' | Set-Content -Encoding ASCII $denied
  try {
    Stdin @('acl', 'grant', '--holder-pid', $PID, '--sandbox-user-sid', $sbSid) `
          "{`"write`":[`"$(JsonPath $granted)`"]}"
    $r = SbOn @($cmd, '/d', '/s', '/c', "echo B-NEW> `"$granted\w.txt`"")
    if (Test-Path "$granted\w.txt") { Ok 'B: write inside the granted root succeeds with the option on' }
    else { Fail "B: write inside the granted root FAILED with the option on. raw: $($r.raw)" }

    Stdin @('acl', 'stamp', '--holder-pid', $PID, '--sandbox-user-sid', $sbSid) `
          "{`"denyRead`":[],`"denyWrite`":[`"$(JsonPath $denied)`"]}"
    $r = SbOn @($cmd, '/d', '/s', '/c',
      "echo B-HIT>> `"$denied`" & del /q `"$denied`" & echo B-NEW2> `"$granted\w2.txt`"")
    if (-not (Test-Path $denied) -or (Get-Content -Raw $denied) -match 'B-HIT') {
      Fail "B: deny-stamped file inside the granted root was modified or deleted. raw: $($r.raw)"
    } else { Ok 'B: deny-stamped file inside the granted root still denied' }
    if (Test-Path "$granted\w2.txt") { Ok 'B: sibling of the deny-stamped file still writable' }
    else { Fail "B: sibling write failed after the deny stamp. raw: $($r.raw)" }
  } finally {
    & $Exe acl revoke  --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
    & $Exe acl restore --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
  }
  $r = SbOn @($cmd, '/d', '/s', '/c', "echo B-AFTER> `"$granted\after.txt`"")
  if (Test-Path "$granted\after.txt") { Fail 'B: write still possible after the grant was revoked' }
  else { Ok 'B: write denied again after revoke' }

  # ── C: egress fence for this token ───────────────────────────────
  $outL = Bind-OutOfRange
  $tgt = "127.0.0.1:$($outL.LocalEndpoint.Port)"
  try {
    foreach ($flag in @($true, $false)) {
      $vargs = @('wfp', 'verify', '--target', $tgt)
      if ($flag) { $vargs += '--write-restricted-token' }
      $vout  = & $Exe @vargs
      $vexit = $LASTEXITCODE
      Write-Host "C: srt-win $($vargs -join ' ') exit=$vexit stdout='$vout'"
      $v = $null
      try { $v = $vout | ConvertFrom-Json } catch { }
      if ($vexit -ne 0 -or -not $v -or $v.egress_probe -ne 'blocked') {
        Fail "C: wfp verify (write-restricted=$flag) expected exit 0 + blocked, got exit $vexit '$vout'"
      } elseif ($flag -and -not $v.write_restricted_token) {
        Fail 'C: wfp verify --write-restricted-token did not report the token shape it probed'
      } else { Ok "C: wfp verify (write-restricted=$flag) reports blocked" }
    }
    # The same connect from an ordinary sandboxed command. `probe
    # connect` exits 0 = refused by the fence, 3 = connected.
    $r = SbOn @($ExeAbs, 'probe', 'connect', '--target', $tgt)
    if ($r.exit -eq 0) { Ok "C: out-of-range connect from a write-restricted child refused by the fence ($tgt)" }
    else { Fail "C: out-of-range connect from a write-restricted child was NOT refused (probe exit=$($r.exit); 3 = connected). raw: $($r.raw)" }
    # The listener was live: the unsandboxed side reaches it.
    $c = [System.Net.Sockets.TcpClient]::new()
    try { $c.Connect('127.0.0.1', $outL.LocalEndpoint.Port) } finally { $c.Dispose() }
  } finally { $outL.Stop() }

  # The permitted loopback range — the path to the host proxies.
  $inL = Bind-Listener ($PortHi..($PortLo + 5))
  $inPort = $inL.LocalEndpoint.Port
  try {
    $r = SbOn @($ExeAbs, 'probe', 'connect', '--target', "127.0.0.1:$inPort")
    if ($r.exit -eq 3) { Ok "C: in-range loopback (the proxy path) reachable from a write-restricted child (port=$inPort)" }
    else { Fail "C: in-range loopback connect failed from a write-restricted child (probe exit=$($r.exit); want 3). raw: $($r.raw)" }

    # ── F: Schannel observation (never fails the run) ──────────────
    # System32 curl.exe is a Schannel client. The listener accepts the
    # TCP connect and stays silent, so with a working Schannel the
    # request times out waiting for a ServerHello; if Schannel cannot
    # acquire credentials it fails before sending anything.
    $observed = 0
    foreach ($mode in @('OFF', 'ON')) {
      $tail = @($curl, '-sS', '-m', '6', '--ssl-no-revoke', "https://127.0.0.1:$inPort/")
      $r = if ($mode -eq 'ON') { SbOn $tail } else { SbOff $tail }
      $msg = ($r.out.Trim() -replace "`r?`n", ' | ')
      $noCred = $msg -match 'SEC_E_NO_CREDENTIALS|AcquireCredentialsHandle'
      Write-Host "F: Schannel client (curl.exe) option ${mode}: exit=$($r.exit) cannot-acquire-credentials=$noCred  error: $msg"
      if ($r.exit -ne -1) { $observed++ }
    }
    if ($observed -eq 2) { Ok 'F: Schannel handshake observation recorded for both token shapes (see the two F lines)' }
    else { Fail 'F: the Schannel observation could not be made (a curl.exe run timed out)' }
  } finally { $inL.Stop() }

  # ── D: programs start; local IPC works ───────────────────────────
  $r = SbOn @($cmd, '/d', '/s', '/c', 'echo D-CMD-OK')
  if ($r.exit -eq 0 -and $r.out -match 'D-CMD-OK') { Ok 'D: cmd starts' }
  else { Fail "D: cmd did not start. exit=$($r.exit) raw: $($r.raw)" }

  # Windows PowerShell, plus a named mutex and event created and then
  # opened by name in the session namespace.
  $n = [guid]::NewGuid().ToString('N')
  $ps = "Write-Output D-PS-OK; " +
        "`$m = New-Object System.Threading.Mutex(`$false, 'Local\srt-wr-m-$n'); " +
        "`$m2 = [System.Threading.Mutex]::OpenExisting('Local\srt-wr-m-$n'); " +
        "if (`$m2) { Write-Output D-MUTEX-OK }; " +
        "`$e = New-Object System.Threading.EventWaitHandle(`$false, [System.Threading.EventResetMode]::ManualReset, 'Local\srt-wr-e-$n'); " +
        "`$e2 = [System.Threading.EventWaitHandle]::OpenExisting('Local\srt-wr-e-$n'); " +
        "[void]`$e2.Set(); if (`$e.WaitOne(0)) { Write-Output D-EVENT-OK }"
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $r = SbOn @($pwsh, '-NoProfile', '-Command', $ps) 300
  Write-Host "D: powershell.exe under the option took $([int]$sw.Elapsed.TotalSeconds)s"
  if ($r.out -match 'D-PS-OK') { Ok 'D: Windows PowerShell starts' }
  else { Fail "D: Windows PowerShell did not start. exit=$($r.exit) raw: $($r.raw)" }
  if ($r.out -match 'D-MUTEX-OK') { Ok 'D: named mutex created and opened' }
  else { Fail "D: named mutex create/open failed. raw: $($r.raw)" }
  if ($r.out -match 'D-EVENT-OK') { Ok 'D: named event created, opened and signalled' }
  else { Fail "D: named event create/open failed. raw: $($r.raw)" }

  $node = (Get-Command node -ea SilentlyContinue | Select-Object -First 1).Source
  if (-not $node) { Fail 'D: node not found on PATH — node and named-pipe rows not run' }
  else {
    $r = SbOn @($node, '-e', "console.log('D-NODE-OK')")
    if ($r.exit -eq 0 -and $r.out -match 'D-NODE-OK') { Ok 'D: node starts' }
    else { Fail "D: node did not start. exit=$($r.exit) raw: $($r.raw)" }

    # Two sandboxed node processes over a named pipe. libuv creates
    # the pipe with no security attributes, i.e. the default
    # descriptor built from the creating token's default DACL.
    $pipe = "srt-wr-pipe-$n"
    $srvJs = @'
const n=require('net');const p=String.raw`\\.\pipe\NAME`;const s=n.createServer(c=>{c.on('data',d=>{console.log('PIPE-SRV-GOT:'+d);c.end('pong');s.close()})});s.on('error',e=>{console.log('PIPE-SRV-ERR:'+e.code);process.exit(5)});s.listen(p,()=>console.log('PIPE-SRV-LISTENING'));setTimeout(()=>process.exit(7),90000).unref()
'@.Replace('NAME', $pipe).Trim()
    $cliJs = @'
const n=require('net');const p=String.raw`\\.\pipe\NAME`;let t=0;(function go(){const c=n.connect(p);c.on('connect',()=>c.write('ping'));c.on('data',d=>{console.log('PIPE-CLI-GOT:'+d);process.exit(0)});c.on('error',e=>{if(++t>120){console.log('PIPE-CLI-ERR:'+e.code);process.exit(6)}setTimeout(go,500)})})()
'@.Replace('NAME', $pipe).Trim()
    $srv = Start-Sb @('--write-restricted-token', '--', $node, '-e', $srvJs)
    $cli = SbOn @($node, '-e', $cliJs)
    $srvR = Wait-Sb $srv 120
    if ($cli.out -match 'PIPE-CLI-GOT:pong' -and $srvR.out -match 'PIPE-SRV-GOT:ping') {
      Ok 'D: two sandboxed processes talk over a default-descriptor named pipe'
    } else {
      Fail "D: named pipe between two sandboxed processes failed. client: $($cli.raw)  server: $($srvR.raw)"
    }
  }

  $bash = @((Join-Path $env:ProgramFiles 'Git\bin\bash.exe'),
            (Join-Path $env:ProgramFiles 'Git\usr\bin\bash.exe')) |
          Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $bash) { Fail 'D: git-bash not found under Program Files\Git — row not run' }
  else {
    # The command substitution makes bash fork, which is where an
    # msys2 runtime needs its shared named objects.
    $r = SbOn @($bash, '-c', 'echo D-BASH-$(echo FORK)-OK')
    if ($r.exit -eq 0 -and $r.out -match 'D-BASH-FORK-OK') { Ok 'D: git-bash starts and forks' }
    else { Fail "D: git-bash did not start or could not fork. exit=$($r.exit) raw: $($r.raw)" }
  }

  # ── E: the child cannot reach into the runner ────────────────────
  # `probe parent-access` (test-hooks build only) runs as the lockdown
  # child, whose parent is the default build's runner; it tries every
  # write / code-execution / impersonation right on the runner process
  # and on each of its threads.
  if (-not $HooksAbs) { Skip 'E (child cannot open the runner process or its threads)' } else {
    $r = SbOn @($HooksAbs, 'probe', 'parent-access')
    $a = JsonLine $r
    Write-Host "E: option ON : $($r.out.Trim())"
    if ($r.exit -ne 0 -or -not $a) {
      Fail "E: parent-access probe did not run with the option on (exit=$($r.exit)). raw: $($r.raw)"
    } else {
      if ($a.threads -lt 1) { Fail 'E: the probe saw no runner thread — row proves nothing' }
      elseif (@($a.opened).Count -gt 0) {
        Fail "E: the child opened the runner with: $(@($a.opened) -join ', ')"
      } else { Ok "E: no write/VM/impersonation open of the runner process or its $($a.threads) thread(s) succeeded" }
      if (@($a.errors).Count -gt 0) { Write-Host "E: note: non-access-denied results: $(@($a.errors) -join '; ')" }
    }
    # For the record only: the same probe under the ordinary token.
    $r = SbOff @($HooksAbs, 'probe', 'parent-access')
    Write-Host "E-obs: option OFF (not asserted): $($r.out.Trim())"
  }

  # ══ Write grants kept between sessions ═══════════════════════════
  $pa = New-AclDir 'pa' @()
  $pb = New-AclDir 'pb' @()
  # What `acl forget` has to leave behind (P9).
  $pbBase = Dacl $pb
  $st = Persist-Status
  if ($st.state -eq 'none') { Ok 'P: no persistent grant recorded before the first one is made' }
  else { Fail "P: user status reports persistent_grants=$($st | ConvertTo-Json -Compress) before any was made" }

  # ── P0: no kept grant on an install of the previous setup version ─
  $reg = 'HKLM:\SOFTWARE\sandbox-runtime'
  $curMarker = (Get-ItemProperty $reg).MarkerVersion
  Set-ItemProperty $reg -Name MarkerVersion -Value ($curMarker - 1)
  try {
    $us0 = J @('user', 'status')
    $g = Grant-P @($pa)
    $r = SbOn @($cmd, '/c', 'echo P0-RAN')
    $st = Persist-Status
    if ($us0.marker_version -ne ($curMarker - 1) -or $us0.setup_version -ne $curMarker) {
      Fail "P0: user status reports marker_version=$($us0.marker_version) setup_version=$($us0.setup_version) (marker set to $($curMarker - 1), build needs $curMarker)"
    } elseif ($g.exit -ne 15 -or $g.raw -notmatch '(?i)marker version mismatch.*re-run') {
      Fail "P0: acl grant --persistent on a previous-version install: exit=$($g.exit), expected 15 with the re-run-install message"
    } elseif ((Has-Persistent $pa) -or $st.state -ne 'none' -or @($st.roots).Count -ne 0) {
      Fail "P0: the refused grant left something behind: sddl=$(Sddl $pa) status=$($st | ConvertTo-Json -Compress)"
    } elseif ($r.exit -ne 15 -or $r.out -match 'P0-RAN') {
      Fail "P0: exec on a previous-version install: exit=$($r.exit) raw=$($r.raw)"
    } else { Ok 'P0: a previous-version install gets no kept grant and no exec until it is re-installed' }
  } finally {
    Set-ItemProperty $reg -Name MarkerVersion -Value $curMarker
  }

  # ── P1: two roots; a session writes only its own ─────────────────
  $ga = Grant-P @($pa)
  $gb = Grant-P @($pb)
  if ($ga.exit -ne 0 -or $gb.exit -ne 0) {
    Fail "P1: acl grant --persistent failed (PA exit=$($ga.exit), PB exit=$($gb.exit))"
  } elseif ($ga.writes -lt 1 -or $gb.writes -lt 1) {
    Fail "P1: a first grant reported no DACL write (PA=$($ga.writes), PB=$($gb.writes))"
  } else { Ok 'P1: both roots granted; each first grant wrote its DACL' }
  Write-Host "P1: PA Sddl=$(Sddl $pa)"
  Write-Host "P1: PB Sddl=$(Sddl $pb)"
  foreach ($d in @($pa, $pb)) {
    $sd = Sddl $d
    if ($sd -match [regex]::Escape(";;;$sbSid)")) { Fail "P1: $d carries an ACE for the sandbox USER SID: $sd" }
    $caps = [regex]::Matches($sd, [regex]::Escape($CapPrefix) + '[0-9-]+') | ForEach-Object Value | Sort-Object -Unique
    if (@($caps).Count -ne 1) { Fail "P1: $d carries $(@($caps).Count) capability SIDs, want 1: $sd" }
    if ($sd -notmatch [regex]::Escape("(A;OICI;0x1301bf;;;$($script:grpSid))")) { Fail "P1: $d lacks the sandbox-group modify ACE: $sd" }
    if ($sd -notmatch '\(A;OICI;RC;;;OW\)') { Fail "P1: $d lacks the OWNER RIGHTS read-control ACE: $sd" }
  }
  $st = Persist-Status
  if ($st.state -eq 'present' -and @($st.roots).Count -eq 2) { Ok 'P1: user status lists both persistent roots' }
  else { Fail "P1: user status persistent_grants=$($st | ConvertTo-Json -Compress), want present with 2 roots" }

  function MutateRoots { param([string] $d, [string[]] $roots)
    $line = "echo APPENDED>> `"$d\keep.txt`" & echo NEW> `"$d\new.txt`" & del /q `"$d\del.txt`""
    SbRoots $roots @($cmd, '/d', '/s', '/c', $line)
  }
  Seed-Dir $pa
  Seed-Dir $pb
  $r = MutateRoots $pa @($pa)
  $s = State $pa
  if ($s.appended -and $s.created -and $s.deleted) { Ok 'P1: a session given PA writes, creates and deletes in PA' }
  else { Fail "P1: a session given PA could not use it (appended=$($s.appended) created=$($s.created) deleted=$($s.deleted)). raw: $($r.raw)" }
  $r = MutateRoots $pb @($pa)
  $s = State $pb
  if ($s.appended) { Fail 'P1: a session given only PA WROTE an existing file in PB' }
  if ($s.created)  { Fail 'P1: a session given only PA CREATED a file in PB' }
  if ($s.deleted)  { Fail 'P1: a session given only PA DELETED a file in PB' }
  if (-not ($s.appended -or $s.created -or $s.deleted)) {
    Ok 'P1: a session given only PA cannot write, create or delete in PB (which carries the group ACE)'
  }
  $r = SbRoots @($pa) @($cmd, '/c', "type `"$pb\keep.txt`"")
  if ($r.out -match 'KEEP') { Ok 'P1: reads of another kept root are possible (as documented)' }
  else { Fail "P1: read of PB from a session given PA failed. raw: $($r.raw)" }
  # A write-restricted session that was given no root at all.
  $r = SbOn @($cmd, '/d', '/s', '/c', "echo NOROOT> `"$pb\noroot.txt`"")
  if (Test-Path "$pb\noroot.txt") { Fail 'P1: a write-restricted session with no write root wrote PB' }
  else { Ok 'P1: a write-restricted session with no write root cannot write PB' }
  if (-not $HooksAbs) { Skip 'P1 (restricting SIDs of a session with a write root)' } else {
    $r = SbRoots @($pa) @($HooksAbs, 'probe', 'token')
    $t = JsonLine $r
    Write-Host "P1: child token with --write-root PA: $($r.out.Trim())"
    $got = @($t.restricted_sids)
    $capsInTok = @($got | Where-Object { $_.StartsWith($CapPrefix) })
    $rest = @($got | Where-Object { -not $_.StartsWith($CapPrefix) } | Sort-Object)
    $want = @($sbSid, 'S-1-1-0', 'S-1-5-12') | Sort-Object
    if (-not $t -or -not $t.write_restricted) { Fail "P1: could not read a write-restricted child token. raw: $($r.raw)" }
    elseif ($capsInTok.Count -ne 1 -or ($rest -join ',') -ne ($want -join ',')) {
      Fail "P1: restricting SIDs are [$($got -join ', ')], want one capability SID plus [$($want -join ', ')]"
    } elseif ((Sddl $pa) -notmatch [regex]::Escape($capsInTok[0])) {
      Fail "P1: the token's capability SID $($capsInTok[0]) is not the one on PA"
    } else { Ok 'P1: child token carries exactly PA''s capability SID plus the three fixed SIDs' }
  }

  # ── P6: fence and program start under a session's token ──────────
  $outL = Bind-OutOfRange
  $tgt = "127.0.0.1:$($outL.LocalEndpoint.Port)"
  try {
    $vout  = & $Exe wfp verify --target $tgt --write-restricted-token --write-root $pa
    $vexit = $LASTEXITCODE
    Write-Host "P6: wfp verify --write-restricted-token --write-root PA exit=$vexit stdout='$vout'"
    $v = $null
    try { $v = $vout | ConvertFrom-Json } catch { }
    if ($vexit -eq 0 -and $v -and $v.egress_probe -eq 'blocked') { Ok 'P6: wfp verify with a write root reports blocked' }
    else { Fail "P6: wfp verify with a write root expected exit 0 + blocked, got exit $vexit '$vout'" }
    $r = SbRoots @($pa) @($ExeAbs, 'probe', 'connect', '--target', $tgt)
    if ($r.exit -eq 0) { Ok 'P6: out-of-range connect from a session with a write root refused by the fence' }
    else { Fail "P6: out-of-range connect from a session with a write root was NOT refused (probe exit=$($r.exit); 3 = connected). raw: $($r.raw)" }
    # A root with no capability SID recorded: no probe, not `blocked`.
    $vout  = & $Exe wfp verify --target $tgt --write-restricted-token --write-root $root 2>$null
    if ($LASTEXITCODE -ne 0 -and "$vout" -notmatch 'blocked') { Ok 'P6: wfp verify with an ungranted write root fails without reporting blocked' }
    else { Fail "P6: wfp verify with an ungranted write root: exit=$LASTEXITCODE '$vout'" }
  } finally { $outL.Stop() }
  $r = SbRoots @($pa) @($cmd, '/d', '/s', '/c', 'echo P6-CMD-OK')
  if ($r.exit -eq 0 -and $r.out -match 'P6-CMD-OK') { Ok 'P6: cmd starts' }
  else { Fail "P6: cmd did not start. exit=$($r.exit) raw: $($r.raw)" }
  $r = SbRoots @($pa) @($pwsh, '-NoProfile', '-Command', 'Write-Output P6-PS-OK') 300
  if ($r.out -match 'P6-PS-OK') { Ok 'P6: Windows PowerShell starts' }
  else { Fail "P6: Windows PowerShell did not start. exit=$($r.exit) raw: $($r.raw)" }
  if (-not $node) { Fail 'P6: node not found on PATH — row not run' } else {
    $r = SbRoots @($pa) @($node, '-e', "require('fs').writeFileSync(String.raw``$pa\node.txt``,'x');console.log('P6-NODE-OK')")
    if ($r.exit -eq 0 -and $r.out -match 'P6-NODE-OK' -and (Test-Path "$pa\node.txt")) { Ok 'P6: node starts and writes its root' }
    else { Fail "P6: node did not start or could not write its root. exit=$($r.exit) raw: $($r.raw)" }
  }
  if (-not $bash) { Fail 'P6: git-bash not found under Program Files\Git — row not run' } else {
    $r = SbRoots @($pa) @($bash, '-c', 'echo P6-BASH-$(echo FORK)-OK')
    if ($r.exit -eq 0 -and $r.out -match 'P6-BASH-FORK-OK') { Ok 'P6: git-bash starts and forks' }
    else { Fail "P6: git-bash did not start or could not fork. exit=$($r.exit) raw: $($r.raw)" }
  }

  # ── P2: objects the sandbox user owns in another root ────────────
  $sbFile = Join-Path $pb 'sbfile.txt'
  $sbDir  = Join-Path $pb 'sbdir'
  $r = SbRoots @($pb) @($cmd, '/d', '/s', '/c', "echo OWN> `"$sbFile`" & mkdir `"$sbDir`"")
  if (-not (Test-Path $sbFile) -or -not (Test-Path $sbDir)) {
    Fail "P2: the session on PB could not create a file and a directory there. raw: $($r.raw)"
  } else {
    Write-Host "P2: owner of sbfile.txt=$((Get-Acl -LiteralPath $sbFile).Owner)  of sbdir=$((Get-Acl -LiteralPath $sbDir).Owner)"
    $ownerSid = (Get-Acl -LiteralPath $sbFile).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -ne $sbSid) { Fail "P2: sbfile.txt is owned by $ownerSid, not the sandbox user — the row would prove nothing" }
    $before = @((Sddl $sbFile), (Sddl $sbDir))
    # (a) icacls, then the writes the new ACE would allow.
    $line = "icacls `"$sbFile`" /grant *S-1-1-0:(F) & icacls `"$sbDir`" /grant *S-1-1-0:(OI)(CI)(F) & " +
            "echo P2-HIT>> `"$sbFile`" & echo P2-NEW> `"$sbDir\in.txt`""
    $r = SbRoots @($pa) @($cmd, '/d', '/s', '/c', $line)
    Write-Host "P2: icacls from a session given only PA: $($r.out.Trim() -replace "`r?`n", ' | ')"
    # (b) the DACL through a handle (SetSecurityInfo), no icacls.
    $ps = "foreach (`$p in @('$sbFile','$sbDir')) { try { " +
          "`$i = Get-Item -LiteralPath `$p; `$a = `$i.GetAccessControl('Access'); " +
          "`$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('Everyone','FullControl','Allow'); " +
          "`$a.AddAccessRule(`$rule); `$i.SetAccessControl(`$a); Write-Output ('P2-SETACL-OK ' + `$p) } " +
          "catch { Write-Output ('P2-SETACL-FAILED ' + `$p + ' ' + `$_.Exception.GetType().Name) } }"
    $r2 = SbRoots @($pa) @($pwsh, '-NoProfile', '-Command', $ps) 300
    Write-Host "P2: SetAccessControl from a session given only PA: $($r2.out.Trim() -replace "`r?`n", ' | ')"
    $after = @((Sddl $sbFile), (Sddl $sbDir))
    if ($r2.out -match 'P2-SETACL-OK') { Fail "P2: SetAccessControl on a sandbox-owned object in PB succeeded from a session given only PA. raw: $($r2.raw)" }
    if ($r2.out -notmatch 'P2-SETACL-FAILED') { Fail "P2: the SetAccessControl attempt did not run. raw: $($r2.raw)" }
    if ($before[0] -ne $after[0] -or $before[1] -ne $after[1]) {
      Fail "P2: the DACL of a sandbox-owned object in PB was changed by a session given only PA. before=$($before -join ' / ') after=$($after -join ' / ')"
    } else { Ok 'P2: a session given only PA cannot change the DACL of sandbox-owned objects in PB (icacls, SetAccessControl)' }
    if ((Get-Content -Raw $sbFile) -match 'P2-HIT') { Fail 'P2: a session given only PA wrote a sandbox-owned file in PB' }
    else { Ok 'P2: a session given only PA cannot write a sandbox-owned file in PB' }
    if (Test-Path "$sbDir\in.txt") { Fail 'P2: a session given only PA created a file inside a sandbox-owned directory in PB' }
    else { Ok 'P2: a session given only PA cannot create inside a sandbox-owned directory in PB' }
    # The session on PB still uses what it created.
    $r = SbRoots @($pb) @($cmd, '/d', '/s', '/c', "echo P2-OWN>> `"$sbFile`" & echo P2-OWN> `"$sbDir\in.txt`"")
    if ((Get-Content -Raw $sbFile) -match 'P2-OWN' -and (Test-Path "$sbDir\in.txt")) { Ok 'P2: the session on PB writes the objects it created' }
    else { Fail "P2: the session on PB cannot write the objects it created. raw: $($r.raw)" }
  }

  # ── P3: a repeat session start writes nothing ────────────────────
  End-Session
  if (-not (Has-Persistent $pa)) { Fail 'P3: the per-session release removed the persistent grant on PA' }
  $g = Grant-P @($pa)
  if ($g.exit -eq 0 -and $g.writes -eq 0 -and $g.raw -notmatch 'persistent DACL write') {
    Ok 'P3: a repeat session start on PA performed zero DACL writes'
  } else { Fail "P3: a repeat session start on PA: exit=$($g.exit), DACL writes=$($g.writes) (want 0). raw: $($g.raw)" }

  # ── P4: denies live as long as the grant ─────────────────────────
  $denyF   = Join-Path $pa 'deny.txt'
  $sbOwned = Join-Path $pa 'sb-deny.txt'
  'DENY' | Set-Content -Encoding ASCII $denyF
  $r = SbRoots @($pa) @($cmd, '/d', '/s', '/c', "echo SBDENY> `"$sbOwned`"")
  if (-not (Test-Path $sbOwned)) { Fail "P4: the session could not create the file to be denied. raw: $($r.raw)" }
  $g = Grant-P @($pa) @($denyF, $sbOwned)
  if ($g.exit -ne 0) { Fail "P4: session start with deny targets failed (exit=$($g.exit))" }
  Write-Host "P4: deny.txt Sddl=$(Sddl $denyF)"
  Write-Host "P4: sb-deny.txt Sddl=$(Sddl $sbOwned) owner=$((Get-Acl -LiteralPath $sbOwned).Owner)"
  function Try-Denied { param([string] $tag)
    $line = "echo $tag>> `"$denyF`" & echo $tag>> `"$sbOwned`" & " +
            "icacls `"$sbOwned`" /remove:d *$($script:grpSid) & icacls `"$sbOwned`" /grant *${sbSid}:(F) & " +
            "echo $tag-2>> `"$sbOwned`" & del /q `"$denyF`" `"$sbOwned`" & echo $tag-SIB> `"$pa\$tag.txt`""
    $r = SbRoots @($pa) @($cmd, '/d', '/s', '/c', $line)
    $bad = @()
    foreach ($f in @($denyF, $sbOwned)) {
      if (-not (Test-Path $f)) { $bad += "$f deleted" }
      elseif ((Get-Content -Raw $f) -match $tag) { $bad += "$f written" }
    }
    if (-not (Test-Path "$pa\$tag.txt")) { $bad += 'sibling no longer writable' }
    [pscustomobject]@{ bad = $bad; raw = $r.raw }
  }
  $t = Try-Denied 'P4-DURING'
  if ($t.bad.Count -eq 0) { Ok 'P4: deny targets in PA (one real-user-owned, one sandbox-owned) hold during a session; the owner cannot take the deny off' }
  else { Fail "P4: during the session: $($t.bad -join '; '). raw: $($t.raw)" }
  # Between sessions: after the per-session release the ACEs are
  # still on disk; the next start (which does not list them again)
  # writes nothing and they still hold.
  End-Session
  $denyAce = '\(D;[^)]*;;;' + [regex]::Escape($script:grpSid) + '\)'
  foreach ($f in @($denyF, $sbOwned)) {
    if ((Sddl $f) -notmatch $denyAce) { Fail "P4: $f lost its sandbox-group deny ACE after the session ended: $(Sddl $f)" }
  }
  $g = Grant-P @($pa)
  if ($g.exit -ne 0 -or $g.writes -ne 0) { Fail "P4: the next session start: exit=$($g.exit), DACL writes=$($g.writes) (want 0)" }
  $t = Try-Denied 'P4-AFTER'
  if ($t.bad.Count -eq 0) { Ok 'P4: the deny targets still hold in the next session, with zero DACL writes at its start' }
  else { Fail "P4: in the next session: $($t.bad -join '; '). raw: $($t.raw)" }

  # ── P5: the real user and their own file ─────────────────────────
  # A root that gives the real user no full-control ACE: SYSTEM, and
  # modify for Authenticated Users.
  $pc = Join-Path $root 'pc'
  New-Item -ItemType Directory -Path $pc -Force | Out-Null
  Set-OnlyAces $pc @('(A;OICI;FA;;;SY)', (ModifyAce 'AU'))
  $pcBase = Dacl $pc
  $mine = Join-Path $pc 'mine.txt'
  'MINE' | Set-Content -Encoding ASCII $mine
  $g = Grant-P @($pc)
  Write-Host "P5: PC Sddl=$(Sddl $pc)  mine.txt owner=$((Get-Acl -LiteralPath $mine).Owner)"
  if ($g.exit -ne 0) { Fail "P5: acl grant --persistent on a root without a full-control ACE failed (exit=$($g.exit))" }
  else {
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ((Sddl $pc) -notmatch [regex]::Escape("(A;OICI;RCWD;;;$me)") -and (Sddl $pc) -notmatch '\(A;OICI;RCWD;;;[A-Z]{2}\)') {
      Fail "P5: PC lacks the real user's READ_CONTROL|WRITE_DAC ACE: $(Sddl $pc)"
    }
    $out = & icacls $mine /grant '*S-1-5-32-546:(R)' 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0 -and (Sddl $mine) -match ';;;BG\)') { Ok 'P5: the real user can still change the ACL of their own file under a persistent root' }
    else { Fail "P5: the real user could not change the ACL of their own file under a persistent root (icacls exit=$LASTEXITCODE): $out" }
  }

  # ── P7: forget one root ──────────────────────────────────────────
  $fo = & $Exe acl forget $pa --json 2>$null
  $fexit = $LASTEXITCODE
  Write-Host "P7: acl forget PA exit=$fexit stdout='$fo'"
  $leftDeny = @($denyF, $sbOwned) | Where-Object { (Sddl $_) -match $denyAce }
  if ($fexit -ne 0 -or "$fo" -notmatch '"removed"') { Fail "P7: acl forget PA: exit=$fexit '$fo'" }
  elseif (Has-Persistent $pa) { Fail "P7: PA still carries persistent ACEs after forget: $(Sddl $pa)" }
  elseif (Has-Persistent (Join-Path $pa 'keep.txt')) { Fail "P7: a file in PA still inherits persistent ACEs after forget: $(Sddl (Join-Path $pa 'keep.txt'))" }
  elseif ($leftDeny) { Fail "P7: deny ACEs kept with PA survived its forget: $($leftDeny -join ', ')" }
  else { Ok 'P7: acl forget removed PA''s ACEs, their inherited copies, and the denies kept with it' }
  $r = SbRoots @($pa) @($cmd, '/d', '/s', '/c', "echo GONE> `"$pa\after-forget.txt`"")
  if ($r.exit -ne 0 -and -not (Test-Path "$pa\after-forget.txt")) { Ok 'P7: an exec naming the forgotten root does not run' }
  else { Fail "P7: an exec naming the forgotten root ran (exit=$($r.exit)). raw: $($r.raw)" }

  # ── P8: no ordinary token while a persistent grant exists ────────
  # PB and PC are still granted.
  function Refused { param([string] $when)
    $r = SbOff @($cmd, '/d', '/s', '/c', "echo P8-RAN> `"$root\p8-ran.txt`" & echo P8-RAN")
    if ($r.exit -eq 20 -and $r.out -notmatch 'P8-RAN' -and $r.raw -match 'refusing to run' -and -not (Test-Path "$root\p8-ran.txt")) {
      Ok "P8: exec without the token flag is refused $when"
    } else { Fail "P8: exec without the token flag was NOT refused $when (exit=$($r.exit)). raw: $($r.raw)" }
  }
  Refused 'while a persistent grant exists'
  $raw = "{`"write`":[`"$(JsonPath $pb)`"]}" |
    & $Exe acl grant --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0 -and (Sddl $pb) -notmatch [regex]::Escape(";;;$sbSid)")) { Ok 'P8: a per-session acl grant is refused while a persistent grant exists' }
  else { Fail "P8: a per-session acl grant was not refused (exit=$LASTEXITCODE): $raw" }
  $dbDir = Join-Path $env:LOCALAPPDATA 'sandbox-runtime'
  Remove-Item (Join-Path $dbDir 'state.db*') -Force -ErrorAction SilentlyContinue
  if (Test-Path (Join-Path $dbDir 'state.db')) { Fail 'P8: could not delete the state database — the next rows prove less' }
  Refused 'after the state database is deleted'
  $st = Persist-Status
  if ($st.state -ne 'none') { Ok "P8: user status still reports persistent grants ($($st.state)) without the database" }
  else { Fail 'P8: user status reports no persistent grants after the database was deleted' }
  $r = SbRoots @($pb) @($cmd, '/d', '/s', '/c', "echo NOSID> `"$pb\nosid.txt`"")
  if ($r.exit -ne 0 -and -not (Test-Path "$pb\nosid.txt")) { Ok 'P8: with no capability SID on record a restricted exec naming the root does not run' }
  else { Fail "P8: a restricted exec ran for a root with no capability SID on record (exit=$($r.exit)). raw: $($r.raw)" }

  # ── P9: option off — forget everything, then the ordinary token ──
  $fo = & $Exe acl forget --all --json 2>$null
  $fexit = $LASTEXITCODE
  Write-Host "P9: acl forget --all exit=$fexit stdout='$fo'"
  $still = @($pb, $pc, (Join-Path $pb 'keep.txt'), $mine) | Where-Object { Has-Persistent $_ }
  if ($fexit -ne 0) { Fail "P9: acl forget --all exited $fexit" }
  elseif ($still) { Fail "P9: persistent ACEs remain after forget --all (database deleted) on: $($still -join ', ')" }
  elseif ((Sddl $pb) -match '\(A;OICI;RC;;;OW\)') { Fail "P9: PB still carries the OWNER RIGHTS ACE: $(Sddl $pb)" }
  else { Ok 'P9: forget --all removed every persistent ACE, from the marker alone' }
  # Nothing of a grant stays, and nothing else went with it: each
  # root's own DACL is the one it had before its first grant.
  Write-Host "P9: PB Sddl=$(Sddl $pb)"
  Write-Host "P9: PC Sddl=$(Sddl $pc)"
  foreach ($c in @(@{ n = 'PB'; p = $pb; base = $pbBase }, @{ n = 'PC'; p = $pc; base = $pcBase })) {
    $now = Dacl $c.p
    if ($now -eq $c.base) { Ok "P9: $($c.n)'s DACL is the one it had before its grant" }
    else { Fail "P9: $($c.n)'s DACL after forget --all is not the one it had before its grant. before: $($c.base)  after: $now" }
  }
  $st = Persist-Status
  if ($st.state -eq 'none' -and @($st.roots).Count -eq 0) { Ok 'P9: user status reports no persistent grants' }
  else { Fail "P9: user status persistent_grants=$($st | ConvertTo-Json -Compress) after forget --all" }
  $r = SbOff @($cmd, '/d', '/s', '/c', 'echo P9-RUNS')
  if ($r.exit -eq 0 -and $r.out -match 'P9-RUNS') { Ok 'P9: the ordinary token runs again' }
  else { Fail "P9: the ordinary token does not run after forget --all (exit=$($r.exit)). raw: $($r.raw)" }
  # PB's own DACL names Administrators and SYSTEM only, so with the
  # grant forgotten the sandbox account has no write access to it
  # under any token. (A root whose own DACL lets Authenticated Users
  # or BUILTIN\Users write stays writable to the ordinary token — rows
  # A — and forgetting a grant does not change that.)
  $p9 = Join-Path $pb 'p9.txt'
  $r = SbOff @($cmd, '/d', '/s', '/c', "echo P9-W> `"$p9`"")
  if (-not (Test-Path -LiteralPath $p9)) { Ok 'P9: the ordinary token cannot write a root whose grant was forgotten' }
  else {
    Fail ("P9: the ordinary token CREATED a file in PB after its grant was forgotten. " +
          "exec exit=$($r.exit) raw: $($r.raw)  PB Sddl=$(Sddl $pb)  " +
          "p9.txt Sddl=$(Sddl $p9) owner=$((Get-Acl -LiteralPath $p9).Owner)")
  }

  # ── P10: a grant neither store records ───────────────────────────
  $g = Grant-P @($pb)
  Remove-Item 'HKCU:\Software\sandbox-runtime\PersistentGrants' -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path $dbDir 'state.db*') -Force -ErrorAction SilentlyContinue
  if ($g.exit -ne 0 -or -not (Has-Persistent $pb)) { Fail 'P10: setup — PB is not carrying a persistent grant' }
  else {
    try {
      $raw = "{`"write`":[`"$(JsonPath $pb)`"]}" |
        & $Exe acl grant --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-String
      $gexit = $LASTEXITCODE
      Write-Host -NoNewline $raw
      if ($gexit -eq 0 -and -not (Has-Persistent $pb) -and (Sddl $pb) -match [regex]::Escape(";;;$sbSid)")) {
        Ok 'P10: a per-session acl grant removed the unrecorded persistent grant before granting'
      } else { Fail "P10: per-session acl grant on a root with an unrecorded persistent grant: exit=$gexit Sddl=$(Sddl $pb)" }
    } finally { End-Session }
  }

  # ── P11: uninstall removes persistent grants ─────────────────────
  $g = Grant-P @($pb)
  if ($g.exit -ne 0 -or -not (Has-Persistent $pb)) { Fail 'P11: setup — PB is not carrying a persistent grant' }
  else {
    & $Exe uninstall --sublayer-guid $Sublayer 2>&1 | Out-String | Write-Host
    $left = @((Get-ItemProperty 'HKCU:\Software\sandbox-runtime\PersistentGrants' -ErrorAction SilentlyContinue).Roots |
      Where-Object { $_ })
    if ((Sddl $pb) -match [regex]::Escape($CapPrefix) -or (Sddl $pb) -match [regex]::Escape($script:grpSid)) {
      Fail "P11: PB still carries persistent ACEs after uninstall: $(Sddl $pb)"
    } elseif ($left.Count -gt 0) { Fail "P11: the marker still lists roots after uninstall: $($left -join ', ')" }
    else { Ok 'P11: uninstall removed the persistent grant and its record' }
  }
}
finally {
  & $Exe acl forget --all 2>&1 | Out-Null
  if ($sbSid) {
    & $Exe acl revoke  --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
    & $Exe acl restore --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
  }
  Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
  & $Exe uninstall --sublayer-guid $Sublayer 2>&1 | Out-Null
}

if ($script:Failures.Count -gt 0) {
  Write-Host "smoke-write-restricted: $($script:Failures.Count) row(s) FAILED:"
  $script:Failures | ForEach-Object { Write-Host "  - $_" }
  throw "smoke-write-restricted: $($script:Failures.Count) row(s) failed"
}
if ($script:Skipped.Count -gt 0) {
  Write-Host "smoke-write-restricted: PASS (A, B, C, F-observed, D, P1-P11) — SKIPPED, no test-hooks binary: $($script:Skipped -join '; ')"
} else {
  Write-Host 'smoke-write-restricted: PASS (G, A, B, C, F-observed, D, E, P1-P11)'
}
