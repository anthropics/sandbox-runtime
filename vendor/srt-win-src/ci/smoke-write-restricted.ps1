<#
  Smoke test for the opt-in write-restricted child token
  (`srt-win exec --write-restricted-token`, `token.rs`).

  The sandbox account is a member of BUILTIN\Users and Authenticated
  Users, so with the default token it can write wherever those groups
  hold write access. The option adds WRITE_RESTRICTED and the
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
# Sandboxed exec, default token.
function SbOff { param([string[]] $tail, [int] $TimeoutSec = 180)
  Wait-Sb (Start-Sb (@('--') + $tail)) $TimeoutSec
}
# Sandboxed exec, write-restricted token.
function SbOn { param([string[]] $tail, [int] $TimeoutSec = 180)
  Wait-Sb (Start-Sb (@('--write-restricted-token', '--') + $tail)) $TimeoutSec
}
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

# Scratch tree at the system-drive root, with inheritance cut on each
# test directory so the ACEs below are the only ones that apply.
# Administrators + SYSTEM keep full control so this script can seed
# and clean up.
$root = Join-Path "$env:SystemDrive\" "srt-wr-smoke-$([guid]::NewGuid().ToString('N'))"
$adm  = @('*S-1-5-32-544:(OI)(CI)(F)', '*S-1-5-18:(OI)(CI)(F)')
function New-AclDir { param([string] $name, [string[]] $extraGrants)
  $d = Join-Path $root $name
  New-Item -ItemType Directory -Path $d -Force | Out-Null
  $grants = $adm + $extraGrants
  & icacls $d /inheritance:r /grant:r @grants | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls $d exited $LASTEXITCODE" }
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
try {
  Run @('install', '--sublayer-guid', $Sublayer, '--proxy-port-range', $PortRange)
  $us = J @('user', 'status')
  $sbSid = $us.marker_user_sid
  if (-not $sbSid) { throw 'setup marker missing user_sid' }
  Write-Host "sandbox user provisioned (sid=$sbSid)"
  New-Item -ItemType Directory -Path $root -Force | Out-Null

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
      Fail 'G: default child token carries restricting SIDs (option off must be unchanged)'
    } else { Ok 'G: default child token has no restricting SIDs' }
  }
  # For the log: the group view of the same token.
  $r = SbOn @($cmd, '/c', 'whoami /user /groups /fo csv /nh')
  Write-Host "G: whoami under the option (exit=$($r.exit)):`n$($r.out.Trim())"

  # ── A: ambient group-held write access ───────────────────────────
  foreach ($case in @(
      @{ tag = 'Authenticated Users'; name = 'au';    ace = '*S-1-5-11:(OI)(CI)(M)' },
      @{ tag = 'BUILTIN\Users';       name = 'users'; ace = '*S-1-5-32-545:(OI)(CI)(M)' })) {
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
  $d = New-AclDir 'everyone' @('*S-1-1-0:(OI)(CI)(M)')
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
    # For the record only: the same probe under the default token.
    $r = SbOff @($HooksAbs, 'probe', 'parent-access')
    Write-Host "E-obs: option OFF (not asserted): $($r.out.Trim())"
  }
}
finally {
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
  Write-Host "smoke-write-restricted: PASS (A, B, C, F-observed, D) — SKIPPED, no test-hooks binary: $($script:Skipped -join '; ')"
} else {
  Write-Host 'smoke-write-restricted: PASS (G, A, B, C, F-observed, D, E)'
}
