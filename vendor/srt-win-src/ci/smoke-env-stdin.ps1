<#
  Smoke test for `srt-win exec --env-stdin` (the secret-env frame).

  Proves the per-session proxy auth token delivered via the stdin
  frame (a) reaches the sandboxed child's environment, and (b) never
  appears on ANY command line - not the broker's (`srt-win exec`),
  not the runner's, not the child's - as observed both from the HOST
  (real user, full visibility of its own processes) and from INSIDE
  the sandbox (Win32_Process sweep as srt-sandbox).

  Self-contained: provisions the `srt-sandbox` account + WFP filters
  under a fixed test-only sublayer GUID via `srt-win install`, and
  tears them down in `finally`. The fixed GUID is also listed in
  cleanup.ps1 for `if: always()` CI teardown.

  PowerShell 5.1-safe: no ProcessStartInfo.ArgumentList, no
  Process.Kill(bool), no ternary. Pure ASCII.

  Usage:
    powershell -File vendor/srt-win-src/ci/smoke-env-stdin.ps1 <path-to-srt-win.exe>
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe
)

$ErrorActionPreference = 'Stop'

# Fixed test-only sublayer; distinct from srt-win's compile-time
# default and from every other ci/ script (see cleanup.ps1).
$Sublayer  = 'a7f3c9d1-5e28-4b06-8f4a-9c1d2e6b0a35'
$PortRange = '60080-60089'
$PortLo    = 60080

# Unique, greppable, strictly alphanumeric (safe to interpolate into
# JSON and URLs without escaping).
$Token = 'tokprobe' + [Guid]::NewGuid().ToString('N')

$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
$ps  = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Run {
  param([string[]] $argv)
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited $LASTEXITCODE"
  }
}

# Quote one argument for a Win32 command line (MSVCRT rules). This
# hand-rolled quoter cannot represent EMBEDDED quotes - rather than
# emit a silently-mangled Arguments string (which can swallow later
# flags into a quoted value), refuse loudly.
function Quote-Arg {
  param([string] $a)
  if ($a.Contains('"')) {
    throw ("Quote-Arg: argument contains an embedded quote and would " +
           "mangle the command line: " + $a)
  }
  if ($a -notmatch '[ \t]') { return $a }
  $escaped = $a -replace '(\\+)$', '$1$1'
  return '"' + $escaped + '"'
}

# Sweep every Win32_Process command line visible to the CURRENT
# security context; return the ones containing $needle.
function Find-CmdlinesContaining {
  param([string] $needle)
  $hits = @()
  foreach ($q in Get-CimInstance Win32_Process) {
    if ($q.CommandLine -and $q.CommandLine.Contains($needle)) {
      $hits += "pid=$($q.ProcessId) cmd=$($q.CommandLine)"
    }
  }
  return $hits
}

# The child-side probe runs from a file the sandbox user can read
# (ProgramData is world-readable); a file avoids three layers of
# cmd/powershell quoting.
$ProbeDir   = Join-Path $env:ProgramData 'srt-env-stdin-probe'
$InnerProbe = Join-Path $ProbeDir 'inner.ps1'
# Primary S4/S5 oracle: the child WRITES its dump here (host reads it
# after the chain exits). Cycle-4 showed the child's bulk stdout can
# go missing in the VM while single trailing lines (CHILD-DONE)
# arrive, so stdout parsing is only the fallback oracle.
$CenvFile   = Join-Path $ProbeDir 'cenv.txt'

$decoy = $null
try {
  try { Start-Service seclogon -ea Stop } catch {
    Write-Host "smoke-env-stdin: WARNING: Start-Service seclogon: $_"
  }

  Run @('install',
        '--sublayer-guid', $Sublayer,
        '--proxy-port-range', $PortRange)
  $us = (& $Exe user status) | ConvertFrom-Json
  if ($LASTEXITCODE -ne 0) { throw 'S0: srt-win user status failed' }
  $sbSid = $us.marker_user_sid
  if (-not $sbSid) { throw 'S0: setup marker missing user_sid' }
  Write-Host "S0 ok: installed under test sublayer (sb sid=$sbSid)"

  # -- S1: detection method works: a token planted on a decoy argv IS found --
  # ping -n 30 keeps the decoy alive ~29s; no -WindowStyle (it can
  # fail from a session-0 / service context). Fall back to
  # Diagnostics.Process if Start-Process itself refuses.
  $decoyArgs = '/c', ('ping -n 30 127.0.0.1 >nul & rem {0}' -f $Token)
  try {
    $decoy = Start-Process -FilePath $cmd -ArgumentList $decoyArgs -PassThru
  } catch {
    Write-Host "S1: Start-Process failed ($_); falling back to Diagnostics.Process"
    $dpsi = New-Object System.Diagnostics.ProcessStartInfo
    $dpsi.FileName        = $cmd
    $dpsi.Arguments       = '/c "ping -n 30 127.0.0.1 >nul & rem {0}"' -f $Token
    $dpsi.UseShellExecute = $false
    $dpsi.CreateNoWindow  = $true
    $decoy = [System.Diagnostics.Process]::Start($dpsi)
  }
  Start-Sleep -Seconds 1
  # Self-diagnosing control: before trusting the generic sweep,
  # interrogate the decoy DIRECTLY by PID so a failure names its own
  # cause instead of 'sweep method is broken'.
  if ($decoy.HasExited) {
    throw (('S1: decoy exited early with code {0} - the planted-token ' +
            'process did not stay alive for the sweep') -f $decoy.ExitCode)
  }
  $row = Get-CimInstance Win32_Process -Filter ('ProcessId={0}' -f $decoy.Id)
  if ($null -eq $row) {
    throw (('S1: decoy pid {0} is alive but has no Win32_Process row - ' +
            'CIM/WMI is not returning processes in this context') -f $decoy.Id)
  }
  if ([string]::IsNullOrEmpty($row.CommandLine)) {
    $who = & whoami
    throw (('S1: decoy pid {0} row exists but CommandLine is empty - this ' +
            'context ({1}) lacks command-line read rights via WMI') -f $decoy.Id, $who)
  }
  if (-not $row.CommandLine.Contains($Token)) {
    throw (('S1: decoy CommandLine lacks the token (quoting bug). ' +
            'Actual: {0}') -f $row.CommandLine)
  }
  $hits = Find-CmdlinesContaining $Token
  if ($hits.Count -lt 1) {
    throw ('S1: direct PID query sees the token but the generic sweep ' +
           'does not - Find-CmdlinesContaining is broken')
  }
  # Kill the decoy and WAIT for it to be gone - Stop-Process is
  # async, and a lingering decoy would false-fail S3's clean sweep.
  Stop-Process -Id $decoy.Id -Force -ea SilentlyContinue
  if (-not $decoy.WaitForExit(5000)) {
    throw 'S1: decoy did not exit within 5s of Stop-Process'
  }
  $decoy = $null
  Write-Host "S1 ok: cmdline sweep detects a planted token ($($hits.Count) hit(s))"

  # -- S2: run exec with the token ONLY in the --env-stdin frame ----------
  New-Item -ItemType Directory -Force -Path $ProbeDir | Out-Null
  # Explicit modify grants (locale-proof SID form) so the srt-sandbox
  # child can create cenv.txt here regardless of what ProgramData's
  # inherited ACL says on this VM: BUILTIN\Users, plus the sandbox
  # user's own SID in case srt-sandbox is not a Users member.
  & icacls $ProbeDir /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "S2: icacls Users grant on $ProbeDir failed ($LASTEXITCODE)"
  }
  & icacls $ProbeDir /grant ('*{0}:(OI)(CI)M' -f $sbSid) | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "S2: icacls sandbox-sid grant on $ProbeDir failed ($LASTEXITCODE)"
  }
  # The child writes its dump to $CenvFile (primary oracle) AND to
  # stdout (fallback). FILEOK/FILEERR on stdout says which happened.
  $inner = @(
    "`$ErrorActionPreference = 'Continue'"
    '$lines = @()'
    'try {'
    '  $mp = Get-CimInstance Win32_Process -Filter "ProcessId=$PID"'
    '  $lines += "SELFCMD=$($mp.CommandLine)"'
    '  $pp = Get-CimInstance Win32_Process -Filter "ProcessId=$($mp.ParentProcessId)"'
    '  $lines += "PARENTCMD=$($pp.CommandLine)"'
    '  foreach ($q in Get-CimInstance Win32_Process) {'
    '    if ($q.CommandLine) { $lines += "ANYCMD=$($q.CommandLine)" }'
    '  }'
    '  $lines += "WMIOK=1"'
    '} catch {'
    '  $lines += "WMIERR=$_"'
    '}'
    # Env enumeration, DOUBLE-sourced with distinct prefixes and a
    # per-source try/catch that leaves a CENV*ERR trace in the dump
    # (cycle 5: Get-ChildItem env: produced zero entries under real
    # 5.1 in-sandbox with no trace - the loop sat outside any
    # catch, so a statement-terminating provider error vanished).
    # [Environment]::GetEnvironmentVariables() is pure .NET, no PS
    # provider involved.
    'try {'
    '  foreach ($de in [Environment]::GetEnvironmentVariables().GetEnumerator()) {'
    '    $lines += "CENVD=$($de.Key)=$($de.Value)"'
    '  }'
    '} catch {'
    '  $lines += "CENVDERR=$_"'
    '}'
    'try {'
    '  foreach ($e in Get-ChildItem env:) { $lines += "CENV=$($e.Name)=$($e.Value)" }'
    '} catch {'
    '  $lines += "CENVERR=$_"'
    '}'
    'try {'
    ('  Set-Content -Path ''{0}'' -Value ($lines -join "`r`n") -Encoding Ascii' -f $CenvFile)
    '  Write-Output "FILEOK=1"'
    '} catch {'
    '  Write-Output "FILEERR=$_"'
    '}'
    '$lines | Write-Output'
    'Start-Sleep -Seconds 6'
    "Write-Output 'CHILD-DONE'"
  )
  Set-Content -Path $InnerProbe -Value ($inner -join "`r`n") -Encoding Ascii

  # Same shapes the TS wrapper (wrapCommandWithSandboxWindows)
  # emits: tokenless entries on --env, token-bearing proxy entries in
  # the length-prefixed JSON stdin frame gated by --env-stdin. The
  # frame bytes here are a third, hand-rolled copy of the wire
  # format - the canonical definitions are encodeEnvStdinFrame
  # (src/sandbox/windows-sandbox-utils.ts, writer) and
  # runner::decode_env_frame (vendor/srt-win-src/src/runner.rs,
  # reader); keep all three in sync.
  $proxyUrl = "http://sb:$Token@localhost:$PortLo"
  $frameJson = '[["HTTP_PROXY","' + $proxyUrl + '"],["HTTPS_PROXY","' + $proxyUrl + '"]]'
  $frameBody = [Text.Encoding]::UTF8.GetBytes($frameJson)
  $frameLen  = [BitConverter]::GetBytes([UInt32]$frameBody.Length)

  # MINIMAL literal PATH/PATHEXT, not the host's ($env:PATH can
  # contain embedded quotes from third-party installers, which the
  # hand-rolled Quote-Arg cannot represent - a mangled Arguments
  # string can silently swallow later tokens like --env-stdin into a
  # quoted value, and exec would then run happily WITHOUT ever
  # reading the frame). The child only runs cmd + powershell by
  # absolute path, so this minimal set is sufficient.
  $probePath = ('{0}\System32;{0};{0}\System32\WindowsPowerShell\v1.0' -f $env:SystemRoot)
  $argv = @('exec',
            '--env', "PATH=$probePath",
            '--env', 'PATHEXT=.COM;.EXE;.BAT;.CMD;.PS1',
            '--env-stdin',
            '--', $cmd, '/c',
            "$ps -NoProfile -ExecutionPolicy Bypass -File $InnerProbe")
  $quoted = @()
  foreach ($a in $argv) { $quoted += (Quote-Arg $a) }

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName               = $Exe
  $psi.Arguments              = $quoted -join ' '
  $psi.UseShellExecute        = $false
  $psi.RedirectStandardInput  = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  # Broker-side debug breadcrumbs (spawn_runner checkpoints, DACL
  # dump). Note this does NOT reach the runner - seclogon rebuilds
  # its env from the sandbox user's profile - so the runner's own
  # 'spec read' line is best-effort only (see S2c).
  $psi.Environment['SANDBOX_RUNTIME_WIN_DEBUG'] = '1'
  $p = [System.Diagnostics.Process]::Start($psi)
  # Drain output pipes concurrently so a full buffer cannot wedge
  # WaitForExit.
  $so = $p.StandardOutput.ReadToEndAsync()
  $se = $p.StandardError.ReadToEndAsync()
  # Write the frame immediately - exec blocks on it before spawning
  # the runner.
  $stdin = $p.StandardInput.BaseStream
  $stdin.Write($frameLen, 0, 4)
  $stdin.Write($frameBody, 0, $frameBody.Length)
  $stdin.Flush()
  $p.StandardInput.Close()

  # -- S3 data collection: HOST-side sweep while the chain is alive -----
  # The child sleeps 6s after printing; broker + runner + child are
  # all up during this window. The host is the broker's owner, so
  # every process that used to carry the token on argv is visible.
  # COLLECT only here - assertions run after the exec's own exit
  # state is known, so a fast exec failure (install race, seclogon
  # down) surfaces as the exec error it is, not as a sweep
  # misdiagnosis.
  Start-Sleep -Seconds 3
  $hostHits = Find-CmdlinesContaining $Token
  $brokerRows = Find-CmdlinesContaining '--env-stdin'
  if (-not $p.WaitForExit(60000)) {
    try { $p.Kill() } catch { }
    $p.WaitForExit()
    throw "S2: exec TIMEOUT after 60s. stderr: $($se.Result)"
  }
  $raw = $so.Result + "`n" + $se.Result

  # -- S2 verdict FIRST: did exec itself succeed? -----------------------
  if ($p.ExitCode -ne 0) {
    throw "S2: exec exited $($p.ExitCode). raw: $raw"
  }
  if ($raw -notmatch 'CHILD-DONE') {
    throw "S2: child probe did not complete. raw: $raw"
  }
  Write-Host 'S2 ok: exec chain ran the probe to completion'

  # -- S2b/S2c: frame-delivery breadcrumbs, localizing any S4 fail --
  # exec (non-quiet) prints 'launching runner as ... (overlay=N
  # var(s))': N must be 4 (PATH + PATHEXT + the 2 frame vars). N=2
  # with exit 0 means clap never saw --env-stdin (exec cannot exit 0
  # with the flag parsed but the frame unread - the read errors or
  # times out), i.e. the Arguments string was mangled.
  if ($raw -notmatch 'overlay=4 var\(s\)') {
    $srtLines = ($raw -split "`r?`n") | Where-Object { $_ -match 'srt-win:' }
    throw ("S2b FAIL: exec did not report overlay=4 - the stdin frame " +
           "vars never joined the overlay (flag lost or frame unread). " +
           "srt-win lines:`n" + ($srtLines -join "`n"))
  }
  Write-Host 'S2b ok: exec merged the frame (overlay=4)'
  # Runner debug line ('spec read (argv=N env_overlay=M)'): only
  # printed when the RUNNER's env has SANDBOX_RUNTIME_WIN_DEBUG,
  # which the broker-side setting above does NOT provide (the runner
  # starts from the sandbox user's profile env - lpEnvironment=NULL
  # across seclogon). Assert when present, note when absent.
  if ($raw -match 'env_overlay=(\d+)') {
    if ($Matches[1] -ne '4') {
      throw ("S2c FAIL: runner reported env_overlay=$($Matches[1]), " +
             "expected 4 - the spec pipe dropped entries")
    }
    Write-Host 'S2c ok: runner received all 4 overlay entries'
  } else {
    Write-Host ('S2c skipped: no runner spec-read line (debug env does ' +
                'not cross the seclogon boundary)')
  }

  # -- S3: host-side sweep assertions -----------------------------------
  if ($hostHits.Count -ne 0) {
    throw ("S3 FAIL: token visible on a command line (host sweep):`n" +
           ($hostHits -join "`n"))
  }
  if ($brokerRows.Count -lt 1) {
    throw ("S3 FAIL: exec succeeded but no live process carried " +
           "--env-stdin during the sweep window - the sweep timing " +
           "missed the chain; consider a longer child sleep")
  }
  Write-Host 'S3 ok: host-side sweep - token on no command line; exec chain was live'

  # -- Child-dump oracle: prefer the FILE the child wrote; fall back
  # to stdout parsing. (Cycle 4: the child's bulk stdout dump went
  # missing while CHILD-DONE arrived, so stdout alone is not a
  # trustworthy negative.)
  $rawLines = $raw -split "`r?`n"
  if (Test-Path $CenvFile) {
    $oracleSrc = 'file'
    $dump = @(Get-Content -Path $CenvFile)
  } else {
    $oracleSrc = 'stdout'
    $dump = @($rawLines | Where-Object {
      $_ -match '^(SELFCMD|PARENTCMD|ANYCMD|CENV|CENVD|CENVERR|CENVDERR|WMIOK|WMIERR)='
    })
    $fileNote = @($rawLines | Where-Object { $_ -match '^FILE(OK|ERR)=' })
    Write-Host ("oracle: cenv.txt missing - child file-write said: " +
                ($fileNote -join '; '))
  }
  Write-Host ("oracle: source=$oracleSrc dump lines=$($dump.Count)")

  # -- S4: child got the token in its ENVIRONMENT (mechanism works) -----
  # Either enumeration source counts: CENVD= ([Environment]::
  # GetEnvironmentVariables()) or CENV= (Get-ChildItem env:).
  $tokenEnv = @($dump | Where-Object {
    $_ -match "^CENVD?=HTTPS_PROXY=http://sb:$Token@"
  })
  if ($tokenEnv.Count -lt 1) {
    # With S2b green the drop is in build_env_block / CreateProcess /
    # the cmd->powershell hop OR in the child-side enumeration. The
    # dump is small on failure - print it VERBATIM so the next cycle
    # needs no guessing about what the child recorded.
    $srtLines = @($rawLines | Where-Object { $_ -match 'srt-win:' })
    throw ("S4 FAIL: token missing from child env - delivery broken " +
           "past the runner (see S2b/S2c). oracle=$oracleSrc; " +
           "dump ($($dump.Count) line(s)) verbatim:`n" +
           ($dump -join "`n") +
           "`nsrt-win lines:`n" + ($srtLines -join "`n"))
  }
  Write-Host "S4 ok: token present in the sandboxed child environment ($oracleSrc)"

  # -- S5: child-side view - own + parent + visible cmdlines token-free -
  $selfLine = $dump | Where-Object { $_ -match '^SELFCMD=' }
  $parentLine = $dump | Where-Object { $_ -match '^PARENTCMD=' }
  if (-not $selfLine -or -not $parentLine) {
    Write-Host ("S5 WARNING: child could not read its own/parent command " +
                "line via WMI (restricted token); host sweep in S3 already " +
                "covers those processes")
  }
  $badChild = @()
  foreach ($line in $dump) {
    if (($line -match '^(SELFCMD|PARENTCMD|ANYCMD)=') -and $line.Contains($Token)) {
      $badChild += $line
    }
  }
  if ($badChild.Count -ne 0) {
    throw ("S5 FAIL: token visible on a command line (sandbox-side sweep):`n" +
           ($badChild -join "`n"))
  }
  Write-Host 'S5 ok: sandbox-side sweep - token on no visible command line'

  Write-Host 'smoke-env-stdin: ALL OK'
} finally {
  if ($decoy) { Stop-Process -Id $decoy.Id -Force -ea SilentlyContinue }
  Remove-Item -Recurse -Force $ProbeDir -ea SilentlyContinue
  $ErrorActionPreference = 'SilentlyContinue'
  & $Exe wfp uninstall --sublayer-guid $Sublayer
  & $Exe uninstall --sublayer-guid $Sublayer
  $ErrorActionPreference = 'Stop'
}
