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

# Quote one argument for a Win32 command line (MSVCRT rules; our
# arguments contain no embedded quotes, so wrapping and doubling
# backslashes before a closing quote is enough).
function Quote-Arg {
  param([string] $a)
  if ($a -notmatch '[ \t"]') { return $a }
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

$decoy = $null
try {
  try { Start-Service seclogon -ea Stop } catch {
    Write-Host "smoke-env-stdin: WARNING: Start-Service seclogon: $_"
  }

  Run @('install',
        '--sublayer-guid', $Sublayer,
        '--proxy-port-range', $PortRange)
  Write-Host 'S0 ok: installed under test sublayer'

  # -- S1: detection method works: a token planted on a decoy argv IS found --
  # ping -n 30 keeps the decoy alive ~29s; no -WindowStyle (it can
  # fail from a session-0 / service context). Fall back to
  # Diagnostics.Process if Start-Process itself refuses.
  $decoyArgs = '/c', ('rem {0} & ping -n 30 127.0.0.1 >nul' -f $Token)
  try {
    $decoy = Start-Process -FilePath $cmd -ArgumentList $decoyArgs -PassThru
  } catch {
    Write-Host "S1: Start-Process failed ($_); falling back to Diagnostics.Process"
    $dpsi = New-Object System.Diagnostics.ProcessStartInfo
    $dpsi.FileName        = $cmd
    $dpsi.Arguments       = '/c "rem {0} & ping -n 30 127.0.0.1 >nul"' -f $Token
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
    'foreach ($e in Get-ChildItem env:) { $lines += "CENV=$($e.Name)=$($e.Value)" }'
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

  $argv = @('exec',
            '--env', "PATH=$($env:PATH)",
            '--env', "PATHEXT=$($env:PATHEXT)",
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

  # -- S4: child got the token in its ENVIRONMENT (mechanism works) -----
  if ($raw -notmatch "CENV=HTTPS_PROXY=http://sb:$Token@") {
    throw "S4 FAIL: token missing from child env - delivery broken. raw: $raw"
  }
  Write-Host 'S4 ok: token present in the sandboxed child environment'

  # -- S5: child-side view - own + parent + visible cmdlines token-free -
  $selfLine = ($raw -split "`r?`n") | Where-Object { $_ -match '^SELFCMD=' }
  $parentLine = ($raw -split "`r?`n") | Where-Object { $_ -match '^PARENTCMD=' }
  if (-not $selfLine -or -not $parentLine) {
    Write-Host ("S5 WARNING: child could not read its own/parent command " +
                "line via WMI (restricted token); host sweep in S3 already " +
                "covers those processes")
  }
  $badChild = @()
  foreach ($line in ($raw -split "`r?`n")) {
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
