<#
  Smoke test for `srt-win exec` (the two-hop sandbox-user launch).

  Self-contained: provisions the `srt-sandbox` account + WFP filters
  under a fixed test-only sublayer GUID via `srt-win install`, then
  exercises exec end-to-end. The fixed GUID lets the workflow's
  `if: always()` cleanup step uninstall any leaked filters even if
  this script throws mid-run.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe
)

$ErrorActionPreference = 'Stop'

# Fixed test-only sublayer; distinct from srt-win's compile-time
# default and from anything smoke.ps1 uses. Referenced verbatim by
# the workflow's always()-cleanup step.
$Sublayer  = '5b0e64f4-09f1-4c2e-8c97-4d2c0f4e9b7d'
# Loopback PERMIT is scoped to this port range. Anything on
# 127.0.0.1 outside it is BLOCKed. Match srt-win's default but pass
# it explicitly so this script doesn't drift if the default changes.
$PortRange = '60080-60089'
$PortLo    = 60080
$PortHi    = 60089

# Bind a TcpListener on the first free port from $candidates, on
# 127.0.0.1 unless another address is given. Throws if none bind.
function Bind-Listener {
  param([int[]] $Candidates,
        [System.Net.IPAddress] $Address = [System.Net.IPAddress]::Loopback)
  foreach ($p in $Candidates) {
    try {
      $l = [System.Net.Sockets.TcpListener]::new($Address, $p)
      $l.Start()
      return $l
    } catch {
      # port in use — try next
    }
  }
  throw "no free port among: $($Candidates -join ',')"
}

function Run {
  param([string[]] $argv)
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited $LASTEXITCODE"
  }
}
function J { param([string[]] $argv) Run $argv | ConvertFrom-Json }

$cmd  = Join-Path $env:SystemRoot 'System32\cmd.exe'
$pwsh = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
# Enable srt-win's per-exec stderr diagnostics (notably the
# self-protect SDDL dump).
$env:SANDBOX_RUNTIME_WIN_DEBUG = '1'
Write-Host "smoke-exec: sublayer=$Sublayer  exe=$Exe"

# CreateProcessWithLogonW routes through the Secondary Logon
# service. GHA runners have it; ensure it's running (idempotent).
try { Start-Service seclogon -ea Stop } catch {
  Write-Host "smoke-exec: WARNING: Start-Service seclogon: $_"
}

# ── R0b: exec without provisioning → exit 15 ──
$r0b = & $Exe exec -- $cmd /c 'exit 0' 2>&1 | Out-String
if ($LASTEXITCODE -ne 15) {
  throw "R0b: expected exit 15 (not provisioned), got ${LASTEXITCODE}. out: $r0b"
}
if ($r0b -notmatch '(?i)srt-win install') {
  throw "R0b: expected re-run install hint. out: $r0b"
}
Write-Host 'R0b ok: exec exits 15 with install hint when not provisioned'

# Full install under the test sublayer: provisions srt-sandbox +
# sandbox-runtime-users + DPAPI cred + setup marker + the user-SID
# WFP filter pair.
Run @('install',
      '--sublayer-guid',$Sublayer,
      '--proxy-port-range',$PortRange)
$us = J @('user','status')
if (-not $us.user.exists) { throw 'R: srt-sandbox not provisioned' }
$sbSid = $us.marker_user_sid
if (-not $sbSid) { throw 'R: setup marker missing user_sid' }
Write-Host "R: sandbox user provisioned (sid=$sbSid)"

# ── V1: wfp verify — behavioral egress-block probe ──────────────
# The non-elevated readiness check that replaced exec's WFP
# pre-flight. The block-user filter from `install` above fires at
# ALE_AUTH_CONNECT → WSAEACCES → exit 0 + "blocked". stderr (the
# runner's BLOCKED line) flows to the host so it's in the CI log;
# stdout is JUST the JSON line. `--target` is required: bind a
# local listener on an out-of-range loopback port (same shape as
# the product path — `verifyWindowsWfpEgress` does this in TS).
$v1Lsn = Bind-Listener (49990..49999)
$v1Tgt = "127.0.0.1:$($v1Lsn.LocalEndpoint.Port)"
$vout = & $Exe wfp verify --target $v1Tgt --anonymous-egress
$vexit = $LASTEXITCODE
# V1d: without the flag (the session-start form) that attempt is not made.
$v1dOut = & $Exe wfp verify --target $v1Tgt
$v1dExit = $LASTEXITCODE
$v1Lsn.Stop()
Write-Host "V1: wfp verify --target $v1Tgt exit=$vexit stdout='$vout'"
# The exit code first: only 0, 2 and 3 come with a probe report to parse.
if ($vexit -notin 0, 2, 3) { throw "V1: wfp verify exited $vexit without a probe report. stdout: $vout" }
$v = $vout | ConvertFrom-Json

# ── V1c: lowered-integrity copies of the sandbox token are blocked ──
# `error` means the lowered token could not be assumed (the kernel refuses
# it under some tokens): accepted only with the residual that reports it.
$loweredFields = 'low_integrity_probe','low_integrity_loopback_probe',
                 'untrusted_integrity_probe','untrusted_integrity_loopback_probe'
foreach ($f in $loweredFields) {
  if ($null -eq $v.PSObject.Properties[$f]) { throw "V1c: wfp verify output lacks '$f': $vout" }
}
$loweredRaw = ($loweredFields | ForEach-Object { "$_=$($v.$_)" }) -join ' '
Write-Host "V1c raw: $loweredRaw (off-loopback target=$($v.anonymous_target))"
$loweredOpen = @($loweredFields | Where-Object { $v.$_ -in 'connected','refused' })
if ($loweredOpen.Count -gt 0) {
  throw "V1c: BYPASS - a connect under a lowered-integrity copy of the sandbox token was NOT blocked " +
        "($($loweredOpen -join ', ')); block-user does not match that token. $loweredRaw exit=$vexit"
}
foreach ($f in $loweredFields) {
  $got = $v.$f
  $offLoopback = $f -notlike '*_loopback_probe'
  if ($got -eq 'error') {
    if ($v.residuals -notcontains 'lowered-integrity-unprobed') {
      throw "V1c: $f=error without the lowered-integrity-unprobed residual; an attempt that was " +
            "not made must be reported. $loweredRaw residuals=$($v.residuals -join ',')"
    }
    Write-Host "V1c note: $f not set up (error), reported as lowered-integrity-unprobed"
  } elseif ($got -eq 'skipped' -and $offLoopback) {
    Write-Host "V1c note: $f skipped (no off-loopback address on this runner)"
  } elseif ($got -ne 'blocked') {
    throw "V1c: $f expected blocked, got '$got'. $loweredRaw"
  }
}
Write-Host "V1c ok: no lowered-integrity connect got out: $loweredRaw"

if ($vexit -ne 0) {
  throw "V1: wfp verify expected exit 0 (blocked), got $vexit. stdout: $vout"
}
if ($v.egress_probe -ne 'blocked') {
  throw "V1: wfp verify expected egress_probe=blocked, got '$($v.egress_probe)'"
}
Write-Host 'V1 ok: wfp verify reports egress_probe=blocked'

# ── V1b: wfp verify reports each token shape separately ─────────
# Recorded, not asserted (no filter covers these shapes). Asserted: a
# connect is named in `residuals`, and only a connect.
foreach ($f in 'anonymous_probe','anonymous_loopback_probe','deny_only_probe','residuals') {
  if ($null -eq $v.PSObject.Properties[$f]) { throw "V1b: wfp verify output lacks '$f': $vout" }
}
if ($v.anonymous_probe -eq 'skipped') {
  Write-Host 'V1b note: anonymous attempt skipped (no off-loopback address on this runner)'
}
foreach ($pair in @(@('anonymous_probe','anonymous-egress'), @('anonymous_loopback_probe','anonymous-loopback'), @('deny_only_probe','deny-only-user-sid'))) {
  $got = $v.($pair[0])
  $open = $got -in 'connected','refused'
  if ($open -ne ($v.residuals -contains $pair[1])) {
    throw "V1b: $($pair[0])='$got' but residuals=[$($v.residuals -join ',')] - a connect must be named as '$($pair[1])', and only a connect"
  }
  Write-Host "V1b obs: $($pair[1]) $($pair[0])=$got named-in-residuals=$open"
}
# Kept for the in-sandbox rows below, which print these beside theirs.
$verify = $v

if ($v1dExit -ne 0) { throw "V1d: wfp verify without --anonymous-egress expected exit 0, got $v1dExit. stdout: $v1dOut" }
$v1d = $v1dOut | ConvertFrom-Json
if ($v1d.anonymous_probe -ne 'skipped' -or $v1d.residuals -contains 'anonymous-egress') {
  throw "V1d: without --anonymous-egress expected anonymous_probe=skipped and no anonymous-egress residual: $v1dOut"
}
if ($v1d.egress_probe -ne 'blocked' -or $v1d.anonymous_loopback_probe -eq 'skipped') {
  throw "V1d: the other attempts must still be made: $v1dOut"
}
Write-Host 'V1d ok: wfp verify makes the anonymous off-loopback attempt only with --anonymous-egress'
Write-Host "V1b ok: anonymous_probe=$($v.anonymous_probe) target=$($v.anonymous_target); residuals=[$($v.residuals -join ',')]"

# Exec helper. Same .exit/.raw/.out shape as before. The broker
# forwards exactly what it is told via --env (it does NOT enumerate
# its own environment), so pass PATH/PATHEXT here — same overlay the
# TS wrapper builds.
#
# Watchdog: the two-hop chain (broker → CPWLW runner → restricted
# child) has no console; a hang anywhere inside it would otherwise
# sit until the GHA job timeout. 30s is generous — every R-row
# payload is sub-second. System.Diagnostics.Process (not the `&`
# call operator or Start-Process) so we get (a) WaitForExit with a
# timeout and (b) per-element ArgumentList quoting that survives
# PATH-with-spaces.
function RExec {
  # 120s: a row that starts Windows PowerShell as the sandbox user can take
  # over 30s on some hosted runner images (powershell.exe is CPU-bound in
  # startup the whole time, then finishes). A limit only matters on a hang.
  param([string[]] $tail, [int] $TimeoutSec = 120)
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
  # Drain both pipes concurrently so a full pipe buffer can't wedge
  # WaitForExit.
  $so = $p.StandardOutput.ReadToEndAsync()
  $se = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    # Report through the host, not the exception: the error view truncates a
    # long message, and the child's output and the processes it got as far as
    # starting are what say where it stopped.
    $since = $p.StartTime
    Get-CimInstance Win32_Process |
      Where-Object { $_.ProcessId -eq $p.Id -or $_.CreationDate -ge $since } |
      Sort-Object CreationDate |
      ForEach-Object {
        Write-Host ("RExec timeout: proc pid={0} ppid={1} {2} cpu={3:n1}s" -f
          $_.ProcessId, $_.ParentProcessId, $_.Name,
          (($_.UserModeTime + $_.KernelModeTime) / 1e7))
      }
    try { $p.Kill($true) } catch { }
    $p.WaitForExit()
    Write-Host "RExec timeout: argv tail: $($tail -join ' ')"
    Write-Host "RExec timeout: stderr:`n$($se.Result)"
    Write-Host "RExec timeout: stdout:`n$($so.Result)"
    throw "RExec: TIMEOUT after ${TimeoutSec}s (child output above)"
  }
  $exit  = $p.ExitCode
  $raw   = $so.Result + $se.Result
  $lines = $raw -split "`r?`n"
  $child = ($lines | Where-Object { $_ -notmatch '^srt-win:' }) -join "`n"
  return [pscustomobject]@{ exit = $exit; raw = $raw; out = $child }
}

# ── R1: child runs as srt-sandbox ───────────────────────────────
$r = RExec @('--', $cmd, '/c', 'whoami /user /FO CSV /NH')
if ($r.exit -ne 0) { throw "R1: whoami exited $($r.exit). raw: $($r.raw)" }
$row = $r.out | ConvertFrom-Csv -Header Name,SID
if ($row.SID -ne $sbSid) {
  throw "R1: child user SID $($row.SID), expected $sbSid. raw: $($r.raw)"
}
Write-Host "R1 ok: two-hop child runs as srt-sandbox (sid=$($row.SID))"

# ── R2: stdio piped broker ← runner ← child ─────────────────────
$r = RExec @('--', $cmd, '/c', 'echo R2-STDOUT-MARK & echo R2-STDERR-MARK 1>&2')
if ($r.out -notmatch 'R2-STDOUT-MARK') {
  throw "R2: stdout marker missing. raw: $($r.raw)"
}
if ($r.raw -notmatch 'R2-STDERR-MARK') {
  throw "R2: stderr marker missing. raw: $($r.raw)"
}
Write-Host 'R2 ok: stdout+stderr piped through runner to broker'

# ── R3: exit code propagates broker ← runner ← child ────────────
$r = RExec @('--', $cmd, '/c', 'exit 23')
if ($r.exit -ne 23) {
  throw "R3: expected exit 23, got $($r.exit). raw: $($r.raw)"
}
Write-Host 'R3 ok: child exit code propagates through runner'

# ── R4: env-merge — USERPROFILE isolated, PATH overlaid ─────────
# LOGON_WITH_PROFILE gives the runner the sandbox user's profile
# env (USERPROFILE/TEMP under C:\Users\srt-sandbox). The broker's
# PATH is overlaid via the spec so tools resolve. Probe both.
$r = RExec @('--', $cmd, '/c', 'echo UP=%USERPROFILE%& echo PATH=%PATH%')
if ($r.out -notmatch '(?i)UP=.*srt-sandbox') {
  throw "R4: USERPROFILE not isolated to srt-sandbox. out: $($r.out)"
}
if ($r.out -notmatch '(?i)PATH=.*System32') {
  throw "R4: PATH overlay missing System32. out: $($r.out)"
}
Write-Host 'R4 ok: USERPROFILE isolated, broker PATH overlaid'

# Names in `set` output that appear more than once ignoring case.
function Get-RepeatedEnvNames {
  param([string] $SetOutput)
  $SetOutput -split "`r?`n" |
    Where-Object { $_ -match '^[^=]+=' } |
    ForEach-Object { ($_ -split '=', 2)[0].ToUpperInvariant() } |
    Group-Object | Where-Object { $_.Count -gt 1 } |
    ForEach-Object { $_.Name }
}

# ── R4b: an upper-case proxy variable reaches the child in lower case, once ──
$r = RExec @('--env', "HTTP_PROXY=http://127.0.0.1:$PortLo",
             '--', $cmd, '/c', 'set http')
if ($r.exit -ne 0) { throw "R4b: 'set http' exited $($r.exit). out: $($r.out)" }
$lines = $r.out -split "`r?`n"
if (-not ($lines | Where-Object { $_ -clike 'http_proxy=*' })) {
  throw "R4b: lowercase http_proxy missing in child. out: $($r.out)"
}
$n = @($lines | Where-Object { $_ -like 'http_proxy=*' }).Count
if ($n -ne 1) {
  throw "R4b: http_proxy is in the child's environment $n times ignoring case. out: $($r.out)"
}
Write-Host 'R4b ok: an overlay proxy var reaches the child in lower case, once'

$bothCases = @(
  '--env', "HTTP_PROXY=http://127.0.0.1:$PortLo",
  '--env', "HTTPS_PROXY=http://127.0.0.1:$PortLo",
  '--env', "http_proxy=http://127.0.0.1:$PortLo",
  '--env', "https_proxy=http://127.0.0.1:$PortLo",
  '--env', "ALL_PROXY=http://127.0.0.1:$PortLo",
  '--env', "all_proxy=http://127.0.0.1:$PortLo",
  '--env', "GRPC_PROXY=http://127.0.0.1:$PortLo",
  '--env', "grpc_proxy=http://127.0.0.1:$PortLo",
  '--env', "FTP_PROXY=socks5h://127.0.0.1:$PortLo",
  '--env', "ftp_proxy=socks5h://127.0.0.1:$PortLo",
  '--env', "RSYNC_PROXY=127.0.0.1:$PortLo",
  '--env', "rsync_proxy=127.0.0.1:$PortLo",
  '--env', 'NODE_USE_ENV_PROXY=1')

# ── R4c: no name is in the child's environment twice ─────────────
$r = RExec ($bothCases + @('--', $cmd, '/c', 'set'))
if ($r.exit -ne 0) { throw "R4c: 'set' exited $($r.exit). out: $($r.out)" }
$repeated = @(Get-RepeatedEnvNames $r.out)
if ($repeated.Count -ne 0) {
  throw "R4c: names in the child's environment twice ignoring case: $($repeated -join ', '). out: $($r.out)"
}
$lines = $r.out -split "`r?`n"
foreach ($name in 'http_proxy', 'https_proxy', 'all_proxy', 'grpc_proxy',
                  'ftp_proxy', 'RSYNC_PROXY', 'NODE_USE_ENV_PROXY') {
  if (-not ($lines | Where-Object { $_ -clike "$name=*" })) {
    throw "R4c: $name missing in child under that spelling. out: $($r.out)"
  }
}
$r = RExec ($bothCases + @('--', $cmd, '/c',
  'set "NODE_USE_ENV_PROXY=" & set NODE_USE_ENV & echo R4C-DONE'))
if ($r.out -notmatch 'R4C-DONE' -or $r.out -match '(?im)^NODE_USE_ENV_PROXY=') {
  throw "R4c: NODE_USE_ENV_PROXY survived being cleared. raw: $($r.raw)"
}
Write-Host 'R4c ok: each name once ignoring case; a cleared variable is gone'

# ── R4d: .NET can load the child's environment ───────────────────
$r = RExec ($bothCases + @('--', $pwsh, '-NoProfile', '-Command',
  "try { 'R4D-COUNT=' + (New-Object System.Diagnostics.ProcessStartInfo).EnvironmentVariables.Count } " +
  "catch { 'R4D-ERR: ' + `$_ }"))
if ($r.out -notmatch 'R4D-COUNT=\d+') {
  throw "R4d: .NET could not load the environment. raw: $($r.raw)"
}
Write-Host 'R4d ok: ProcessStartInfo.EnvironmentVariables loads'

# ── R4e: Windows PowerShell Start-Process with redirection ───────
$r = RExec ($bothCases + @('--', $pwsh, '-NoProfile', '-Command',
  "`$o = Join-Path `$env:TEMP 'srt-r4e-out.txt'; " +
  "try { Start-Process cmd -ArgumentList '/c','echo R4E-OK' -RedirectStandardOutput `$o -Wait -NoNewWindow; Get-Content `$o } " +
  "catch { 'R4E-ERR: ' + `$_ } finally { Remove-Item `$o -ErrorAction SilentlyContinue }"))
if ($r.out -notmatch 'R4E-OK') {
  throw "R4e: Start-Process -RedirectStandardOutput did not run its command. raw: $($r.raw)"
}
Write-Host 'R4e ok: Start-Process -RedirectStandardOutput starts its command'

# ── R4f: an MSYS2 shell sees one name, and so does what it starts ─
$gitBash = 'C:\Program Files\Git\usr\bin\bash.exe'
if (Test-Path $gitBash) {
  # Built as one string first: in an array literal `,` binds tighter than `+`.
  $script = "/usr/bin/env | /usr/bin/grep -i '^http_proxy=' | /usr/bin/wc -l; " +
            "/usr/bin/env | /usr/bin/grep -c '^http_proxy='"
  $r = RExec ($bothCases + @('--', $gitBash, '-c', $script))
  $counts = @($r.out -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  if ($r.exit -ne 0 -or $counts.Count -ne 2 -or $counts[0] -ne '1' -or $counts[1] -ne '1') {
    throw "R4f: expected one http_proxy, in lower case, in the shell's environment; counts: $($counts -join ' / '). exit: $($r.exit). raw: $($r.raw)"
  }
  $r = RExec ($bothCases + @('--', $gitBash, '-c', 'cmd.exe //c set'))
  $proxyLines = @($r.out -split "`r?`n" | Where-Object { $_ -match '(?i)^[^=]*_proxy=' })
  $repeated = @(Get-RepeatedEnvNames ($proxyLines -join "`n"))
  if ($r.exit -ne 0 -or $repeated.Count -ne 0 -or
      -not ($proxyLines | Where-Object { $_ -clike 'http_proxy=*' })) {
    throw "R4f: a native child of the shell has repeated names ($($repeated -join ', ')) or no http_proxy. raw: $($r.raw)"
  }
  Write-Host 'R4f ok: one http_proxy in an MSYS2 shell and in its native child'
} else {
  Write-Host 'R4f skipped: no Git Bash on this runner'
}

# ── R5: outbound blocked by block-user filter ───────────────────
# The user-SID WFP filter blocks all srt-sandbox egress except
# in-range loopback. No proxy env in this row, so the child's
# direct curl must fail.
$r = RExec @('--', $cmd, '/c', 'curl -sS -m 5 https://example.com')
if ($r.exit -eq 0) {
  throw "R5: outbound curl succeeded under sandbox " +
        "(block-user not in effect?). out: $($r.out)"
}
Write-Host "R5 ok: outbound blocked for srt-sandbox (curl exit=$($r.exit))"

# ── R5b: in-range loopback permitted ─────────────────────────────
$inRangeR = Bind-Listener ($PortHi..($PortLo+5))
$portInR  = $inRangeR.LocalEndpoint.Port
try {
  # TcpClient, as in R5d/R5e, not Test-NetConnection: the cmdlet loads the
  # NetTCPIP module and falls back to a ping, which roughly doubles the row.
  # This is the first Windows PowerShell started as the sandbox user; log how
  # long it took.
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command',
    "try { `$c = New-Object Net.Sockets.TcpClient; `$c.Connect('127.0.0.1', $portInR); Write-Output CONNECTED } " +
    "catch { Write-Output blocked }")
  Write-Host "R5b: first powershell.exe as srt-sandbox took $([int]$sw.Elapsed.TotalSeconds)s"
  if ($r.out -notmatch 'CONNECTED') {
    throw "R5b: loopback to in-range port $portInR did not succeed. raw: $($r.raw)"
  }
  Write-Host "R5b ok: in-range loopback permitted for srt-sandbox (port=$portInR)"
} finally {
  $inRangeR.Stop()
}

# ── R5c: out-of-range loopback blocked ───────────────────────────
$outRange = Bind-Listener (50000, 50001, 50002, 49999)
$portOut  = $outRange.LocalEndpoint.Port
try {
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command',
    "try { `$c = New-Object Net.Sockets.TcpClient; `$c.Connect('127.0.0.1', $portOut); Write-Output CONNECTED } " +
    "catch { Write-Output blocked }")
  if ($r.out -match 'CONNECTED') {
    throw "R5c: loopback to out-of-range port $portOut succeeded. raw: $($r.raw)"
  }
  # Sanity: prove the listener was actually live (reachable from
  # the unsandboxed broker), so a False isn't just "port closed".
  $bs = (Test-NetConnection 127.0.0.1 -Port $portOut `
         -WarningAction SilentlyContinue).TcpTestSucceeded
  if (-not $bs) {
    throw "R5c: broker-side connect to its own listener on " +
          "$portOut failed — test invalid"
  }
  Write-Host "R5c ok: loopback to out-of-range port $portOut blocked"
} finally {
  $outRange.Stop()
}

# ── R5d: IPv6 loopback out-of-range blocked ──────────────────────
# The WFP fence must cover the v6 layers too: a v4-only filter set
# would leave [::1] as a silent hole to every local service. Real
# listener on [::1], child connect must be denied (an
# AccessDenied/timeout, never a successful connect).
# Ephemeral, not a fixed port: a bind inside one of Windows' per-machine
# excluded port ranges fails with WSAEACCES. Re-draw if the OS hands out a
# port inside the permit range.
do {
  $v6l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::IPv6Loopback, 0)
  $v6l.Start()
  $portV6 = $v6l.LocalEndpoint.Port
  $inPermit = $portV6 -ge $PortLo -and $portV6 -le $PortHi
  if ($inPermit) { $v6l.Stop() }
} while ($inPermit)
try {
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command',
    "try { `$c = New-Object Net.Sockets.TcpClient([Net.Sockets.AddressFamily]::InterNetworkV6); " +
    "`$c.Connect('::1', $portV6); Write-Output CONNECTED } catch { Write-Output blocked }")
  if ($r.out -match 'CONNECTED') {
    throw "R5d: sandboxed connect to [::1]:$portV6 succeeded — v6 fence hole. raw: $($r.raw)"
  }
  Write-Host 'R5d ok: IPv6 loopback out-of-range blocked'
} finally {
  $v6l.Stop()
}

# ── R5e: loopback ALIAS (127.0.0.2) out-of-range blocked ─────────
# 127.0.0.0/8 is all loopback; a filter keyed on 127.0.0.1 alone
# would leave every other alias open. No listener needed — the
# discriminating signal is AccessDenied (WFP) vs ConnectionRefused
# (no filter, nothing listening).
$r = RExec @('--', $pwsh, '-NoProfile', '-Command',
  "try { `$c = New-Object Net.Sockets.TcpClient; `$c.Connect('127.0.0.2', 49998); Write-Output CONNECTED } " +
  "catch { Write-Output ('code=' + `$_.Exception.InnerException.SocketErrorCode) }")
if ($r.out -match 'CONNECTED') {
  throw "R5e: sandboxed connect to 127.0.0.2 succeeded. raw: $($r.raw)"
}
if ($r.out -notmatch 'AccessDenied') {
  throw "R5e: expected AccessDenied (WFP block), got: $($r.raw)"
}
Write-Host 'R5e ok: loopback alias 127.0.0.2 blocked by the fence'

# ── R5g-R5j: connects made under an assumed token ────────────────────
# The engine attributes a connect to the token in effect when its SOCKET
# was created, so each shape is tried with the socket made BEFORE and AFTER.
function TokenProbeScript {
  param([string] $Ip, [int] $Port, [string[]] $Shapes)
  $calls = foreach ($entry in $Shapes) {
    $label, $shape = $entry -split '=', 2
    "'$label.BEFORE=' + [SrtTok]::Go('$Ip', $Port, '$shape', `$false)"
    "'$label.AFTER=' + [SrtTok]::Go('$Ip', $Port, '$shape', `$true)"
  }
  return @"
`$src = @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
public static class SrtTok {
  [StructLayout(LayoutKind.Sequential)] struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
  [StructLayout(LayoutKind.Sequential)] struct TokenMandatoryLabel { public SidAndAttributes Label; }
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateAnonymousToken(IntPtr thread);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenThreadToken(IntPtr thread, uint access, bool openAsSelf, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attrs, int level, int type, out IntPtr dup);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool CreateRestrictedToken(IntPtr token, uint flags, uint disableCount, ref SidAndAttributes disable, uint deleteCount, IntPtr delete, uint restrictCount, IntPtr restrict, out IntPtr newToken);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool ConvertStringSidToSidW(string sid, out IntPtr psid);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool ConvertSidToStringSidW(IntPtr psid, out IntPtr str);
  [DllImport("advapi32.dll")] static extern int GetLengthSid(IntPtr sid);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool SetTokenInformation(IntPtr token, int cls, ref TokenMandatoryLabel info, int len);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr info, int len, out int ret);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool SetThreadToken(IntPtr thread, IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool RevertToSelf();
  [DllImport("ws2_32.dll", SetLastError=true)] static extern IntPtr socket(int af, int type, int protocol);
  [DllImport("ws2_32.dll", SetLastError=true)] static extern int closesocket(IntPtr s);
  [DllImport("ws2_32.dll", SetLastError=true)] static extern int connect(IntPtr s, byte[] name, int len);
  const int TokenUser = 1, TokenImpersonationLevel = 9, TokenIntegrityLevel = 25;
  static readonly IntPtr InvalidSocket = new IntPtr(-1);
  static SrtTok() {
    // Start Winsock under the process's own token, once.
    new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp).Dispose();
  }
  static string Fail(string step) { return "TOKEN_FAILED:" + step + ":" + Marshal.GetLastWin32Error(); }
  static string TokenSid(IntPtr token, int cls) {
    IntPtr buf = Marshal.AllocHGlobal(256), str = IntPtr.Zero;
    try {
      int ret;
      if (!GetTokenInformation(token, cls, buf, 256, out ret)) return null;
      if (!ConvertSidToStringSidW(Marshal.ReadIntPtr(buf), out str)) return null;
      return Marshal.PtrToStringUni(str);
    } finally {
      if (str != IntPtr.Zero) LocalFree(str);
      Marshal.FreeHGlobal(buf);
    }
  }
  static string Assume(string shape) {
    if (shape == "anonymous")
      return ImpersonateAnonymousToken(GetCurrentThread()) ? null : Fail("impersonate-anonymous");
    IntPtr own = IntPtr.Zero, restricted = IntPtr.Zero, dup = IntPtr.Zero, psid = IntPtr.Zero;
    IntPtr userBuf = IntPtr.Zero;
    try {
      // TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY
      if (!OpenProcessToken(GetCurrentProcess(), 0x000B, out own)) return Fail("open");
      IntPtr source = own;
      if (shape == "denyonly") {
        // The user SID in the disable list becomes deny-only.
        userBuf = Marshal.AllocHGlobal(256);
        int ret;
        if (!GetTokenInformation(own, TokenUser, userBuf, 256, out ret)) return Fail("query-user");
        SidAndAttributes disable = new SidAndAttributes();
        disable.Sid = Marshal.ReadIntPtr(userBuf);
        if (!CreateRestrictedToken(own, 0, 1, ref disable, 0, IntPtr.Zero, 0, IntPtr.Zero, out restricted)) return Fail("restrict");
        source = restricted;
      }
      // TOKEN_ALL_ACCESS, SecurityImpersonation, TokenImpersonation
      if (!DuplicateTokenEx(source, 0xF01FF, IntPtr.Zero, 2, 2, out dup)) return Fail("duplicate");
      if (shape.StartsWith("integrity:")) {
        if (!ConvertStringSidToSidW(shape.Substring(10), out psid)) return Fail("sid");
        TokenMandatoryLabel tml = new TokenMandatoryLabel();
        tml.Label.Sid = psid;
        tml.Label.Attributes = 0x20; // SE_GROUP_INTEGRITY
        if (!SetTokenInformation(dup, TokenIntegrityLevel, ref tml, Marshal.SizeOf(tml) + GetLengthSid(psid))) return Fail("set-integrity");
      }
      if (!SetThreadToken(IntPtr.Zero, dup)) return Fail("impersonate");
      return null;
    } finally {
      if (userBuf != IntPtr.Zero) Marshal.FreeHGlobal(userBuf);
      if (psid != IntPtr.Zero) LocalFree(psid);
      if (dup != IntPtr.Zero) CloseHandle(dup);
      if (restricted != IntPtr.Zero) CloseHandle(restricted);
      if (own != IntPtr.Zero) CloseHandle(own);
    }
  }
  // Returns null when the thread's token is the one the shape asks for.
  static string Lost(string shape) {
    IntPtr cur = IntPtr.Zero, buf = Marshal.AllocHGlobal(8);
    try {
      // TOKEN_QUERY, opened as the process.
      if (!OpenThreadToken(GetCurrentThread(), 0x0008, true, out cur)) return "TOKEN_LOST:no-thread-token:" + Marshal.GetLastWin32Error();
      int ret;
      if (!GetTokenInformation(cur, TokenImpersonationLevel, buf, 4, out ret)) return "TOKEN_LOST:query-level:" + Marshal.GetLastWin32Error();
      int level = Marshal.ReadInt32(buf);
      if (level < 2) return "TOKEN_LOST:level:" + level;
      if (shape == "anonymous") {
        string user = TokenSid(cur, TokenUser);
        if (user != "S-1-5-7") return "TOKEN_LOST:user:" + user;
      }
      if (shape.StartsWith("integrity:")) {
        string il = TokenSid(cur, TokenIntegrityLevel);
        if (il != shape.Substring(10)) return "TOKEN_LOST:integrity:" + il;
      }
      return null;
    } finally {
      if (cur != IntPtr.Zero) CloseHandle(cur);
      Marshal.FreeHGlobal(buf);
    }
  }
  // shape "plain" connects under the process's own token.
  public static string Go(string ip, int port, string shape, bool socketAfter) {
    byte[] a = IPAddress.Parse(ip).GetAddressBytes();
    byte[] sa = new byte[16];
    sa[0] = 2; sa[2] = (byte)(port >> 8); sa[3] = (byte)(port & 0xff);
    Array.Copy(a, 0, sa, 4, 4);
    bool assume = shape != "plain";
    IntPtr s = InvalidSocket;
    bool assumed = false;
    try {
      if (!socketAfter || !assume) {
        s = socket(2, 1, 6);
        if (s == InvalidSocket) return "SOCKET_FAILED:" + Marshal.GetLastWin32Error();
      }
      if (assume) {
        string failed = Assume(shape);
        if (failed != null) return failed;
        assumed = true;
        if (socketAfter) {
          s = socket(2, 1, 6);
          if (s == InvalidSocket) return "SOCKET_FAILED:" + Marshal.GetLastWin32Error();
        }
        string lost = Lost(shape);
        if (lost != null) return lost;
      }
      int rc = connect(s, sa, sa.Length);
      int err = Marshal.GetLastWin32Error();
      return rc == 0 ? "CONNECTED" : "WSA:" + err;
    } finally {
      if (assumed) RevertToSelf();
      if (s != InvalidSocket) closesocket(s);
    }
  }
}
'@
Add-Type -TypeDefinition `$src
'PLAIN=' + [SrtTok]::Go('$Ip', $Port, 'plain', `$false)
$($calls -join "`n")
"@
}

# One result of the probe above as the word `wfp verify` uses for it.
function Probe-Word([string] $raw) {
  switch -Regex ($raw) {
    '^WSA:10013$' { return 'blocked' }
    '^CONNECTED$' { return 'connected' }
    '^WSA:10061$' { return 'refused' }
    default       { return $raw }
  }
}

function Probe-Orderings([string] $out, [string] $label, [string] $row) {
  $r = @{}
  foreach ($order in 'BEFORE','AFTER') {
    if ($out -notmatch "(?m)^$label\.$order=(\S+)") { throw "${row}: no $label.$order result. out: $out" }
    $r[$order] = $Matches[1]
  }
  return $r
}

# Print each ordering's result beside what `wfp verify` reported.
# Never fails: for shapes no filter covers.
function Write-OrderingsObserved([string] $out, [string] $label, [string] $row, [string] $residual, [string] $verifyField) {
  $o = Probe-Orderings $out $label $row
  Write-Host ("$row obs: $residual " +
              "socket-before=$(Probe-Word $o.BEFORE) socket-after=$(Probe-Word $o.AFTER) " +
              "(raw before=$($o.BEFORE) after=$($o.AFTER)); " +
              "wfp verify $verifyField=$($verify.$verifyField) " +
              "residuals=[$($verify.residuals -join ',')]")
}

# Assert that a shape was blocked in both orderings. A token the child
# could not set up is reported as NOT EXERCISED, never as blocked.
function Assert-BothOrderingsBlocked([string] $out, [string] $label, [string] $row, [string] $what, [string] $raw) {
  $res = Probe-Orderings $out $label $row
  Write-Host "$row raw: $label socket-before=$($res.BEFORE) socket-after=$($res.AFTER)"
  foreach ($order in 'BEFORE','AFTER') {
    $got = $res[$order]
    $name = "socket-$($order.ToLower())"
    if ($got -in 'CONNECTED','WSA:10061') {
      throw "${row}: BYPASS - $what was NOT blocked with the $name ordering ($label.$order=$got). raw: $raw"
    } elseif ($got -like 'TOKEN_FAILED:*' -or $got -like 'SOCKET_FAILED:*') {
      Write-Host "$row NOT EXERCISED ($name): $what - the child could not set it up ($got); see wfp verify (V1b/V1c)"
    } elseif ($got -eq 'WSA:10013') {
      Write-Host "$row ok ($name): $what blocked (WSA:10013)"
    } else {
      throw "${row}: expected $label.$order=WSA:10013, got '$got'. raw: $raw"
    }
  }
}

# R5g: anonymous, off-loopback - an OBSERVATION (no filter is keyed on
# the anonymous token). Fails only if the PLAIN connect gets through.
$lanIp = (Get-NetIPAddress -AddressFamily IPv4 -ea SilentlyContinue |
  Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
  Select-Object -First 1).IPAddress
if (-not $lanIp) {
  Write-Host 'R5g SKIPPED: runner has no off-loopback IPv4 address'
} else {
  $lanLsn = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($lanIp), 0)
  $lanLsn.Start()
  $lanPort = $lanLsn.LocalEndpoint.Port
  try {
    $bs = (Test-NetConnection $lanIp -Port $lanPort `
           -WarningAction SilentlyContinue).TcpTestSucceeded
    if (-not $bs) { throw "R5g: broker-side connect to ${lanIp}:$lanPort failed - test invalid" }
    $r = RExec @('--', $pwsh, '-NoProfile', '-Command',
                 (TokenProbeScript $lanIp $lanPort @('ANON=anonymous')))
    Write-Host "R5g probe output (${lanIp}:$lanPort): $($r.out.Trim() -replace '\s+',' ')"
    if ($r.out -notmatch 'PLAIN=WSA:10013') {
      throw "R5g: plain connect to ${lanIp}:$lanPort expected WSA:10013 (block-user). raw: $($r.raw)"
    }
    Write-OrderingsObserved $r.out 'ANON' 'R5g' 'anonymous-egress' 'anonymous_probe'
  } finally {
    $lanLsn.Stop()
  }
}

# R5h, R5i, R5j share one out-of-range LOOPBACK listener, live from
# the broker, so "not blocked" is an actual connect.
$tokLsn = Bind-Listener (50003, 50004, 50005, 49997)
$tokPort = $tokLsn.LocalEndpoint.Port
try {
  $bs = (Test-NetConnection 127.0.0.1 -Port $tokPort `
         -WarningAction SilentlyContinue).TcpTestSucceeded
  if (-not $bs) { throw "R5h-j: broker-side connect to 127.0.0.1:$tokPort failed - test invalid" }
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command',
               (TokenProbeScript '127.0.0.1' $tokPort @(
                  'ANON=anonymous', 'LOW=integrity:S-1-16-4096',
                  'UNTRUSTED=integrity:S-1-16-0', 'DENYONLY=denyonly')))
  Write-Host "R5h-j probe output (127.0.0.1:$tokPort): $($r.out.Trim() -replace '\s+',' ')"
  if ($r.out -notmatch 'PLAIN=WSA:10013') {
    throw "R5h-j: plain connect to out-of-range loopback expected WSA:10013 (block-user). raw: $($r.raw)"
  }

  # R5h: anonymous, out-of-range loopback - an OBSERVATION (no filter
  # covers it).
  Write-OrderingsObserved $r.out 'ANON' 'R5h' 'anonymous-loopback' 'anonymous_loopback_probe'

  # R5i: a lowered-integrity copy of the child's own token - ASSERTED in
  # both orderings: it still carries the sandbox account's SID.
  foreach ($shape in 'LOW','UNTRUSTED') {
    Assert-BothOrderingsBlocked $r.out $shape 'R5i' `
      "connect under a $shape-integrity copy of the sandboxed child's token" $r.raw
  }

  # R5j: the child's own token with the user SID deny-only - an
  # OBSERVATION: no allow entry matches a deny-only SID.
  Write-OrderingsObserved $r.out 'DENYONLY' 'R5j' 'deny-only-user-sid' 'deny_only_probe'
} finally {
  $tokLsn.Stop()
}

# ── R5f: non-interactive logon types refused for the sandbox account ─
# These rights govern logons TO this machine; they are no limit on outbound
# SMB. INTERACTIVE must stay granted: the launch depends on it.
$pwPlain = (& $Exe user read-cred).Trim()
if ($LASTEXITCODE -ne 0 -or -not $pwPlain) { throw 'R5f: read-cred failed' }
$lsig = '[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool LogonUserW(string u, string d, string p, uint type, uint prov, out IntPtr tok);'
$lt = Add-Type -MemberDefinition $lsig -Name R5fLogon -Namespace Srt -PassThru
$sbUser = ((& $Exe user status | ConvertFrom-Json).user.name)
foreach ($probe in @(@{n='NETWORK'; t=3; want=$false}, @{n='BATCH'; t=4; want=$false}, @{n='SERVICE'; t=5; want=$false}, @{n='INTERACTIVE'; t=2; want=$true})) {
  $tok = [IntPtr]::Zero
  $ok = [Srt.R5fLogon]::LogonUserW($sbUser, '.', $pwPlain, [uint32]$probe.t, 0, [ref]$tok)
  $gle = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if ($probe.want -and -not $ok) { throw "R5f: $($probe.n) logon REFUSED (gle=$gle) - launch path broken" }
  if (-not $probe.want -and $ok) { throw "R5f: $($probe.n) logon GRANTED - logon-type denial not in effect" }
  if (-not $probe.want -and $gle -ne 1385) { Write-Host "R5f note: $($probe.n) refused with gle=$gle (expected 1385; still refused)" }
}
$pwPlain = $null
Write-Host 'R5f ok: network/batch/service logons refused (1385), interactive granted'

# ── R6: child cannot read the credential key (sandbox DENY) ──────
# The Cred subkey's DACL is the load-bearing gate: machine-scope
# DPAPI means readable = decryptable, and a child that learned its
# own password could CreateProcessWithLogonW itself a fresh logon
# session outside the job/desktop confinement.
$r = RExec @('--', $cmd, '/c', 'reg query HKLM\SOFTWARE\sandbox-runtime\Cred /v Blob')
if ($r.exit -eq 0) {
  throw "R6: child READ the Cred registry key (DENY not in effect?). raw: $($r.raw)"
}
if ($r.raw -notmatch '(?i)access is denied|denied') {
  throw "R6: expected Access is denied. raw: $($r.raw)"
}
Write-Host 'R6 ok: child cannot read the Cred registry key'

# ── R7: cmd.exe /c passthrough — user-quoted payload survives ───
# build_cmdline wraps the post-/c content in ONE outer "…" pair
# for /s to strip; inner content is verbatim. The `&` is inside
# the user's own "…" so cmd treats it literally.
$r = RExec @('--', $cmd, '/d', '/s', '/c', 'echo "x & y"')
if ($r.exit -ne 0) { throw "R7 exited $($r.exit): $($r.out)" }
$got = $r.out.Trim()
if ($got -ne '"x & y"') {
  throw "R7: expected literal '`"x & y`"', got '$got'"
}
Write-Host 'R7 ok: user-quoted payload passes through verbatim'

# ── R7b: cmd metachar passthrough — `&` works as separator ──────
$r = RExec @('--', $cmd, '/d', '/s', '/c', 'echo MARKER & exit 5')
if ($r.exit -ne 5) {
  throw "R7b: expected exit 5 from chained command, got $($r.exit). " +
        "out: $($r.out)"
}
if ($r.out.Trim() -notlike 'MARKER*') {
  throw "R7b: expected MARKER in output. out: $($r.out)"
}
Write-Host 'R7b ok: & chains commands inside sandboxed cmd (passthrough)'

# ── R7c: target_is_cmd recognises trailing-dot cmd.exe. ──────────
$r = RExec @('--', "$cmd.", '/d', '/s', '/c', 'echo MARKER & exit 5')
if ($r.exit -ne 5 -or $r.out.Trim() -notlike 'MARKER*') {
  throw "R7c: trailing-dot cmd.exe. did NOT take the cmd-quoting " +
        "branch (target_is_cmd trim missing). exit=$($r.exit) " +
        "out: $($r.out)"
}
Write-Host 'R7c ok: target_is_cmd recognises trailing-dot cmd.exe.'

# ── R9: child cannot OpenProcess(PROCESS_CREATE_PROCESS) on a ────
#        real-user process (cross-user boundary)
# ── R9b: child cannot OpenProcess(PROCESS_CREATE_PROCESS) on the ─
#        RUNNER (runner self-protect — would let the child
#        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS-spawn under the
#        runner's unrestricted token and escape job/winsta/mitigations)
$hostPid = $PID
$probeR9 = @"
`$sig = '[DllImport("kernel32.dll",SetLastError=true)]public static extern System.IntPtr OpenProcess(uint a,bool b,uint p);'
`$k32 = Add-Type -MemberDefinition `$sig -Name K32R -Namespace W -PassThru
function Probe([string]`$tag, [int]`$targetPid) {
  # 0x0080 = PROCESS_CREATE_PROCESS
  `$h = `$k32::OpenProcess(0x0080, `$false, `$targetPid)
  `$le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if (`$h -ne [System.IntPtr]::Zero) { "OPENED:`$tag pid=`$targetPid" }
  elseif (`$le -eq 5)                { "DENIED:`$tag pid=`$targetPid" }
  else                               { "OTHER:`$tag pid=`$targetPid le=`$le" }
}
`$rp = 0
`$cur = `$PID
for (`$i = 0; `$i -lt 8; `$i++) {
  `$p = Get-CimInstance Win32_Process -Filter "ProcessId=`$cur" -ea SilentlyContinue
  if (-not `$p) { break }
  if (`$p.Name -eq 'srt-win.exe') { `$rp = [int]`$p.ProcessId; break }
  if (-not `$p.ParentProcessId) { break }
  `$cur = `$p.ParentProcessId
}
Probe 'real-user' $hostPid
if (`$rp -eq 0) { 'NORUNNER' } else { Probe 'runner' `$rp }
"@
$r = RExec @('--', $pwsh, '-NoProfile', '-Command', $probeR9)
Write-Host "R9 probe output: $($r.out.Trim())"
if ($r.out -match 'OPENED:real-user') {
  throw "R9: child got PROCESS_CREATE_PROCESS on a real-user " +
        "process (cross-user boundary breached). raw: $($r.raw)"
}
if ($r.out -notmatch 'DENIED:real-user') {
  throw "R9: expected ACCESS_DENIED for real-user target. raw: $($r.raw)"
}
Write-Host 'R9 ok: child denied PROCESS_CREATE_PROCESS on real-user process'
if ($r.out -match 'NORUNNER') {
  throw "R9b: runner discovery failed. raw: $($r.raw)"
}
if ($r.out -match 'OPENED:runner') {
  throw "R9b: child got PROCESS_CREATE_PROCESS on the runner " +
        "(runner self-protect ineffective — sandbox escape). raw: $($r.raw)"
}
if ($r.out -notmatch 'DENIED:runner') {
  throw "R9b: expected ACCESS_DENIED for runner target. raw: $($r.raw)"
}
Write-Host 'R9b ok: child denied PROCESS_CREATE_PROCESS on the runner (self-protect holds)'

# ── R11: child cannot OpenProcess(PROCESS_VM_READ) on a default-DACL ──
#         real-user process (logon-SID strip).
# seclogon stamps the broker's interactive logon SID into the
# runner's token; CreateRestrictedToken disables it so the child
# does NOT match the default per-process logon-session ACE
# (VM_READ|QUERY|TERMINATE) on same-session real-user processes.
# Without the strip the child can ReadProcessMemory the broker's
# browser/shell/host orchestrator. Spawn a fresh victim under the
# broker user so the target is unambiguously default-DACL (no
# harness side effects on its SD).
$victim = Start-Process -FilePath $cmd -ArgumentList '/c','timeout /t 60 >nul' `
            -PassThru -WindowStyle Hidden
try {
  $probeR11 = @"
`$sig = '[DllImport("kernel32.dll",SetLastError=true)]public static extern System.IntPtr OpenProcess(uint a,bool b,uint p);'
`$k32 = Add-Type -MemberDefinition `$sig -Name K32V -Namespace W -PassThru
function Probe([string]`$tag, [uint32]`$mask) {
  `$h = `$k32::OpenProcess(`$mask, `$false, $($victim.Id))
  `$le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if (`$h -ne [System.IntPtr]::Zero) { "OPENED:`$tag" }
  elseif (`$le -eq 5)                { "DENIED:`$tag" }
  else                               { "OTHER:`$tag le=`$le" }
}
# 0x0010 = PROCESS_VM_READ; 0x1000 = PROCESS_QUERY_LIMITED_INFORMATION
Probe 'vm-read'  0x0010
Probe 'query-li' 0x1000
"@
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command', $probeR11)
  Write-Host "R11 probe output: $($r.out.Trim())"
  if ($r.out -match 'OPENED:vm-read') {
    throw "R11: child got PROCESS_VM_READ on a default-DACL " +
          "real-user process (logon-SID not stripped — child " +
          "can ReadProcessMemory the broker's session). raw: $($r.raw)"
  }
  if ($r.out -notmatch 'DENIED:vm-read') {
    throw "R11: expected ACCESS_DENIED for VM_READ. raw: $($r.raw)"
  }
  if ($r.out -match 'OPENED:query-li') {
    throw "R11: child got PROCESS_QUERY_LIMITED_INFORMATION on a " +
          "default-DACL real-user process. raw: $($r.raw)"
  }
  if ($r.out -notmatch 'DENIED:query-li') {
    throw "R11: expected ACCESS_DENIED for QUERY_LIMITED. raw: $($r.raw)"
  }
  Write-Host ('R11 ok: child denied VM_READ + QUERY_LIMITED on ' +
              'default-DACL real-user process (logon-SID stripped)')
} finally {
  try { $victim.Kill() } catch { }
}

# ── R12: child is on the broker-created srt-sb-* desktop ─────────
# The broker creates `WinSta0\srt-sb-<pid>-<rand>` and passes it via
# CreateProcessWithLogonW's lpDesktop; the runner attaches there and
# the lockdown child inherits. If the child reports `Default`, the
# fail-closed assertion in run_lockdown was bypassed and the child
# can WH_KEYBOARD_LL-hook the interactive desktop (the Job's UI
# limits do NOT gate low-level hooks). The child's own
# GetThreadDesktop name is the substantive check (the runner's
# `caller_desk=` debug line is gated on SANDBOX_RUNTIME_WIN_DEBUG
# in the RUNNER's env, which isn't in the --env overlay).
$probeR12 = @"
`$sig = @'
[DllImport("user32.dll")]public static extern System.IntPtr GetThreadDesktop(uint t);
[DllImport("kernel32.dll")]public static extern uint GetCurrentThreadId();
[DllImport("user32.dll",CharSet=CharSet.Unicode)]public static extern bool GetUserObjectInformationW(System.IntPtr h,int i,System.Text.StringBuilder b,uint n,out uint r);
'@
`$u = Add-Type -MemberDefinition `$sig -Name U32D -Namespace W -PassThru
`$d = `$u::GetThreadDesktop(`$u::GetCurrentThreadId())
`$sb = [System.Text.StringBuilder]::new(256); `$r = 0
[void]`$u::GetUserObjectInformationW(`$d, 2, `$sb, 512, [ref]`$r)
"CHILD_DESK=" + `$sb.ToString()
"@
$r = RExec @('--', $pwsh, '-NoProfile', '-Command', $probeR12)
Write-Host "R12 probe output: $($r.out.Trim())"
if ($r.out -notmatch 'CHILD_DESK=srt-sb-') {
  throw "R12: child not on srt-sb-* desktop — desktop isolation " +
        "broken (WH_KEYBOARD_LL keylogging risk). raw: $($r.raw)"
}
if ($r.out -match 'CHILD_DESK=Default') {
  throw "R12: child on Default desktop. raw: $($r.raw)"
}
Write-Host 'R12 ok: child on broker-created srt-sb-* desktop (not Default)'

# ── R13: the child's stdio handles are pipe CLIENT ends ──────────
$r13Lsn  = Bind-Listener (50003, 50004, 50005, 49997)
$r13Port = $r13Lsn.LocalEndpoint.Port
try {
  $probeR13 = @"
`$src = @'
using System;
using System.Net.Sockets;
using System.Runtime.InteropServices;
public static class StdinProbe {
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr GetStdHandle(int n);
  [DllImport("kernel32.dll", SetLastError=true)] static extern uint GetFileType(IntPtr h);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateNamedPipeClient(IntPtr h);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool RevertToSelf();
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetNamedPipeInfo(IntPtr h, out uint flags, IntPtr o, IntPtr i, IntPtr m);
  static string End(IntPtr h) {
    if (GetFileType(h) != 3) { return "notpipe"; }
    uint flags;
    if (!GetNamedPipeInfo(h, out flags, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)) { return "unknown le=" + Marshal.GetLastWin32Error(); }
    return (flags & 1) != 0 ? "server" : "client";
  }
  static string Connect(int port) {
    try { using (var c = new TcpClient()) { c.Connect("127.0.0.1", port); return "CONNECTED"; } }
    catch (SocketException e) { return "blocked code=" + e.SocketErrorCode; }
    catch (Exception e) { return "blocked ex=" + e.GetType().Name; }
  }
  public static string Run(int port) {
    string o = "DIRECT=" + Connect(port) + "\n";
    int[] ids = { -10, -11, -12 };
    string[] names = { "STDIN", "STDOUT", "STDERR" };
    for (int i = 0; i < 3; i++) { o += "END_" + names[i] + "=" + End(GetStdHandle(ids[i])) + "\n"; }
    for (int i = 0; i < 3; i++) {
      bool ok = ImpersonateNamedPipeClient(GetStdHandle(ids[i]));
      int le = Marshal.GetLastWin32Error();
      if (ok) {
        string r = Connect(port);
        if (!RevertToSelf()) { Environment.Exit(97); }
        return o + "IMPERSONATE=ok via " + names[i] + "\nIMPERSONATED_CONNECT=" + r + "\n";
      }
      o += "IMPERSONATE_" + names[i] + "=fail le=" + le + "\n";
    }
    return o + "IMPERSONATE=fail\n";
  }
}
'@
Add-Type -TypeDefinition `$src
[StdinProbe]::Run($r13Port)
"@
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command', $probeR13)
  Write-Host "R13 probe output: $($r.out.Trim())"
  if ($r.out -match 'CONNECTED') {
    throw "R13: a sandboxed connect to out-of-range port $r13Port succeeded. raw: $($r.raw)"
  }
  if ($r.out -notmatch 'DIRECT=blocked') {
    throw "R13: probe did not report its direct connect. raw: $($r.raw)"
  }
  # GetNamedPipeInfo names the end; a refused impersonation alone does not
  # (a server end is refused too until data has been read through it).
  if ($r.out -notmatch '(?m)^END_STDIN=client\s*$') {
    throw "R13: child stdin is not a pipe CLIENT end. raw: $($r.raw)"
  }
  foreach ($n in 'STDOUT', 'STDERR') {
    if ($r.out -notmatch "(?m)^END_$n=(client|unknown)") {
      throw "R13: child $n is not a pipe client end. raw: $($r.raw)"
    }
  }
  if ($r.out -match 'IMPERSONATE=ok') {
    throw "R13: child impersonated through a stdio handle (a pipe server end). raw: $($r.raw)"
  }
  if ($r.out -notmatch 'IMPERSONATE=fail') {
    throw "R13: probe did not report an impersonation result. raw: $($r.raw)"
  }
  # The listener was live, so "blocked" is the fence and not a closed port.
  $hc = [System.Net.Sockets.TcpClient]::new()
  try { $hc.Connect('127.0.0.1', $r13Port) } catch {
    throw "R13: broker-side connect to its own listener on $r13Port failed — test invalid"
  } finally { $hc.Dispose() }
  Write-Host 'R13 ok: stdio handles are pipe client ends and cannot impersonate; out-of-range connect blocked'
} finally {
  $r13Lsn.Stop()
}

# ── R14: the child's stdin reads as end-of-file ──────────────────
# `&&`: the marker is printed only if `sort` read its input to the end.
$r = RExec @('--', $cmd, '/c', 'sort && echo R14-EOF-MARK') -TimeoutSec 60
if ($r.exit -ne 0 -or $r.out -notmatch 'R14-EOF-MARK') {
  throw "R14: child could not read its stdin to the end (exit $($r.exit)). raw: $($r.raw)"
}
$r14Read = (($r.out -split 'R14-EOF-MARK')[0]).Trim()
if ($r14Read -ne '') {
  throw "R14: child stdin was not empty, or the read wrote to stderr: '$r14Read'. raw: $($r.raw)"
}
Write-Host 'R14 ok: child stdin is readable and at end-of-file'

# ── G-rows: per-session FS access for the sandbox user ──────────
# The sandbox child has NO inherent rights on real-user-owned
# files. `acl grant` adds an inheritable MODIFY_NO_FDC ALLOW ACE
# for <sb-SID> on the working-tree root; `acl stamp
# --sandbox-user-sid <sb>` adds an additive (D;OICI;mask;;;<sb>)
# DENY ACE on a path inside it (plus a parent-FDC DENY). The
# G-rows are the design probe: with grant on the root + DENY on a
# file inside, the child reads siblings but not the denied file
# AND cannot del/ren it (the grant lacks FDC and the parent
# carries an explicit FDC DENY for <sb-SID>).
$gRoot = Join-Path $env:TEMP "srt-gscratch-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $gRoot -Force | Out-Null
# Expand to the long-form path: $env:TEMP on the GHA runner is
# `C:\Users\RUNNER~1\...` (8.3 short name). The grant lands on the
# canonical (long-form) file object regardless, but the CHILD opens
# by the path we pass it — and resolving an 8.3 component requires
# enumerating the parent dir, which srt-sandbox cannot do for the
# real user's profile. Passing the long form lets bypass-traverse
# (SeChangeNotifyPrivilege) reach the file directly without an
# enumerate step.
$k32 = Add-Type -PassThru -Namespace W -Name K -MemberDefinition `
  '[DllImport("kernel32.dll",CharSet=CharSet.Unicode)] public static extern uint GetLongPathName(string s,System.Text.StringBuilder l,uint n);'
$lp  = [System.Text.StringBuilder]::new(1024)
if ($k32::GetLongPathName($gRoot, $lp, 1024) -gt 0) { $gRoot = $lp.ToString() }
$gSub  = Join-Path $gRoot  'sub'
New-Item -ItemType Directory -Path $gSub -Force | Out-Null
$secret  = Join-Path $gSub 'secret.txt'
$sibling = Join-Path $gSub 'sibling.txt'
$subDeny = Join-Path $gRoot 'sub-deny'
New-Item -ItemType Directory -Path $subDeny | Out-Null
$inDeny  = Join-Path $subDeny 'inner.txt'
$inAllow = Join-Path $subDeny 'reallow.txt'
# NOT -NoNewline: RExec concatenates child stdout + broker stderr
# before line-splitting, so a no-newline file body would fuse with
# the first `srt-win:` diag line and survive the `^srt-win:` filter.
'SECRET'  | Set-Content -Encoding ASCII $secret
'SIBLING' | Set-Content -Encoding ASCII $sibling
'INNER'   | Set-Content -Encoding ASCII $inDeny
'REALLOW' | Set-Content -Encoding ASCII $inAllow
Write-Host "G: scratch=$gRoot  sbSid=$sbSid"
function Stdin { param([string[]] $argv, [string] $json)
  $raw = $json | & $Exe @argv 2>&1 | Out-String
  Write-Host -NoNewline $raw
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited ${LASTEXITCODE}: $raw"
  }
}

try {
  # ── G1: working-tree grant — child can list/read/write inside ────
  Stdin @('acl','grant','--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"write`":[`"$($gRoot -replace '\\','\\')`"]}"
  $r = RExec @('--', $cmd, '/c', "type `"$sibling`"")
  if ($r.exit -ne 0 -or $r.out -notmatch 'SIBLING') {
    throw "G1: child read sibling failed. exit=$($r.exit) raw: $($r.raw)"
  }
  $r = RExec @('--', $cmd, '/c', "echo G1-NEW> `"$gSub\new.txt`"")
  if ($r.exit -ne 0 -or -not (Test-Path "$gSub\new.txt")) {
    throw "G1: child write under granted tree failed. raw: $($r.raw)"
  }
  Write-Host 'G1 ok: working-tree MODIFY_NO_FDC grant — child reads + creates inside'

  # ── G2: DENY ACE inside the grant — read denied ──────────────────
  Stdin @('acl','stamp','--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"denyRead`":[`"$($secret -replace '\\','\\')`"]}"
  $r = RExec @('--', $cmd, '/c', "type `"$secret`"")
  if ($r.exit -eq 0 -or $r.out -match 'SECRET') {
    throw "G2: child READ the stamped file. raw: $($r.raw)"
  }
  $r = RExec @('--', $cmd, '/c', "type `"$sibling`"")
  if ($r.out -notmatch 'SIBLING') {
    throw "G2: sibling no longer readable post-stamp. raw: $($r.raw)"
  }
  Write-Host 'G2 ok: DENY ACE + working-tree grant compose — sibling readable, stamped file denied'

  # ── G3: parent-FDC DENY — child cannot del/ren the stamped file ──
  # The stamp adds (D;OICI;FILE_DELETE_CHILD;;;<sb-SID>) on the
  # parent; explicit DENY is evaluated first, so even where the
  # parent inherits an allow-FDC the child has no path through it.
  $r = RExec @('--', $cmd, '/c', "del `"$secret`"")
  if (-not (Test-Path $secret) -or
      (Get-Content -Raw $secret).Trim() -ne 'SECRET') {
    throw "G3: child deleted/altered the stamped file (parent-FDC DENY did not take). raw: $($r.raw)"
  }
  $r = RExec @('--', $cmd, '/c', "ren `"$secret`" gone.txt")
  if (-not (Test-Path $secret) -or (Test-Path "$gSub\gone.txt")) {
    throw "G3: child renamed the stamped file. raw: $($r.raw)"
  }
  Write-Host 'G3 ok: parent-FDC DENY ACE — child cannot del/ren the stamped file'

  # ── G3b: parent-FDC DENY overrides BUILTIN\Users:FA on parent ────
  # The sandbox user is a Users member; without the explicit DENY a
  # parent with Users:(F) would give it FILE_DELETE_CHILD directly
  # (the C:\ProgramData case). The DENY ACE is evaluated before
  # any ALLOW, so the deny still holds.
  $g3bDir  = Join-Path $gRoot 'g3b'
  New-Item -ItemType Directory -Path $g3bDir | Out-Null
  & icacls $g3bDir /grant '*S-1-5-32-545:(OI)(CI)(F)' | Out-Null
  $g3bFile = Join-Path $g3bDir 'sec.txt'
  'G3B' | Set-Content -Encoding ASCII $g3bFile
  Stdin @('acl','stamp','--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"denyRead`":[`"$($g3bFile -replace '\\','\\')`"]}"
  $r = RExec @('--', $cmd, '/c', "del `"$g3bFile`"")
  if (-not (Test-Path $g3bFile) -or
      (Get-Content -Raw $g3bFile).Trim() -ne 'G3B') {
    throw "G3b: child deleted file under Users:FA parent (DENY did not override). raw: $($r.raw)"
  }
  $r = RExec @('--', $cmd, '/c', "type `"$g3bFile`"")
  if ($r.exit -eq 0 -or $r.out -match 'G3B') {
    throw "G3b: child READ file under Users:FA parent. raw: $($r.raw)"
  }
  Write-Host 'G3b ok: parent-FDC DENY overrides inherited BUILTIN\Users:(F) on parent'

  # ── G4: broker (real user) can still read the stamped file ───────
  if ((Get-Content -Raw $secret).Trim() -ne 'SECRET') {
    throw 'G4: broker lost read on the stamped file'
  }
  Write-Host 'G4 ok: real-user trustee keeps full access to stamped file'

  # ── G5: directory deny — (OI)(CI) DENY ACE covers the subtree; ───
  # allowWithinDeny via grant on an inner file.
  Stdin @('acl','stamp','--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"denyRead`":[`"$($subDeny -replace '\\','\\')`"]}"
  Stdin @('acl','grant','--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"read`":[`"$($inAllow -replace '\\','\\')`"]}"
  # Instrumentation: dump exactly what landed on the inner file
  # post dir-stamp + inner-grant. The icacls/SDDL pair shows the
  # explicit srt-sandbox ALLOW ACE alongside the inherited DENY
  # ACE; the child-side `if exist` tells us whether
  # bypass-traverse through the denied dir works. Kept on the
  # success path too — the dump is the proof for the design claim
  # (explicit ALLOW is evaluated before inherited DENY).
  Write-Host "G5 diag: icacls $inAllow ->"
  & icacls $inAllow
  Write-Host "G5 diag: inAllow Sddl=$((Get-Acl $inAllow).Sddl)"
  Write-Host "G5 diag: subDeny Sddl=$((Get-Acl $subDeny).Sddl)"
  $r = RExec @('--', $cmd, '/c',
    "whoami /priv | findstr /i SeChangeNotify")
  Write-Host "G5 diag: child SeChangeNotify=$($r.out)"
  $r = RExec @('--', $cmd, '/c', "type `"$inDeny`"")
  if ($r.exit -eq 0 -or $r.out -match 'INNER') {
    throw "G5: child read file under denied dir. raw: $($r.raw)"
  }
  # Combined probe: echo the path the child sees + if-exist +
  # type-via-builtin + read-via-stdin-redirect (cmd's `<` is a
  # direct CreateFileW(GENERIC_READ) — bypasses any extra path
  # checks `type` might do). Everything goes through one RExec so
  # the throw carries it all.
  $r = RExec @('--', $cmd, '/c',
    ("echo PATH=$inAllow & " +
     "if exist `"$inAllow`" (echo IFEXIST=YES) else (echo IFEXIST=NO) & " +
     "type `"$inAllow`" 2>&1 & echo --- & " +
     "more < `"$inAllow`" 2>&1"))
  if ($r.out -notmatch 'REALLOW') {
    throw ("G5: allowWithinDeny grant on inner file did not take " +
           "effect.`n  child raw: $($r.raw)`n  " +
           "inAllow Sddl: $((Get-Acl $inAllow).Sddl)`n  " +
           "subDeny Sddl: $((Get-Acl $subDeny).Sddl)")
  }
  $r = RExec @('--', $cmd, '/c', "type `"$sibling`"")
  if ($r.out -notmatch 'SIBLING') {
    throw "G5: sibling-of-denied-dir lost access. raw: $($r.raw)"
  }
  Write-Host 'G5 ok: dir-deny (OI)(CI) covers subtree; sibling unaffected; inner grant overrides'

  # ── G6: revoke + restore — child loses access; DACLs round-trip ──
  Run @('acl','revoke','--holder-pid',$PID,
        '--sandbox-user-sid',$sbSid)
  Run @('acl','restore','--holder-pid',$PID,
        '--sandbox-user-sid',$sbSid)
  $post = (Get-Acl $gRoot).Sddl
  if ($post -match [regex]::Escape($sbSid)) {
    throw "G6: srt-sandbox ACE still present on root after revoke: $post"
  }
  $postSub = (Get-Acl $subDeny).Sddl
  if ($postSub -match [regex]::Escape($sbSid)) {
    throw "G6: srt-sandbox ACE still on dir after restore: $postSub"
  }
  $r = RExec @('--', $cmd, '/c', "type `"$sibling`"")
  if ($r.exit -eq 0) {
    throw "G6: child still reads after revoke. raw: $($r.raw)"
  }
  Write-Host 'G6 ok: revoke + restore remove all sb-user ACEs; child loses access'
} finally {
  # Best-effort: don't leak ACEs/stamps if a G-row threw mid-way.
  & $Exe acl revoke  --holder-pid $PID `
        --sandbox-user-sid $sbSid 2>&1 | Out-Null
  & $Exe acl restore --holder-pid $PID `
        --sandbox-user-sid $sbSid 2>&1 | Out-Null
  Remove-Item -Recurse -Force $gRoot -ErrorAction SilentlyContinue
}

# ── L-rows: open loopback ────────────────────────────────────────
# The listeners sit clear of the proxy range, the fixed ports used above
# and the dynamic range (49152+), where Windows keeps its excluded ranges.
$LbLo = 41000
# The one loopback port that stays blocked with loopback open (wfp.rs).
$LbProbePort = 1
$regBase = 'HKLM:\SOFTWARE\sandbox-runtime'
$st0 = J @('wfp','status','--sublayer-guid',$Sublayer)

# The install record's loopback mode for a sublayer (`open`, `closed`),
# or $null when it has no line.
function Get-LoopbackMode([string] $sublayer) {
  $props = Get-ItemProperty $regBase -ea SilentlyContinue
  if (-not $props -or -not $props.PSObject.Properties['LoopbackModes']) { return $null }
  $lines = @($props.LoopbackModes)
  $line = $lines | Where-Object { $_ -like "$($sublayer.ToLower())=*" } | Select-Object -First 1
  if ($line) { return ($line -split '=')[1] }
  return $null
}

# One raw TCP connect from inside the sandbox: CONNECTED, or
# code=<SocketErrorCode> (AccessDenied = refused by a filter).
function SbConnect {
  param([string] $Address, [int] $Port, [string[]] $ExecFlags = @())
  $new = if ($Address -match ':') {
    'New-Object Net.Sockets.TcpClient([Net.Sockets.AddressFamily]::InterNetworkV6)'
  } else {
    'New-Object Net.Sockets.TcpClient'
  }
  return RExec ($ExecFlags + @('--', $pwsh, '-NoProfile', '-Command',
    "try { `$c = $new; `$c.Connect('$Address', $Port); Write-Output CONNECTED } " +
    "catch { Write-Output ('code=' + `$_.Exception.InnerException.SocketErrorCode) }"))
}
function Assert-SbRefused {
  param([string] $Row, [string] $Address, [int] $Port, [string[]] $ExecFlags = @())
  $r = SbConnect $Address $Port $ExecFlags
  if ($r.out -match 'CONNECTED') {
    throw "${Row}: sandboxed connect to ${Address}:$Port succeeded. raw: $($r.raw)"
  }
  if ($r.out -notmatch 'AccessDenied') {
    throw "${Row}: expected AccessDenied (WFP block) for ${Address}:$Port, got: $($r.raw)"
  }
}
function Assert-SbConnected {
  param([string] $Row, [string] $Address, [int] $Port, [string[]] $ExecFlags = @())
  $r = SbConnect $Address $Port $ExecFlags
  if ($r.out -notmatch 'CONNECTED') {
    throw "${Row}: sandboxed connect to ${Address}:$Port did not succeed. raw: $($r.raw)"
  }
}

# Start a sandboxed command without waiting; same argv and env as RExec.
function RExecStart {
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
  $p = [System.Diagnostics.Process]::Start($psi)
  return [pscustomobject]@{
    p  = $p
    so = $p.StandardOutput.ReadToEndAsync()
    se = $p.StandardError.ReadToEndAsync()
  }
}

# A server started INSIDE the sandbox, then one connect from a second sandboxed
# command. The server prints SERVED on accept, so reaching another listener does not pass.
function SbServerRoundTrip {
  param([string] $Row, [int] $Port, [string[]] $ExecFlags = @())
  $srv = RExecStart ($ExecFlags + @('--', $pwsh, '-NoProfile', '-Command',
    "`$l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port); `$l.Start(); " +
    "`$t = `$l.AcceptTcpClientAsync(); " +
    "if (`$t.Wait(240000)) { Write-Output SERVED } else { Write-Output NOCLIENT }; `$l.Stop()"))
  try {
    # Wait for the listener without connecting to it: a connect from
    # here would be the one the server is waiting to accept.
    $deadline = (Get-Date).AddSeconds(120)
    while (-not (Get-NetTCPConnection -State Listen -LocalPort $Port -ea SilentlyContinue)) {
      if ($srv.p.HasExited) {
        throw "${Row}: sandboxed server exited before listening. out: $($srv.so.Result) err: $($srv.se.Result)"
      }
      if ((Get-Date) -gt $deadline) { throw "${Row}: sandboxed server did not listen on $Port within 120s" }
      Start-Sleep -Milliseconds 250
    }
    $client = SbConnect '127.0.0.1' $Port $ExecFlags
    # A refused client leaves the server waiting: do not sit out its timeout.
    $served = $false
    if ($client.out -match 'CONNECTED') {
      if (-not $srv.p.WaitForExit(60000)) { throw "${Row}: sandboxed server did not exit after a client connected" }
      $served = $srv.so.Result -match 'SERVED'
    }
    return [pscustomobject]@{ client = $client; served = $served }
  } finally {
    if (-not $srv.p.HasExited) { try { $srv.p.Kill($true) } catch { } }
  }
}

# A port that binds right now, for a listener another process will open.
function Free-LbPort {
  param([int[]] $Candidates)
  $l = Bind-Listener $Candidates
  $port = $l.LocalEndpoint.Port
  $l.Stop()
  return $port
}

# A UDP echo server in a process of this account (not the sandbox); it
# answers one datagram and exits. Returns once it is bound.
function Start-UdpEcho {
  param([string] $Row, [int] $Port)
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName               = $pwsh
  $psi.UseShellExecute        = $false
  $psi.RedirectStandardOutput = $true
  $server =
    "`$u = New-Object Net.Sockets.UdpClient(" +
      "(New-Object Net.IPEndPoint([Net.IPAddress]::Loopback, $Port))); " +
    "`$u.Client.ReceiveTimeout = 240000; " +
    "`$ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0); " +
    "Write-Output READY; " +
    "`$d = `$u.Receive([ref]`$ep); [void]`$u.Send(`$d, `$d.Length, `$ep); Write-Output ECHOED"
  foreach ($a in @('-NoProfile', '-Command', $server)) { $null = $psi.ArgumentList.Add($a) }
  $p = [System.Diagnostics.Process]::Start($psi)
  if ($p.StandardOutput.ReadLine() -ne 'READY') {
    try { $p.Kill($true) } catch { }
    throw "${Row}: UDP echo server did not come up on 127.0.0.1:$Port"
  }
  return $p
}

# One UDP datagram from inside the sandbox: ECHO=<payload>, or
# code=<SocketErrorCode> (AccessDenied = a filter; TimedOut = no answer).
function SbUdpEcho {
  param([int] $Port, [string[]] $ExecFlags = @())
  $client =
    "try { `$u = New-Object Net.Sockets.UdpClient; `$u.Client.ReceiveTimeout = 15000; " +
    "`$u.Connect('127.0.0.1', $Port); " +
    "`$b = [Text.Encoding]::ASCII.GetBytes('udp-ping'); [void]`$u.Send(`$b, `$b.Length); " +
    "`$ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0); " +
    "Write-Output ('ECHO=' + [Text.Encoding]::ASCII.GetString(`$u.Receive([ref]`$ep))) } " +
    "catch { Write-Output ('code=' + `$_.Exception.InnerException.SocketErrorCode) }"
  return RExec ($ExecFlags + @('--', $pwsh, '-NoProfile', '-Command', $client))
}

# L0: loopback closed (the default install): all refused but the proxy range.
$l0v4 = Bind-Listener ($LbLo..($LbLo + 7))
$l0v6 = Bind-Listener (($LbLo + 8)..($LbLo + 15)) ([System.Net.IPAddress]::IPv6Loopback)
try {
  Assert-SbRefused 'L0' '127.0.0.1' $l0v4.LocalEndpoint.Port
  Assert-SbRefused 'L0' '::1' $l0v6.LocalEndpoint.Port
} finally {
  $l0v4.Stop(); $l0v6.Stop()
}
if (-not $lanIp) {
  Write-Host 'L0 note: no off-loopback IPv4 address on this runner; non-loopback half skipped'
} else {
  $l0lan = Bind-Listener (($LbLo + 16)..($LbLo + 23)) ([System.Net.IPAddress]::Parse($lanIp))
  try { Assert-SbRefused 'L0' $lanIp $l0lan.LocalEndpoint.Port } finally { $l0lan.Stop() }
}
$rt = SbServerRoundTrip 'L0' (Free-LbPort (($LbLo + 24)..($LbLo + 31)))
if ($rt.client.out -match 'CONNECTED' -or $rt.client.out -notmatch 'AccessDenied') {
  throw "L0: connect to a sandbox-started server expected AccessDenied with loopback closed. raw: $($rt.client.raw)"
}
$l0udpPort = $LbLo + 32
$l0udp = Start-UdpEcho 'L0' $l0udpPort
try {
  # No answer is the requirement; how the refusal surfaces to a
  # datagram sender is logged, not asserted.
  $r = SbUdpEcho $l0udpPort
  if ($r.out -match 'ECHO=' -or $r.out -notmatch 'code=') {
    throw "L0: UDP to 127.0.0.1:$l0udpPort expected no echo with loopback closed. raw: $($r.raw)"
  }
  Write-Host "L0: UDP to 127.0.0.1:$l0udpPort with loopback closed: $(($r.out -split "`n" | Select-String 'code=') -join ' ')"
} finally {
  try { $l0udp.Kill($true) } catch { }
}
$l0proxy = Bind-Listener ($PortHi..$PortLo)
try { Assert-SbConnected 'L0' '127.0.0.1' $l0proxy.LocalEndpoint.Port } finally { $l0proxy.Stop() }
Write-Host 'L0 ok: with loopback closed, loopback (v4, v6, UDP), non-loopback and sandbox-to-sandbox connects are all refused; the proxy port range is reachable'

# L0b: a session expecting loopback open on a closed install is refused (19).
$r = RExec @('--allow-loopback', '--', $cmd, '/c', 'echo L0b-RAN')
if ($r.exit -ne 19) { throw "L0b: exec expected exit 19 (loopback not open), got $($r.exit). raw: $($r.raw)" }
if ($r.raw -match 'L0b-RAN') { throw "L0b: child RAN expecting open loopback on a closed install. raw: $($r.raw)" }
if ($r.raw -notmatch '(?i)loopback mode' -or $r.raw -notmatch '(?i)srt-win install --allow-loopback') {
  throw "L0b: exec message lacks the loopback mode / reinstall hint. raw: $($r.raw)"
}
$lvOut = & $Exe wfp verify --target "127.0.0.1:$LbLo" --allow-loopback
$lvExit = $LASTEXITCODE
if ($lvExit -ne 19) { throw "L0b: wfp verify expected exit 19, got $lvExit. out: $lvOut" }
$lvDoc = $lvOut | ConvertFrom-Json
if (-not $lvDoc.allow_loopback_mismatch -or $lvDoc.hint -notmatch '(?i)srt-win install --allow-loopback --force') {
  throw "L0b: wfp verify output lacks allow_loopback_mismatch / the reinstall hint: $lvOut"
}
$l0bTyped = ($r.raw -split "`r?`n") | Where-Object { $_.Trim().StartsWith('{') -and $_ -match '"code"' } | Select-Object -First 1
if (-not $l0bTyped -or ($l0bTyped | ConvertFrom-Json).code -ne 'wfp_loopback_mismatch') {
  throw "L0b: exec refusal is not a typed {code: wfp_loopback_mismatch} line. raw: $($r.raw)"
}
Write-Host 'L0b ok: a session expecting open loopback on a closed install is refused (exec 19, wfp verify 19)'

# L1: opening loopback on an existing install: refused (13) without --force.
& $Exe install --sublayer-guid $Sublayer --proxy-port-range $PortRange --allow-loopback 2>$null
if ($LASTEXITCODE -ne 13) { throw "L1: install --allow-loopback without --force expected exit 13, got $LASTEXITCODE" }
Run @('install',
      '--sublayer-guid',$Sublayer,
      '--proxy-port-range',$PortRange,
      '--allow-loopback',
      '--force')
$l1 = J @('wfp','status','--sublayer-guid',$Sublayer)
if ($l1.state -ne 'installed' -or $l1.filters -ne ($st0.filters + 2)) {
  throw "L1: expected installed/$($st0.filters + 2) filters, got $($l1.state)/$($l1.filters)"
}
if ($l1.allow_loopback -ne $true -or $l1.loopback_notice -notmatch '(?i)loopback is open') {
  throw "L1: wfp status expected allow_loopback=true with a loopback_notice, got $($l1 | ConvertTo-Json -Compress)"
}
if (($l1.port_range -join '-') -ne $PortRange) {
  throw "L1: wfp status port_range changed: '$($l1.port_range -join '-')'"
}
$l1c = J @('status','--sublayer-guid',$Sublayer)
if ($l1c.wfp.allow_loopback -ne $true -or $l1c.wfp.loopback_notice -notmatch '(?i)off the machine') {
  throw "L1: status .wfp expected allow_loopback=true with a loopback_notice, got $($l1c.wfp | ConvertTo-Json -Compress)"
}
if ((Get-LoopbackMode $Sublayer) -ne 'open') {
  throw "L1: install did not record the sublayer's loopback mode as open under $regBase"
}
Write-Host "L1 ok: loopback opened: $($l1.filters) filters, reported by wfp status and status with the notice"

# L1b: open filters without their record: status says so, and exec goes by the record.
$l1bSaved = @((Get-ItemProperty $regBase -ea Stop).LoopbackModes)
Remove-ItemProperty $regBase -Name LoopbackModes -ea Stop
try {
  $l1b = J @('wfp','status','--sublayer-guid',$Sublayer)
  $r = RExec @('--allow-loopback', '--', $cmd, '/c', 'echo L1b-RAN')
} finally {
  Set-ItemProperty $regBase -Name LoopbackModes -Value $l1bSaved -Type MultiString
}
if ($l1b.state -ne 'loopback-mismatch' -or $l1b.hint -notmatch '(?i)srt-win install --force') {
  throw "L1b: wfp status expected loopback-mismatch with the reinstall hint, got $($l1b | ConvertTo-Json -Compress)"
}
if ($r.exit -ne 19 -or $r.raw -match 'L1b-RAN') { throw "L1b: exec with no recorded mode expected exit 19, got $($r.exit). raw: $($r.raw)" }
Write-Host 'L1b ok: filters whose mode is not recorded read as loopback-mismatch; exec refuses open loopback without the record'

$lb = @('--allow-loopback')

# L2: wfp verify with loopback open, aimed as the library aims it: at a
# loopback listener of its own outside the proxy port range.
$l2Lsn = Bind-Listener (($LbLo + 40)..($LbLo + 47))
$l2tgt = "127.0.0.1:$($l2Lsn.LocalEndpoint.Port)"
try {
  $l2out = & $Exe wfp verify --target $l2tgt @lb
  $l2exit = $LASTEXITCODE
} finally {
  $l2Lsn.Stop()
}
Write-Host "L2: wfp verify exit=$l2exit stdout='$l2out'"
if ($l2exit -ne 0) { throw "L2: wfp verify with loopback open expected exit 0, got $l2exit" }
$l2 = $l2out | ConvertFrom-Json
if ($l2.open_loopback_probe -ne 'connected') {
  throw "L2: loopback listener $l2tgt expected connected, got '$($l2.open_loopback_probe)'"
}
if ($l2.allow_loopback -ne $true -or $l2.loopback_notice -notmatch '(?i)loopback is open') {
  throw "L2: wfp verify output does not say loopback is open: $l2out"
}
# What must still be refused is the reserved loopback port, where nothing listens.
if ($l2.egress_target -ne "127.0.0.1:$LbProbePort" -or $l2.egress_probe -ne 'blocked') {
  throw "L2: connect to the reserved port 127.0.0.1:$LbProbePort expected blocked, got '$($l2.egress_probe)' at '$($l2.egress_target)'"
}
foreach ($f in 'anonymous_loopback_probe', 'deny_only_probe') {
  if ($l2.$f -ne 'skipped') { throw "L2: $f expected skipped with loopback open, got '$($l2.$f)'. out: $l2out" }
}
foreach ($f in $loweredFields) {
  $got = $l2.$f
  if ($got -eq 'skipped' -and $f -notlike '*_loopback_probe') {
    Write-Host "L2 note: $f skipped (no off-loopback address on this runner)"
  } elseif ($got -eq 'error' -and $l2.residuals -contains 'lowered-integrity-unprobed') {
    Write-Host "L2 note: $f not set up (error), reported as lowered-integrity-unprobed"
  } elseif ($got -ne 'blocked') {
    throw "L2: $f expected blocked with loopback open, got '$got'. out: $l2out"
  }
}
# With loopback open the target is the loopback listener: another is a usage error.
& $Exe wfp verify --target '192.0.2.1:9' @lb 2>$null | Out-Null
if ($LASTEXITCODE -ne 1) { throw "L2: wfp verify with an off-loopback --target expected exit 1, got $LASTEXITCODE" }
Write-Host 'L2 ok: wfp verify with loopback open reaches its listener, finds the reserved port blocked, and says loopback is open'

# L3/L4: loopback listeners are reachable on 127.0.0.1 and ::1, low
# ports and high alike: one PERMIT covers every port.
foreach ($slice in @((1100..1107), (9229..9236), ($LbLo..($LbLo + 7)))) {
  $l3 = Bind-Listener $slice
  try {
    Assert-SbConnected 'L3' '127.0.0.1' $l3.LocalEndpoint.Port $lb
    Write-Host "L3 ok: loopback 127.0.0.1:$($l3.LocalEndpoint.Port) reachable"
  } finally {
    $l3.Stop()
  }
}
$l4 = Bind-Listener (($LbLo + 8)..($LbLo + 15)) ([System.Net.IPAddress]::IPv6Loopback)
try {
  Assert-SbConnected 'L4' '::1' $l4.LocalEndpoint.Port $lb
  Write-Host "L4 ok: loopback [::1]:$($l4.LocalEndpoint.Port) reachable"
} finally {
  $l4.Stop()
}

# L5: UDP on loopback works: a datagram is echoed back.
$l5port = $LbLo + 32
$l5 = Start-UdpEcho 'L5' $l5port
try {
  $r = SbUdpEcho $l5port $lb
  if ($r.out -notmatch 'ECHO=udp-ping') {
    throw "L5: UDP echo through 127.0.0.1:$l5port did not come back. raw: $($r.raw)"
  }
} finally {
  try { $l5.Kill($true) } catch { }
}
Write-Host "L5 ok: UDP echo on 127.0.0.1:$l5port works"

# L6: the reserved port is refused for the sandbox account, listener or
# not; its neighbour is reachable.
$l6 = $null
try { $l6 = Bind-Listener @($LbProbePort) } catch { Write-Host "L6 note: port $LbProbePort is taken on this runner; probing it as it is" }
try { Assert-SbRefused 'L6' '127.0.0.1' $LbProbePort $lb } finally { if ($l6) { $l6.Stop() } }
$l6n = Bind-Listener (($LbProbePort + 1)..($LbProbePort + 8))
$l6nPort = $l6n.LocalEndpoint.Port
try { Assert-SbConnected 'L6' '127.0.0.1' $l6nPort $lb } finally { $l6n.Stop() }
Write-Host "L6 ok: with loopback open, port $LbProbePort is still refused and port $l6nPort is reachable"

# L7: a port open on loopback is still refused off loopback, on and off this machine.
if (-not $lanIp) {
  Write-Host 'L7 SKIPPED (non-loopback half): runner has no off-loopback IPv4 address'
} else {
  $l7 = Bind-Listener (($LbLo + 16)..($LbLo + 23)) ([System.Net.IPAddress]::Parse($lanIp))
  $l7port = $l7.LocalEndpoint.Port
  try {
    $l7lo = Bind-Listener @($l7port)
    try { Assert-SbConnected 'L7' '127.0.0.1' $l7port $lb } finally { $l7lo.Stop() }
    Assert-SbRefused 'L7' $lanIp $l7port $lb
    Write-Host "L7 ok: port $l7port reachable on 127.0.0.1, refused on non-loopback $lanIp"
  } finally {
    $l7.Stop()
  }
}
$r = RExec ($lb + @('--', $cmd, '/c', 'curl -sS -m 5 https://example.com'))
if ($r.exit -eq 0) {
  throw "L7: outbound curl succeeded under the sandbox with loopback open. out: $($r.out)"
}
Write-Host "L7 ok: off-machine egress still blocked with loopback open (curl exit=$($r.exit))"

# L8: a server started by one sandboxed command is reachable from another.
$rt = SbServerRoundTrip 'L8' (Free-LbPort (($LbLo + 24)..($LbLo + 31))) $lb
if ($rt.client.out -notmatch 'CONNECTED' -or -not $rt.served) {
  throw "L8: sandbox-started server not reached from a second sandboxed command (served=$($rt.served)). raw: $($rt.client.raw)"
}
Write-Host 'L8 ok: a sandbox-started server is reachable from a second sandboxed command'

# L9: a session expecting loopback CLOSED on this open install is refused.
$r = RExec @('--', $cmd, '/c', 'echo L9-RAN')
if ($r.exit -ne 19) { throw "L9: exec expecting closed loopback expected exit 19, got $($r.exit). raw: $($r.raw)" }
if ($r.raw -match 'L9-RAN') { throw "L9: child RAN expecting closed loopback on an open install. raw: $($r.raw)" }
if ($r.raw -notmatch '(?i)loopback mode' -or $r.raw -notmatch '(?i)srt-win install') {
  throw "L9: exec message lacks the loopback mode / reinstall hint. raw: $($r.raw)"
}
$l9Lsn = Bind-Listener (49950..49959)
$l9out = & $Exe wfp verify --target "127.0.0.1:$($l9Lsn.LocalEndpoint.Port)"
$l9exit = $LASTEXITCODE
$l9Lsn.Stop()
if ($l9exit -ne 19) { throw "L9: wfp verify expecting closed loopback expected exit 19, got $l9exit. out: $l9out" }
$l9doc = $l9out | ConvertFrom-Json
if (-not $l9doc.allow_loopback_mismatch -or $l9doc.hint -notmatch '(?i)srt-win install --force') {
  throw "L9: wfp verify output lacks allow_loopback_mismatch / the reinstall hint: $l9out"
}
Write-Host 'L9 ok: a session expecting closed loopback on an open install is refused (exec 19, wfp verify 19)'

# L10: closing loopback is the install step again; loopback is refused once more.
Run @('install',
      '--sublayer-guid',$Sublayer,
      '--proxy-port-range',$PortRange,
      '--force')
$l10 = J @('wfp','status','--sublayer-guid',$Sublayer)
if ($l10.state -ne 'installed' -or $l10.filters -ne $st0.filters -or $l10.allow_loopback -ne $false -or
    $null -ne $l10.PSObject.Properties['loopback_notice']) {
  throw "L10: after closing loopback expected installed/$($st0.filters) filters/allow_loopback=false, got $($l10 | ConvertTo-Json -Compress)"
}
if ((Get-LoopbackMode $Sublayer) -ne 'closed') {
  throw "L10: the sublayer's recorded loopback mode expected closed, got '$(Get-LoopbackMode $Sublayer)'"
}
$l10Lsn = Bind-Listener ($LbLo..($LbLo + 7))
try { Assert-SbRefused 'L10' '127.0.0.1' $l10Lsn.LocalEndpoint.Port } finally { $l10Lsn.Stop() }
$r = RExec @('--', $cmd, '/c', 'echo L10-RAN')
if ($r.exit -ne 0 -or $r.out -notmatch 'L10-RAN') {
  throw "L10: exec after closing loopback failed. exit=$($r.exit) raw: $($r.raw)"
}
Write-Host 'L10 ok: reinstalling without --allow-loopback closes it again and leaves no permit behind'

# ── S-rows: Secondary Logon (seclogon) preflight + typed failure ─
# Reconfigures a machine-wide service: runs last and restores it in `finally`.
function Seclogon-State {
  return (J @('status','--sublayer-guid',$Sublayer)).user.seclogon
}
function Seclogon-Err {
  param([string] $text)
  $line = ($text -split "`r?`n") |
    Where-Object { $_ -match '^\s*\{.*"code"\s*:\s*"seclogon_disabled"' } |
    Select-Object -First 1
  if (-not $line) { return $null }
  return $line | ConvertFrom-Json
}
# seclogon refuses STOP briefly after each launch (1052) and while a process it launched lives.
function Stop-Seclogon {
  param([int] $TimeoutSec = 60)
  $start    = [DateTime]::UtcNow
  $deadline = $start.AddSeconds($TimeoutSec)
  $swept    = $false
  $last     = ''
  while ($true) {
    $s = Get-Service seclogon
    if ($s.Status -eq 'Stopped') { return }
    # CanStop is not consulted: it can stay false while a stop is accepted.
    try { Stop-Service seclogon -Force -ErrorAction Stop; return } catch { $last = "$_" }
    if (-not $swept -and ([DateTime]::UtcNow - $start).TotalSeconds -ge 5) {
      $swept = $true
      $left = @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
                Where-Object { $_.UserName -like '*\srt-sandbox' })
      Write-Host "S: seclogon not stoppable after 5s; processes owned by the sandbox account: $(
        if ($left) { ($left | ForEach-Object { "$($_.ProcessName)#$($_.Id)" }) -join ', ' } else { '(none)' })"
      foreach ($p in $left) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    } elseif ([DateTime]::UtcNow -ge $deadline) {
      $q = (& sc.exe queryex seclogon 2>&1 | Out-String) -replace '\s+', ' '
      throw "seclogon: not accepting STOP after ${TimeoutSec}s (Status=$($s.Status)); last error: $last; sc queryex: $q"
    }
    Start-Sleep -Milliseconds 20
  }
}
$slSvc        = Get-Service seclogon
$slStartType  = [string]$slSvc.StartType
$slWasRunning = $slSvc.Status -eq 'Running'
Write-Host "S: seclogon before: StartType=$slStartType Status=$($slSvc.Status)"
$slSkipped = $false
try {
  # ── S1: Manual + stopped → ok; the launch demand-starts it ─────
  Set-Service seclogon -StartupType Manual
  # Unstoppable where this session itself came through seclogon: rows skipped by name.
  try { Stop-Seclogon -TimeoutSec 20 } catch { throw "SECLOGON-UNSTOPPABLE: $_" }
  $st = Seclogon-State
  if ($st -ne 'ok') { throw "S1: Manual+stopped expected seclogon=ok, got '$st'" }
  $r = RExec @('--', $cmd, '/c', 'echo S1-RAN')
  if ($r.exit -ne 0 -or $r.out -notmatch 'S1-RAN') {
    throw "S1: exec under Manual+stopped seclogon failed (exit $($r.exit)). raw: $($r.raw)"
  }
  Write-Host 'S1 ok: Manual+stopped reports ok and exec demand-starts the service'

  # ── S2: Disabled but still running → ok (and it does launch) ───
  if ((Get-Service seclogon).Status -eq 'Running') {
    Set-Service seclogon -StartupType Disabled
    $st = Seclogon-State
    if ($st -ne 'ok') { throw "S2: Disabled+running expected seclogon=ok, got '$st'" }
    $r = RExec @('--', $cmd, '/c', 'echo S2-RAN')
    if ($r.exit -ne 0 -or $r.out -notmatch 'S2-RAN') {
      throw "S2: preflight said ok but exec failed under Disabled+running seclogon (exit $($r.exit)). raw: $($r.raw)"
    }
    Write-Host 'S2 ok: Disabled+running reports ok and exec still launches'
  } else {
    Write-Host 'S2 skipped: seclogon not running after S1'
  }

  # ── S3: Disabled + stopped → status disabled; typed exit 18 ────
  # Stop-Service refuses a Disabled service: stop under Manual, then disable.
  Set-Service seclogon -StartupType Manual
  Stop-Seclogon
  (Get-Service seclogon).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
  Set-Service seclogon -StartupType Disabled
  $st = Seclogon-State
  if ($st -ne 'disabled') { throw "S3: Disabled+stopped expected seclogon=disabled, got '$st'" }
  $st = (J @('user','status')).seclogon
  if ($st -ne 'disabled') { throw "S3: user status expected seclogon=disabled, got '$st'" }

  $r = RExec @('--', $cmd, '/c', 'echo S3-RAN')
  if ($r.exit -ne 18) {
    throw "S3: exec expected exit 18 (seclogon_disabled), got $($r.exit). raw: $($r.raw)"
  }
  if ($r.raw -match 'S3-RAN') {
    throw "S3: the command RAN with seclogon disabled (fail-open). raw: $($r.raw)"
  }
  $e = Seclogon-Err $r.raw
  if (-not $e) { throw "S3: exec stderr has no seclogon_disabled JSON line. raw: $($r.raw)" }
  if ($e.state -ne 'disabled') { throw "S3: exec error state '$($e.state)', expected disabled" }
  if ($e.message -notmatch 'startup type to Manual') {
    throw "S3: exec error message lacks the fix: $($e.message)"
  }
  Write-Host "S3 ok: exec exits 18 with seclogon_disabled ($($e.message))"

  # ── S3b: wfp verify — same typed failure, no stdout verdict ────
  $vErrFile = Join-Path ([System.IO.Path]::GetTempPath()) "srt-smoke-s3b-$PID.err"
  $vout  = & $Exe wfp verify --target '127.0.0.1:9' 2>$vErrFile
  $vexit = $LASTEXITCODE
  $verr  = Get-Content -Raw $vErrFile -ErrorAction SilentlyContinue
  Remove-Item $vErrFile -ErrorAction SilentlyContinue
  if ($vexit -ne 18) {
    throw "S3b: wfp verify expected exit 18, got $vexit. stdout: '$vout' stderr: $verr"
  }
  if ($vout) {
    throw "S3b: wfp verify printed a probe verdict without launching: '$vout'"
  }
  if (-not (Seclogon-Err $verr)) {
    throw "S3b: wfp verify stderr has no seclogon_disabled JSON line. stderr: $verr"
  }
  Write-Host 'S3b ok: wfp verify exits 18 with seclogon_disabled'
} catch {
  if ("$_" -notlike 'SECLOGON-UNSTOPPABLE:*') { throw }
  $slSkipped = $true
  Write-Host "S1-S3 SKIPPED: the Secondary Logon service cannot be stopped on this machine. $_"
} finally {
  # Warn rather than throw so an S-row failure above is not masked; S4 is the check.
  try {
    Set-Service seclogon -StartupType $slStartType
    if ($slWasRunning) { Start-Service seclogon } else { Stop-Seclogon }
  } catch {
    Write-Host "S: WARNING: restoring seclogon (StartType=$slStartType running=$slWasRunning): $_"
  }
  $slNow = Get-Service seclogon
  Write-Host "S: seclogon after:  StartType=$($slNow.StartType) Status=$($slNow.Status)"
}

# ── S4: restored — status ok and exec launches again ─────────────
$st = Seclogon-State
if ($st -ne 'ok') { throw "S4: after restore expected seclogon=ok, got '$st'" }
$r = RExec @('--', $cmd, '/c', 'echo S4-RAN')
if ($r.exit -ne 0 -or $r.out -notmatch 'S4-RAN') {
  throw "S4: exec after restoring seclogon failed (exit $($r.exit)). raw: $($r.raw)"
}
Write-Host 'S4 ok: seclogon restored; exec launches again'

# ── teardown ─────────────────────────────────────────────────────
Run @('uninstall','--sublayer-guid',$Sublayer)
$post = J @('wfp','status','--sublayer-guid',$Sublayer)
if ($post.state -ne 'absent') {
  throw "post-uninstall expected absent, got $($post.state)"
}
# An uninstall drops the sublayer's recorded loopback mode with its filters.
if ($null -ne (Get-LoopbackMode $Sublayer)) {
  throw "post-uninstall: the sublayer's loopback mode is still recorded: '$(Get-LoopbackMode $Sublayer)'"
}
$slRows = if ($slSkipped) { 'S4; S1-S3 SKIPPED' } else { 'S1-S4' }
Write-Host "smoke-exec: PASS (R0b, V1/V1b/V1c/V1d, R1-R7c, R5g-R5j, R9/R9b, R11, R12, R13, R14, G1-G6/G3b, L0-L10, $slRows)"
