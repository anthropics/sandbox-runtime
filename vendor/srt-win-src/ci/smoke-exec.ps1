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

# Bind a TcpListener on the first free port from $candidates.
# Throws if none bind.
function Bind-Listener {
  param([int[]] $Candidates)
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
$vout = & $Exe wfp verify --target $v1Tgt
$vexit = $LASTEXITCODE
$v1Lsn.Stop()
Write-Host "V1: wfp verify --target $v1Tgt exit=$vexit stdout='$vout'"
if ($vexit -ne 0) {
  throw "V1: wfp verify expected exit 0 (blocked), got $vexit"
}
$v = $vout | ConvertFrom-Json
if ($v.egress_probe -ne 'blocked') {
  throw "V1: wfp verify expected egress_probe=blocked, got '$($v.egress_probe)'"
}
Write-Host 'V1 ok: wfp verify reports egress_probe=blocked'

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
  # Drain both pipes concurrently so a full pipe buffer can't wedge
  # WaitForExit.
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

# ── R4b: --env overlay restores the *_PROXY case-twin ───────────
# The host spawn layer keeps only ONE casing of an env key, but
# Cygwin/MSYS2 children read the lowercase names — so the runner
# appends the missing twin. Passing HTTP_PROXY via --env and
# finding BOTH casings in the child proves the repair.
$r = RExec @('--env', "HTTP_PROXY=http://127.0.0.1:$PortLo",
             '--', $cmd, '/c', 'set http')
if ($r.exit -ne 0) { throw "R4b: 'set http' exited $($r.exit). out: $($r.out)" }
$lines = $r.out -split "`r?`n"
if (-not ($lines | Where-Object { $_ -clike 'http_proxy=*' })) {
  throw "R4b: lowercase http_proxy twin missing in child. out: $($r.out)"
}
if (-not ($lines | Where-Object { $_ -clike 'HTTP_PROXY=*' })) {
  throw "R4b: uppercase HTTP_PROXY missing in child. out: $($r.out)"
}
Write-Host 'R4b ok: runner restores the lowercase twin of overlay-proxy vars'

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
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command',
    "(Test-NetConnection 127.0.0.1 -Port $portInR " +
    "-WarningAction SilentlyContinue).TcpTestSucceeded")
  if ($r.out -notmatch '(?i)\bTrue\b') {
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
    "(Test-NetConnection 127.0.0.1 -Port $portOut " +
    "-WarningAction SilentlyContinue).TcpTestSucceeded")
  if ($r.out -match '(?i)\bTrue\b') {
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
$v6l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::IPv6Loopback, 49998)
$v6l.Start()
try {
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command',
    "try { `$c = New-Object Net.Sockets.TcpClient([Net.Sockets.AddressFamily]::InterNetworkV6); " +
    "`$c.Connect('::1', 49998); Write-Output CONNECTED } catch { Write-Output blocked }")
  if ($r.out -match 'CONNECTED') {
    throw "R5d: sandboxed connect to [::1]:49998 succeeded — v6 fence hole. raw: $($r.raw)"
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

# ── R5f: non-interactive logon types refused for the sandbox account ─
# The SMB redirector dials from kernel mode as SYSTEM, so the
# SID-keyed WFP fence never sees its connects; the fix denies the
# sandbox group every logon type except interactive. LOOPBACK SMB is
# exempt by NTLM loopback-session reuse (no new logon occurs), so the
# CI-provable check is LogonUser itself: type NETWORK/BATCH/SERVICE
# must refuse with 1385 (what any remote server's LSA runs at SMB
# session setup), INTERACTIVE must stay granted (the
# CreateProcessWithLogonW launch depends on it).
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
  # The stamp adds (D;;FILE_DELETE_CHILD;;;<sb-SID>) on the
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

# ── teardown ─────────────────────────────────────────────────────
Run @('uninstall','--sublayer-guid',$Sublayer)
$post = J @('wfp','status','--sublayer-guid',$Sublayer)
if ($post.state -ne 'absent') {
  throw "post-uninstall expected absent, got $($post.state)"
}
Write-Host 'smoke-exec: PASS (R0b, V1, R1-R7c, R9/R9b, R11, R12, G1-G6/G3b)'
