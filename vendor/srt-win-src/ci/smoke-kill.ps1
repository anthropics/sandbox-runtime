<#
  Kill-chain invariant smoke (K1/K2): NO sandbox process survives
  the broker. Pins the ground-truthed probe result that the
  broker→runner `AssignProcessToJobObject` succeeds and the
  kill-on-close Job cascade reaps the whole tree — if a future
  Windows build (or a lockdown change) regresses the assign, these
  rows turn CI red instead of silently orphaning trees.

  K1: hard kill — `Stop-Process -Force` on the broker (no cleanup
      code runs) → broker→runner→cmd→PING all gone within 5s via
      the Job cascade.

  K2: graceful exit — the child finishes on its own, the broker
      returns normally (the always-armed TerminateProcess guard
      no-ops on the already-exited runner) → tree gone.

  Asserts on `Get-Process -Id … -ea SilentlyContinue` emptiness,
  NOT on Job membership or assign rc — the invariant is "no
  survivors", not "assigned to job".
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe
)

$ErrorActionPreference = 'Stop'

# Fixed test-only sublayer; distinct from the other smoke scripts.
# Referenced verbatim by the workflow's always()-cleanup step.
$Sublayer  = '4c1f7a2e-8b9d-4e3a-9f6c-1d7e5a0b8c4f'
$PortRange = '60080-60089'

function Run { param([string[]] $argv)
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited $LASTEXITCODE"
  }
}

$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
Write-Host "smoke-kill: sublayer=$Sublayer  exe=$Exe"

try { Start-Service seclogon -ea Stop } catch {
  Write-Host "smoke-kill: WARNING: Start-Service seclogon: $_"
}

Run @('install','--sublayer-guid',$Sublayer,'--proxy-port-range',$PortRange)

# ── Tree helpers ────────────────────────────────────────────────────
# Identify sandbox procs by ParentProcessId chain, NOT GetOwner —
# self-protect denies the owner query to a non-elevated caller.

function Get-TreePids { param([int] $Root)
  # Single-snapshot BFS over Win32_Process on ParentProcessId.
  $all = Get-CimInstance Win32_Process |
         Select-Object ProcessId, ParentProcessId, Name
  $out  = New-Object System.Collections.Generic.List[object]
  $seen = New-Object System.Collections.Generic.HashSet[int]
  $q    = New-Object System.Collections.Generic.Queue[int]
  $q.Enqueue($Root); [void]$seen.Add($Root)
  $out.Add(($all | Where-Object { $_.ProcessId -eq $Root }))
  while ($q.Count -gt 0) {
    $p = $q.Dequeue()
    foreach ($c in $all | Where-Object { $_.ParentProcessId -eq $p }) {
      if ($seen.Add($c.ProcessId)) {
        $out.Add($c); $q.Enqueue($c.ProcessId)
      }
    }
  }
  return $out
}

function Assert-Gone { param([int[]] $Pids, [string] $Tag, [int] $WaitSec = 5)
  $deadline = [DateTime]::UtcNow.AddSeconds($WaitSec)
  do {
    $alive = @(Get-Process -Id $Pids -ea SilentlyContinue |
               Select-Object -Expand Id)
    if ($alive.Count -eq 0) {
      Write-Host ("${Tag} ok: all $($Pids.Count) tree PID(s) gone " +
                  "within $WaitSec s")
      return
    }
    Start-Sleep -Milliseconds 200
  } while ([DateTime]::UtcNow -lt $deadline)
  throw ("${Tag}: $($alive.Count) survivor(s) after ${WaitSec}s: " +
         "$($alive -join ',') (full tree: $($Pids -join ','))")
}

# Launch a sandbox tree whose leaf pings for $PingCount probes
# (~1s apart) and wait for the leaf, so the rows assert against a
# fully-formed tree. `ping -n N` is the leaf (`timeout /t` aborts
# under redirected stdin). Must use ProcessStartInfo.ArgumentList
# (per-element quoting) — `Start-Process -ArgumentList` space-joins
# without quoting, splitting the `cmd /c "…"` payload so `>nul`
# reaches ping as a hostname.
function Start-Tree {
  param([int] $PingCount = 300)
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName        = $Exe
  $psi.UseShellExecute = $false
  foreach ($a in @('exec','--quiet','--',
                   $cmd,'/c',"ping -n $PingCount 127.0.0.1 >nul")) {
    [void]$psi.ArgumentList.Add($a)
  }
  $p = [System.Diagnostics.Process]::Start($psi)
  $bpid = $p.Id
  # Poll until the leaf (`PING.EXE`) is present — a depth count
  # alone can be inflated by conhost.exe before the leaf spawns.
  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 250
    $t = @(Get-TreePids $bpid)
    if (($t | Where-Object { $_.Name -match '^PING\.EXE$' })) {
      $pids = @($t | Select-Object -Expand ProcessId)
      $names = ($t | ForEach-Object { "$($_.ProcessId)=$($_.Name)" }) -join ','
      Write-Host "smoke-kill: tree = $names (broker=$bpid)"
      return [pscustomobject]@{ broker = $bpid; proc = $p; pids = $pids }
    }
  }
  try { $p.Kill($true) } catch { }
  throw "Start-Tree: PING.EXE leaf never appeared (broker=$bpid)"
}

try {
  # ── K1: hard-kill broker → whole tree gone ────────────────────────
  $t = Start-Tree
  Stop-Process -Id $t.broker -Force
  Assert-Gone -Pids $t.pids -Tag 'K1' -WaitSec 5

  # ── K2: graceful broker exit → whole tree gone ────────────────────
  # Short leaf (~7s): the child finishes, the runner returns its
  # exit code, the broker's armed guard no-ops on the already-dead
  # runner and the broker exits cleanly. Nothing may linger.
  $t = Start-Tree -PingCount 8
  if (-not $t.proc.WaitForExit(30000)) {
    try { $t.proc.Kill($true) } catch { }
    throw 'K2: broker did not exit within 30s of a ~7s child'
  }
  Write-Host "K2: broker exited (code=$($t.proc.ExitCode))"
  Assert-Gone -Pids $t.pids -Tag 'K2' -WaitSec 5
}
finally {
  & $Exe uninstall --sublayer-guid $Sublayer 2>&1 | Out-Null
}

Write-Host 'smoke-kill: PASS (K1/K2)'
