<#
  Machine-wide state store lifecycle smoke (`%ProgramData%\sandbox-runtime`).

  Asserts the elevated install provisions the shared state — the
  registry store (HKLM\SOFTWARE\sandbox-runtime: identity/marker;
  Cred subkey Users-read-only + sandbox DENY; Ca subkey
  user-recordable + sandbox DENY) and the ca\-hosting directory
  (owned by Administrators, sandbox-group DENY, Users modify) —
  that a sandboxed child can read neither the credential key nor
  the store directory,
  that an install running as SYSTEM (the SCCM/Intune fleet shape)
  leaves a credential the INTERACTIVE user's broker can read and
  spawn with — the per-user-store bug this store exists to fix —
  that a re-install rotates the shared credential in place, that a
  NON-ADMIN standard user's broker can read the credential and
  write the shared state DB (acl grant/restore — the BUILTIN\Users
  ACEs, which the elevated outer script cannot prove) while its
  exec refuses fail-closed inside a session it doesn't own (the
  BNO-hardening gate), and that a full uninstall removes the
  credential with the account.

  Self-contained: installs under a fixed test-only sublayer GUID
  (distinct from the other smoke scripts); uninstalls in `finally`.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe
)

$ErrorActionPreference = 'Stop'

# Fixed test-only sublayer; referenced by cleanup.ps1.
$Sublayer  = '4c7d9b21-3e58-4a06-9d17-8f2a6c40be93'
$PortRange = '60080-60089'

function Run { param([string[]] $argv)
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited $LASTEXITCODE"
  }
}
function J { param([string[]] $argv) Run $argv | ConvertFrom-Json }
function RunCapture { param([string[]] $argv)
  $raw = & $Exe @argv 2>&1 | Out-String
  return [pscustomobject]@{ exit = $LASTEXITCODE; raw = $raw }
}

$cmd      = Join-Path $env:SystemRoot 'System32\cmd.exe'
$stateDir = Join-Path $env:ProgramData 'sandbox-runtime'
$regBase  = 'HKLM:\SOFTWARE\sandbox-runtime'
function CredRecorded { [bool](Get-ItemProperty "$regBase\Cred" -Name Blob -ea SilentlyContinue) }
$env:SANDBOX_RUNTIME_WIN_DEBUG = '1'
Write-Host "smoke-machine-store: sublayer=$Sublayer  exe=$Exe"

try { Start-Service seclogon -ea Stop } catch {
  Write-Host "smoke-machine-store: WARNING: Start-Service seclogon: $_"
}

try {
  # ── MS1: elevated install provisions the machine store ───────────
  Run @('install', '--sublayer-guid', $Sublayer, '--proxy-port-range', $PortRange, '--force')
  $us = J @('user', 'status')
  if (-not $us.cred_present)     { throw 'MS1: cred_present false after machine-store install' }
  if (-not (CredRecorded)) { throw 'MS1: Cred\Blob missing from HKLM store' }

  $acl = Get-Acl $stateDir
  if ($acl.Owner -notmatch 'Administrators$') {
    throw "MS1: state dir owner expected Administrators, got '$($acl.Owner)'"
  }
  $deny = $acl.Access | Where-Object {
    $_.AccessControlType -eq 'Deny' -and
    $_.IdentityReference.Value -match 'sandbox-runtime-users$'
  }
  if (-not $deny) {
    throw "MS1: state-dir DACL has no DENY for sandbox-runtime-users; got:`n$($acl.Access | Out-String)"
  }
  $usersModify = $acl.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.IdentityReference.Value -match '\\Users$' -and
    ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::WriteData)
  }
  if (-not $usersModify) {
    throw "MS1: state-dir DACL grants BUILTIN\Users no write; got:`n$($acl.Access | Out-String)"
  }

  $cacl = Get-Acl "$regBase\Cred"
  $credDeny = $cacl.Access | Where-Object {
    $_.AccessControlType -eq 'Deny' -and
    $_.IdentityReference.Value -match 'sandbox-runtime-users$'
  }
  if (-not $credDeny) {
    throw "MS1: Cred key has no DENY for sandbox-runtime-users; got:`n$($cacl.Access | Out-String)"
  }
  $credUsersWrite = $cacl.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.IdentityReference.Value -match '\\Users$' -and
    ($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::SetValue)
  }
  if ($credUsersWrite) {
    throw "MS1: Cred key is writable by BUILTIN\Users; got:`n$($cacl.Access | Out-String)"
  }
  Write-Host 'MS1 ok: store provisioned (dir owner+deny+Users modify; Cred key read-only + denied)'

  # ── MS2: sandboxed child denied on the Cred key and store dir ────
  $r = RunCapture @('exec', '--quiet', '--', $cmd, '/c', 'reg query HKLM\SOFTWARE\sandbox-runtime\Cred /v Blob')
  if ($r.exit -eq 0) { throw "MS2: child READ Cred\Blob. raw: $($r.raw)" }
  $r = RunCapture @('exec', '--quiet', '--', $cmd, '/c', 'reg add HKLM\SOFTWARE\sandbox-runtime /v rtEsc /d x /f')
  if ($r.exit -eq 0) { throw 'MS2: child WROTE the HKLM store' }
  $r = RunCapture @('exec', '--quiet', '--', $cmd, '/c', "dir `"$stateDir`"")
  if ($r.exit -eq 0) { throw "MS2: child LISTED the store dir. raw: $($r.raw)" }
  Write-Host 'MS2 ok: sandbox child denied on Cred key, store key write, and store dir'

  # ── MS3: SYSTEM install is readable by the interactive user ──────
  # The fleet shape (SCCM/Intune run installs as SYSTEM). Under the
  # per-user store this left the interactive user's dependency check
  # at cred_present:false — the bug the machine store fixes.
  Run @('uninstall', '--sublayer-guid', $Sublayer)
  if (CredRecorded) { throw 'MS3: Cred\Blob survived full uninstall' }
  $task = 'srt-win-ms3-system-install'
  # A scheduled task starts in System32, so the exe path must be
  # absolute; run through a wrapper .cmd that captures output, since
  # a SYSTEM task's console is otherwise invisible.
  $exeFull = (Resolve-Path $Exe).Path
  $ms3Log  = 'C:\Windows\Temp\srt-ms3-system-install.log'
  $runner  = 'C:\Windows\Temp\srt-ms3-system-install.cmd'
  Remove-Item $ms3Log -ea SilentlyContinue
  $ms3Rc = 'C:\Windows\Temp\srt-ms3-system-install.rc'
  Remove-Item $ms3Rc -ea SilentlyContinue
  @(
    '@echo off'
    "`"$exeFull`" install --sublayer-guid $Sublayer --proxy-port-range $PortRange --force > `"$ms3Log`" 2>&1"
    "echo %errorlevel% > `"$ms3Rc`""
  ) | Set-Content $runner -Encoding ascii
  schtasks /Create /F /RU SYSTEM /SC ONCE /ST 00:00 /TN $task /TR "`"$runner`"" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "MS3: schtasks /Create exited $LASTEXITCODE" }
  try {
    schtasks /Run /TN $task | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "MS3: schtasks /Run exited $LASTEXITCODE" }
    $deadline = (Get-Date).AddSeconds(120)
    while (-not (CredRecorded)) {
      if ((Get-Date) -gt $deadline) {
        $installOut = if (Test-Path $ms3Log) { Get-Content $ms3Log | Out-String } else { '<no log>' }
        throw "MS3: SYSTEM install did not record Cred\Blob in 120s. install output:`n$installOut"
      }
      Start-Sleep -Seconds 2
    }
    # The credential is recorded BEFORE the WFP step, so its appearance
    # alone can mask a WFP-stage failure — wait for the wrapper's
    # recorded exit code and assert the whole install succeeded.
    $deadline = (Get-Date).AddSeconds(60)
    while (-not (Test-Path $ms3Rc)) {
      if ((Get-Date) -gt $deadline) { throw 'MS3: SYSTEM install exit code never recorded' }
      Start-Sleep -Seconds 2
    }
    $rc = (Get-Content $ms3Rc -Raw).Trim()
    if ($rc -ne '0') {
      $installOut = if (Test-Path $ms3Log) { Get-Content $ms3Log | Out-String } else { '<no log>' }
      throw "MS3: SYSTEM install exited ${rc}. install output:`n$installOut"
    }
  } finally {
    schtasks /Delete /F /TN $task | Out-Null
    Remove-Item $runner, $ms3Log, $ms3Rc -ea SilentlyContinue
  }
  $us = J @('user', 'status')   # interactive user's view
  if (-not $us.cred_present) { throw 'MS3: interactive user sees cred_present:false after SYSTEM install' }
  $pw = & $Exe user read-cred
  if ($LASTEXITCODE -ne 0) { throw "MS3: interactive read-cred exited $LASTEXITCODE" }
  if ($pw.Length -ne 32)   { throw "MS3: read-cred expected 32 chars, got $($pw.Length)" }
  $r = RunCapture @('exec', '--quiet', '--', $cmd, '/c', 'whoami')
  if ($r.exit -ne 0) { throw "MS3: interactive exec after SYSTEM install failed: $($r.raw)" }
  Write-Host 'MS3 ok: SYSTEM install; interactive user reads cred and spawns'

  # ── MS4: re-install rotates the shared credential in place ───────
  # Compare the DECRYPTED secret, not the blob bytes: DPAPI output
  # embeds random salt, so ciphertext differs on every write even
  # when the password was NOT rotated — the bytes comparison would
  # be vacuously green.
  $pwBefore = & $Exe user read-cred
  if ($LASTEXITCODE -ne 0) { throw "MS4: read-cred before rotation exited $LASTEXITCODE" }
  Run @('install', '--sublayer-guid', $Sublayer, '--proxy-port-range', $PortRange, '--force')
  $pwAfter = & $Exe user read-cred
  if ($LASTEXITCODE -ne 0 -or $pwAfter.Length -ne 32) {
    throw "MS4: read-cred after rotation failed (exit $LASTEXITCODE, len $($pwAfter.Length))"
  }
  if ($pwAfter -eq $pwBefore) {
    throw 'MS4: password unchanged across rotating re-install'
  }
  Write-Host 'MS4 ok: rotation refreshed the shared credential'

  # ── MS6: a NON-ADMIN user's broker works against the shared store ─
  # The outer script runs as an elevated Administrator, which would
  # pass even if the BUILTIN\Users ACEs were wrong (the BA ACE grants
  # full control) — so prove the Users leg with a real standard user:
  # status reads the shared credential, an acl grant/restore
  # round-trip exercises their own per-user session DB, and exec
  # (foreign-session here) refuses closed.
  $u6 = 'srt-ms6-user'
  $pw6 = 'Ms6!' + [guid]::NewGuid().ToString('N').Substring(0, 16)
  # /y: net.exe interactively prompts Y/N for passwords longer than
  # 14 chars, which hangs (exit -1) with no stdin in CI.
  net user $u6 $pw6 /add /y | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "MS6: net user add exited $LASTEXITCODE" }
  try {
    $cred6 = [pscredential]::new(
      "$env:COMPUTERNAME\$u6",
      (ConvertTo-SecureString $pw6 -AsPlainText -Force))
    $pub = 'C:\Users\Public'
    $o6 = Join-Path $pub 'srt-ms6-out.txt'
    $e6 = Join-Path $pub 'srt-ms6-err.txt'
    $i6 = Join-Path $pub 'srt-ms6-in.json'
    function RunAsUser6 { param([string[]] $argv, [string] $stdin)
      Remove-Item $o6, $e6 -ea SilentlyContinue
      # -LoadUserProfile (LOGON_WITH_PROFILE) creates the account's
      # profile, but Start-Process -Credential still hands the child
      # the CALLER's environment — %LOCALAPPDATA% would point at the
      # admin's profile, which the standard user cannot even stat.
      # The acl commands open the per-user session store under
      # %LOCALAPPDATA%, so route through cmd and override the profile
      # variables to the standard user's own tree explicitly.
      $prof6 = "C:\Users\$u6"
      $inner = "set `"USERPROFILE=$prof6`" && set `"LOCALAPPDATA=$prof6\AppData\Local`" && `"$exeFull`" " + ($argv -join ' ')
      $sp = @{
        FilePath = $cmd; ArgumentList = @('/c', $inner); Credential = $cred6
        WorkingDirectory = $pub; NoNewWindow = $true; Wait = $true
        PassThru = $true; LoadUserProfile = $true
        RedirectStandardOutput = $o6; RedirectStandardError = $e6
      }
      if ($stdin) {
        Set-Content -Path $i6 -Value $stdin -Encoding ascii
        $sp.RedirectStandardInput = $i6
      }
      $p = Start-Process @sp
      [pscustomobject]@{
        exit = $p.ExitCode
        out  = (Get-Content $o6 -Raw -ea SilentlyContinue)
        err  = (Get-Content $e6 -Raw -ea SilentlyContinue)
      }
    }
    $r = RunAsUser6 @('user', 'status')
    if ($r.exit -ne 0) { throw "MS6: user status as standard user exited $($r.exit): $($r.err)" }
    $st6 = $r.out | ConvertFrom-Json
    if (-not $st6.cred_present) { throw 'MS6: standard user cannot see the shared credential' }
    # The grant target must be created BY the standard user: writing
    # an ACE needs WRITE_DAC, which they hold via CREATOR OWNER on
    # their own files (the real broker shape — a user grants on their
    # own working tree), not on directories some admin created.
    $probe6 = Join-Path $pub 'srt-ms6-probe'
    Remove-Item $probe6 -Recurse -Force -ea SilentlyContinue
    $mk = Start-Process -FilePath $cmd -ArgumentList @('/c', "mkdir `"$probe6`"") `
            -Credential $cred6 -WorkingDirectory $pub -NoNewWindow -Wait -PassThru -LoadUserProfile
    if ($mk.ExitCode -ne 0) { throw "MS6: mkdir as standard user exited $($mk.ExitCode)" }
    $r = RunAsUser6 @('acl', 'grant', '--holder-pid', $PID,
                      '--sandbox-user-sid', $st6.marker_user_sid) `
                    "{`"write`":[`"$($probe6 -replace '\\','\\')`"]}"
    if ($r.exit -ne 0) { throw "MS6: acl grant as standard user exited $($r.exit): $($r.err)" }
    # The Ca record must be WRITABLE by a standard user (unelevated
    # trust-ca records the DER there). Probe with an open requesting
    # exactly RegistryRights::SetValue — the DACL grants Users
    # KEY_READ|KEY_SET_VALUE and deliberately NOT KEY_WRITE (whose
    # CREATE_SUB_KEY bit is withheld), so tools that open with
    # KEY_WRITE (reg.exe add, the old product bug) are denied while
    # the product's set-value open succeeds. ReadWriteSubTree only
    # sets .NET's managed writable flag; the explicit rights arg
    # still governs the actual open.
    $caProbe = 'try { ' +
      '$k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(''SOFTWARE\sandbox-runtime\Ca'', ' +
      '[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, ' +
      '[System.Security.AccessControl.RegistryRights]::SetValue); ' +
      '$k.SetValue(''Ms6Probe'',''x''); Write-Output SETVALUE-OK } catch { Write-Output (''failed: '' + $_.Exception.Message) }'
    $r = RunAsUser6 @('user', 'status')  # keep env plumbing warm
    $o7 = Join-Path $pub 'srt-ms6-ca.txt'
    Remove-Item $o7 -ea SilentlyContinue
    $pp = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -ArgumentList @('-NoProfile','-Command', $caProbe) -Credential $cred6 -WorkingDirectory $pub `
            -NoNewWindow -Wait -PassThru -LoadUserProfile -RedirectStandardOutput $o7
    $caOut = Get-Content $o7 -Raw -ea SilentlyContinue
    if ($caOut -notmatch 'SETVALUE-OK') {
      throw "MS6: standard user cannot set-value the Ca record: $caOut"
    }
    Remove-ItemProperty 'HKLM:\SOFTWARE\sandbox-runtime\Ca' -Name Ms6Probe -ea SilentlyContinue
    Remove-Item $o7 -ea SilentlyContinue
    # revoke, not restore: grants are released by `acl revoke`
    # (restore releases deny stamps) — and assert the ALLOW ACE is
    # actually gone rather than trusting the exit code.
    $r = RunAsUser6 @('acl', 'revoke', '--holder-pid', $PID,
                      '--sandbox-user-sid', $st6.marker_user_sid)
    if ($r.exit -ne 0) { throw "MS6: acl revoke as standard user exited $($r.exit): $($r.err)" }
    # Explicit ACEs only: C:\Users\Public is an ambient write-deny
    # target, so the probe dir INHERITS a srt-sandbox deny from it
    # ((I) in icacls) — that one is supposed to be there. The revoke
    # must remove the explicit grant ACE.
    $explicit = (icacls $probe6 | Out-String) -split "`n" |
      Where-Object { $_ -match 'srt-sandbox' -and $_ -notmatch '\(I\)' }
    if ($explicit) {
      throw "MS6: explicit sandbox-user ACE still on $probe6 after revoke: $explicit"
    }
    # exec from THIS shape must refuse, fail-closed: Start-Process
    # -Credential runs the standard user INSIDE the admin's session,
    # and the broker requires WRITE_DAC on the session's
    # BaseNamedObjects to stamp BNO hardening before spawning — a
    # session the user doesn't own is exactly where an unstampable
    # child could squat named objects, so erroring is the invariant.
    # (Real multi-user brokers run in their owner's own session,
    # which grants WRITE_DAC; the same-session spawn is MS3.)
    $r = RunAsUser6 @('exec', '--quiet', '--', $cmd, '/c', 'whoami')
    if ($r.exit -eq 0) { throw 'MS6: exec inside a foreign session unexpectedly succeeded' }
    if (($r.err + $r.out) -notmatch 'BaseNamedObjects|BNO') {
      throw "MS6: exec refusal should name the session BNO gate; got: $($r.err)$($r.out)"
    }
    Write-Host 'MS6 ok: standard user reads the cred + runs session acl ops; foreign-session exec refuses closed'
  } finally {
    net user $u6 /delete | Out-Null
    Remove-Item $o6, $e6, $i6, (Join-Path $pub 'srt-ms6-probe') -Recurse -Force -ea SilentlyContinue
  }

  # ── MS5: full uninstall removes the credential with the account ──
  Run @('uninstall', '--sublayer-guid', $Sublayer)
  if (CredRecorded) { throw 'MS5: Cred\Blob survived uninstall' }
  if (Test-Path $regBase) { throw 'MS5: HKLM store key survived uninstall' }
  $us = J @('user', 'status')
  if ($us.cred_present) { throw 'MS5: cred_present still true after uninstall' }
  Write-Host 'MS5 ok: uninstall removed the shared credential'

  Write-Host 'smoke-machine-store: all checks passed'
} finally {
  & $Exe uninstall --sublayer-guid $Sublayer 2>&1 | Out-Null
}
