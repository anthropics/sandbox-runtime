<#
  Measurement rows for traffic the egress fence does not attribute to
  the sandbox account, because a system component carries it:

    SMB  - the kernel redirector connects for a UNC path, and the
           child can present credentials other than its own.
    WSL  - the WSL service runs a distribution whose traffic is
           forwarded by the virtual switch or a host component.

  Nothing here is an assertion. Each row prints one line

      RESIDUAL <name>: <observed>

  and the script ends with a table of all of them. An observation,
  whatever it is, never fails the script. The script exits non-zero
  only when it could not do its own work: provisioning, a row's own
  code throwing, or cleanup. Even then every remaining row still runs
  and the table is still printed, and the failure is raised last.

  The runner has no second machine, so the "remote" server is this
  machine's own SMB server reached through a non-loopback address.

  Self-contained: installs under a fixed test-only sublayer GUID
  (distinct from the other smoke scripts, listed in cleanup.ps1) and
  removes everything it created in `finally`.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe
)

$ErrorActionPreference = 'Stop'

# Fixed test-only sublayer; referenced by cleanup.ps1.
$Sublayer  = 'b7524f53-6892-434c-93d5-46e02c3f8cdc'
$PortRange = '60080-60089'

$cmd  = Join-Path $env:SystemRoot 'System32\cmd.exe'
$wps  = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$sc   = Join-Path $env:SystemRoot 'System32\sc.exe'
$wsl  = Join-Path $env:SystemRoot 'System32\wsl.exe'

$rows   = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[string]]::new()

# ── helpers ────────────────────────────────────────────────────────
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

# Collapse to one line. wsl.exe writes UTF-16, which arrives here as
# text with a NUL after every character, so NULs are dropped first.
function OneLine { param([string] $s, [int] $Max = 500)
  $t = (("$s" -replace "`0", '') -replace '\s+', ' ').Trim()
  if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + ' ...' }
  return $t
}
function FirstLines { param([string] $s, [int] $n = 4)
  $l = @(("$s" -replace "`0", '') -split "`r?`n" |
         ForEach-Object { $_.Trim() } | Where-Object { $_ })
  if ($l.Count -eq 0) { return '(no output)' }
  return (($l | Select-Object -First $n) -join ' | ')
}

function Record { param([string] $Name, [string] $Observed)
  $o = OneLine $Observed
  Write-Host "RESIDUAL ${Name}: $o"
  $rows.Add([pscustomobject]@{ Row = $Name; Observed = $o })
}
# One row. The body returns the observation as a string. A body that
# throws is this script failing, not an observation: it is recorded
# in the row, the remaining rows still run, and the script fails at
# the end.
function Row { param([string] $Name, [scriptblock] $Body)
  try {
    Record $Name ((& $Body | Out-String))
  } catch {
    $errors.Add("row ${Name}: $_")
    Record $Name "script error: $_"
  }
}
function Cleanup { param([string] $What, [scriptblock] $Body)
  try { & $Body } catch { $errors.Add("cleanup ($What): $_") }
}

# Run a command as the sandbox account through `srt-win exec`. The
# broker forwards only what --env names, so PATH/PATHEXT are passed
# as the other smoke scripts do. A timeout is returned, not thrown:
# here a command that hangs is something to record.
function SbExec {
  param([string[]] $tail, [int] $TimeoutSec = 120, [string[]] $ExtraEnv = @())
  $argv = @('exec', '--quiet',
            '--env', "PATH=$($env:PATH)",
            '--env', "PATHEXT=$($env:PATHEXT)")
  foreach ($e in $ExtraEnv) { $argv += @('--env', $e) }
  $argv += $tail
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName               = $Exe
  $psi.UseShellExecute        = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  # An empty, closed stdin: nothing in a row may wait for a key.
  $psi.RedirectStandardInput  = $true
  foreach ($a in $argv) { $null = $psi.ArgumentList.Add($a) }
  $p  = [System.Diagnostics.Process]::Start($psi)
  $p.StandardInput.Close()
  $so = $p.StandardOutput.ReadToEndAsync()
  $se = $p.StandardError.ReadToEndAsync()
  $timedOut = -not $p.WaitForExit($TimeoutSec * 1000)
  if ($timedOut) {
    try { $p.Kill($true) } catch { }
    $null = $p.WaitForExit(10000)
  }
  # Bounded: a process that outlives the broker and still holds the
  # pipe must not hang the script.
  $out = if ($so.Wait(10000)) { $so.Result } else { '' }
  $err = if ($se.Wait(10000)) { $se.Result } else { '' }
  $raw = $out + $err
  $child = (($raw -split "`r?`n") |
            Where-Object { $_ -notmatch '^srt-win:' }) -join "`n"
  $exit = if ($timedOut) { -1 } else { $p.ExitCode }
  Write-Host "  [exec exit=$exit timedOut=$timedOut] $($tail -join ' ')"
  foreach ($line in (("$raw" -replace "`0", '') -split "`r?`n")) {
    if ($line.Trim()) { Write-Host "    | $line" }
  }
  return [pscustomobject]@{
    exit = $exit; raw = $raw; out = $child
    timedOut = $timedOut; timeout = $TimeoutSec
  }
}
function Detail { param($r)
  if ($r.timedOut) { return "timeout after $($r.timeout)s" }
  return "exit=$($r.exit); text: $(OneLine $r.out 300)"
}
# A read is allowed when the canary's content came back.
function ReadVerdict { param($r)
  if ("$($r.out)" -match [regex]::Escape($CanaryToken)) { return 'allowed' }
  return 'denied'
}
# A write is allowed when the file is in the shared directory, seen
# from this side, holding the nonce.
function WriteVerdict { param([string] $File, [string] $Nonce)
  $p = Join-Path $shareDir $File
  if ((Test-Path -LiteralPath $p) -and
      ("$(Get-Content -Raw -LiteralPath $p)" -match [regex]::Escape($Nonce))) {
    return 'allowed'
  }
  return 'denied'
}
function NewNonce { return "nonce-$([guid]::NewGuid().ToString('N'))-end" }

Add-Type -Namespace SrtResid -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
public static extern uint GetLongPathName(string s, System.Text.StringBuilder l, uint n);
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(
  string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool GetKernelObjectSecurity(
  Microsoft.Win32.SafeHandles.SafeFileHandle h, uint info, byte[] sd, uint len, out uint needed);
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool SetKernelObjectSecurity(
  Microsoft.Win32.SafeHandles.SafeFileHandle h, uint info, byte[] sd);
'@
function Win32Text { param([int] $Code)
  return "error $Code ($(([System.ComponentModel.Win32Exception]::new($Code)).Message))"
}
# The sandbox account opens by the path it is given, and cannot list
# the runner's profile to resolve an 8.3 component of %TEMP%.
function LongPath { param([string] $p)
  $sb = [System.Text.StringBuilder]::new(1024)
  if ([SrtResid.Native]::GetLongPathName($p, $sb, 1024) -gt 0) { return $sb.ToString() }
  return $p
}

# \Device\Mup, opened through the Win32 alias for the object
# manager's root. Only security rights are requested, so no I/O is
# done on the device.
$MupWin32Path = '\\.\GLOBALROOT\Device\Mup'
$DACL_INFO    = 0x4
function OpenMup { param([uint32] $Access)
  $h  = [SrtResid.Native]::CreateFileW($MupWin32Path, $Access, 7, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
  $le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if ($h.IsInvalid) { throw (Win32Text $le) }
  return $h
}
function ReadMupDacl { param($h)
  $buf = [byte[]]::new(8192)
  $needed = [uint32]0
  $ok = [SrtResid.Native]::GetKernelObjectSecurity($h, $DACL_INFO, $buf, $buf.Length, [ref] $needed)
  $le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if (-not $ok -and $le -eq 122 -and $needed -gt $buf.Length) {
    $buf = [byte[]]::new($needed)
    $ok = [SrtResid.Native]::GetKernelObjectSecurity($h, $DACL_INFO, $buf, $buf.Length, [ref] $needed)
    $le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  }
  if (-not $ok) { throw (Win32Text $le) }
  # Keep the bytes exactly as the system returned them: they are what
  # the restore writes back.
  $len = if ($needed -gt 0 -and $needed -le $buf.Length) { [int] $needed } else { $buf.Length }
  $out = [byte[]]::new($len)
  [Array]::Copy($buf, $out, $len)
  return ,$out
}
function WriteMupDacl { param($h, [byte[]] $sd)
  $ok = [SrtResid.Native]::SetKernelObjectSecurity($h, $DACL_INFO, $sd)
  $le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if (-not $ok) { throw (Win32Text $le) }
}
function SddlOf { param([byte[]] $sd)
  return [System.Security.AccessControl.RawSecurityDescriptor]::new($sd, 0).GetSddlForm('Access')
}
# Put the descriptor read before the experiment back, and confirm the
# device then reads back byte for byte the same.
function RestoreMup {
  if (-not $script:mupOriginal) { return 'nothing to restore' }
  $h = OpenMup 0x00060000
  try {
    WriteMupDacl $h $script:mupOriginal
    $now = ReadMupDacl $h
  } finally { $h.Dispose() }
  if ([Convert]::ToBase64String($now) -ne [Convert]::ToBase64String($script:mupOriginal)) {
    throw "descriptor after restore differs from the original: now $(SddlOf $now)"
  }
  $script:mupOriginal = $null
  return 'restored, reads back identical to the original'
}

# ── state the finally block needs ──────────────────────────────────
$installed    = $false
$sbSid        = $null
$ws           = $null
$shareDir     = $null
$shareName    = "srtresid$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$shareCreated = $false
$acct         = "srt-resid-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$acctCreated  = $false
# Letters and digits only: it is written into a .cmd file.
$acctPw       = 'Aa1' + [guid]::NewGuid().ToString('N').Substring(0, 11)
$addr         = $null
$CanaryToken  = "canary-$([guid]::NewGuid().ToString('N'))-end"
$script:mupOriginal = $null

Write-Host "smoke-residual-egress: sublayer=$Sublayer  exe=$Exe"

try { Start-Service seclogon -ea Stop } catch {
  Write-Host "smoke-residual-egress: WARNING: Start-Service seclogon: $_"
}

try {
  # ── provisioning ─────────────────────────────────────────────────
  Run @('install', '--sublayer-guid', $Sublayer, '--proxy-port-range', $PortRange)
  $installed = $true
  $us = J @('user', 'status')
  $sbSid = $us.marker_user_sid
  if (-not $sbSid) { throw 'setup marker missing user_sid' }
  Write-Host "setup: sandbox account provisioned (sid=$sbSid)"

  # The workspace: the one directory the sandbox account is granted.
  # Probe scripts and their output live here. The shared directory is
  # a sibling and is not part of the grant.
  $ws = Join-Path $env:TEMP "srt-resid-ws-$([guid]::NewGuid().ToString('N'))"
  New-Item -ItemType Directory -Path $ws -Force | Out-Null
  $ws = LongPath $ws
  Stdin @('acl', 'grant', '--holder-pid', $PID, '--sandbox-user-sid', $sbSid) `
        (@{ write = @($ws) } | ConvertTo-Json -Compress)

  $r = SbExec @('--', $cmd, '/c', 'whoami /user /FO CSV /NH')
  Record 'setup-child-identity' (Detail $r)

  # ── SMB setup ────────────────────────────────────────────────────
  $smbReady = $false
  $smbWhy   = ''
  try {
    $shareDir = Join-Path $env:TEMP "srt-resid-share-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $shareDir -Force | Out-Null
    $shareDir = LongPath $shareDir
    $CanaryToken | Set-Content -Encoding ASCII (Join-Path $shareDir 'canary.txt')
    # Everyone may modify, on the directory and on the share, so that
    # neither the file ACL nor the share ACL is what decides a row.
    & icacls $shareDir /grant '*S-1-1-0:(OI)(CI)M' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls on the shared directory exited $LASTEXITCODE" }
    $everyone = ([System.Security.Principal.SecurityIdentifier] 'S-1-1-0').Translate(
      [System.Security.Principal.NTAccount]).Value
    New-SmbShare -Name $shareName -Path $shareDir -ChangeAccess $everyone | Out-Null
    $shareCreated = $true

    & net.exe user $acct $acctPw /add /y | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "net user $acct /add exited $LASTEXITCODE" }
    $acctCreated = $true

    $addr = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
      Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' } |
      ForEach-Object { $_.GetIPProperties().UnicastAddresses } |
      Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } |
      ForEach-Object { $_.Address.ToString() } |
      Where-Object { $_ -notlike '127.*' -and $_ -notlike '169.254.*' } |
      Select-Object -First 1
    $smbReady = $true
    Write-Host "setup: share \\<address>\$shareName -> $shareDir; account $acct; address $addr"
  } catch {
    $smbWhy = "$_"
    $errors.Add("SMB setup: $_")
    Write-Host "setup: SMB setup FAILED: $_"
  }

  # Without these the rows cannot run; each still gets its line.
  $noRemote = if (-not $smbReady) { "not attempted: SMB setup failed: $smbWhy" }
              elseif (-not $addr) { 'not attempted: no non-loopback local IPv4 address found' }
              else { $null }
  $noLocal  = if (-not $smbReady) { "not attempted: SMB setup failed: $smbWhy" } else { $null }
  $unc      = "\\$addr\$shareName"
  $uncLoop  = "\\127.0.0.1\$shareName"

  # Controls. If the administrator cannot read the share through the
  # address, or the sandbox account can read the directory by its
  # local path, the rows below mean something different.
  Row 'smb-control-admin-unc-read' {
    if ($noRemote) { return $noRemote }
    try {
      $t = "$(Get-Content -Raw -LiteralPath "$unc\canary.txt" -ErrorAction Stop)"
      if ($t -match [regex]::Escape($CanaryToken)) { 'allowed' } else { "unexpected content: $(OneLine $t 80)" }
    } catch { "denied; text: $_" }
  }
  Row 'smb-control-sandbox-local-path-read' {
    if ($noLocal) { return $noLocal }
    $r = SbExec @('--', $cmd, '/c', "type `"$shareDir\canary.txt`"")
    "$(ReadVerdict $r); $(Detail $r)"
  }

  # ── (a) read through the address, default identity ──────────────
  $script:aVerdict = $null
  Row 'smb-a-default-identity-read' {
    if ($noRemote) { return $noRemote }
    $r = SbExec @('--', $cmd, '/c', "type `"$unc\canary.txt`"")
    $script:aVerdict = ReadVerdict $r
    "$($script:aVerdict); $(Detail $r)"
  }

  # ── (b) write through the address, default identity ─────────────
  Row 'smb-b-default-identity-write' {
    if ($noRemote) { return $noRemote }
    $n = NewNonce
    $r = SbExec @('--', $cmd, '/c', "echo $n> `"$unc\b-write.txt`"")
    "$(WriteVerdict 'b-write.txt' $n); $(Detail $r)"
  }

  # ── (c) net use with the temporary account, then read and write ──
  # One exec: a mapping belongs to the logon session that made it,
  # and every exec is a new logon session. The mapping is deleted by
  # the same command.
  Row 'smb-c-net-use-explicit-credentials' {
    if ($noRemote) { return $noRemote }
    $n = NewNonce
    @"
@echo off
net use "$unc" "$acctPw" /user:$($env:COMPUTERNAME)\$acct /persistent:no < nul
echo NETUSE_EXIT=%errorlevel%
type "$unc\canary.txt"
echo READ_EXIT=%errorlevel%
echo $n> "$unc\c-write.txt"
echo WRITE_EXIT=%errorlevel%
net use "$unc" /delete /y < nul
echo NETUSE_DELETE_EXIT=%errorlevel%
"@ | Set-Content -Encoding ASCII (Join-Path $ws 'probe-c.cmd')
    $r = SbExec @('--', $cmd, '/c', "`"$ws\probe-c.cmd`"")
    $nu = if ("$($r.out)" -match 'NETUSE_EXIT=(-?\d+)') { $Matches[1] } else { 'not reached' }
    "net use exit=$nu; read: $(ReadVerdict $r); write: $(WriteVerdict 'c-write.txt' $n); $(Detail $r)"
  }

  # ── (d) a process started with network-only credentials ─────────
  # The child calls CreateProcessWithLogonW with
  # LOGON_NETCREDENTIALS_ONLY (2): the new process keeps the caller's
  # local identity and presents the temporary account to servers. It
  # is started by the Secondary Logon service, so its output is
  # collected through a file in the workspace.
  Row 'smb-d-network-only-credentials' {
    if ($noRemote) { return $noRemote }
    $n = NewNonce
    @"
@echo off
type "$unc\canary.txt"
echo READ_EXIT=%errorlevel%
echo $n> "$unc\d-write.txt"
echo WRITE_EXIT=%errorlevel%
"@ | Set-Content -Encoding ASCII (Join-Path $ws 'probe-d-inner.cmd')
    $probeD = @'
$ErrorActionPreference = 'Stop'
try {
  Add-Type -Namespace Resid -Name Native -MemberDefinition @"
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFO {
  public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
  public int dwX; public int dwY; public int dwXSize; public int dwYSize;
  public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags;
  public short wShowWindow; public short cbReserved2;
  public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
}
[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION {
  public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId;
}
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool CreateProcessWithLogonW(
  string user, string domain, string password, int logonFlags,
  string application, System.Text.StringBuilder commandLine, int creationFlags,
  IntPtr environment, string currentDirectory,
  ref STARTUPINFO si, out PROCESS_INFORMATION pi);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern uint WaitForSingleObject(IntPtr h, uint ms);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GetExitCodeProcess(IntPtr h, out uint code);
[DllImport("kernel32.dll")]
public static extern bool CloseHandle(IntPtr h);
"@
  $si = New-Object 'Resid.Native+STARTUPINFO'
  $si.cb = [Runtime.InteropServices.Marshal]::SizeOf($si)
  $pinfo = New-Object 'Resid.Native+PROCESS_INFORMATION'
  $cl = New-Object System.Text.StringBuilder ('"@@CMD@@" /c ""@@WS@@\probe-d-inner.cmd" > "@@WS@@\d-out.txt" 2>&1"')
  # 2 = LOGON_NETCREDENTIALS_ONLY, 0x08000000 = CREATE_NO_WINDOW
  $ok = [Resid.Native]::CreateProcessWithLogonW('@@USER@@', '@@DOMAIN@@', '@@PW@@', 2,
          '@@CMD@@', $cl, 0x08000000, [IntPtr]::Zero, '@@WS@@', [ref] $si, [ref] $pinfo)
  $le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if (-not $ok) {
    $msg = (New-Object System.ComponentModel.Win32Exception $le).Message
    "CPWLW_RESULT=failed error=$le ($msg)"
  } else {
    $w = [Resid.Native]::WaitForSingleObject($pinfo.hProcess, 60000)
    $code = [uint32] 0
    [void] [Resid.Native]::GetExitCodeProcess($pinfo.hProcess, [ref] $code)
    [void] [Resid.Native]::CloseHandle($pinfo.hThread)
    [void] [Resid.Native]::CloseHandle($pinfo.hProcess)
    "CPWLW_RESULT=started wait=$w exit=$code"
    if (Test-Path -LiteralPath '@@WS@@\d-out.txt') {
      Get-Content -LiteralPath '@@WS@@\d-out.txt'
    } else {
      'INNER_OUTPUT=missing'
    }
  }
} catch {
  "PROBE_ERROR=$($_.Exception.Message)"
}
'@
    $probeD = $probeD.Replace('@@CMD@@', $cmd).Replace('@@WS@@', $ws).
      Replace('@@USER@@', $acct).Replace('@@DOMAIN@@', $env:COMPUTERNAME).Replace('@@PW@@', $acctPw)
    $probeD | Set-Content -Encoding ASCII (Join-Path $ws 'probe-d.ps1')
    $r = SbExec @('--', $wps, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                  '-File', (Join-Path $ws 'probe-d.ps1')) -TimeoutSec 180
    $start = if ("$($r.out)" -match '(CPWLW_RESULT=[^\r\n]*|PROBE_ERROR=[^\r\n]*)') { $Matches[1] } else { 'no result line' }
    "start: $start; read: $(ReadVerdict $r); write: $(WriteVerdict 'd-write.txt' $n); $(Detail $r)"
  }

  # ── (e) control: the same read through the loopback address ─────
  Row 'smb-e-loopback-read-control' {
    if ($noLocal) { return $noLocal }
    $r = SbExec @('--', $cmd, '/c', "type `"$uncLoop\canary.txt`"")
    "$(ReadVerdict $r); $(Detail $r)"
  }

  # ── EXPERIMENT: a deny entry for the sandbox account on ──────────
  #    \Device\Mup. Not a mechanism the product uses. It changes a
  #    machine-wide object, so the original descriptor is put back in
  #    this row's own finally, and again in the outer finally if that
  #    did not happen.
  Row 'smb-EXPERIMENT-mup-deny-ace' {
    $api = 'CreateFileW(\\.\GLOBALROOT\Device\Mup) + GetKernelObjectSecurity/SetKernelObjectSecurity(DACL)'
    $h = $null
    try { $h = OpenMup 0x00060000 } catch {
      # Not openable for READ_CONTROL|WRITE_DAC. Record whether it can
      # at least be read.
      $openErr = "$_"
      try {
        $hr = OpenMup 0x00020000
        try { $sddl = SddlOf (ReadMupDacl $hr) } finally { $hr.Dispose() }
        return "EXPERIMENT via ${api}: readable (DACL $sddl); not settable: open for WRITE_DAC failed: $openErr"
      } catch {
        return "EXPERIMENT via ${api}: not readable: open for READ_CONTROL failed: $_ (open for READ_CONTROL|WRITE_DAC failed: $openErr)"
      }
    }
    $out = "EXPERIMENT via ${api}: "
    try {
      try { $orig = ReadMupDacl $h } catch { return $out + "opened; reading the DACL failed: $_" }
      $out += "readable (DACL $(SddlOf $orig)); "
      $sd = [System.Security.AccessControl.RawSecurityDescriptor]::new($orig, 0)
      if ($null -eq $sd.DiscretionaryAcl) {
        return $out + 'not attempted: the device has no DACL to add an entry to'
      }
      # FILE_ALL_ACCESS, denied, first in the list.
      $ace = [System.Security.AccessControl.CommonAce]::new(
        [System.Security.AccessControl.AceFlags]::None,
        [System.Security.AccessControl.AceQualifier]::AccessDenied,
        0x001F01FF, [System.Security.Principal.SecurityIdentifier] $sbSid, $false, $null)
      $sd.DiscretionaryAcl.InsertAce(0, $ace)
      $new = [byte[]]::new($sd.BinaryLength)
      $sd.GetBinaryForm($new, 0)

      $script:mupOriginal = $orig
      try { WriteMupDacl $h $new } catch {
        $script:mupOriginal = $null
        return $out + "not settable: SetKernelObjectSecurity failed: $_"
      }
      $after = SddlOf (ReadMupDacl $h)
      $present = $after -match [regex]::Escape($sbSid)
      $out += "set returned success; deny entry present on re-read: $present; "
      if ($noRemote) {
        $out += "re-run of (a) $noRemote; "
      } else {
        $r = SbExec @('--', $cmd, '/c', "type `"$unc\canary.txt`"")
        $v = ReadVerdict $r
        $out += "(a) before: $($script:aVerdict); (a) with the deny entry: $v ($(Detail $r)); changed: $($v -ne $script:aVerdict); "
      }
    } finally {
      $h.Dispose()
      if ($script:mupOriginal) {
        try { $out += "restore: $(RestoreMup)" } catch {
          $errors.Add("restore of the \Device\Mup descriptor: $_")
          $out += "restore: FAILED: $_"
        }
      }
    }
    $out
  }

  # ── WSL ──────────────────────────────────────────────────────────
  # Read-only. Nothing is imported, and no registry value or COM
  # permission is changed. WSL_UTF8 asks wsl.exe for UTF-8 output.
  Row 'wsl-exe-as-sandbox' {
    $r = SbExec @('--', $cmd, '/c',
      "where wsl.exe & if exist `"$wsl`" (echo SYSTEM32_WSL=present) else (echo SYSTEM32_WSL=absent)")
    Detail $r
  }
  Row 'wsl-status-as-sandbox' {
    $r = SbExec @('--', $cmd, '/c', 'wsl.exe --status < nul') -TimeoutSec 90 -ExtraEnv @('WSL_UTF8=1')
    if ($r.timedOut) { return "timeout after $($r.timeout)s; first lines: $(FirstLines $r.out)" }
    "exit=$($r.exit); first lines: $(FirstLines $r.out)"
  }
  Row 'wsl-list-verbose-as-sandbox' {
    $r = SbExec @('--', $cmd, '/c', 'wsl.exe --list --verbose < nul') -TimeoutSec 90 -ExtraEnv @('WSL_UTF8=1')
    if ($r.timedOut) { return "timeout after $($r.timeout)s; first lines: $(FirstLines $r.out)" }
    "exit=$($r.exit); first lines: $(FirstLines $r.out)"
  }
  Row 'wsl-service-as-sandbox' {
    $parts = foreach ($svc in @('WslService', 'LxssManager')) {
      $r = SbExec @('--', $sc, 'query', $svc)
      $state = if ("$($r.out)" -match 'STATE\s*:\s*\d+\s+(\w+)') { $Matches[1] }
               elseif ($r.timedOut) { "timeout after $($r.timeout)s" }
               else { OneLine $r.out 120 }
      $admin = Get-Service -Name $svc -ErrorAction SilentlyContinue
      $adminView = if ($admin) { "$($admin.Status)/$($admin.StartType)" } else { 'absent' }
      "${svc}: sc query exit=$($r.exit) state=$state (as administrator: $adminView)"
    }
    $parts -join '; '
  }
  # As Administrator: AppID entries that name WSL, and whether each
  # carries its own launch or access permission value. Presence only;
  # the keys are opened read-only and no value's bytes are printed.
  Row 'wsl-com-appid-permissions' {
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
      [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
      $found = [System.Collections.Generic.List[string]]::new()
      $root = $hklm.OpenSubKey('SOFTWARE\Classes\AppID')
      if ($null -eq $root) { return 'HKLM\SOFTWARE\Classes\AppID not found' }
      try {
        foreach ($name in $root.GetSubKeyNames()) {
          $k = $null
          try { $k = $root.OpenSubKey($name) } catch { continue }
          if ($null -eq $k) { continue }
          try {
            $label = "$($k.GetValue(''))"
            $svc   = "$($k.GetValue('LocalService'))"
            if ("$name $label $svc" -notmatch '(?i)wsl|lxss') { continue }
            $vals  = $k.GetValueNames()
            $lp = if ($vals -contains 'LaunchPermission') { 'present' } else { 'absent' }
            $ap = if ($vals -contains 'AccessPermission') { 'present' } else { 'absent' }
            $found.Add("$name name='$label' LocalService='$svc' LaunchPermission=$lp AccessPermission=$ap")
          } finally { $k.Dispose() }
        }
      } finally { $root.Dispose() }
      # What applies where an AppID has no value of its own.
      $ole = $hklm.OpenSubKey('SOFTWARE\Microsoft\Ole')
      $defaults = if ($null -eq $ole) { 'HKLM\SOFTWARE\Microsoft\Ole not found' } else {
        try {
          $ov = $ole.GetValueNames()
          (@('DefaultLaunchPermission', 'DefaultAccessPermission',
             'MachineLaunchRestriction', 'MachineAccessRestriction') | ForEach-Object {
            "$_=$(if ($ov -contains $_) { 'present' } else { 'absent' })"
          }) -join ' '
        } finally { $ole.Dispose() }
      }
      $list = if ($found.Count -eq 0) { 'no AppID entry names WSL' } else { $found -join ' ;; ' }
      "$($found.Count) AppID entr$(if ($found.Count -eq 1) { 'y' } else { 'ies' }): $list ;; machine defaults: $defaults"
    } finally { $hklm.Dispose() }
  }
}
catch {
  $errors.Add("$_")
  Write-Host "smoke-residual-egress: ERROR: $_"
}
finally {
  # Everything below runs whatever happened above, and each step runs
  # whether or not the one before it worked.
  Cleanup 'restore the \Device\Mup descriptor' {
    if ($script:mupOriginal) { Write-Host "cleanup: \Device\Mup: $(RestoreMup)" }
  }
  # A mapping made by a child went with the child's logon session;
  # this removes one in the script's own session, should there be one.
  Cleanup 'remove net use mappings' {
    foreach ($a in @($addr, '127.0.0.1')) {
      if ($a) { & net.exe use "\\$a\$shareName" /delete /y 2>&1 | Out-Null }
    }
  }
  Cleanup 'remove the share' {
    if ($shareCreated) { Remove-SmbShare -Name $shareName -Force -Confirm:$false }
  }
  Cleanup 'remove the temporary account' {
    if ($acctCreated) {
      & net.exe user $acct /delete | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "net user $acct /delete exited $LASTEXITCODE" }
    }
  }
  Cleanup 'release the workspace grant' {
    if ($sbSid) {
      & $Exe acl revoke  --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
      & $Exe acl restore --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
    }
  }
  Cleanup 'remove the temporary directories' {
    foreach ($d in @($ws, $shareDir)) {
      if ($d -and (Test-Path -LiteralPath $d)) { Remove-Item -Recurse -Force -LiteralPath $d }
    }
  }
  Cleanup 'uninstall' {
    & $Exe uninstall --sublayer-guid $Sublayer 2>&1 | Out-Null
    if ($installed -and $LASTEXITCODE -ne 0) { throw "uninstall exited $LASTEXITCODE" }
  }
}

# ── summary ────────────────────────────────────────────────────────
Write-Host ''
Write-Host 'smoke-residual-egress: summary (observations, not assertions)'
$width = 0
foreach ($row in $rows) { if ($row.Row.Length -gt $width) { $width = $row.Row.Length } }
foreach ($row in $rows) {
  Write-Host ("  {0}  {1}" -f $row.Row.PadRight($width), $row.Observed)
}
Write-Host ''

if ($errors.Count -gt 0) {
  Write-Host "smoke-residual-egress: FAILED - the script itself hit $($errors.Count) error(s):"
  foreach ($e in $errors) { Write-Host "  - $e" }
  exit 1
}
Write-Host "smoke-residual-egress: DONE ($($rows.Count) rows recorded)"
