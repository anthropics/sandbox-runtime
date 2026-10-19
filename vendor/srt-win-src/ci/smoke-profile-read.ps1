<#
  Smoke test for the profile read grant
  (`srt-win profile grant | forget | status`, `profile.rs`).

  The grant makes the real user's profile readable to the sandbox
  group, except for the excluded credential stores. This script never
  touches the runner's own profile: it builds a made-up profile tree
  under a scratch root and hands it to `profile grant` through
  `--test-profile`, which exists only in the test-hooks build.

  Two binaries. `$Exe` is the default-feature build: it is the broker
  and runner of every sandboxed command, and runs `profile forget`,
  `uninstall` and the status rows that do not need the override.
  `$HooksExe` (built with `--features test-hooks`) runs `profile
  grant` and `profile status` on the made-up profile, and nothing
  else. Without `$HooksExe` the whole script is SKIPPED, with a
  message: there is no way to run it without the override.

  Sandboxed commands run under the write-restricted token (the
  library's default), with no write root.

  Rows:

    T   a default build refuses `--test-profile` and records nothing.
    G   the grant completes on a tree of a few thousand files; the
        time it took is printed. `profile status` reports it current
        for the made-up profile and outdated for the real one; `user
        status` reports a grant.
    R1  a sandboxed command reads a file under a granted child.
    R2  it runs an .exe from a per-user tool directory on PATH.
    R3  it reads `.npmrc` in the profile root.
    R4  it lists a container, and cannot read a file in the root that
        is not granted by name.
    X   it cannot read a key directory, a credential file in the
        root, or a store under AppData\Roaming.
    TMP the temporary directory is left ungranted, not denied: a file
        directly in AppData\Local\Temp is unreadable and the directory
        carries no entry for the sandbox group; a subdirectory a
        session grants itself is readable for that session, and only
        that. The record lists the directory as ungranted-only, which
        is what the library refuses a session grant of the directory
        itself on (that refusal is the library's, before it calls
        srt-win; its unit tests have the row).
    X2  an exclusion deleted and created again is still unreadable,
        and so is a credential file replaced by write-then-rename
        (in the root and in a container).
    N   a new top-level child is unreadable until `profile grant` is
        run again, and readable after.
    E   a path added with `--exclude` becomes unreadable; a refresh
        that does not name it keeps it excluded, and the record lists
        it beside the built-in exclusions; only `--replace-excludes`
        re-admits it, and no built-in exclusion goes with it.
    A   `acl grant` (a session's grants) refuses, and grants nothing,
        when a write root is a protected exclusion, lies inside one,
        or lies above one (the profile directory), and when it is the
        temporary directory; the target's SDDL is unchanged each time.
        A read grant on a protected path is refused the same way, and
        granted only with `--allow-profile-exclusion`; that flag
        admits no write root. A write root inside the temporary
        directory is granted as usual.
    W   it cannot write, create, delete, rename or mkdir under a
        granted child, a container, or the profile root.
    J   a junction inside a granted directory pointing at an excluded
        store, and one pointing outside the profile, cannot be read
        through; the targets' DACLs are unchanged after the grant and
        after a refresh. A top-level junction is skipped and
        reported. (A file symbolic link too, where one can be made.)
    D   a session read deny on the profile directory — stamped on
        every path the grant made readable, as the library does —
        and one on a granted child, deny for that session and are
        gone after it; a deny beneath a granted child needs no more
        than its own path. OBSERVATION: what a deny stamped on the
        profile directory alone leaves readable.
    O   an exec under the ordinary token is refused (exit 20) while
        the grant exists.
    F   `profile forget` (what a session under the ordinary token
        runs first): nothing is readable any more, every touched DACL is
        what it was before the grant, the empty directories the grant
        created are gone, nothing is recorded, and the ordinary token
        runs again.
    U   `uninstall` does the same to a grant that is still there.

  A failing row is recorded and the script keeps going; it throws at
  the end if any row failed.

  Self-contained: installs under a fixed test-only sublayer GUID
  (referenced by cleanup.ps1) and uninstalls in `finally`.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe,
  [Parameter(Position = 1)]
  [string] $HooksExe
)

$ErrorActionPreference = 'Stop'

# Fixed test-only sublayer; referenced by cleanup.ps1.
$Sublayer  = 'e1a47c93-5d28-4b6f-a3c1-7f0e9d2b4a58'
$PortRange = '60080-60089'

if (-not $HooksExe) {
  Write-Host 'smoke-profile-read: SKIPPED — needs the test-hooks build of srt-win (cargo build --features test-hooks) as the second argument: the made-up profile is passed through --test-profile, which only that build has'
  exit 0
}
if (-not (Test-Path $HooksExe)) { throw "test-hooks binary not found: $HooksExe" }
$ExeAbs   = (Resolve-Path $Exe).Path
$HooksAbs = (Resolve-Path $HooksExe).Path
$cmd      = Join-Path $env:SystemRoot 'System32\cmd.exe'
$env:SANDBOX_RUNTIME_WIN_DEBUG = '1'
Write-Host "smoke-profile-read: sublayer=$Sublayer  exe=$ExeAbs  test-hooks exe=$HooksAbs"

$script:Failures = [System.Collections.Generic.List[string]]::new()
function Fail { param([string] $m) Write-Host "FAIL $m"; $script:Failures.Add($m) }
function Ok   { param([string] $m) Write-Host "ok   $m" }

function Run { param([string[]] $argv)
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) { throw "srt-win $($argv -join ' ') exited $LASTEXITCODE" }
}
function J { param([string[]] $argv) Run $argv | ConvertFrom-Json }
function JsonPath { param([string] $p) $p -replace '\\', '\\' }

# Run one of the two binaries; returns exit code, all output, and the
# last output line that parses as a JSON object (or $null).
function Invoke-Srt { param([string] $bin, [string[]] $argv)
  $lines = @(& $bin @argv 2>&1 | ForEach-Object { "$_" })
  $code = $LASTEXITCODE
  $raw = $lines -join "`n"
  Write-Host $raw
  $json = $null
  $line = $lines | Where-Object { $_.TrimStart().StartsWith('{') } | Select-Object -Last 1
  if ($line) { try { $json = $line | ConvertFrom-Json } catch { } }
  return [pscustomobject]@{ exit = $code; raw = $raw; json = $json }
}

# Sandboxed exec under the write-restricted token (or the ordinary one
# with -Ordinary), with `$extraPath` appended to the child's PATH.
function Sb { param([string[]] $tail, [string] $extraPath = '', [switch] $Ordinary, [int] $TimeoutSec = 180, [string[]] $WriteRoots = @(), [switch] $ExecFlagsFirst)
  $path = $env:PATH
  if ($extraPath) { $path = "$path;$extraPath" }
  $argv = @('exec', '--env', "PATH=$path", '--env', "PATHEXT=$($env:PATHEXT)")
  if (-not $Ordinary) { $argv += '--write-restricted-token' }
  foreach ($w in $WriteRoots) { $argv += @('--write-root', $w) }
  if ($ExecFlagsFirst) { $argv += $tail } else { $argv += @('--') + $tail }
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName               = $ExeAbs
  $psi.UseShellExecute        = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.Environment['SANDBOX_RUNTIME_WIN_DEBUG'] = '1'
  foreach ($a in $argv) { $null = $psi.ArgumentList.Add($a) }
  $p = [System.Diagnostics.Process]::Start($psi)
  $so = $p.StandardOutput.ReadToEndAsync()
  $se = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    try { $p.Kill($true) } catch { }
    $p.WaitForExit()
    $raw = "TIMEOUT`n" + $so.Result + $se.Result
    return [pscustomobject]@{ exit = -1; raw = $raw; out = $raw }
  }
  $raw   = $so.Result + $se.Result
  $child = (($raw -split "`r?`n") | Where-Object { $_ -notmatch '^srt-win:' }) -join "`n"
  return [pscustomobject]@{ exit = $p.ExitCode; raw = $raw; out = $child }
}
# Whether a sandboxed `type` of `$file` printed `$marker`.
function Sb-Reads { param([string] $file, [string] $marker)
  $r = Sb @($cmd, '/d', '/s', '/c', "type `"$file`"")
  return [pscustomobject]@{ read = ($r.out -match [regex]::Escape($marker)); r = $r }
}
function Expect-Read { param([string] $row, [string] $file, [string] $marker)
  $x = Sb-Reads $file $marker
  if ($x.read) { Ok "${row}: readable: $file" }
  else { Fail "${row}: NOT readable: $file (exit=$($x.r.exit)) raw: $($x.r.raw)  Sddl=$(Sddl $file)" }
}
function Expect-NoRead { param([string] $row, [string] $file, [string] $marker)
  $x = Sb-Reads $file $marker
  if (-not $x.read -and $x.r.exit -ne 0) { Ok "${row}: not readable: $file" }
  else { Fail "${row}: READABLE (or the command did not fail): $file (exit=$($x.r.exit)) raw: $($x.r.raw)  Sddl=$(Sddl $file)" }
}

function Sddl { param([string] $p) (Get-Acl -LiteralPath $p).Sddl }
# The DACL of an SDDL string in a form two of them can be compared in:
# whether it is protected, then its ACEs, sorted.
function DaclOf { param([string] $sd)
  $prot = if ($sd -match 'D:[A-Z]*P[A-Z]*\(') { 'protected' } else { 'inheriting' }
  $aces = @([regex]::Matches($sd, '\([^)]*\)') | ForEach-Object Value | Sort-Object)
  return "$prot $($aces -join '')"
}
function Dacl { param([string] $p) DaclOf (Sddl $p) }
# Give directory `$d` a protected DACL holding exactly `$aces`,
# written whole and read back (see smoke-write-restricted.ps1).
function Set-OnlyAces { param([string] $d, [string[]] $aces)
  $want = "D:PAI$($aces -join '')"
  $sec = [System.Security.AccessControl.DirectorySecurity]::new()
  $sec.SetSecurityDescriptorSddlForm(
    $want, [System.Security.AccessControl.AccessControlSections]::Access)
  $sec.SetAccessRuleProtection($true, $false)
  [System.IO.FileSystemAclExtensions]::SetAccessControl(
    [System.IO.DirectoryInfo]::new($d), $sec)
  $got = Dacl $d
  if ($got -ne (DaclOf $want)) {
    Fail "setup: the DACL of $d is not the one set on it; rows that use it prove less. want: $(DaclOf $want)  got: $got"
  }
}
function Seed { param([string] $rel, [string] $content)
  $f = Join-Path $prof $rel
  New-Item -ItemType Directory -Path (Split-Path $f) -Force | Out-Null
  $content | Set-Content -Encoding ASCII -LiteralPath $f
  return $f
}
# Whether a path's DACL names the sandbox group at all / in an ALLOW.
function Has-Group { param([string] $p) (Sddl $p) -match [regex]::Escape($script:grpSid) }
function Has-GroupAllow { param([string] $p)
  @([regex]::Matches((Sddl $p), '\(A;[^)]*\)') | ForEach-Object Value |
    Where-Object { $_ -match [regex]::Escape($script:grpSid) }).Count -gt 0
}
function Grant { param([string[]] $extra = @())
  Invoke-Srt $HooksAbs (@('profile', 'grant', '--test-profile', $prof, '--json') + $extra)
}
function Status { (Invoke-Srt $HooksAbs @('profile', 'status', '--test-profile', $prof, '--paths')).json }
# A session's deny stamps (`acl grant --persistent` with no roots, as
# initialize() sends them), and their release.
function Session-Deny { param([string[]] $denyRead)
  $json = @{ read = @(); write = @(); denyRead = @($denyRead); denyWrite = @() } |
    ConvertTo-Json -Compress
  $raw = $json | & $Exe acl grant --holder-pid $PID --sandbox-user-sid $sbSid --persistent 2>&1 |
    Out-String
  if ($LASTEXITCODE -ne 0) { Write-Host $raw }
  return $LASTEXITCODE
}
function End-Session {
  & $Exe acl revoke  --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
  & $Exe acl restore --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
}
# The explicit ACEs of a path's DACL, in order, and whether they are
# in canonical order: every deny before the first allow.
function Explicit-Aces { param([string] $p)
  $dacl = ((Sddl $p) -replace '^.*?D:', '') -replace 'S:.*$', ''
  @([regex]::Matches($dacl, '\(([^;)]*);([^;)]*);[^)]*\)') | Where-Object { $_.Groups[2].Value -notmatch 'ID' } |
    ForEach-Object Value)
}
function Denies-First { param([string] $p)
  $seenAllow = $false
  foreach ($a in (Explicit-Aces $p)) {
    if ($a.StartsWith('(A')) { $seenAllow = $true }
    elseif ($a.StartsWith('(D') -and $seenAllow) { return $false }
  }
  return $true
}

try { Start-Service seclogon -ea Stop } catch {
  Write-Host "smoke-profile-read: WARNING: Start-Service seclogon: $_"
}

# Scratch tree at the system-drive root, with a protected DACL written
# whole.
$root = Join-Path "$env:SystemDrive\" "srt-pr-smoke-$([guid]::NewGuid().ToString('N'))"
$prof = Join-Path $root 'profile'
$outside = Join-Path $root 'outside'

$sbSid = $null
$script:grpSid = $null
$lSsh = $null; $lCfg = $null; $ownerDenied = $null; $wrDeny = $null
$lockedDir = $null; $disowned = @()
try {
  Run @('install', '--sublayer-guid', $Sublayer, '--proxy-port-range', $PortRange)
  $us = J @('user', 'status')
  $sbSid = $us.marker_user_sid
  if (-not $sbSid) { throw 'setup marker missing user_sid' }
  $script:grpSid = $us.user.group_sid
  if (-not $script:grpSid) { throw 'user status missing group_sid' }
  # Grants left by an earlier, interrupted run.
  & $Exe profile forget 2>&1 | Out-Null
  & $Exe acl forget --all 2>&1 | Out-Null

  New-Item -ItemType Directory -Path $root -Force | Out-Null
  Set-OnlyAces $root @('(A;OICI;FA;;;BA)', '(A;OICI;FA;;;SY)', '(A;;0x1200a9;;;BU)')
  New-Item -ItemType Directory -Path $prof, $outside -Force | Out-Null

  # ── The made-up profile ──────────────────────────────────────────
  $note     = Seed 'Documents\note.txt'                         'NOTE-CONTENT'
  $subFile  = Seed 'Documents\sub\deep.txt'                     'DEEP-CONTENT'
  $null     = Seed 'Documents\del.txt'                          'DEL'
  $null     = Seed 'Documents\ren.txt'                          'REN'
  $npmrc    = Seed '.npmrc'                                     'NPMRC-CONTENT'
  $stray    = Seed 'stray.txt'                                  'STRAY-CONTENT'
  $netrc    = Seed '.netrc'                                     'NETRC-CONTENT'
  $sshKey   = Seed '.ssh\id_test'                               'SSH-CONTENT'
  $cargoCr  = Seed '.cargo\credentials.toml'                    'CARGO-CRED-CONTENT'
  $cargoCfg = Seed '.cargo\config.toml'                         'CARGO-CONFIG-CONTENT'
  $null     = Seed '.rustup\settings.toml'                      'RUSTUP-SETTINGS-CONTENT'
  $credBlob = Seed 'AppData\Roaming\Microsoft\Credentials\blob' 'CRED-CONTENT'
  $npmTool  = Seed 'AppData\Roaming\npm\tool.cmd'               '@echo NPM-TOOL'
  $tempFile = Seed 'AppData\Local\Temp\t.txt'                   'TEMP-CONTENT'
  $sessFile = Seed 'AppData\Local\Temp\session\s.txt'          'SESSION-CONTENT'
  $toolDir  = Join-Path $prof 'AppData\Local\Programs\MyTool'
  New-Item -ItemType Directory -Path $toolDir -Force | Out-Null
  Copy-Item $cmd (Join-Path $toolDir 'srtsmoketool.exe')
  $bulkDirs = 20; $bulkFiles = 150
  foreach ($i in 0..($bulkDirs - 1)) {
    $d = Join-Path $prof ("bulk\d{0:d3}" -f $i)
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    foreach ($k in 0..($bulkFiles - 1)) { [System.IO.File]::WriteAllText((Join-Path $d ("f{0:d3}.txt" -f $k)), 'BULK-CONTENT') }
  }
  $bulkSample = Join-Path $prof 'bulk\d019\f149.txt'
  $secret = Join-Path $outside 'secret.txt'
  'OUTSIDE-CONTENT' | Set-Content -Encoding ASCII -LiteralPath $secret
  $jTop     = Join-Path $prof 'link'
  $jOutside = Join-Path $prof 'Documents\to-outside'
  $jSsh     = Join-Path $prof 'Documents\to-ssh'
  New-Item -ItemType Junction -Path $jTop     -Target $outside               | Out-Null
  New-Item -ItemType Junction -Path $jOutside -Target $outside               | Out-Null
  New-Item -ItemType Junction -Path $jSsh     -Target (Join-Path $prof '.ssh') | Out-Null
  $symFile = Join-Path $prof 'Documents\sym.txt'
  $haveSym = $false
  try {
    New-Item -ItemType SymbolicLink -Path $symFile -Target $secret -ea Stop | Out-Null
    $haveSym = $true
  } catch { Write-Host "J: no file symbolic link on this runner ($_); that part of J is not run" }

  $touched = @(
    $prof, (Join-Path $prof 'Documents'), $note, $npmrc, (Join-Path $prof '.cargo'), $cargoCfg,
    (Join-Path $prof 'AppData'), (Join-Path $prof 'AppData\Roaming'),
    (Join-Path $prof 'AppData\Roaming\Microsoft'), (Join-Path $prof 'AppData\Roaming\Microsoft\Credentials'),
    $credBlob, (Join-Path $prof 'AppData\Roaming\npm'), $npmTool, (Join-Path $prof 'AppData\Local'),
    (Join-Path $prof 'AppData\Local\Temp'), $tempFile, (Join-Path $prof 'AppData\Local\Temp\session'),
    $sessFile, (Join-Path $prof 'AppData\Local\Programs'),
    $toolDir, (Join-Path $prof 'bulk'), $bulkSample, $stray)
  $replaced = @((Join-Path $prof '.ssh'), $sshKey, $netrc, $cargoCr)
  $pre = @{}
  foreach ($p in $touched) { $pre[$p] = Dacl $p }
  $preOutside = @{ $outside = (Dacl $outside); $secret = (Dacl $secret) }
  function Outside-Unchanged { param([string] $when)
    $bad = @($preOutside.Keys | Where-Object { (Dacl $_) -ne $preOutside[$_] })
    if ($bad.Count -eq 0) { Ok "J: the junction targets outside the profile have their DACLs unchanged $when" }
    else { Fail "J: DACL changed through a junction $when`: $($bad | ForEach-Object { "$_ now $(Sddl $_)" })" }
  }
  function Restored { param([string] $row)
    $bad = @($touched | Where-Object { (Dacl $_) -ne $pre[$_] })
    $left = @($replaced | Where-Object { (Test-Path -LiteralPath $_) -and (Has-Group $_) })
    if ($bad.Count -eq 0 -and $left.Count -eq 0) { Ok "${row}: every touched DACL is what it was before the grant" }
    else {
      Fail ("${row}: DACLs differ from before the grant: " +
            (($bad | ForEach-Object { "$_ was [$($pre[$_])] is [$(Dacl $_)]" }) -join '; ') +
            " still naming the group: $($left -join ', ')")
    }
    $ph = @('.aws', '.gnupg', '.kube', 'AppData\Local\Google', 'AppData\Roaming\gcloud') |
      Where-Object { Test-Path -LiteralPath (Join-Path $prof $_) }
    if (@($ph).Count -eq 0) { Ok "${row}: the empty directories the grant created are gone" }
    else { Fail "${row}: created directories left behind: $($ph -join ', ')" }
    $st = (Invoke-Srt $HooksAbs @('profile', 'status', '--test-profile', $prof)).json
    $reg = Get-ItemProperty 'HKCU:\Software\sandbox-runtime\PersistentGrants' -ErrorAction SilentlyContinue
    if ($st.state -eq 'none' -and -not $reg.Profile -and -not $reg.ProfilePaths) { Ok "${row}: nothing is recorded" }
    else { Fail "${row}: still recorded: state=$($st.state) Profile=$($reg.Profile) paths=$(@($reg.ProfilePaths).Count)" }
  }

  Expect-NoRead 'setup' $note 'NOTE-CONTENT'

  # ── T: the override is not in a default build ────────────────────
  $r = Invoke-Srt $ExeAbs @('profile', 'grant', '--test-profile', $prof)
  $st = (Invoke-Srt $ExeAbs @('profile', 'status')).json
  if ($r.exit -ne 0 -and $st.state -eq 'none' -and -not (Has-Group $prof)) {
    Ok 'T: a default build refuses --test-profile and records nothing'
  } else { Fail "T: default build with --test-profile: exit=$($r.exit) state=$($st.state) Sddl=$(Sddl $prof)" }

  # ── B: objects in a real profile that its user may not change ────
  $lockedDir  = Join-Path $prof '.azure'
  $lockedFile = Seed '.azure\tok.txt' 'LOCKED-CONTENT'
  & icacls $lockedDir /deny '*S-1-1-0:(OI)(CI)(RX)' '*S-1-5-11:(OI)(CI)(RX)' '*S-1-5-32-545:(OI)(CI)(RX)' | Out-Null
  $instDir  = Join-Path $prof 'AppData\Roaming\Microsoft\Installer'
  $instFile = Seed 'AppData\Roaming\Microsoft\Installer\x.txt' 'INSTALLER-CONTENT'
  $openDir  = Join-Path $prof '.docker'
  $openFile = Seed '.docker\config.json' 'DOCKER-CONTENT'
  foreach ($d in @($instDir, $openDir)) {
    & icacls $d /setowner '*S-1-5-18' | Out-Null
    if ($LASTEXITCODE -eq 0) { $disowned += $d } else { Fail "B: setup — could not hand $d to SYSTEM" }
  }
  Set-OnlyAces $instDir @('(A;OICI;0x1200a9;;;WD)', '(A;OICI;FA;;;SY)')
  Set-OnlyAces $openDir @('(A;OICI;0x1200a9;;;BU)', '(A;OICI;FA;;;SY)')
  foreach ($d in @($instDir, $openDir)) {
    if ((Get-Acl -LiteralPath $d).Owner -notmatch 'SYSTEM') {
      Fail "B: setup — $d is not owned by SYSTEM; the rows about it prove nothing"
    }
  }

  # ── G: the grant ─────────────────────────────────────────────────
  $files = $bulkDirs * $bulkFiles
  # A write root kept from an earlier session that lies above an
  # exclusion: the grant must take it off, or what is created in the
  # excluded directory later inherits the root's allow.
  $keptAbove = Join-Path $prof '.config'
  New-Item -ItemType Directory -Force -Path (Join-Path $keptAbove 'gh') | Out-Null
  $kj = @{ read = @(); write = @($keptAbove); denyRead = @(); denyWrite = @() } | ConvertTo-Json -Compress
  $kj | & $Exe acl grant --holder-pid $PID --sandbox-user-sid $sbSid --persistent 2>&1 | Out-Null
  $keptCode = $LASTEXITCODE
  End-Session
  if ($keptCode -ne 0 -or (Sddl $keptAbove) -notmatch 'S-1-0-1936880739-') { Fail "G: setup — no kept write root on $keptAbove (exit=$keptCode): $(Sddl $keptAbove)" }
  $untouched = @((Join-Path $prof 'AppData\Local\Temp'), $sessFile)
  $sdBefore = @($untouched | ForEach-Object { Sddl $_ })
  function Dacl-Flags { param([string] $p) [regex]::Match((Sddl $p), 'D:([A-Z]*)\(').Groups[1].Value }
  $profFlags = Dacl-Flags $prof
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $g = Grant
  $sw.Stop()
  Write-Host ("G: TIMING: profile grant on a tree with {0} files in {1} directories under one granted child: {2} ms wall, {3} ms reported; {4} DACL write(s), {5} with a walk of the tree, {6} without" -f `
    $files, $bulkDirs, $sw.ElapsedMilliseconds, $g.json.elapsed_ms, $g.json.writes, $g.json.tree_walks, $g.json.local_writes)
  $sdAfter = @($untouched | ForEach-Object { Sddl $_ })
  if (($sdBefore -join '|') -eq ($sdAfter -join '|')) { Ok 'G: a child and a grandchild of a container keep their security descriptors, auto-inherited mark included' }
  else { Fail "G: below a container: before=$($sdBefore -join ' | ') after=$($sdAfter -join ' | ')" }
  if ($g.json.local_writes -ge $g.json.containers -and $g.json.containers -ge 1 -and (Dacl-Flags $prof) -eq $profFlags) { Ok "G: containers are written on the object alone ($($g.json.local_writes) such write(s) for $($g.json.containers) container(s)); the profile's access list keeps its marks ('$profFlags')" }
  else { Fail "G: local_writes=$($g.json.local_writes) containers=$($g.json.containers) tree_walks=$($g.json.tree_walks) flags before='$profFlags' profile=$(Sddl $prof)" }
  $lateToken = Join-Path $keptAbove 'gh\late-token.txt'
  'LATE-TOKEN' | Set-Content -Encoding ASCII -LiteralPath $lateToken
  $lateSd = Sddl $lateToken
  $forgot = @($g.json.forgotten_roots | ForEach-Object { $_.path })
  if (@($forgot | Where-Object { $_ -like '*\.config' }).Count -eq 1 -and (Sddl $keptAbove) -notmatch 'S-1-0-1936880739-' -and
      $lateSd -notmatch 'S-1-0-1936880739-' -and $lateSd -notmatch ('\(A;[^)]*;;;' + [regex]::Escape($script:grpSid) + '\)')) {
    Ok 'G: a kept write root above an exclusion is forgotten by the grant; a file created later in the excluded directory inherits no allow'
  } else { Fail "G: kept root above an exclusion: forgotten_roots=[$($forgot -join ', ')] root=$(Sddl $keptAbove) late=$lateSd" }
  if ($g.exit -eq 0 -and $g.json.complete) { Ok "G: grant complete ($($g.json.containers) containers, $($g.json.granted) granted, $($g.json.files) files, $($g.json.denied) excluded, $($g.json.placeholders) created)" }
  else { Fail "G: profile grant exit=$($g.exit) complete=$($g.json.complete) raw: $($g.raw)" }
  if ($g.raw -match 'top-level item\(s\) done') { Ok 'G: progress lines on stderr' }
  else { Fail 'G: no progress line in the output' }
  if ($g.json.complete -and @($g.json.stale_allow).Count -eq 0) { Ok 'G: the grant is complete and left no entry behind' }
  else { Fail "G: complete=$($g.json.complete) stale_allow=$($g.json.stale_allow | ConvertTo-Json -Compress)" }
  $st = Status
  if ($st.state -eq 'current' -and $st.env.NPM_CONFIG_USERCONFIG -and @($st.paths).Count -gt 0) {
    Ok "G: status is current for the made-up profile, with NPM_CONFIG_USERCONFIG=$($st.env.NPM_CONFIG_USERCONFIG)"
  } else { Fail "G: status: $($st | ConvertTo-Json -Compress -Depth 4)" }
  # A file granted by name and then saved by write-and-rename is another
  # object with no entry: its pointer is withheld until the next grant.
  $staged = "$npmrc.lock"
  'NPMRC-CONTENT' | Set-Content -Encoding ASCII -LiteralPath $staged
  Move-Item -LiteralPath $staged -Destination $npmrc -Force
  $st = Status
  if ($st.state -eq 'current' -and -not $st.env.NPM_CONFIG_USERCONFIG -and @($st.replaced_files).Count -eq 1) { Ok 'G: a replaced configuration file loses its pointer and is named in the status' }
  else { Fail "G: after replacing .npmrc: $($st | ConvertTo-Json -Compress -Depth 4)" }
  $gr = Grant
  $st = Status
  if ($gr.exit -eq 0 -and $st.env.NPM_CONFIG_USERCONFIG -and @($st.replaced_files).Count -eq 0) { Ok 'G: the next grant gives the replaced file its entry back' }
  else { Fail "G: re-grant after replacing .npmrc: exit=$($gr.exit) status=$($st | ConvertTo-Json -Compress -Depth 4)" }
  $savedHomes = @{ RUSTUP_HOME = $env:RUSTUP_HOME; CARGO_HOME = $env:CARGO_HOME }
  try {
    $env:RUSTUP_HOME = $null; $env:CARGO_HOME = $null
    $st = Status
    if ($st.env.CARGO_HOME -eq (Join-Path $prof '.cargo') -and $st.env.RUSTUP_HOME -eq (Join-Path $prof '.rustup')) {
      Ok "G: status names RUSTUP_HOME and CARGO_HOME in the profile"
    } else { Fail "G: Rust homes: env=$($st.env | ConvertTo-Json -Compress)" }
    $env:RUSTUP_HOME = $outside; $env:CARGO_HOME = $outside
    $st = Status
    if (-not $st.env.CARGO_HOME -and -not $st.env.RUSTUP_HOME) { Ok 'G: Rust homes outside the profile are not named' }
    else { Fail "G: Rust homes outside the profile: env=$($st.env | ConvertTo-Json -Compress)" }
  } finally {
    $env:RUSTUP_HOME = $savedHomes.RUSTUP_HOME; $env:CARGO_HOME = $savedHomes.CARGO_HOME
  }
  $real = (Invoke-Srt $ExeAbs @('profile', 'status')).json
  if ($real.state -eq 'outdated') { Ok 'G: for the real profile the same record is outdated (made for another directory)' }
  else { Fail "G: status for the real profile is '$($real.state)', want outdated" }
  $brief = (J @('user', 'status')).profile_grant
  if ($brief.state -eq 'present') { Ok 'G: user status reports a profile grant' }
  else { Fail "G: user status profile_grant = $($brief | ConvertTo-Json -Compress)" }
  Outside-Unchanged 'after the grant'

  $paths = { param($items) @($items | ForEach-Object { ($_.path -replace '^\\\\\?\\', '') }) }
  $notGranted  = & $paths $g.json.not_granted
  $unprotected = & $paths $g.json.unprotected
  $closedOrDenied = (& $paths $g.json.self_closed) -contains $lockedDir -or
    -not ((& $paths $g.json.unverifiable) + $unprotected + $notGranted -contains $lockedDir)
  if ($closedOrDenied -and ((& $paths $g.json.unverifiable) -notcontains $lockedDir) -and ($unprotected -notcontains $lockedDir)) {
    Ok 'B: an excluded directory its owner is denied reading of is denied, or recorded as closed by its own access list'
  } else { Fail "B: the locked excluded directory: $($g.json | ConvertTo-Json -Compress -Depth 4)" }
  Expect-NoRead 'B (the locked excluded directory)' $lockedFile 'LOCKED-CONTENT'
  if ($notGranted -contains $instDir -and -not (Has-Group $instDir)) {
    Ok 'B: a directory the caller may not change is reported as not granted, and carries nothing of ours'
  } else { Fail "B: Installer-like directory: not_granted=[$($notGranted -join ', ')] Sddl=$(Sddl $instDir)" }
  if ($unprotected -contains $openDir) { Ok 'B: an excluded directory that cannot be denied and that Users may read is reported as unprotected' }
  else { Fail "B: unprotected=[$($unprotected -join ', ')] want $openDir" }
  if (@($st.unprotected | Where-Object { ($_.path -replace '^\\\\\?\\', '') -eq $openDir }).Count -eq 1 -and
      @($st.not_granted).Count -ge 1) { Ok 'B: profile status lists them with the reason' }
  else { Fail "B: status: unprotected=$($st.unprotected | ConvertTo-Json -Compress) not_granted=$($st.not_granted | ConvertTo-Json -Compress)" }
  $g2 = Grant
  if ($g2.exit -eq 0 -and $g2.json.complete -and $g2.json.writes -eq 0) { Ok 'B: a refresh of that grant writes nothing and is complete' }
  else { Fail "B: refresh: exit=$($g2.exit) writes=$($g2.json.writes) raw: $($g2.raw)" }

  # ── R: what is readable ──────────────────────────────────────────
  Expect-Read 'R1' $note 'NOTE-CONTENT'
  Expect-Read 'R1' $subFile 'DEEP-CONTENT'
  Expect-Read 'R1' $bulkSample 'BULK-CONTENT'
  $r = Sb @($cmd, '/d', '/s', '/c', 'srtsmoketool.exe /d /c echo TOOL-RAN') $toolDir
  if ($r.exit -eq 0 -and $r.out -match 'TOOL-RAN') { Ok 'R2: an .exe in a per-user tool directory on PATH runs' }
  else { Fail "R2: srtsmoketool.exe from $toolDir on PATH: exit=$($r.exit) raw: $($r.raw)" }
  Expect-Read 'R3' $npmrc 'NPMRC-CONTENT'
  Expect-Read 'R3 (a file of a container)' $cargoCfg 'CARGO-CONFIG-CONTENT'
  $r = Sb @($cmd, '/d', '/s', '/c', "dir /b /a `"$prof`"")
  if ($r.exit -eq 0 -and $r.out -match 'Documents' -and $r.out -match 'stray\.txt') { Ok 'R4: the profile directory (a container) can be listed' }
  else { Fail "R4: dir of the profile directory: exit=$($r.exit) raw: $($r.raw)" }
  Expect-NoRead 'R4 (a root file not granted by name)' $stray 'STRAY-CONTENT'

  # A container's entry covers a generic-read open of the directory,
  # which asks for READ_CONTROL as well: reading its access list does.
  $r = Sb @($cmd, '/d', '/s', '/c', "icacls `"$(Join-Path $prof '.cargo')`"")
  if ($r.exit -eq 0 -and $r.out -match ':\(') { Ok 'R4: a container can be opened for a generic read (its access list is readable)' }
  else { Fail "R4: reading a container's access list: exit=$($r.exit) raw: $($r.raw)" }

  # ── X: exclusions ────────────────────────────────────────────────
  Expect-NoRead 'X (key directory)' $sshKey 'SSH-CONTENT'
  Expect-NoRead 'X (credential file in the root)' $netrc 'NETRC-CONTENT'
  Expect-NoRead 'X (credential file in a container)' $cargoCr 'CARGO-CRED-CONTENT'
  Expect-NoRead 'X (store under AppData\Roaming)' $credBlob 'CRED-CONTENT'

  # ── TMP: the temporary directory ─────────────────────────────────
  $tempDir = Join-Path $prof 'AppData\Local\Temp'
  $sessDir = Join-Path $tempDir 'session'
  Expect-NoRead 'TMP (a file directly in AppData\Local\Temp)' $tempFile 'TEMP-CONTENT'
  Expect-NoRead 'TMP (a subdirectory no session granted)' $sessFile 'SESSION-CONTENT'
  $named = @($tempDir, $tempFile, $sessDir, $sessFile) | Where-Object { Has-Group $_ }
  if (@($named).Count -eq 0) { Ok 'TMP: neither the directory nor anything in it carries an entry for the sandbox group (ungranted, not denied)' }
  else { Fail "TMP: the sandbox group is named on: $($named | ForEach-Object { "$_ $(Sddl $_)" })" }
  $st = Status
  if (@($st.ungranted_only | Where-Object { $_ -match '\\AppData\\Local\\Temp$' }).Count -eq 1 -and
      @($st.exclusions | Where-Object { $_ -match '\\AppData\\Local\\Temp$' }).Count -eq 0) {
    Ok 'TMP: the record lists the directory as ungranted-only, not as a protected path'
  } else { Fail "TMP: ungranted_only=$($st.ungranted_only -join ' | ')" }
  $json = @{ read = @($sessDir); write = @(); denyRead = @(); denyWrite = @() } | ConvertTo-Json -Compress
  $raw = $json | & $Exe acl grant --holder-pid $PID --sandbox-user-sid $sbSid --persistent 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { Fail "TMP: a session read grant inside the temporary directory failed: $raw" }
  else {
    Expect-Read 'TMP (a subdirectory the session granted)' $sessFile 'SESSION-CONTENT'
    Expect-NoRead 'TMP (the rest of the directory, during that session)' $tempFile 'TEMP-CONTENT'
  }
  End-Session
  Expect-NoRead 'TMP (the subdirectory after the session)' $sessFile 'SESSION-CONTENT'
  $r = Sb @($cmd, '/d', '/s', '/c', "dir /b /a `"$(Join-Path $prof '.ssh')`"")
  if ($r.exit -ne 0 -and $r.out -notmatch 'id_test') { Ok 'X: an excluded directory cannot be listed' }
  else { Fail "X: dir of .ssh: exit=$($r.exit) raw: $($r.raw)" }
  $aws = Join-Path $prof '.aws'
  if ((Test-Path -LiteralPath $aws) -and (Has-Group $aws) -and -not (Has-GroupAllow $aws)) { Ok 'X: a missing excluded directory was created and carries the deny' }
  else { Fail "X: .aws: exists=$(Test-Path -LiteralPath $aws)" }

  # ── X2: an exclusion that is replaced ────────────────────────────
  Remove-Item -Recurse -Force -LiteralPath (Join-Path $prof '.ssh')
  $sshKey = Seed '.ssh\id_test' 'SSH2-CONTENT'
  foreach ($f in @($netrc, $cargoCr)) {
    $tmp = "$f.tmp"
    'REPLACED-CONTENT' | Set-Content -Encoding ASCII -LiteralPath $tmp
    Move-Item -Force -LiteralPath $tmp -Destination $f
  }
  Expect-NoRead 'X2 (key directory deleted and created again)' $sshKey 'SSH2-CONTENT'
  Expect-NoRead 'X2 (root credential file replaced by rename)' $netrc 'REPLACED-CONTENT'
  Expect-NoRead 'X2 (container credential file replaced by rename)' $cargoCr 'REPLACED-CONTENT'
  $allowed = @((Join-Path $prof '.ssh'), $sshKey, $netrc, $cargoCr) | Where-Object { Has-GroupAllow $_ }
  if (@($allowed).Count -eq 0) { Ok 'X2: none of the replaced objects carries an allow for the sandbox group, inherited or its own' }
  else { Fail "X2: an allow for the group on: $($allowed | ForEach-Object { "$_ $(Sddl $_)" })" }

  # ── N: a new top-level child, and the refresh ────────────────────
  $newFile = Seed 'NewTop\n.txt' 'NEWTOP-CONTENT'
  Expect-NoRead 'N (before the refresh)' $newFile 'NEWTOP-CONTENT'
  $g2 = Grant
  if ($g2.exit -eq 0 -and $g2.json.complete) { Ok "N: refresh complete ($($g2.json.writes) DACL write(s), $($g2.json.unchanged) unchanged, $($g2.json.elapsed_ms) ms)" }
  else { Fail "N: refresh exit=$($g2.exit) raw: $($g2.raw)" }
  Expect-Read 'N (after the refresh)' $newFile 'NEWTOP-CONTENT'
  Expect-NoRead 'N (the replaced exclusions after the refresh)' $sshKey 'SSH2-CONTENT'
  Expect-NoRead 'N (the replaced exclusions after the refresh)' $netrc 'REPLACED-CONTENT'
  $g3 = Grant
  if ($g3.exit -eq 0 -and $g3.json.writes -eq 0) { Ok "N: a refresh with nothing new writes no DACL ($($g3.json.elapsed_ms) ms)" }
  else { Fail "N: an idle refresh wrote $($g3.json.writes) DACL(s): $($g3.raw)" }
  Outside-Unchanged 'after the refresh'

  # ── E: added exclusions ──────────────────────────────────────────
  $ge = Grant @('--exclude', (Join-Path $prof 'NewTop'))
  if ($ge.exit -ne 0) { Fail "E: grant --exclude exit=$($ge.exit) raw: $($ge.raw)" }
  Expect-NoRead 'E (an added exclusion)' $newFile 'NEWTOP-CONTENT'
  $ge = Grant
  if ($ge.exit -ne 0) { Fail "E: refresh exit=$($ge.exit) raw: $($ge.raw)" }
  Expect-NoRead 'E (kept by a refresh that does not name it)' $newFile 'NEWTOP-CONTENT'
  $st = Status
  $listed = @($st.exclusions)
  if (@($st.extra_exclusions) -contains 'NewTop' -and
      @($listed | Where-Object { $_ -match '\\NewTop$' }).Count -eq 1 -and
      @($listed | Where-Object { $_ -match '\\\.ssh$' }).Count -eq 1 -and
      @($listed | Where-Object { $_ -match '\\AppData\\Local\\Temp$' }).Count -eq 0) {
    Ok "E: the record lists the added exclusion with the built-in ones ($($listed.Count) in all)"
  } else { Fail "E: recorded exclusions: extra=$($st.extra_exclusions -join ',') all=$($listed -join ' | ')" }
  $ge = Grant @('--replace-excludes')
  if ($ge.exit -ne 0) { Fail "E: grant --replace-excludes exit=$($ge.exit) raw: $($ge.raw)" }
  Expect-Read 'E (re-admitted by replacing the added list)' $newFile 'NEWTOP-CONTENT'
  Expect-NoRead 'E (a built-in exclusion is not replaceable)' $sshKey 'SSH2-CONTENT'

  # ── A: a session's grants against the exclusions ─────────────────
  function Session-Grant { param([string[]] $read = @(), [string[]] $write = @(), [string[]] $flags = @())
    $json = @{ read = @($read); write = @($write); denyRead = @(); denyWrite = @() } | ConvertTo-Json -Compress
    $script:lastGrant = $json | & $Exe acl grant --holder-pid $PID --sandbox-user-sid $sbSid --persistent @flags 2>&1 | Out-String
    return $LASTEXITCODE
  }
  function Refused { param([string] $what, [string] $target, [string[]] $read = @(), [string[]] $write = @(), [string[]] $flags = @())
    $before = Sddl $target
    $code = Session-Grant $read $write $flags
    $after = Sddl $target
    End-Session
    if ($code -ne 0 -and $after -eq $before -and $script:lastGrant -match 'nothing was granted') {
      Ok "A: refused, target unchanged: $what"
    } else {
      Fail "A: $what — exit=$code SDDL $(if ($after -eq $before) { 'unchanged' } else { "CHANGED to $after" }) output: $($script:lastGrant)"
    }
  }
  $sshDir = Join-Path $prof '.ssh'
  $sshSub = Join-Path $sshDir 'sub'
  New-Item -ItemType Directory -Path $sshSub -Force | Out-Null
  $workDir = Join-Path $root 'work'
  New-Item -ItemType Directory -Path $workDir -Force | Out-Null
  Refused 'a write root that is a protected exclusion'            $sshDir -write @($sshDir)
  Refused 'a write root inside a protected exclusion'             $sshSub -write @($sshSub)
  Refused 'a write root above a protected exclusion (the profile)' $prof  -write @($prof)
  Refused 'a write root above one (AppData)' (Join-Path $prof 'AppData') -write @((Join-Path $prof 'AppData'))
  Refused 'the temporary directory as a write root'               $tempDir -write @($tempDir)
  Refused 'a read grant on a protected exclusion'                 $sshDir -read @($sshDir)
  Refused 'a read grant above a protected exclusion'              $prof   -read @($prof)
  Refused 'a write root that is a protected exclusion, with the read override' $sshDir -write @($sshDir) -flags @('--allow-profile-exclusion', $sshDir)
  Refused 'a read grant above an exclusion, with the override'    $prof   -read @($prof) -flags @('--allow-profile-exclusion', $prof)
  $before = Sddl $workDir
  $code = Session-Grant -write @($workDir, $sshDir)
  End-Session
  if ($code -ne 0 -and (Sddl $workDir) -eq $before) { Ok 'A: a call with one refused path grants none of its paths' }
  else { Fail "A: mixed call: exit=$code work SDDL=$(Sddl $workDir) output: $($script:lastGrant)" }
  $code = Session-Grant -read @($sshDir) -flags @('--allow-profile-exclusion', $sshDir)
  if ($code -ne 0) { Fail "A: read grant with --allow-profile-exclusion failed: $($script:lastGrant)" }
  else { Expect-Read 'A (a protected path opened to this session on purpose)' $sshKey 'SSH2-CONTENT' }
  End-Session
  Expect-NoRead 'A (after that session)' $sshKey 'SSH2-CONTENT'
  $code = Session-Grant -write @($sessDir)
  if ($code -eq 0) { Ok 'A: a write root inside the temporary directory is granted' }
  else { Fail "A: write root inside the temporary directory: exit=$code output: $($script:lastGrant)" }
  End-Session
  & $Exe acl forget $sessDir 2>&1 | Out-Null
  Remove-Item -Recurse -Force -LiteralPath $sshSub
  $noWeb   = Join-Path $prof 'AppData\Local\NoWeb'
  $withWeb = Join-Path $prof 'AppData\Local\WithWeb'
  New-Item -ItemType Directory -Path (Join-Path $noWeb 'cache'), (Join-Path $withWeb 'EBWebView') -Force | Out-Null
  $code = Session-Grant -write @($noWeb)
  if ($code -eq 0) { Ok 'A: a directory of the local application data with no embedded browser profile in it is granted as a write root' }
  else { Fail "A: write root AppData\Local\NoWeb: exit=$code output: $($script:lastGrant)" }
  End-Session
  & $Exe acl forget $noWeb 2>&1 | Out-Null
  $code = Session-Grant -read @($noWeb)
  if ($code -eq 0) { Ok 'A: … and for reading' } else { Fail "A: read grant AppData\Local\NoWeb: exit=$code output: $($script:lastGrant)" }
  End-Session
  Refused 'a write root with an embedded browser profile beneath it' $withWeb -write @($withWeb)
  Refused 'a read grant on such a directory'                         $withWeb -read @($withWeb)
  New-Item -ItemType Directory -Path (Join-Path $noWeb 'EBWebView') -Force | Out-Null
  Refused 'a root that was granted before, once a store has appeared beneath it' $noWeb -write @($noWeb)
  Remove-Item -Recurse -Force -LiteralPath (Join-Path $noWeb 'EBWebView')

  # ── P: a write root with a read-denied file inside it ────────────
  $proj    = Join-Path $prof 'Documents\proj'
  $envFile = Seed 'Documents\proj\.env'    'ENV-CONTENT'
  $srcFile = Seed 'Documents\proj\src.txt' 'SRC-CONTENT'
  $json = @{ read = @(); write = @($proj); denyRead = @($envFile); denyWrite = @() } | ConvertTo-Json -Compress
  $raw = $json | & $Exe acl grant --holder-pid $PID --sandbox-user-sid $sbSid --persistent 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { Fail "P: a write root with a read-denied file inside is refused: $raw" }
  else {
    $r = Sb @($cmd, '/d', '/s', '/c', "type `"$srcFile`" & echo NEW> `"$proj\p-new.txt`" & type `"$envFile`"") -WriteRoots @($proj)
    $made = Test-Path -LiteralPath (Join-Path $proj 'p-new.txt')
    if ($r.out -match 'SRC-CONTENT' -and $made -and $r.out -notmatch 'ENV-CONTENT') {
      Ok 'P: the root is readable and writable, the denied file inside it is not readable'
    } else { Fail "P: read=$($r.out -match 'SRC-CONTENT') created=$made env-read=$($r.out -match 'ENV-CONTENT') raw: $($r.raw)" }
    $before = (Status).exclusions
    if (@($before | Where-Object { $_ -match 'proj' }).Count -eq 0) { Ok "P: the session's deny is not among the recorded exclusions" }
    else { Fail "P: recorded exclusions name the session's deny: $($before -join ', ')" }
  }
  End-Session
  & $Exe acl forget $proj 2>&1 | Out-Null
  Remove-Item -Recurse -Force -LiteralPath $proj

  # ── W: nothing is writable ───────────────────────────────────────
  foreach ($case in @(
      @{ tag = 'a granted child'; dir = (Join-Path $prof 'Documents'); keep = 'note.txt'; text = 'NOTE-CONTENT' },
      @{ tag = 'a container';     dir = (Join-Path $prof '.cargo');    keep = 'config.toml'; text = 'CARGO-CONFIG-CONTENT' },
      @{ tag = 'the profile directory'; dir = $prof;                   keep = '.npmrc'; text = 'NPMRC-CONTENT' })) {
    $d = $case.dir
    $keep = Join-Path $d $case.keep
    $line = "echo W>> `"$keep`" & echo N> `"$d\w-new.txt`" & del /q `"$keep`" & ren `"$keep`" w-renamed.txt & mkdir `"$d\w-newdir`" & exit /b 0"
    $r = Sb @($cmd, '/d', '/s', '/c', $line)
    $state = "content=[$((Get-Content -Raw -LiteralPath $keep -ErrorAction SilentlyContinue))] " +
             "new=$(Test-Path -LiteralPath (Join-Path $d 'w-new.txt')) " +
             "renamed=$(Test-Path -LiteralPath (Join-Path $d 'w-renamed.txt')) " +
             "newdir=$(Test-Path -LiteralPath (Join-Path $d 'w-newdir'))"
    $want = "content=[$($case.text)`r`n] new=False renamed=False newdir=False"
    if ($state -eq $want) { Ok "W: no write, create, delete, rename or mkdir in $($case.tag)" }
    else { Fail "W: $($case.tag) changed: $state (want $want). raw: $($r.raw)" }
  }

  # ── J: junctions ─────────────────────────────────────────────────
  Expect-NoRead 'J (through a junction to an excluded store)' (Join-Path $jSsh 'id_test') 'SSH2-CONTENT'
  Expect-NoRead 'J (through a junction to outside the profile)' (Join-Path $jOutside 'secret.txt') 'OUTSIDE-CONTENT'
  Expect-NoRead 'J (through the top-level junction)' (Join-Path $jTop 'secret.txt') 'OUTSIDE-CONTENT'
  if ($haveSym) { Expect-NoRead 'J (through a file symbolic link)' $symFile 'OUTSIDE-CONTENT' }
  $skipped = @($g.json.skipped | Where-Object { $_.path -match '\\link$' })
  if ($skipped.Count -eq 1) { Ok "J: the top-level junction is skipped and reported ($($skipped[0].reason))" }
  else { Fail "J: the top-level junction is not in the skipped list: $($g.json.skipped | ConvertTo-Json -Compress)" }
  $sshDir = Join-Path $prof '.ssh'
  if (-not (Has-GroupAllow $sshDir) -and -not (Has-GroupAllow $sshKey)) { Ok 'J: the excluded store behind a junction carries no allow' }
  else { Fail "J: .ssh carries an allow for the group: $(Sddl $sshDir) / $(Sddl $sshKey)" }

  # ── D: session read denies ───────────────────────────────────────
  $capsUser = @((J @('user', 'status')).capabilities)
  $capsProf = @((Status).capabilities)
  $need = @('profile-deny-expansion', 'profile-session-grant-check', 'kept-grant-holders', 'read-deny-except', 'exec-holder')
  if (@($need | Where-Object { $capsUser -notcontains $_ -or $capsProf -notcontains $_ }).Count -eq 0) { Ok 'D: user status and profile status name the capabilities the library relies on' }
  else { Fail "D: capabilities: user status [$($capsUser -join ', ')] profile status [$($capsProf -join ', ')]" }
  if ((Session-Deny @($prof)) -ne 0) { Fail 'D: the session stamps for a deny on the profile directory could not be written' }
  else {
    Expect-NoRead 'D (deny on the profile: granted child)' $note 'NOTE-CONTENT'
    Expect-NoRead 'D (deny on the profile: file under a granted child)' $subFile 'DEEP-CONTENT'
    Expect-NoRead 'D (deny on the profile: root file)' $npmrc 'NPMRC-CONTENT'
    Expect-NoRead 'D (deny on the profile: file of a container)' $cargoCfg 'CARGO-CONFIG-CONTENT'
    Expect-NoRead 'D (deny on the profile: file under a nested container)' $npmTool 'NPM-TOOL'
    $r = Sb @($cmd, '/d', '/s', '/c', "dir /b /a `"$prof`"")
    if ($r.exit -ne 0) { Ok 'D: the denied profile directory cannot be listed' }
    else { Fail "D: dir of the denied profile directory: exit=$($r.exit) raw: $($r.raw)" }
  }
  End-Session
  Expect-Read 'D (after the session)' $note 'NOTE-CONTENT'
  Expect-Read 'D (after the session)' $npmrc 'NPMRC-CONTENT'
  Expect-Read 'D (after the session)' $cargoCfg 'CARGO-CONFIG-CONTENT'
  if ((Session-Deny @((Join-Path $prof 'AppData'))) -ne 0) { Fail 'D: the session stamps for a deny on a container could not be written' }
  else {
    Expect-NoRead 'D (deny on a container: a granted directory two levels down)' $npmTool 'NPM-TOOL'
    Expect-Read 'D (deny on a container leaves the rest)' $note 'NOTE-CONTENT'
  }
  End-Session
  $r = Sb @('--deny-read', (Join-Path $prof 'AppData'), '--', $cmd, '/d', '/s', '/c', "type `"$npmTool`"") -ExecFlagsFirst
  if ($r.out -notmatch 'NPM-TOOL' -and $r.exit -ne 0) { Ok 'D: a per-command deny on a container reaches the granted directory beneath it' }
  else { Fail "D: per-command deny on AppData: exit=$($r.exit) raw: $($r.raw)" }
  Expect-Read 'D (after that command)' $npmTool 'NPM-TOOL'
  $ownRoot = Split-Path $newFile
  $json = @{ read = @(); write = @($ownRoot); denyRead = @($prof); denyWrite = @() } | ConvertTo-Json -Compress
  $raw = $json | & $Exe acl grant --holder-pid $PID --sandbox-user-sid $sbSid --persistent 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { Fail "D: a deny on the profile with a write root inside it: $raw" }
  else {
    $r = Sb @($cmd, '/d', '/s', '/c', "type `"$newFile`" & echo W> `"$ownRoot\d-own.txt`"") -WriteRoots @($ownRoot)
    if ($r.out -match 'NEWTOP-CONTENT' -and (Test-Path -LiteralPath (Join-Path $ownRoot 'd-own.txt'))) {
      Ok 'D: under a deny on the profile, the write root inside it is still read and written'
    } else { Fail "D: write root under a profile deny: raw: $($r.raw)  Sddl=$(Sddl $ownRoot)" }
    Expect-NoRead 'D (the rest of the profile under that deny)' $note 'NOTE-CONTENT'
    End-Session
    $null = Session-Grant -write @($ownRoot)
    $r = Sb @('--write-root', $ownRoot, '--deny-read', $prof, '--deny-read-except', $ownRoot, '--', $cmd, '/d', '/s', '/c', "type `"$newFile`" & type `"$note`"") -ExecFlagsFirst
    if ($r.out -match 'NEWTOP-CONTENT' -and $r.out -notmatch 'NOTE-CONTENT') { Ok 'D: a per-command deny on the profile spares the session write root named with it' }
    else { Fail "D: per-command deny with --deny-read-except: raw: $($r.raw)" }
  }
  End-Session
  $code = Session-Grant -write @($ownRoot)
  if ($code -ne 0) { Fail "D: the write root again: $($script:lastGrant)" }
  else {
    $r = Sb @($cmd, '/d', '/s', '/c', "type `"$newFile`"") -WriteRoots @($ownRoot)
    if ($r.out -match 'NEWTOP-CONTENT') { Ok 'D: the root is readable in the next session — the deny was not kept with it' }
    else { Fail "D: the root after a session that denied the profile: raw: $($r.raw)  Sddl=$(Sddl $ownRoot)" }
    Expect-Read 'D (and so is the rest)' $note 'NOTE-CONTENT'
  }
  End-Session
  & $Exe acl forget $ownRoot 2>&1 | Out-Null
  Remove-Item -Force -LiteralPath (Join-Path $ownRoot 'd-own.txt') -ErrorAction SilentlyContinue
  $docs = Join-Path $prof 'Documents'
  if ((Session-Deny @($docs)) -ne 0) { Fail 'D: the session stamp for a deny on a granted child could not be written' }
  else {
    Expect-NoRead 'D (deny on a granted child)' $note 'NOTE-CONTENT'
    Expect-NoRead 'D (deny on a granted child, deeper)' $subFile 'DEEP-CONTENT'
    Expect-Read 'D (deny on a granted child leaves the rest)' $npmrc 'NPMRC-CONTENT'
  }
  End-Session
  Expect-Read 'D (after the session)' $note 'NOTE-CONTENT'
  $sub = Join-Path $docs 'sub'
  if ((Session-Deny @($sub)) -ne 0) { Fail 'D: the session stamp for a deny beneath a granted child could not be written' }
  else {
    Expect-NoRead 'D (deny beneath a granted child)' $subFile 'DEEP-CONTENT'
    Expect-Read 'D (deny beneath a granted child leaves its siblings)' $note 'NOTE-CONTENT'
  }
  End-Session
  Expect-Read 'D (after the session)' $subFile 'DEEP-CONTENT'

  # ── O: the ordinary token ────────────────────────────────────────
  $r = Sb @($cmd, '/d', '/s', '/c', 'echo ORDINARY-RAN') -Ordinary
  if ($r.exit -eq 20 -and $r.out -notmatch 'ORDINARY-RAN') { Ok 'O: exec under the ordinary token is refused (exit 20) while the grant exists' }
  else { Fail "O: ordinary-token exec with a profile grant: exit=$($r.exit) raw: $($r.raw)" }

  # ── F: profile forget ────────────────────────────────────────────
  $f = Invoke-Srt $ExeAbs @('profile', 'forget', '--json')
  if ($f.exit -eq 0 -and @($f.json.failed).Count -eq 0) { Ok "F: profile forget ($($f.json.removed) cleared, $($f.json.placeholders_removed) created directories removed)" }
  else { Fail "F: profile forget exit=$($f.exit) raw: $($f.raw)" }
  Expect-NoRead 'F (after forget)' $note 'NOTE-CONTENT'
  Expect-NoRead 'F (after forget)' $npmrc 'NPMRC-CONTENT'
  Expect-NoRead 'F (after forget)' $newFile 'NEWTOP-CONTENT'
  Restored 'F'
  Outside-Unchanged 'after forget'
  $r = Sb @($cmd, '/d', '/s', '/c', 'echo ORDINARY-RAN') -Ordinary
  if ($r.exit -eq 0 -and $r.out -match 'ORDINARY-RAN') { Ok 'F: the ordinary token runs again' }
  else { Fail "F: ordinary-token exec after forget: exit=$($r.exit) raw: $($r.raw)" }

  # ── L: excluded names that are links ─────────────────────────────
  $prof2 = Join-Path $root 'profile2'
  $dot   = Join-Path $prof2 'dotfiles'
  New-Item -ItemType Directory -Path (Join-Path $dot '.ssh'), (Join-Path $dot '.config\gh'), (Join-Path $dot '.config\nvim') -Force | Out-Null
  $lKey    = Join-Path $dot '.ssh\id_test';          'LKEY-CONTENT'   | Set-Content -Encoding ASCII -LiteralPath $lKey
  $lHosts  = Join-Path $dot '.config\gh\hosts.yml';  'LHOSTS-CONTENT' | Set-Content -Encoding ASCII -LiteralPath $lHosts
  $lNvim   = Join-Path $dot '.config\nvim\init.lua'; 'LNVIM-CONTENT'  | Set-Content -Encoding ASCII -LiteralPath $lNvim
  $lReadme = Join-Path $dot 'README';                 'LREADME-CONTENT' | Set-Content -Encoding ASCII -LiteralPath $lReadme
  $lSsh = Join-Path $prof2 '.ssh'
  $lCfg = Join-Path $prof2 '.config'
  New-Item -ItemType Junction -Path $lSsh -Target (Join-Path $dot '.ssh')    | Out-Null
  New-Item -ItemType Junction -Path $lCfg -Target (Join-Path $dot '.config') | Out-Null
  $gl = Invoke-Srt $HooksAbs @('profile', 'grant', '--test-profile', $prof2, '--json')
  if ($gl.exit -ne 0) { Fail "L: profile grant on the profile with links: exit=$($gl.exit) raw: $($gl.raw)" }
  else {
    Expect-Read   'L (beside the linked stores)'                 $lReadme 'LREADME-CONTENT'
    Expect-Read   'L (configuration no rule names, behind the link)' $lNvim 'LNVIM-CONTENT'
    Expect-NoRead 'L (the keys, where they really are)'          $lKey   'LKEY-CONTENT'
    Expect-NoRead 'L (the keys, through the link)'               (Join-Path $lSsh 'id_test') 'LKEY-CONTENT'
    Expect-NoRead 'L (the sign-in, where it really is)'          $lHosts 'LHOSTS-CONTENT'
    Expect-NoRead 'L (the sign-in, through the link)'            (Join-Path $lCfg 'gh\hosts.yml') 'LHOSTS-CONTENT'
    if (-not (Has-GroupAllow (Join-Path $dot '.ssh')) -and -not (Has-GroupAllow (Join-Path $dot '.config\gh'))) {
      Ok 'L: the link targets carry no allow for the group'
    } else { Fail "L: a link target carries an allow: $(Sddl (Join-Path $dot '.ssh')) / $(Sddl (Join-Path $dot '.config\gh'))" }
    $st2 = (Invoke-Srt $HooksAbs @('profile', 'status', '--test-profile', $prof2)).json
    $want = @((Join-Path $dot '.ssh'), (Join-Path $dot '.config\gh')) | ForEach-Object { $_.ToLowerInvariant() }
    $have = @($st2.exclusions | ForEach-Object { ($_ -replace '^\\\\\?\\', '').ToLowerInvariant() })
    $missing = @($want | Where-Object { $have -notcontains $_ })
    if ($missing.Count -eq 0) { Ok 'L: the exclusions are recorded where the objects really are' }
    else { Fail "L: not among the recorded exclusions: $($missing -join ', ') (recorded: $($have -join ', '))" }
    $code = Session-Grant -read @((Join-Path $dot '.ssh'))
    End-Session
    if ($code -ne 0) { Ok 'L: a session read grant on the real location of the keys is refused' }
    else { Fail "L: a session read grant on dotfiles\.ssh was accepted: $($script:lastGrant)" }
  }
  $fl = Invoke-Srt $ExeAbs @('profile', 'forget', '--json')
  if ($fl.exit -ne 0) { Fail "L: profile forget exit=$($fl.exit) raw: $($fl.raw)" }

  # ── C: a deny the owner put there stays in front ──────────────────
  $ownerDenied = Join-Path $prof 'OwnerDenied'
  $odFile = Seed 'OwnerDenied\f.txt' 'OWNER-DENIED-CONTENT'
  & icacls $ownerDenied /deny '*S-1-5-32-545:(OI)(CI)(RD)' | Out-Null
  $g = Grant
  if ($g.exit -ne 0) { Fail "C: profile grant exit=$($g.exit) raw: $($g.raw)" }
  else {
    if (Has-GroupAllow $ownerDenied) { Ok 'C: the directory is granted like any other child' }
    else { Fail "C: OwnerDenied carries no allow for the group: $(Sddl $ownerDenied)" }
    Expect-NoRead "C (a profile directory with the owner's deny for Users)" $odFile 'OWNER-DENIED-CONTENT'
    if (Denies-First $ownerDenied) { Ok 'C: every explicit deny precedes the first allow on it' }
    else { Fail "C: the DACL of OwnerDenied is not in canonical order: $((Explicit-Aces $ownerDenied) -join '')" }
    Expect-Read 'C (the rest of the profile reads as before)' $note 'NOTE-CONTENT'
  }
  $wrDeny = Join-Path $root 'wr-deny'
  New-Item -ItemType Directory -Path $wrDeny -Force | Out-Null
  'KEEP' | Set-Content -Encoding ASCII -LiteralPath (Join-Path $wrDeny 'keep.txt')
  & icacls $wrDeny /deny '*S-1-5-32-545:(OI)(CI)(DE,DC)' | Out-Null
  $code = Session-Grant -write @($wrDeny)
  if ($code -ne 0) { Fail "C: write root with the owner's deny: exit=$code output: $($script:lastGrant)" }
  else {
    $r = Sb @($cmd, '/d', '/s', '/c', "echo NEW> `"$wrDeny\c-new.txt`" & del /q `"$wrDeny\keep.txt`" & exit /b 0") -WriteRoots @($wrDeny)
    $kept = Test-Path -LiteralPath (Join-Path $wrDeny 'keep.txt')
    $made = Test-Path -LiteralPath (Join-Path $wrDeny 'c-new.txt')
    if ($kept -and $made) { Ok "C: in a kept write root the command writes, and the owner's deny of delete still holds" }
    else { Fail "C: kept write root: keep.txt present=$kept new file created=$made raw: $($r.raw)" }
    if (Denies-First $wrDeny) { Ok 'C: every explicit deny precedes the first allow on the root' }
    else { Fail "C: the DACL of the write root is not in canonical order: $((Explicit-Aces $wrDeny) -join '')" }
  }
  End-Session
  & $Exe acl forget $wrDeny 2>&1 | Out-Null
  & icacls $wrDeny /remove:d '*S-1-5-32-545' | Out-Null

  # ── H: a kept grant is not removed from under a live session ─────
  $code = Session-Grant -write @($workDir)
  if ($code -ne 0) { Fail "H: setup — the session's grant: $($script:lastGrant)" }
  else {
    $h = Invoke-Srt $ExeAbs @('profile', 'forget', '--json', '--unless-held-by-others', '4')
    $holders = @($h.json.held_by | Where-Object { $_.pid -eq $PID })
    if ($h.exit -eq 22 -and $holders.Count -ge 1 -and (Has-Group $prof)) { Ok 'H: profile forget is refused (exit 22) while another live session reads through the grant, which stays' }
    else { Fail "H: profile forget with a live holder: exit=$($h.exit) grant present=$(Has-Group $prof) raw: $($h.raw)" }
    $h = Invoke-Srt $ExeAbs @('acl', 'forget', '--all', '--unless-held-by-others', '4')
    if ($h.exit -eq 22 -and (Has-Group $workDir)) { Ok 'H: acl forget --all is refused (exit 22) while another live session writes through a kept root, which stays' }
    else { Fail "H: acl forget --all with a live holder: exit=$($h.exit) root still granted=$(Has-Group $workDir) raw: $($h.raw)" }
    $hg = Grant
    if ($hg.exit -eq 24 -and @($hg.json.held_by | Where-Object { $_.pid -eq $PID }).Count -ge 1) { Ok 'H: profile grant is refused (exit 24) while a session is live' }
    else { Fail "H: profile grant with a live holder: exit=$($hg.exit) raw: $($hg.raw)" }
    Expect-Read 'H (the held grant still reads)' $note 'NOTE-CONTENT'
    $h = Invoke-Srt $ExeAbs @('acl', 'forget', '--all', '--unless-held-by-others', "$PID")
    if ($h.exit -eq 0) { Ok 'H: the holder itself is not refused' }
    else { Fail "H: forget asked by the holder: exit=$($h.exit) raw: $($h.raw)" }
  }
  End-Session
  $h = Invoke-Srt $ExeAbs @('acl', 'forget', '--all', '--unless-held-by-others', '4')
  if ($h.exit -eq 0 -and -not (Has-Group $workDir)) { Ok 'H: with the session ended, the kept root is forgotten' }
  else { Fail "H: acl forget --all after the session: exit=$($h.exit) root still granted=$(Has-Group $workDir) raw: $($h.raw)" }

  # ── S: a sandboxed command does not outlive its session ──────────
  function Sb-Pings {
    @(Get-CimInstance Win32_Process -Filter "Name='PING.EXE'" | Where-Object {
        try { (Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid).Sid -eq $sbSid } catch { $false }
      })
  }
  function Wait-Until { param([scriptblock] $cond, [int] $sec)
    $until = (Get-Date).AddSeconds($sec)
    while ((Get-Date) -lt $until) { if (& $cond) { return $true }; Start-Sleep -Milliseconds 250 }
    return [bool](& $cond)
  }
  $helper = Start-Process -FilePath $cmd -PassThru -WindowStyle Hidden -ArgumentList @('/c', 'ping', '-n', '600', '127.0.0.1')
  $held = $null
  try {
    $json = @{ read = @(); write = @(); denyRead = @(); denyWrite = @() } | ConvertTo-Json -Compress
    $reg = $json | & $Exe acl grant --holder-pid $helper.Id --sandbox-user-sid $sbSid --persistent 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Fail "S: setup — the helper could not be registered as a session: $reg" }
    else {
      $psi = [System.Diagnostics.ProcessStartInfo]::new()
      $psi.FileName              = $ExeAbs
      $psi.UseShellExecute       = $false
      $psi.RedirectStandardError = $true
      foreach ($a in @('exec', '--held-by', "$($helper.Id)", '--write-restricted-token',
                       '--env', "PATH=$($env:PATH)", '--env', "PATHEXT=$($env:PATHEXT)",
                       '--', $cmd, '/d', '/s', '/c', 'ping -n 600 127.0.0.1 >nul')) { $null = $psi.ArgumentList.Add($a) }
      $held = [System.Diagnostics.Process]::Start($psi)
      $heldErr = $held.StandardError.ReadToEndAsync()
      if (-not (Wait-Until { (Sb-Pings).Count -ge 1 } 60)) { Fail "S: setup — the sandboxed command did not start (exec exited=$($held.HasExited))" }
      else {
        $sg = Grant
        if ($sg.exit -eq 24 -and @($sg.json.held_by | Where-Object { $_.pid -eq $helper.Id }).Count -ge 1) { Ok 'S: with the session and its command running, profile grant is refused (exit 24)' }
        else { Fail "S: profile grant beside a running command: exit=$($sg.exit) raw: $($sg.raw)" }
        & taskkill /PID $helper.Id /T /F 2>&1 | Out-Null
        $exited = $held.WaitForExit(10000)
        $none = Wait-Until { (Sb-Pings).Count -eq 0 } 5
        if ($exited -and $none) { Ok 'S: the session killed, its sandboxed command and everything it started are gone within seconds' }
        else { Fail "S: after the session was killed: exec exited=$exited sandboxed ping(s) left=$((Sb-Pings).Count)" }
        if ($exited -and $held.ExitCode -eq 26 -and $heldErr.Result -match '"code":"session_ended"') { Ok 'S: srt-win exec says the session ended (exit 26)' }
        else { Fail "S: exec exit=$(if ($exited) { $held.ExitCode } else { 'still running' }) stderr: $(if ($exited) { $heldErr.Result })" }
        $sg = Grant
        if ($sg.exit -eq 0 -and $none) { Ok 'S: with the tree gone, profile grant goes ahead' }
        else { Fail "S: profile grant after the session ended: exit=$($sg.exit) sandboxed ping(s) left=$((Sb-Pings).Count) raw: $($sg.raw)" }
      }
    }
  } finally {
    & taskkill /PID $helper.Id /T /F 2>&1 | Out-Null
    if ($held -and -not $held.HasExited) { try { $held.Kill($true) } catch { } }
  }

  # ── U: uninstall ─────────────────────────────────────────────────
  & icacls $ownerDenied /remove:d '*S-1-5-32-545' | Out-Null
  $g = Grant
  if ($g.exit -ne 0 -or -not (Has-Group $prof)) { Fail "U: setup — the grant is not there: $($g.raw)" }
  else {
    $un = Invoke-Srt $ExeAbs @('uninstall', '--sublayer-guid', $Sublayer)
    if ($un.exit -eq 0) { Ok 'U: uninstall reports a clean removal' }
    else { Fail "U: uninstall exit=$($un.exit) raw: $($un.raw)" }
    if (-not (Has-Group $ownerDenied) -and -not (Has-Group $withWeb)) { Ok 'U: nothing added after the first grant still names the group' }
    else { Fail "U: still naming the group: OwnerDenied=$(Sddl $ownerDenied) WithWeb=$(Sddl $withWeb)" }
    Restored 'U'
    Outside-Unchanged 'after uninstall'
  }
}
finally {
  if ($sbSid) {
    & $Exe acl revoke  --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
    & $Exe acl restore --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
  }
  & $Exe profile forget 2>&1 | Out-Null
  & $Exe acl forget --all 2>&1 | Out-Null
  if ($lockedDir -and (Test-Path -LiteralPath $lockedDir)) {
    & icacls $lockedDir /remove:d '*S-1-1-0' '*S-1-5-11' '*S-1-5-32-545' 2>&1 | Out-Null
  }
  foreach ($d in $disowned) {
    & takeown /F $d /A /R /D Y 2>&1 | Out-Null
    & icacls $d /reset /T /C /Q 2>&1 | Out-Null
  }
  foreach ($d in @($ownerDenied, $wrDeny)) {
    if ($d -and (Test-Path -LiteralPath $d)) { & icacls $d /remove:d '*S-1-5-32-545' 2>&1 | Out-Null }
  }
  foreach ($j in @($jTop, $jOutside, $jSsh, $symFile, $lSsh, $lCfg)) {
    if ($j -and (Test-Path -LiteralPath $j)) { [System.IO.Directory]::Exists($j) ? [System.IO.Directory]::Delete($j) : [System.IO.File]::Delete($j) }
  }
  Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
  & $Exe uninstall --sublayer-guid $Sublayer 2>&1 | Out-Null
}

if ($script:Failures.Count -gt 0) {
  Write-Host "smoke-profile-read: $($script:Failures.Count) row(s) FAILED:"
  $script:Failures | ForEach-Object { Write-Host "  - $_" }
  throw "smoke-profile-read: $($script:Failures.Count) row(s) failed"
}
Write-Host 'smoke-profile-read: PASS (T, B, G, R1-R4, X, TMP, X2, N, E, A, P, W, J, D, O, F, L, C, H, S, U)'
