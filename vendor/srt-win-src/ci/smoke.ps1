<#
  srt-win install/uninstall lifecycle smoke test.

  Exercises `srt-win install` (provisions the `srt-sandbox` user +
  user-SID-keyed WFP filter set) and `srt-win uninstall` against a
  built srt-win.exe. Throws on any assertion failure. Requires
  elevation (NetUserAdd / Fwpm* both need admin).

  Usage (local dev machine):
    pwsh vendor/srt-win-src/ci/smoke.ps1 .\target\release\srt-win.exe

  Usage (CI — workflow passes the path):
    pwsh vendor/srt-win-src/ci/smoke.ps1 vendor\srt-win-src\target\release\srt-win.exe

  All WFP operations target $InstallSublayer (a fixed test GUID), NOT
  the production default sublayer — safe to run on a dev machine
  that has real sandbox-runtime filters installed.
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$Exe,
  # Distinct from wfp::DEFAULT_SUBLAYER_GUID so local runs never
  # touch a production install.
  [string]$InstallSublayer = 'b2e8a6c4-1f73-4d09-9e25-c7b0d3a48f61'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Exe)) {
  throw "srt-win.exe not found at '$Exe'"
}

Write-Host "srt-win smoke: exe=$Exe sublayer=$InstallSublayer"
$isl = @('--sublayer-guid', $InstallSublayer)
# Explicit so the assertions below are deterministic even if the
# compiled-in default changes.
$pr = @('--proxy-port-range', '60080-60089')

function Run([string[]]$argv) {
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited $LASTEXITCODE"
  }
}
function J([string[]]$argv) { Run $argv | ConvertFrom-Json }
function MustFail([string[]]$argv, [string]$why) {
  & $Exe @argv 2>$null
  if ($LASTEXITCODE -eq 0) {
    throw "expected non-zero ($why): srt-win $($argv -join ' ')"
  }
}

# ── negative input ──────────────────────────────────────────────────
MustFail (@('install', '--proxy-port-range', '100-50') + $isl) 'low>high'
MustFail (@('install', '--proxy-port-range', '1-1000') + $isl) 'range too wide'
MustFail (@('install', '--proxy-port-range', '60080') + $isl) 'missing dash'

# ── pre-install absent ───────────────────────────────────────────────
# CI runners are elevated so BFE enum succeeds; a non-elevated caller
# would get `cannot-read` here — that path can't be exercised on the
# elevated runner.
$pre = J (@('wfp', 'status') + $isl)
if ($pre.state -ne 'absent') {
  throw "pre-install wfp status expected absent, got $($pre.state)"
}

# ═════════════════════════════════════════════════════════════════════
# Single-step `install` / `uninstall`.
# ═════════════════════════════════════════════════════════════════════

Run (@('install') + $isl + $pr)
$iw = J (@('wfp', 'status') + $isl)
if ($iw.state -ne 'installed' -or $iw.filters -lt 4) {
  throw "install: wfp expected installed/>=4, got $($iw.state)/$($iw.filters)"
}
if ($iw.port_range[0] -ne 60080 -or $iw.port_range[1] -ne 60089) {
  throw "install: expected port_range [60080,60089], got [$($iw.port_range -join ',')]"
}

# ── sandbox user provisioned by install ────────────────────────────
$us = J @('user', 'status')
Write-Host "user status: $($us | ConvertTo-Json -Compress)"
if (-not $us.user.exists)            { throw "install: sandbox user not provisioned" }
if (-not $us.user.sid -or -not $us.user.sid.StartsWith('S-1-5-21-')) {
  throw "install: sandbox user SID missing or malformed: '$($us.user.sid)'"
}
if (-not $us.user.group_exists)      { throw "install: sandbox-runtime-users group missing" }
if (-not $us.user.in_builtin_users)  { throw "install: sandbox user not in BUILTIN\Users" }
if (-not $us.user.in_sandbox_group)  { throw "install: sandbox user not in sandbox-runtime-users" }
if (-not $us.user.hidden_from_logon) { throw "install: sandbox user not hidden from Winlogon" }
if (-not $us.cred_present)           { throw "install: credential not present (HKLM Cred\Blob)" }
# Keep in sync with SETUP_VERSION (vendor/srt-win-src/src/install.rs).
if ($us.marker_version -ne 2)        { throw "install: setup marker version expected 2, got $($us.marker_version)" }
if ($us.marker_user_sid -ne $us.user.sid) {
  throw "install: marker SID '$($us.marker_user_sid)' != live SID '$($us.user.sid)'"
}
if ($iw.user_sid -ne $us.user.sid) {
  throw "install: WFP user_sid '$($iw.user_sid)' != provisioned '$($us.user.sid)'"
}

# read-cred returns the cleartext password — 32 chars from the
# documented alphabet. Run as the real user (the sandbox user is
# DENY'd on the directory).
$pw = & $Exe user read-cred
if ($LASTEXITCODE -ne 0) { throw "user read-cred exited $LASTEXITCODE" }
if ($pw.Length -ne 32)   { throw "user read-cred: expected 32 chars, got $($pw.Length)" }
if ($pw -match '["\s\\`&|<>^]') {
  throw "user read-cred: password contains an excluded char: '$pw'"
}

# State-dir DACL: explicit DENY for sandbox-runtime-users — the CA
# key material lives under this dir and must be unreadable from
# inside the sandbox. (Credential + marker live in
# HKLM\SOFTWARE\sandbox-runtime now, asserted below.)
$stateDir = Join-Path $env:ProgramData 'sandbox-runtime'
$acl = Get-Acl $stateDir
$deny = $acl.Access | Where-Object {
  $_.AccessControlType -eq 'Deny' -and
  $_.IdentityReference.Value -match 'sandbox-runtime-users$'
}
if (-not $deny) {
  throw "install: state-dir DACL has no DENY for sandbox-runtime-users; got:`n$($acl.Access | Out-String)"
}
# Logon-type denials: the sandbox group must carry the four LSA
# deny rights (everything except interactive, which the
# CreateProcessWithLogonW launch needs). secedit is the only stock
# read path for user-right assignments.
$grpSid = $us.user.group_sid
if (-not $grpSid) { throw 'install: user status carries no group_sid' }
$seceditOut = Join-Path $env:TEMP 'srt-secedit.inf'
Remove-Item $seceditOut -ea SilentlyContinue  # never read a stale export
secedit /export /cfg $seceditOut /areas USER_RIGHTS | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $seceditOut)) {
  throw "install: secedit /export failed (exit $LASTEXITCODE)"
}
$rights = Get-Content $seceditOut -Raw
foreach ($r in @('SeDenyNetworkLogonRight','SeDenyBatchLogonRight','SeDenyServiceLogonRight','SeDenyRemoteInteractiveLogonRight')) {
  $line = ($rights -split "`n" | Where-Object { $_ -match "^$r" })
  # secedit exports resolvable trustees by NAME, unresolvable as *SID.
  if (-not $line -or ($line -notmatch 'sandbox-runtime-users' -and $line -notmatch [regex]::Escape($grpSid))) {
    throw "install: $r does not include the sandbox group ($grpSid); got: $line"
  }
}
$interactive = ($rights -split "`n" | Where-Object { $_ -match '^SeDenyInteractiveLogonRight' })
if ($interactive -match 'sandbox-runtime-users' -or $interactive -match [regex]::Escape($grpSid)) {
  throw "install: SeDenyInteractiveLogonRight includes the sandbox group - the launch path would be broken"
}
Remove-Item $seceditOut -ea SilentlyContinue
Write-Host 'install ok: logon-type denials stamped on the sandbox group (interactive untouched)'

# Registry store: base key present with marker + identity; Cred
# subkey deny for the sandbox group and no BU write; Ca subkey BU
# KEY_SET_VALUE (unelevated trust-ca) but sandbox-group DENY.
$reg = Get-ItemProperty 'HKLM:\SOFTWARE\sandbox-runtime' -ea Stop
if (-not $reg.MarkerVersion) { throw 'install: MarkerVersion missing from HKLM store' }
$credAcl = Get-Acl 'HKLM:\SOFTWARE\sandbox-runtime\Cred'
if (-not ($credAcl.Access | Where-Object { $_.AccessControlType -eq 'Deny' -and $_.IdentityReference.Value -match 'sandbox-runtime-users$' })) {
  throw "install: Cred key has no sandbox-group DENY:`n$($credAcl.Access | Out-String)"
}
if ($credAcl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -match '\\Users$' -and ($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::SetValue) }) {
  throw "install: Cred key is writable by BUILTIN\Users:`n$($credAcl.Access | Out-String)"
}
$caAcl = Get-Acl 'HKLM:\SOFTWARE\sandbox-runtime\Ca'
if (-not ($caAcl.Access | Where-Object { $_.AccessControlType -eq 'Deny' -and $_.IdentityReference.Value -match 'sandbox-runtime-users$' })) {
  throw "install: Ca key has no sandbox-group DENY:`n$($caAcl.Access | Out-String)"
}
if (-not ($caAcl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -match '\\Users$' -and ($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::SetValue) })) {
  throw "install: Ca key lacks BUILTIN\Users SetValue (unelevated trust-ca broken):`n$($caAcl.Access | Out-String)"
}

# ── M1: stale/foreign marker → plain install completes ────────────
# An admin (or an older build) leaves MarkerVersion at a value the
# broker doesn't expect: read_cred refuses with "re-run install",
# status still exits 0, and a plain (no --force) install falls
# through the early-out and heals the marker.
Set-ItemProperty 'HKLM:\SOFTWARE\sandbox-runtime' -Name MarkerVersion -Value 99
$m1b = & $Exe user read-cred 2>&1 | Out-String
if ($LASTEXITCODE -eq 0) { throw "M1b: read-cred succeeded on marker v99. out: $m1b" }
if ($m1b -notmatch '(?i)marker version mismatch.*re-run') {
  throw "M1b: expected marker-mismatch refusal. out: $m1b"
}
$m1c = & $Exe user status 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { throw "M1c: user status on stale marker expected exit 0; got $LASTEXITCODE" }
Write-Host "M1b ok: read-cred refuses + status survives a stale marker"
$m1out = & $Exe @(@('install') + $isl + $pr) 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { throw "M1: install exited $LASTEXITCODE. out: $m1out" }
if ($m1out -match '(?i)already installed.*no changes') {
  throw "M1: install short-circuited on a stale marker. out: $m1out"
}
$mv = (Get-ItemProperty 'HKLM:\SOFTWARE\sandbox-runtime').MarkerVersion
if ($mv -eq 99) { throw "M1: marker not healed (still 99)" }
Write-Host "M1 ok: stale marker healed by plain install (now v$mv)"
# Re-install above re-wrote the cred; downstream rows (read-cred
# etc.) already ran and don't depend on it.

# block-user must NOT match the REAL user — its SD allows only the
# sandbox user's SID.
$r = curl.exe -s -m 10 -o NUL -w "%{http_code}" https://example.com
if ($LASTEXITCODE -ne 0 -or $r -ne '200') {
  throw "install: real-user egress past block-user expected 200, got exit=$LASTEXITCODE code='$r'"
}
Write-Host "install: real-user egress past block-user OK ($r)"

# Idempotency, same range: second install with identical flags is
# a no-op (exit 0, "already installed").
$out = & $Exe @(@('install') + $isl + $pr) 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
  throw "install idempotency: same-range expected exit 0, got $LASTEXITCODE"
}
if ($out -notmatch 'already installed') {
  throw "install idempotency: expected 'already installed' in output, got '$out'"
}
$iw2 = J (@('wfp', 'status') + $isl)
if ($iw2.filters -ne $iw.filters) {
  throw "install idempotency: filters $($iw.filters) -> $($iw2.filters)"
}

# Conflict, different range without --force: exits 13.
& $Exe @(@('install', '--proxy-port-range', '50000-50001') + $isl) 2>$null
if ($LASTEXITCODE -ne 13) {
  throw "install conflict: different-range without --force expected exit 13, got $LASTEXITCODE"
}
# Original range still in place.
$iw3 = J (@('wfp', 'status') + $isl)
if ($iw3.port_range[0] -ne 60080) {
  throw "install conflict: range was overwritten without --force"
}

# --force replaces.
Run (@('install', '--proxy-port-range', '50000-50001', '--force') + $isl)
$iwF = J (@('wfp', 'status') + $isl)
if ($iwF.port_range[0] -ne 50000 -or $iwF.port_range[1] -ne 50001) {
  throw "install --force: expected port_range [50000,50001], got [$($iwF.port_range -join ',')]"
}

# `wfp verify` and `user trust-ca` route through
# CreateProcessWithLogonW (Secondary Logon). GHA runners have it;
# ensure it's running (idempotent).
try { Start-Service seclogon -ea Stop } catch {
  Write-Host "smoke: WARNING: Start-Service seclogon: $_"
}

# ── wfp verify: behavioral egress-block probe ───────────────────────
# Spawns the runner as the sandbox user and direct-connects to a
# target. The block-user filter fires at ALE_AUTH_CONNECT (before
# any packet leaves) → WSAEACCES → exit 0 + "blocked". This is the
# non-elevated readiness check (BFE enum is admin-gated; this
# isn't). stderr (the runner's BLOCKED/UNREACHABLE line) flows to
# the host so it's in the CI log; stdout is JUST the JSON line.
#
# `--target` is a local listener bound below, OUT of the WFP loopback
# permit range (50000-50001 here), so block-user fires when the fence
# is active and the connect succeeds when it isn't. Deterministic;
# no internet. This is the same shape as the product path
# (`verifyWindowsWfpEgress` binds an ephemeral out-of-range loopback
# listener and passes it as `--target`).
#
# Ephemeral, not a fixed port: Windows reserves blocks of the dynamic
# range at boot (excluded port ranges, which differ per machine), and
# a bind inside one fails with WSAEACCES. Re-draw if the OS hands out
# a port inside the permit range.
do {
  $probeLsn = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Loopback, 0)
  $probeLsn.Start()
  $probePort = $probeLsn.LocalEndpoint.Port
  $inPermit = $probePort -ge 50000 -and $probePort -le 50001
  if ($inPermit) { $probeLsn.Stop() }
} while ($inPermit)
$probeTgt = "127.0.0.1:$probePort"
function WfpVerify([string]$tgt) {
  $out = & $Exe wfp verify --target $tgt
  $ec = $LASTEXITCODE
  Write-Host "wfp verify --target ${tgt}: exit=$ec stdout='$out'"
  return [pscustomobject]@{ exit = $ec; json = $out | ConvertFrom-Json }
}
$v = WfpVerify $probeTgt
if ($v.exit -ne 0 -or $v.json.egress_probe -ne 'blocked') {
  throw ("wfp verify (fence-active): expected exit 0 + blocked, " +
         "got exit=$($v.exit) probe='$($v.json.egress_probe)'")
}
if ($v.json.target -ne $probeTgt) {
  throw "wfp verify: --target not honoured; got '$($v.json.target)'"
}
Write-Host "wfp verify ok: fence-active → blocked (target=$probeTgt)"

# ── user trust-ca: cert recorded + written ─────────────────────────
# Cert lifecycle = sandbox-user lifecycle (set via `user trust-ca`,
# persistent until uninstall); `srt-win install` and `srt-win exec`
# never touch it. Mint a throwaway self-signed cert (PEM), pass it
# via `user trust-ca`, and assert `user status` surfaces the thumb +
# a PEM that round-trips back to the same DER.
$caDir = Join-Path $env:TEMP "srt-ca-$(Get-Random)"
$null = mkdir $caDir
try {
  $ca = New-SelfSignedCertificate -Subject 'CN=srt-smoke-ca DO NOT TRUST' `
          -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
  $caPem = Join-Path $caDir 'ca.pem'
  $b64 = [Convert]::ToBase64String($ca.RawData, 'InsertLineBreaks')
  "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----" |
    Set-Content -Path $caPem -Encoding ascii
  $thumb = $ca.Thumbprint
  Remove-Item "Cert:\CurrentUser\My\$thumb" -ea SilentlyContinue

  # `user trust-ca` is the FIRST `spawn_runner` call (CPWLW + the
  # WinSta0/BNO grants). A hang here is the broker waiting on a
  # runner that never finished init — e.g. an under-granted
  # WinSta0 mask. Marker so a hung CI log shows which step it is
  # (the captured `$out` never prints on a hang).
  Write-Host 'ca-trust: spawning runner (CPWLW + station/BNO grants)'
  $out = & $Exe user trust-ca $caPem 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) {
    throw "user trust-ca exited ${LASTEXITCODE}: $out"
  }
  if ($out -notmatch '(?i)CA installed.*thumb=') {
    throw "user trust-ca: runner did not log CA install. out: $out"
  }
  $usCa = J @('user', 'status')
  if ($usCa.ca_cert_thumb -ne $thumb) {
    throw "user status: ca_cert_thumb '$($usCa.ca_cert_thumb)' != '$thumb'"
  }
  if (-not $usCa.ca_cert_pem -or $usCa.ca_cert_pem -notmatch 'BEGIN CERTIFICATE') {
    throw "user status: ca_cert_pem missing or malformed"
  }
  # PEM round-trips back to the same DER (so der_to_pem and the
  # state-DB blob agree).
  $pemBody = ($usCa.ca_cert_pem -replace '-----[^-]+-----', '' -replace '\s', '')
  if ([Convert]::ToBase64String($ca.RawData) -ne $pemBody) {
    throw 'user status: ca_cert_pem does not round-trip to original DER'
  }
  # Real user's Root must NOT have it — the write is scoped to the
  # sandbox user's HKU\<SID>.
  if (Get-ChildItem Cert:\CurrentUser\Root |
      Where-Object Subject -match 'srt-smoke-ca') {
    throw 'user trust-ca: CA leaked into REAL user CurrentUser\Root'
  }
  Write-Host "ca-trust ok: thumb=$thumb recorded + written into sandbox-user Root"

  # `install --force` re-provisions the account but must preserve
  # the recorded CA — write_setup_info's ON CONFLICT DO UPDATE
  # excludes ca_cert (owned by set_ca_cert), so install never
  # touches it.
  Run (@('install', '--force') + $isl + $pr)
  $usCa3 = J @('user', 'status')
  if ($usCa3.ca_cert_thumb -ne $thumb) {
    throw ("install --force: ca_cert wiped — got " +
           "'$($usCa3.ca_cert_thumb)', expected '$thumb'")
  }
  Write-Host 'ca-trust ok: install --force preserves ca_cert'
} finally {
  Remove-Item $caDir -Recurse -Force -ea SilentlyContinue
}

# --keep-user: filters removed, sandbox user + cred file kept.
Run (@('uninstall', '--keep-user') + $isl)
$uw0 = J (@('wfp', 'status') + $isl)
if ($uw0.state -ne 'absent') {
  throw "uninstall --keep-user: wfp expected absent, got $($uw0.state)"
}
$us0 = J @('user', 'status')
if (-not $us0.user.exists -or -not $us0.cred_present) {
  throw "uninstall --keep-user: sandbox user/cred should be kept"
}

# ── wfp verify (fence-INACTIVE): connect succeeds ───────────────────
# Filters were just removed (`uninstall --keep-user`) but the
# sandbox user is kept → the probe runs and the connect to the
# local listener SUCCEEDS (no WFP block) → exit 3 + "connected".
# This is the security-boundary proof that exit 0 above wasn't a
# false positive.
$v = WfpVerify $probeTgt
if ($v.exit -ne 3 -or $v.json.egress_probe -ne 'connected') {
  throw ("wfp verify (fence-inactive): expected exit 3 + " +
         "connected, got exit=$($v.exit) probe=" +
         "'$($v.json.egress_probe)' — probe cannot distinguish " +
         "fence-active from fence-missing")
}
Write-Host 'wfp verify ok: fence-inactive → exit 3 + connected'
$probeLsn.Stop()

# Re-install to set up for the full uninstall below.
Run (@('install') + $isl + $pr)

# Uninstall removes filters AND the sandbox user.
Run (@('uninstall') + $isl)
$uw = J (@('wfp', 'status') + $isl)
if ($uw.state -ne 'absent') {
  throw "uninstall: wfp expected absent, got $($uw.state)"
}
$usGone = J @('user', 'status')
if ($usGone.user.exists) {
  throw "uninstall: sandbox user should be removed, got $($usGone | ConvertTo-Json -Compress)"
}
if ($usGone.cred_present) {
  throw "uninstall: credential row should be cleared"
}
if ($null -ne $usGone.marker_version) {
  throw "uninstall: setup marker row should be cleared"
}
if ($null -ne $usGone.ca_cert_thumb) {
  throw "uninstall: ca_cert row should be cleared"
}
# Idempotent no-op: second uninstall must also exit 0.
Run (@('uninstall') + $isl)

# ── U1: --sandbox-user provisions under a custom name ──────────────
# Not pre-created — install creates it. `user status` reads the name
# from the setup marker, so it reports the custom name.
Run (@('install', '--sandbox-user', 'srt-sb-custom') + $isl + $pr)
$usc = J @('user', 'status')
if ($usc.user.name -ne 'srt-sb-custom') {
  throw "U1: expected user.name='srt-sb-custom', got '$($usc.user.name)'"
}
if (-not $usc.user.exists -or -not $usc.user.sid.StartsWith('S-1-5-21-')) {
  throw "U1: srt-sb-custom not provisioned; got $($usc | ConvertTo-Json -Compress)"
}
Write-Host "U1 ok: --sandbox-user srt-sb-custom provisioned (sid=$($usc.user.sid))"
# Re-install with the DEFAULT name and no --force → exit 13
# (recorded name differs).
& $Exe @(@('install') + $isl + $pr) 2>$null
if ($LASTEXITCODE -ne 13) {
  throw "U1: install with default name over srt-sb-custom expected exit 13, got $LASTEXITCODE"
}
# Uninstall reads the recorded name and removes srt-sb-custom.
Run (@('uninstall') + $isl)
net user srt-sb-custom 2>$null
if ($LASTEXITCODE -eq 0) {
  throw "U1: srt-sb-custom account still exists after uninstall"
}
Write-Host 'U1 ok: uninstall removes the recorded custom-name account'

# ── U1c: --sandbox-user rejects a name we didn't create ────────────
# `Administrators` resolves (as an alias) → the ownership guard at
# ensure_user() entry fires (no HKLM setup record) → provision() bails
# → exit 14.
$u1c = & $Exe @(@('install', '--sandbox-user', 'Administrators') + $isl + $pr) 2>&1 | Out-String
if ($LASTEXITCODE -ne 14) {
  throw "U1c: expected exit 14 for --sandbox-user Administrators, got $LASTEXITCODE. out: $u1c"
}
if ($u1c -notmatch 'already exists and was not created by srt-win') {
  throw "U1c: expected 'already exists and was not created by srt-win' in output. out: $u1c"
}
Write-Host 'U1c ok: --sandbox-user Administrators refused (exit 14)'

# ── U1d: --sandbox-user rejects a foreign local user ───────────────
# Pre-create a local user srt-win has no record of → same ownership
# guard fires (never rotate a password we didn't set). Random suffix
# so a leftover from a prior run can't false-positive.
$foreign = "srt-sb-f$(Get-Random -Max 99999)"
net user $foreign ('Aa1!' + [guid]::NewGuid().ToString('N').Substring(0,16)) /add /Y | Out-Null
if ($LASTEXITCODE -ne 0) { throw "U1d: net user $foreign /add failed" }
try {
  $u1d = & $Exe @(@('install', '--sandbox-user', $foreign) + $isl + $pr) 2>&1 | Out-String
  if ($LASTEXITCODE -ne 14) {
    throw "U1d: expected exit 14 for foreign local user, got $LASTEXITCODE. out: $u1d"
  }
  if ($u1d -notmatch 'already exists and was not created by srt-win') {
    throw "U1d: expected ownership-guard message. out: $u1d"
  }
  Write-Host "U1d ok: foreign local user '$foreign' refused (exit 14)"
} finally {
  net user $foreign /delete 2>$null
}
# U1c/U1d may have created SANDBOX_GROUP before bailing — clean up.
Run (@('uninstall') + $isl)

Write-Host 'srt-win smoke: OK'
