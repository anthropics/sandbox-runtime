# probe-deny-alias.ps1

Probes how `srt-win acl stamp` deny targets interact with junction (reparse-point)
aliases. Deny paths are canonicalized (junctions resolved) and the DENY ACE is stamped
on the canonical object, so the script checks: a junction-spelled deny covers both the
junction and the target spelling (DA2); whether re-pointing or replacing the junction
after the stamp defeats the denied spelling (DA3 admin variant, DA3b sandboxed-child
variant); and whether the junction object itself is protected from deletion (DA4).

Run as admin in the guest (PowerShell 5.1):
`powershell -ExecutionPolicy Bypass -File probe-deny-alias.ps1 C:\path\to\srt-win.exe`
Installs under a test-only sublayer GUID, uninstalls and cleans up everything at the
end. Grep output for `DA[n] PASS|FAIL|INFO`. Runs in the Windows CI legs; non-zero exit = FAIL count.
