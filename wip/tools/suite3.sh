#!/bin/bash
# suite3.sh <worktree> <label>: whole suite with real bwrap, the socat stand-in and the built helper; failing names to <label>.fail
S=${S:-/tmp/srt-scratch}
cd "$1" || exit 1
[ -x vendor/seccomp/x64/apply-seccomp ] || PATH=/opt/srt-stubs/gccshim:$PATH bun vendor/seccomp/build.ts >/dev/null 2>&1
[ -d dist ] || npm run build >/dev/null 2>&1
PATH=/opt/srt-stubs:$PATH bun test > "$S/run3-$2.log" 2>&1
grep -a '^(fail)' "$S/run3-$2.log" | sed -E 's/ \[[0-9.]+m?s\]$//' | sort -u > "$S/run3-$2.fail"
echo "== summary $2"; grep -a -E '^ +[0-9]+ (pass|skip|fail|error)' "$S/run3-$2.log"
if [ "$2" != main ] && [ -f "$S/run3-main.fail" ]; then
  echo "== fails here, not on main:"; comm -23 "$S/run3-$2.fail" "$S/run3-main.fail"
  echo "== fails on main, not here:"; comm -13 "$S/run3-$2.fail" "$S/run3-main.fail"
fi
