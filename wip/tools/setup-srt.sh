#!/bin/bash
# Sets a fresh Linux machine up for testing sandbox-runtime without packaged
# bubblewrap, socat or libseccomp headers. usage: setup-srt.sh <checkout> <worktree dir> <pr:branch>...
set -e
REPO=$1; WT=$2; shift 2
STUBS=/opt/srt-stubs
sudo mkdir -p $STUBS && sudo chown "$(id -un)" $STUBS
mkdir -p $STUBS/build $STUBS/gccshim "$WT"
cd "$REPO"
[ "$(git rev-parse --is-shallow-repository)" = true ] && git fetch -q --unshallow origin
for pb in "$@" 751:claude/project-thread-u33gxn; do
  n=${pb%%:*}; b=${pb#*:}
  git fetch -q origin "$b"
  [ -d "$WT/$n" ] || git worktree add -q --detach "$WT/$n" FETCH_HEAD
done
[ -d node_modules ] || HUSKY=0 npm install --no-save --no-audit --no-fund prettier@3.5.0 eslint-config-prettier@9.1.2 >/dev/null 2>&1
T=$WT/751/wip/tools
gcc -O2 $T/socat.c -o $STUBS/socat
cp $T/gccshim-gcc $STUBS/gccshim/gcc; cp $T/stub-ok $STUBS/stub-ok; chmod +x $STUBS/gccshim/gcc $STUBS/stub-ok
# the shim names two nix store paths: bring them up to this machine's
SEC=$(ls -d /nix/store/*-libseccomp-*-lib/lib | head -1); GLC=$(ls -d /nix/store/*-glibc-*-static/lib | head -1)
sed -i -E "s#L=/nix/store/[^ ]*libseccomp[^ ]*#L=$SEC#; s#-L/nix/store/[^ ]*glibc[^ ]*static/lib#-L$GLC#" $STUBS/gccshim/gcc
cd $STUBS/build
[ -d bubblewrap ] || git clone -q https://github.com/containers/bubblewrap.git
[ -d libseccomp ] || git clone -q --depth 1 --branch v2.6.0 https://github.com/seccomp/libseccomp.git
mkdir -p seccomp-inc cfg inc/sys
sed -e 's/@VERSION_MAJOR@/2/; s/@VERSION_MINOR@/6/; s/@VERSION_MICRO@/0/' libseccomp/include/seccomp.h.in > seccomp-inc/seccomp.h
cp libseccomp/include/seccomp-syscalls.h seccomp-inc/
cat > inc/sys/capability.h <<'H'
#pragma once
#include <linux/capability.h>
typedef int cap_value_t;
int cap_from_name(const char *, cap_value_t *);
int capget(cap_user_header_t, cap_user_data_t);
int capset(cap_user_header_t, const cap_user_data_t);
H
echo '#define PACKAGE_STRING "bubblewrap 0.12.0"' > cfg/config.h
CAP=$(ls -d /nix/store/*-libcap-*-lib/lib | head -1)
( cd bubblewrap && git checkout -q v0.12.0 && gcc -O2 -D_GNU_SOURCE -I../cfg -I../inc -I. *.c -o $STUBS/bwrap -L$CAP -Wl,-rpath,$CAP -l:libcap.so.2 )
cd "$REPO"
PATH=$STUBS/gccshim:$PATH bun vendor/seccomp/build.ts >/dev/null 2>&1 || echo "helper build failed"
for d in "$WT"/*/; do
  [ -e "$d/node_modules" ] || ln -s "$REPO/node_modules" "$d/node_modules"
  ( cd "$d" && PATH=$STUBS/gccshim:$PATH bun vendor/seccomp/build.ts >/dev/null 2>&1 ) || echo "helper build failed in $d"
done
$STUBS/bwrap --version; $STUBS/bwrap --unshare-user --dev-bind / / true && echo namespaces ok
ls -la vendor/seccomp/x64/ 2>/dev/null | tail -2
