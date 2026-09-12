#!/usr/bin/env python3
"""Reproduce issue #391 deterministically, with no keypress.

#391 reports that pressing Ctrl+C under `srt claude` displays the literal text
`^[[99;5u` — the Kitty Keyboard Protocol encoding — instead of it being handled
as a key. That is the signature of a terminal still in canonical+ECHO mode: the
tty driver echoes whatever arrives on its input back to the display, so the
application's own protocol traffic becomes visible text.

The symptom is therefore reproducible without a human: give the child a pty,
let it try to enter raw mode, then write the KKP sequence to the master and see
whether the tty echoes it back.

    raw mode entered  -> ECHO off -> nothing echoed  -> prints KKP-ECHOED=NO
    raw mode refused  -> ECHO on  -> bytes come back -> prints KKP-ECHOED=YES

The child must print READY_MARKER once it has tried to enter raw mode. That is
both the injection trigger and the liveness proof: without it, a child that
died at startup would echo nothing and look identical to a passing run.

Usage: pty-kkp.py <command> [args...]
"""
import fcntl
import os
import pty
import select
import subprocess
import sys
import time

TIOCSCTTY = 0x20007461  # macOS <sys/ttycom.h>
KKP_CTRL_C = b"\x1b[99;5u"  # CSI 99 ; 5 u — 'c' with Ctrl, verbatim from #391
READY_MARKER = b"KKP-CHILD-READY"
READY_TIMEOUT = 30.0
COLLECT_SECONDS = 2.0


def main() -> int:
    master, slave = pty.openpty()

    def make_controlling() -> None:
        os.setsid()
        fcntl.ioctl(slave, TIOCSCTTY, 0)

    proc = subprocess.Popen(
        sys.argv[1:],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        preexec_fn=make_controlling,
        pass_fds=(slave,),
        close_fds=True,
    )
    os.close(slave)

    # Wait for the child to say it has tried raw mode, rather than sleeping a
    # fixed interval: a loaded machine would otherwise get the injection while
    # the tty was still in canonical mode and fail spuriously.
    preamble = b""
    ready_by = time.time() + READY_TIMEOUT
    while READY_MARKER not in preamble and time.time() < ready_by:
        r, _, _ = select.select([master], [], [], 0.2)
        if not r:
            continue
        try:
            preamble += os.read(master, 4096)
        except OSError:
            break

    if READY_MARKER not in preamble:
        # Never inject blind: no marker means the child never got far enough,
        # and "nothing was echoed" would then be a vacuous pass.
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        os.close(master)
        print("KKP-ECHOED=UNKNOWN")
        print(f"child never signalled readiness; captured={preamble!r}")
        return 1

    os.write(master, KKP_CTRL_C)

    echoed = b""
    end = time.time() + COLLECT_SECONDS
    while time.time() < end:
        ready, _, _ = select.select([master], [], [], 0.2)
        if not ready:
            continue
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        echoed += chunk

    if proc.poll() is None:
        proc.kill()
    proc.wait()
    os.close(master)

    leaked = KKP_CTRL_C in echoed or b"[99;5u" in echoed
    print(f"KKP-ECHOED={'YES' if leaked else 'NO'}")
    print(f"captured={echoed!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
