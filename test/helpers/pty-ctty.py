#!/usr/bin/env python3
"""Run argv on a pty that is genuinely the child's CONTROLLING terminal.

Attaching a pty to stdio is not enough for terminal-permission tests. TIOCSTI
is permitted to an unprivileged caller when the fd is its *controlling*
terminal and returns EACCES when it is not, so a harness that skips setsid()
plus TIOCSCTTY measures the missing controlling terminal rather than the
sandbox policy under test.

Exits with the child's status, or 124 if the deadline killed it, so a crash or
hang is visible at the process level instead of only as an absent marker in
stdout.

Usage: pty-ctty.py <command> [args...]
"""
import fcntl
import os
import pty
import select
import subprocess
import sys
import time

TIOCSCTTY = 0x20007461  # macOS <sys/ttycom.h>
DEADLINE = float(os.environ.get("PTY_DEADLINE", "60"))
EXIT_TIMEOUT = 124  # timeout(1)'s convention


def main() -> int:
    master, slave = pty.openpty()

    def make_controlling() -> None:
        os.setsid()
        # The slave fd explicitly, rather than fd 0. Relying on fd 0 assumes
        # CPython has already run its dup2 before preexec_fn, which is true
        # today but is not a documented guarantee.
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

    out = b""
    timed_out = False
    end = time.time() + DEADLINE
    while True:
        if time.time() >= end:
            timed_out = True
            break
        ready, _, _ = select.select([master], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        elif proc.poll() is not None:
            break

    if proc.poll() is None:
        proc.kill()
    status = proc.wait()

    sys.stdout.write(out.decode(errors="replace").replace("\r\n", "\n"))
    if timed_out:
        print(f"[harness] deadline of {DEADLINE}s expired", file=sys.stderr)
        return EXIT_TIMEOUT
    # A signalled child reports -N from wait(); report it the way a shell does.
    return status if status >= 0 else 128 - status


if __name__ == "__main__":
    raise SystemExit(main())
