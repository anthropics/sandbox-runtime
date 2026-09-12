#!/usr/bin/env python3
"""Run argv with stdin on one pty and stdout/stderr on a DIFFERENT pty.

Exists to exercise the case a single-pty harness cannot reach: a process whose
inherited descriptors point at two distinct terminals. Granting only the first
one leaves operations on the other returning EPERM, and a harness that puts all
three fds on one device can never catch that.

Child stdout (second pty) is echoed to our stdout.

Usage: pty-split.py <command> [args...]
"""
import os
import pty
import select
import subprocess
import sys
import time

DEADLINE = float(os.environ.get("PTY_DEADLINE", "60"))
EXIT_TIMEOUT = 124


def main() -> int:
    in_master, in_slave = pty.openpty()
    out_master, out_slave = pty.openpty()

    proc = subprocess.Popen(
        sys.argv[1:],
        stdin=in_slave,
        stdout=out_slave,
        stderr=out_slave,
        close_fds=True,
    )
    os.close(in_slave)
    os.close(out_slave)

    out = b""
    timed_out = False
    end = time.time() + DEADLINE
    while True:
        if time.time() >= end:
            timed_out = True
            break
        ready, _, _ = select.select([out_master], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(out_master, 65536)
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
    os.close(in_master)
    os.close(out_master)

    sys.stdout.write(out.decode(errors="replace").replace("\r\n", "\n"))
    if timed_out:
        print(f"[harness] deadline of {DEADLINE}s expired", file=sys.stderr)
        return EXIT_TIMEOUT
    return status if status >= 0 else 128 - status


if __name__ == "__main__":
    raise SystemExit(main())
