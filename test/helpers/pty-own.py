"""Run one command on a pty that is its controlling terminal.

Node cannot make a pty the controlling terminal of a child without a native
dependency, so this helper does it. The test needs the device name before it
can build the sandbox profile, so the exchange takes two steps:

1. The helper opens two ptys and prints {"own": ..., "other": ...}: the one the
   command will run on, and a second one the command must not reach.
2. It reads {"command": ..., "timeout": ...} on stdin, runs the command with
   /bin/sh -c in a new session whose controlling terminal is the "own" pty,
   and prints {"status": ..., "output": ...} once the command has exited.
"""

import fcntl
import json
import os
import select
import sys
import termios
import time

own_master, own_slave = os.openpty()
other_master, other_slave = os.openpty()
print(
    json.dumps({"own": os.ttyname(own_slave), "other": os.ttyname(other_slave)}),
    flush=True,
)

request = json.loads(sys.stdin.readline())

pid = os.fork()
if pid == 0:
    os.setsid()
    fcntl.ioctl(own_slave, termios.TIOCSCTTY, 0)
    for fd in (0, 1, 2):
        os.dup2(own_slave, fd)
    for fd in (own_master, own_slave, other_master, other_slave):
        os.close(fd)
    os.execv("/bin/sh", ["/bin/sh", "-c", request["command"]])

os.close(own_slave)
deadline = time.monotonic() + request.get("timeout", 10)
output = b""
status = None
while time.monotonic() < deadline:
    ready, _, _ = select.select([own_master], [], [], 0.05)
    if ready:
        try:
            chunk = os.read(own_master, 4096)
        except OSError:
            chunk = b""
        output += chunk
    done, wait_status = os.waitpid(pid, os.WNOHANG)
    if done:
        status = os.waitstatus_to_exitcode(wait_status)
        # Drain what the command wrote before it exited
        while select.select([own_master], [], [], 0.05)[0]:
            try:
                chunk = os.read(own_master, 4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
        break
else:
    os.kill(pid, 9)
    os.waitpid(pid, 0)

print(json.dumps({"status": status, "output": output.decode("utf-8", "replace")}))
