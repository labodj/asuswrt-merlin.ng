# wanduck socket inheritance tests

This companion branch contains test evidence, not files proposed for merging
upstream. Its parent is the exact socket fix on `fix/wanduck-socket-cloexec`.
The separate NAT transition fix is not required.

From the repository root on Linux, with Python 3 and a C compiler:

```sh
CFLAGS=-O2 python3 tests/wanduck_sockets/run.py
python3 tests/wanduck_sockets/run.py --baseline
CC=clang CFLAGS='-fsanitize=address,undefined -g' python3 tests/wanduck_sockets/run.py
```

The tests compile the actual `passivesock()` function extracted from wanduck,
then check both TCP and UDP transport. A child executes the test program and
signals readiness through a pipe. While it remains alive, the parent checks
that the socket was closed in the child and reopens the same listening port.
There are no sleep-based ordering assumptions or root/network changes.

The baseline run must reproduce inherited sockets on the pinned pre-fix
commit. UDP inheritance is checked directly: `SO_REUSEADDR` can permit another
bind even while an inherited UDP socket remains open.

The patched tests also passed on an RT-AX86U_PRO, compiled with the firmware's
ARM GCC 9.2/glibc 2.30 toolchain; both baseline failures were reproduced there
too.

## Firmware verification

On 2026-10-09, a complete image containing this fix and the separate NAT
transition fix was installed on that RT-AX86U_PRO. The installed `rc` binary
matched the build. Both live listening descriptors had `CLOEXEC` set; process
tracing found no child retaining either listener while asynchronous `nat-start`
and `ntpmerlin` hooks were running.

Three online firewall-reload/SIGTERM checks and two full WAN test runs passed.
The latter covered four PPPoE down/up cycles, including two concurrent
firewall-reload/SIGTERM cases. All ten daemon restarts, including cleanup,
released the listeners immediately, without waiting for hook completion or
using watchdog recovery. Each run restored the original settings, normal NAT
and the configured 30/180-second UDP timeouts.

Final DNS UDP/TCP, HTTPS and WireGuard checks passed, including 1432-byte IPv4
packets without fragmentation. These checks do not establish long-term
stability, simulate physical cable or power loss, or validate other models.
