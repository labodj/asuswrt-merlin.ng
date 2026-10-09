# NAT transition regression tests

This companion branch provides review evidence, not files proposed for merging
upstream. The firmware-only change is on `fix/nat-transition-race`;
the test commit adds only this directory on top of that change.

Run on Linux with Python 3 and a C compiler, from the repository root:

```sh
python3 tests/nat_rules/run.py
python3 tests/nat_rules/run.py --baseline
```

The first command runs the tests against the working tree. The second checks
that the original UDP timeout race fails on the pinned pre-fix commit; that
expected failure is reported as `CONFIRMED`.

Two cases are particularly important:

- `start_during_stop`: pause stop during its ICMP wait, then request start.
  Normal NAT must end with the configured UDP timeouts, not 1/6 seconds.
- `reload_during_start`: publish a new ruleset after start has applied the old
  one, then request a reload. The new ruleset must be applied even if the first
  process sets `nat_state` back to normal while the reload is waiting.

The harness extracts the NAT functions, timeout functions and file-lock code
from the source tree. NVRAM, iptables and sysctl operations are simulated;
processes, file locks and signals are real. Pipe handshakes establish the race
ordering. Everything runs in a temporary directory, without root or changes
to the host network.

`CC` and `CFLAGS` can select another compiler or enable sanitizers:

```sh
CC=clang CFLAGS='-fsanitize=address,undefined -g' python3 tests/nat_rules/run.py
```

The Broadcom, QCA and Ralink runs cover conditional branches of these functions.
They do not replace a firmware build or tests on a router.

## Hardware verification

On 2026-10-09, a complete patched image was installed on an RT-AX86U_PRO.
The installed `rc` binary matched the build. With WAN redirect temporarily
enabled, four controlled PPPoE down/up cycles recovered normal NAT and the
configured 30/180-second UDP timeouts. Two cycles also overlapped a firewall
reload and SIGTERM to wanduck during the redirect transition, with unreplied
ICMP entries present. Three further online reload/SIGTERM checks passed.

The initial helper cleanup failures were reproduced and traced to listening
sockets inherited by asynchronous `nat-start` children. Those children briefly
kept the ports occupied after wanduck exited, causing an immediate restart to
fail with `Address already in use`. The socket implementation is unchanged by
this patch; an isolated test reproduced the same behavior on the pre-fix code.

After the helper was corrected to wait for the ports to be released, two full
runs (four more WAN cycles) passed, including daemon restart and final cleanup,
without watchdog recovery. DNS, HTTPS and WireGuard checks also passed,
including 1432-byte IPv4 packets without fragmentation. WAN redirect was left
disabled, as before testing.

A subsequent complete image also included the independent `SOCK_CLOEXEC`
socket fix. Its installed binary matched the build. With the helper's
listener-release wait removed, three online reload/SIGTERM checks and two
full runs (four additional WAN cycles) passed. All ten daemon restarts,
including cleanup, released the listeners immediately. Tracing found no
inherited listener in the running asynchronous hooks or duplicate daemon.
No watchdog recovery was needed; the original settings and 30/180-second UDP
timeouts were restored. Final DNS UDP/TCP, HTTPS and WireGuard checks passed,
including 1432-byte IPv4 packets without fragmentation.

These checks do not establish long-term stability, simulate physical cable or
power loss, or validate other router models.
