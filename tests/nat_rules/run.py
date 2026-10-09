#!/usr/bin/env python3
"""Linux host regression tests; no router, root access or network changes.

Run from the repository root with Python 3 and cc installed:
    python3 tests/nat_rules/run.py
    python3 tests/nat_rules/run.py --baseline

The baseline run must reproduce the known failure, not pass the fixed invariant.
Source excerpts are read from the checkout (or the pinned pre-fix commit), never
maintained as copies. NVRAM and firewall operations are test doubles; file locks,
fork, shared memory and signals are real. This is not a firmware integration test.
"""
import os
import pathlib
import resource
import shlex
import signal
import subprocess
import sys
import tempfile

repo = pathlib.Path(__file__).resolve().parents[2]
here = pathlib.Path(__file__).resolve().parent
baseline = "--baseline" in sys.argv
if sys.argv[1:] not in ([], ["--baseline"]):
    raise SystemExit("Usage: run.py [--baseline]")
base_ref = "2df5b849fdf7af5e9f887703390cc5924c67def9"
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

def source(path):
    if baseline:
        return subprocess.check_output(["git", "show", f"{base_ref}:{path}"], cwd=repo, text=True)
    return (repo / path).read_text()

services = source("release/src/router/rc/services.c")
begin = services.find("static int lock_nat_rules(")
if begin < 0:
    begin = services.index("int start_nat_rules(void)")
services = services[begin:services.index("\n#ifdef RTCONFIG_TOAD", begin)]
common = source("release/src/router/rc/common.c")
timeouts = common[common.index("void setup_udp_timeout("):common.index("\nint scan_icmp_unreplied_conntrack(")]
timeouts += common[common.index("void setup_ct_timeout("):common.index("\nvoid setup_conntrack(")]
files = source("release/src/router/shared/files.c")
locks = files[files.index("#define LET_FD_LEAK"):files.index("\nint file_lock(")]
locks += files[files.index("int _file_unlock("):files.index("\nvoid file_unlock(")]
states = source("release/src/router/shared/rtstate.h")
begin = states.rindex("enum {", 0, states.index("NAT_STATE_INITIALIZING=0"))
states = states[begin:states.index("};", begin) + 2]

with tempfile.TemporaryDirectory(prefix="merlin-nat-test-") as directory:
    work = pathlib.Path(directory)
    (work / "services.inc").write_text(services)
    (work / "timeouts.inc").write_text(timeouts)
    (work / "locks.inc").write_text(locks)
    (work / "states.inc").write_text(states)
    variants = [([], "broadcom"), (["-DRTCONFIG_QCA"], "qca"),
                (["-DRTCONFIG_RALINK"], "ralink")]
    if baseline:
        variants = [(["-Wno-unused-function", "-DTEST_BASELINE"], "broadcom")]
    for flags, name in variants:
        if "int reload_nat_rules(void)" in services:
            flags = [*flags, "-DHAVE_RELOAD_NAT_RULES"]
        exe = work / name
        subprocess.run([*shlex.split(os.environ.get("CC", "cc")),
                        *shlex.split(os.environ.get("CFLAGS", "")),
                        "-std=gnu99", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-but-set-variable", *flags, "-I", str(work),
                        str(here / "test.c"), "-o", str(exe)], check=True)
        tests = ["start_during_stop"] if baseline else subprocess.check_output(
            [str(exe), "--list"], text=True).splitlines()
        for test in tests:
            result = subprocess.run([str(exe), test], cwd=work, timeout=15,
                                    capture_output=baseline, text=True)
            if baseline:
                if result.returncode != -signal.SIGABRT or "assert_normal: Assertion" not in result.stderr:
                    raise SystemExit(f"ERROR: baseline failed for an unexpected reason: {result}")
                print("CONFIRMED: start_during_stop fails on unmodified baseline", flush=True)
            else:
                result.check_returncode()
                print(f"PASS: {name}: {test}", flush=True)
