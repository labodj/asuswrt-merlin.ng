#!/usr/bin/env python3
"""Test the actual wanduck socket function with real sockets and fork/exec."""
import os
from pathlib import Path
import resource
import shlex
import subprocess
import sys
import tempfile

here = Path(__file__).resolve().parent
repo = here.parents[1]
if sys.argv[1:] not in ([], ["--baseline"]):
    raise SystemExit("Usage: run.py [--baseline]")
baseline = bool(sys.argv[1:])
path = "release/src/router/rc/wanduck.c"
base = "2df5b849fdf7af5e9f887703390cc5924c67def9"
source = (subprocess.check_output(["git", "show", f"{base}:{path}"], cwd=repo, text=True)
          if baseline else (repo / path).read_text())
start = source.index("int passivesock(")
function = source[start:source.index("\n#if 0", start)]
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

with tempfile.TemporaryDirectory(prefix="merlin-socket-test-") as directory:
    work = Path(directory)
    (work / "socket.inc").write_text(function)
    executable = work / "check"
    subprocess.run([*shlex.split(os.environ.get("CC", "cc")),
                    *shlex.split(os.environ.get("CFLAGS", "")),
                    "-D_GNU_SOURCE", "-std=gnu99", "-Wall", "-Wextra", "-Werror",
                    "-I", str(work), str(here / "test.c"),
                    "-o", str(executable)], check=True)
    for protocol in ("tcp", "udp"):
        result = subprocess.run([str(executable), protocol], timeout=10,
                                capture_output=True, text=True)
        if baseline:
            if result.returncode != 42 or "FAIL: listener retained across exec" not in result.stderr:
                raise SystemExit(f"Unexpected baseline result: {result}")
            print(f"CONFIRMED: {protocol} listener inherited on pre-fix code")
        else:
            if result.returncode:
                raise SystemExit(f"Socket test failed: {result}")
            print(f"PASS: {protocol} transport and restart after fork/exec")
