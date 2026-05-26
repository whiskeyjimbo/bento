#!/usr/bin/env python3
"""Test ExecCapability: when Exec is empty in the manifest, subprocess
spawning should be blocked by seccomp."""
import subprocess
import sys

try:
    out = subprocess.run(["/bin/echo", "subprocess-ran"], capture_output=True, text=True, timeout=2)
    print(f"FAIL: subprocess succeeded with output {out.stdout!r}")
    sys.exit(1)
except (PermissionError, OSError) as e:
    print(f"PASS: subprocess blocked by seccomp ({type(e).__name__}: {e})")
    sys.exit(0)
