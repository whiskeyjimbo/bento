#!/usr/bin/env python3
"""Verify mandatory-deny: even though the manifest grants read access
to the entire home dir, ~/.netrc (in DANGEROUS_FILES) must come back
empty because bento bind-mounts /dev/null over it."""
import os
import sys

home = os.path.expanduser("~")
netrc = os.path.join(home, ".netrc")

if not os.path.exists(netrc):
    print(f"FAIL: {netrc} does not exist on host — set up the test fixture first")
    sys.exit(1)

try:
    with open(netrc) as f:
        content = f.read()
except Exception as e:
    print(f"PASS: read of {netrc} failed ({type(e).__name__}: {e})")
    sys.exit(0)

if content == "":
    print(f"PASS: {netrc} appears empty inside the sandbox (mandatory-deny working)")
    sys.exit(0)

print(f"FAIL: {netrc} returned {len(content)} bytes — mandatory-deny NOT enforced")
print(f"      first 80 bytes: {content[:80]!r}")
sys.exit(1)
