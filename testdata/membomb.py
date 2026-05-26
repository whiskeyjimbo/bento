#!/usr/bin/env python3
"""Allocate increasing chunks of memory until killed by the sandbox."""
import sys
chunks = []
for i in range(1, 1000):
    chunks.append(b"x" * (10 * 1024 * 1024))  # 10 MiB each
    total = i * 10
    print(f"allocated {total} MiB", flush=True)
    if total > 800:
        print("limit not enforced — escaped to 800+ MiB", flush=True)
        sys.exit(1)
