#!/usr/bin/env python3
"""Boundary probe. argv[1] is a base directory that exists on the host;
the manifest decides which subpaths are allowed/denied."""
import os
import sys
import socket
import urllib.request

FAILS = []

def expect(name, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    print(f"  {tag}  {name}{(': ' + detail) if detail else ''}")
    if not ok:
        FAILS.append(name)

def try_read(path):
    try:
        with open(path) as f:
            f.read(1)
        return True, ""
    except Exception as e:
        return False, type(e).__name__

def try_write(path):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write("x")
        return True, ""
    except Exception as e:
        return False, type(e).__name__

def try_http(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            r.read(16)
        return True, ""
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"

base = sys.argv[1]

print("== filesystem ==")
ok, err = try_read(f"{base}/allowed_read.txt")
expect("read ALLOWED path succeeds", ok, err)
ok, err = try_read(f"{base}/forbidden_read.txt")
expect("read FORBIDDEN path fails", not ok, err)
ok, err = try_write(f"{base}/writable/out.txt")
expect("write ALLOWED dir succeeds", ok, err)
ok, err = try_write(f"{base}/readonly/out.txt")
expect("write to READ-ONLY dir fails", not ok, err)
ok, err = try_read("/etc/shadow")
expect("read /etc/shadow fails", not ok, err)

def try_raw_tcp(host, port):
    """Open a raw socket — does NOT honor HTTP_PROXY. Only succeeds if
    LD_PRELOAD/proxychains intercepts the connect() call."""
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.close()
        return True, ""
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"

print("== network (HTTP_PROXY-aware) ==")
ok, err = try_http("https://example.com/")
expect("HTTPS to ALLOWED host (example.com) succeeds", ok, err if not ok else "")
ok, err = try_http("https://api.github.com/")
expect("HTTPS to DENIED host (api.github.com) fails", not ok, err)

print("== network (raw socket / LD_PRELOAD path) ==")
# Raw TCP bypasses HTTP_PROXY; only proxychains' connect() interception
# can route this through the SOCKS5 filter.
ok, err = try_raw_tcp("example.com", 443)
expect("raw TCP to ALLOWED example.com:443 succeeds", ok, err if not ok else "")
ok, err = try_raw_tcp("api.github.com", 443)
expect("raw TCP to DENIED api.github.com:443 fails", not ok, err)

print()
if FAILS:
    print(f"FAILED ({len(FAILS)}): {', '.join(FAILS)}")
    sys.exit(1)
print("all probes behaved as expected")
