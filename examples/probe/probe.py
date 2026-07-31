#!/usr/bin/env python3
"""Sandbox probe: runs inside bento and reports what the box actually permits.

Each probe prints one line to stdout and nothing else:

    RESULT <group>.<name> <ALLOWED|DENIED> <detail>

ALLOWED means the operation succeeded, DENIED means the kernel or bento refused
it. Neither is inherently a pass - compare the outcome against what the manifest
granted. The manifests next to this file pair each policy with the outcome it
should produce.

Groups run in the order given on the command line, defaulting to every group
except `limits`. Results are flushed as they are produced and the run ends with
a PROBE-COMPLETE sentinel, so a probe that kills the process (a cgroup OOM is a
SIGKILL, not a MemoryError) still leaves every earlier result on stdout.

Two host environment variables shape the run:

  BENTO_PROBE_HOME    The real host home directory. Bento rewrites HOME to /tmp
                      inside the box and does not bind /etc/passwd, so the probe
                      cannot find it unaided; the shield probes skip without it.
                      Export it AND allowlist it in the manifest's `env` - both,
                      or it does not cross into the box. A manifest drafted by
                      `bento profile` does not carry it.
  BENTO_PROBE_CANARY  A value that must NOT reach the sandbox. Export it on the
                      host and leave it out of the `env` allowlist.
"""

import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request

# Paths the shipped manifests grant (or deliberately do not).
READ_GRANTED = "./data/sample.txt"
READ_UNGRANTED = "./secret/token.txt"
WRITE_GRANTED = "./out"

# Shielded even under a broad `read: "~"` grant. Entries starting with ~/ are
# resolved against BENTO_PROBE_HOME, not against the sandbox's rewritten HOME.
SHIELDED_READS = [
    "~/.ssh/id_rsa",
    "~/.aws/credentials",
    "~/.bashrc",
    "/run/docker.sock",
]

# What a probe reports when BENTO_PROBE_HOME did not reach the sandbox. From in here
# the two reasons are indistinguishable - never exported on the host, or exported and
# not allowlisted - and the second is the one that bites: a manifest bento profile drafts
# does not carry it, so the shield probes skip under exactly the manifest the root
# README's quick start produces.
NO_HOST_HOME = "BENTO_PROBE_HOME did not reach the sandbox (export it, and allowlist it in the manifest's env:)"

ALLOWED_HOST = "example.com"
DENIED_HOST = "api.github.com"


def host_path(path):
    """Resolve a ~/-prefixed path against the real host home, or None if unknown."""
    if not path.startswith("~/"):
        return path
    home = os.environ.get("BENTO_PROBE_HOME")
    if not home:
        return None
    return os.path.join(home, path[2:])


def report(group, name, allowed, detail=""):
    # allowed=None is SKIPPED: the probe could not run, which is neither a grant
    # nor a refusal and must not be read as either.
    verdict = "SKIPPED" if allowed is None else "ALLOWED" if allowed else "DENIED"
    print(f"RESULT {group}.{name} {verdict} {detail}".rstrip(), flush=True)


def attempt(group, name, fn):
    """Run fn, reporting ALLOWED on success and DENIED on any OS-level refusal."""
    try:
        detail = fn()
    except OSError as err:
        report(group, name, False, f"{type(err).__name__}: {err.strerror or err}")
    else:
        report(group, name, True, detail or "")


def probe_read():
    def read_head(path):
        with open(path, "rb") as f:
            return f"{len(f.read(64))} bytes"

    attempt("read", "granted", lambda: read_head(READ_GRANTED))
    attempt("read", "ungranted", lambda: read_head(READ_UNGRANTED))
    attempt("read", "cwd-listing", lambda: f"{len(os.listdir('.'))} entries")
    attempt("read", "etc-hostname", lambda: read_head("/etc/hostname"))

    # Control for the shield probes below. If home was never mounted, a shielded
    # path is missing for the boring reason that nothing is there, and a DENIED
    # shield result proves nothing. Only trust those lines when this is ALLOWED.
    home = os.environ.get("BENTO_PROBE_HOME")
    if home:
        attempt("read", "home-listing", lambda: f"{len(os.listdir(home))} entries")
    else:
        report("read", "home-listing", None, NO_HOST_HOME)

    for path in SHIELDED_READS:
        name = "shield" + path.replace("~", "").replace("/", "-")
        resolved = host_path(path)
        if resolved is None:
            report("read", name, None, NO_HOST_HOME)
            continue
        attempt("read", name, lambda p=resolved: read_head(p))


def probe_write():
    def write_file(dirpath, base):
        target = os.path.join(dirpath, base)
        with open(target, "w") as f:
            f.write("probe\n")
        return target

    attempt("write", "granted", lambda: write_file(WRITE_GRANTED, "probe.txt"))
    attempt("write", "ungranted-cwd", lambda: write_file(".", "probe-cwd.txt"))

    # /tmp is the sandbox's own tmpfs, not the host's - writable by design, and
    # discarded with the box. Here to keep that from reading as a leak.
    attempt("write", "sandbox-tmpfs", lambda: write_file("/tmp", "bento-probe.txt"))

    host_home = os.environ.get("BENTO_PROBE_HOME")
    if host_home:
        attempt("write", "shield-home", lambda: write_file(host_home, ".bashrc-probe"))
    else:
        report("write", "shield-home", None, NO_HOST_HOME)

    # Positive control: bento grants write on directories rather than files so
    # that save-via-rename keeps working. Over-blocking shows up here.
    def rename_swap():
        tmp = write_file(WRITE_GRANTED, "probe.tmp")
        final = os.path.join(WRITE_GRANTED, "probe-renamed.txt")
        os.replace(tmp, final)
        return final

    attempt("write", "save-via-rename", rename_swap)


def probe_env():
    # BENTO_PROBE_HOME is the witness: it exists only on the host and only
    # crosses if the allowlist carried it. PATH and HOME are injected by bento
    # itself, so their presence would say nothing about passthrough.
    witness = os.environ.get("BENTO_PROBE_HOME")
    report("env", "passthrough", bool(witness), witness or NO_HOST_HOME)

    injected = [k for k in ("PATH", "HOME", "LANG") if k in os.environ]
    report("env", "sandbox-injected", bool(injected), ",".join(injected) or "none present")

    canary = "BENTO_PROBE_CANARY" in os.environ
    report("env", "canary-leak", canary, "canary reached the sandbox" if canary else "absent")

    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    report("env", "proxy-injected", bool(proxy), proxy or "no proxy in environment")


def probe_net():
    # Egress is proxy-mediated: the netns is unshared and DNS does not resolve
    # inside the box, so anything not routed through HTTP(S)_PROXY fails even
    # for an allowlisted host. urllib picks the proxy up from the environment
    # and CONNECT-tunnels https:// through it.
    def fetch(host):
        req = urllib.request.Request(f"https://{host}/", method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return f"HTTP {resp.status}"

    for label, host in (("allowed-host", ALLOWED_HOST), ("denied-host", DENIED_HOST)):
        try:
            detail = fetch(host)
        except urllib.error.HTTPError as err:
            # The proxy refuses an undeclared host at the CONNECT, which surfaces
            # as a status rather than a transport error.
            report("net", label, False, f"proxy refused: HTTP {err.code}")
        except (urllib.error.URLError, OSError) as err:
            report("net", label, False, f"{type(err).__name__}: {err}")
        else:
            report("net", label, True, f"{host} {detail}")

    def direct():
        with socket.create_connection((ALLOWED_HOST, 443), timeout=8):
            return f"raw socket to {ALLOWED_HOST}:443"

    attempt("net", "direct-socket", direct)

    def dns():
        return socket.gethostbyname(ALLOWED_HOST)

    attempt("net", "dns", dns)


def probe_exec():
    # Ordered late: under `exec: none-strict` these are refused with EPERM
    # rather than a signal, but a stricter future filter could kill the process.
    def run_true():
        subprocess.run(["/bin/true"], check=True, timeout=10)
        return "/bin/true ran"

    attempt("exec", "subprocess", run_true)

    def do_fork():
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        os.waitpid(pid, 0)
        return f"forked pid {pid}"

    attempt("exec", "fork", do_fork)


def probe_limits():
    # A pids cap surfaces as a RuntimeError out of Thread.start rather than an
    # OSError, so this reports for itself instead of going through attempt().
    import threading

    stop = threading.Event()
    threads = []
    refusal = None
    try:
        for _ in range(64):
            t = threading.Thread(target=stop.wait)
            t.start()
            threads.append(t)
    except (RuntimeError, OSError) as err:
        refusal = err
    finally:
        stop.set()
        for t in threads:
            t.join()

    if refusal is None:
        report("limits", "pids", True, f"{len(threads)} threads without a refusal")
    else:
        report("limits", "pids", False, f"refused after {len(threads)} threads: {refusal}")

    # Runs last: the memory cap is the probe that ends the process.
    # A cgroup memory cap kills with SIGKILL, which no handler sees, so announce
    # the high-water mark as it climbs. If the last line printed is a MARK, the
    # box killed the probe at that size - that is the limit being enforced.
    step = 16
    chunks = []
    try:
        for i in range(64):
            chunks.append(bytearray(step * 1024 * 1024))
            print(f"MARK limits.memory {(i + 1) * step} MiB", flush=True)
    except MemoryError:
        report("limits", "memory", False, f"MemoryError at {len(chunks) * step} MiB")
    else:
        report("limits", "memory", True, f"{len(chunks) * step} MiB without a kill")
    finally:
        chunks.clear()


# Destructive or slow groups stay out of the default set.
GROUPS = {
    "read": probe_read,
    "write": probe_write,
    "env": probe_env,
    "net": probe_net,
    "exec": probe_exec,
    "limits": probe_limits,
}
DEFAULT_GROUPS = ["read", "write", "env", "net", "exec"]


def main(argv):
    requested = argv or DEFAULT_GROUPS
    unknown = [g for g in requested if g not in GROUPS]
    if unknown:
        sys.exit(f"unknown probe group(s): {', '.join(unknown)}")

    for group in requested:
        GROUPS[group]()

    print("PROBE-COMPLETE", flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])
