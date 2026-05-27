# Platform Support & Development Guidelines

This document details supported operating systems, kernel configuration requirements, package dependencies, and testing/development procedures for Bento.

---

## Platform Compatibility Matrix

| Platform | Support Status | Notes |
|---|---|---|
| **Linux (x86_64)** | Fully Supported | Supports both Landlock and namespace Bridge network modes. |
| **Linux (arm64)** | Partially Supported | Compiles cleanly. However, the custom precompiled `bento-launcher` is currently `linux/amd64` only; exec-blocking is disabled/degraded on arm64. |
| **macOS** | Compiles (Beta) | Implements the native Apple Seatbelt (`sandbox-exec`) sandbox layer. parities with Linux filesystem paths but does not yet support cgroup resource limits. |
| **Windows** | Not Supported | Sandboxing primitives (`bubblewrap` and `sandbox-exec`) are fundamentally Unix/POSIX-specific. |

---

## Installation & Dependencies

### Host Requirements

To set up Bento, first install the baseline sandboxing engine on your host:

#### 1. Linux Prerequisite
* **Required:** `bubblewrap` (available on almost all distributions: `apt install bubblewrap` or `dnf install bubblewrap`).

#### 2. Optional Linux Utilities (Diagnostics will warn if missing)
* `socat` (`apt install socat`): Necessary only when falling back to network namespace **Bridge Mode**.
* `proxychains4` (`apt install proxychains4`): Required for the SOCKS5 `LD_PRELOAD` layer to intercept traffic from dynamically linked binaries.
* `systemd-run`: Required for enforcing CPU, memory, and task limits via cgroups.

---

## Operating System Configuration (Linux)

### 1. Ubuntu 24.04+ AppArmor Restrictions
Starting with Ubuntu 24.04, unprivileged user namespaces are restricted by default under AppArmor. Running `bubblewrap` without a profile yields:
`bwrap: No permissions to create a new user namespace`

* **Solution:** Apply Bento's AppArmor profile to allow `bwrap` to spawn namespaces.
* Bento provides a sample profile at `testdata/bwrap.apparmor`.
* Running `bento doctor` will detect this issue and print the exact remediation commands required to apply the fix on your host. Alternately, execute `bento setup` to apply configuration fixes automatically.

### 2. Kernel Version Requirements for Landlock TCP
To use native kernel-level Landlock TCP rulesets, your Linux kernel must be **$\ge$ 6.7** (enables Landlock ABI $\ge$ 4). On older kernels, Bento will automatically select and run in network **Bridge Mode** via namespaces and local sockets.

---

## Development & Local Testing

### Building Bento
To compile the launcher shim and build the final `bento` CLI binary:

```bash
# Clean, compile launcher, embed binary, and build CLI
make build

# Build only the linux/amd64 launcher shim (regenerates launcherbin/)
make launcher
```

### Running E2E Test Suite
Bento contains comprehensive end-to-end integration tests to verify isolation across filesystem boundaries, network rules, execution limits, and mandatory blocks:

```bash
# Run unit tests + e2e test probes
make test
```

### Manual Verification
You can manually run specific integration probe scenarios using the test manifests provided in the source repository:

```bash
# 1. Verify standard filesystem and network allowlists
./bin/bento run testdata/probe.manifest.yaml

# 2. Verify that the seccomp execution filter blocks subprocesses
./bin/bento run testdata/exec.manifest.yaml

# 3. Verify cgroup memory ceiling enforcement (should terminate the process)
./bin/bento run testdata/membomb.manifest.yaml

# 4. Verify that static binaries cannot bypass proxies (requires Landlock or Bridge)
./bin/bento run testdata/goprobe.manifest.yaml

# 5. Verify that mandatory-deny paths (like ~/.ssh) cannot be accessed
./bin/bento run testdata/dangerous.manifest.yaml

# 6. Test specific network backend execution directly:
./bin/bento run --network-mode=landlock testdata/probe.manifest.yaml
./bin/bento run --network-mode=bridge   testdata/probe.manifest.yaml
```
