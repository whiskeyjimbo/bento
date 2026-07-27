<p align="center">
  <img src=".github/assets/bento-gopher.png" width="25%" alt="Bento Gopher Logo" />
</p>

# Bento

**Run untrusted scripts under strict, manifest-declared permissions.**

Bento is a lightweight, fail-closed sandbox for Linux that executes untrusted code (build scripts, CLI utilities, AI agent actions) with deny-by-default security. It isolates filesystem access, blocks unauthorized network egress, prevents subprocess execution, and shields host credentials even if a manifest includes broad read grants.

Bento surfaces any gap between what a manifest requests and what the host kernel can enforce, refusing to run under degraded security when `--strict` is enabled.

> **Status:** Fully implemented and verified on **Linux (amd64)** using bubblewrap, seccomp, Landlock, and systemd cgroups. Support for **Linux (arm64)** and **macOS** is planned. See [`docs/architecture.md`](docs/architecture.md) for architecture details and [`docs/threat-model.md`](docs/threat-model.md) for security boundaries.

---

## Why Bento?

- **Default-Deny Isolation:** The sandbox only exposes explicitly granted files and directories. Everything else is hidden.
- **Built-in Credential & Host Shielding:** Sensitive paths (`~/.ssh`, `~/.aws`, GPG keyrings, OS keyrings, environment-relocated secret stores, runtime sockets in `/run`, and persistence targets like `.git/hooks` or `.vscode`) remain shielded even under broad grants like `read: ~`.
- **Declarative Permissions & Fingerprinted Approvals:** Policy lives in a human-readable manifest (`manifest.yaml`). Unattended runs (`bento run`) require a valid approval fingerprint over policy fields to prevent unreviewed permission creep in CI or autonomous agents.
- **Egress-Controlled Proxy:** Network traffic is blocked by default in an unshared network namespace. Per-host egress is strictly routed through a host-side HTTP CONNECT proxy with hostname validation and IP pin checks.
- **Host Honesty & No Quiet Degradation:** `bento doctor` reports kernel capability support. When host isolation layers (such as seccomp or cgroups) are unavailable, Bento flags the shortfall instead of quietly falling back to a weaker sandbox.

---

## Requirements & Installation

### Requirements
- **OS:** Linux with `bubblewrap` (`bwrap`) installed and unprivileged user namespaces enabled.
- **Build Toolchain:** Go 1.26 or later.
- **Optional:** `systemd` user manager with delegated `memory`, `pids`, and `cpu` controllers for resource limits.

### Build from Source
```sh
go build -o bento ./cmd/bento
```

---

## Quick Start Workflow

Bento follows a 4-step workflow: **Profile → Validate → Approve → Run**.

```sh
# 1. Profile: Observe what a script touches under default-deny to generate a draft manifest.
#    Egress is recorded but blocked by default; host credentials are never exposed during profiling.
bento profile ./fetch.py

# 2. Validate: Check manifest syntax and review requested permissions.
bento validate ./fetch.py.manifest.yaml --strict

# 3. Approve: Stamp an approval fingerprint over the reviewed manifest policy fields.
bento approve ./fetch.py.manifest.yaml

# 4. Run: Execute the script inside the enforced sandbox.
#    Refuses to run if the manifest is unapproved or modified unless --allow-unapproved is passed.
bento run ./fetch.py.manifest.yaml

# Inspect Host Capabilities: Verify what isolation mechanisms this host kernel enforces.
bento doctor
```

---

## Security & Threat Model

Bento assumes the sandboxed program may be hostile or contain compromised dependencies. For complete details on adversary assumptions, non-goals, and residual security gaps, see **[`docs/threat-model.md`](docs/threat-model.md)**.

To report a boundary failure privately, and for how versioning treats a shield regression, see **[`SECURITY.md`](SECURITY.md)**.

### What Bento Protects
1. **Credentials & Secrets:** SSH keys, cloud CLI tokens, GPG keyrings, crypto vaults, and shell histories under `$HOME`.
2. **Host Integrity & Persistence:** Blocks write access to persistence vectors such as `.git/hooks`, `.vscode`, `.idea`, and shell initialization files (`.bashrc`, `.zshrc`).
3. **Host Service Sockets:** Shields unix control sockets in `/run` and `/var/run` (e.g., Docker daemon, gpg-agent, session bus) to prevent host compromise via socket connections.
4. **Network Egress:** Denies outbound network connections by default via an empty network namespace (`--unshare-net`).
5. **Secrecy During Profiling:** Profiling inspects syscall registers directly (via `ptrace`) without opening host files, preventing untrusted scripts from probing secrets during manifest discovery.

### Built-in Shields & Exceptions
- **Directory-Granular Write Grants:** Write grants name directories, not individual files (preserving save-via-rename workflows like `os.replace` or `git`). Write grants covering shielded paths (e.g., `write: ~`) are strictly refused.
- **Explicit Shield Opt-In:** An explicit read grant naming an exact shield path (e.g., `read: ~/.ssh/id_rsa`) is honored as a deliberate, read-only exception with loud warnings. Write grants to shield paths remain forbidden.
- **Fail-Closed Principle:** Any ambiguity, missing permission, unhandled network request, or missing kernel feature fails closed by default.

---

## Manifest Reference

Manifests define the sandbox policy in YAML:

```yaml
entrypoint: ./fetch.py          # Script or binary to execute
interpreter: python3            # Optional interpreter (omit for compiled binaries)
args: [--verbose]

env: [LANG, AWS_DEFAULT_REGION]  # Allowlist of environment variable names to pass through

read:  [./data]                 # Allowed read paths (deny-by-default; relative to manifest)
write: [./out]                  # Allowed write directories (automatically created if missing)

network:                        # Allowed egress rules (empty/omitted means all network denied)
  - host: api.github.com
    port: "443"

exec: none                      # Subprocess execution: none | none-strict | all
limits: { memory: 128M, cpu: 100%, pids: 32 }

# Provenance block generated by `bento approve`
provenance:
  generated-by: bento profile
  generated-at: 2026-07-14T00:00:00Z
  approves: <sha256-fingerprint-over-policy-fields>
```

---

## Enforcement Matrix

Bento organizes enforcement capabilities into **Core** and **Hardening** tiers:

| Guarantee | Tier | Linux Mechanism |
|---|---|---|
| Read only granted paths | Core | Bubblewrap read-only bind mounts, deny-by-default root |
| Write only granted directories | Core | Bubblewrap read-write bind mounts; root remounted read-only |
| Shield credentials & dotfiles | Core | Mandatory denylist bind mounts (covers uncreated paths) |
| Deny network egress by default | Core | Empty network namespace (`--unshare-net`) |
| Per-host:port network egress | Core | Host-side HTTP CONNECT proxy over isolated unix socket |
| Block `execve` subprocesses | Hardening | Seccomp syscall filter (`none-strict` blocks fork/clone on amd64) |
| Memory / CPU / PID limits | Hardening | Systemd transient scope with cgroup v2 controllers |
| Filesystem backstop | Hardening | Landlock LSM rules (best-effort secondary layer) |

If a hardening layer is missing on the host, `bento doctor` flags the shortfall. When `--strict` is passed, `bento run` refuses to execute under degraded enforcement.

---

## Architecture

Bento is architected around a platform-decoupled enforcement seam:

- **`enforce`**: Core `Enforcer` interface (`Probe` + `Run`) and degradation reporting (`Report`, enforcement tiers).
- **`policy`**: Domain model, manifest validation, host:port matching, and approval fingerprinting.
- **`internal/denylist`**: Platform-independent mandatory denylist data structures and rules.
- **`internal/linux`**: Linux implementation using bubblewrap, `internal/launcher`, `internal/observe` (ptrace profiler), seccomp, and Landlock.
- **`internal/proxy`**: Shared host-side egress HTTP CONNECT proxy.
- **`manifest`**: YAML manifest loader, serializer, and provenance tracker.
- **`backend`**: Backend selection logic and profiling synthesis.

---

## Embedding Bento (Go Library)

Bento can be imported directly into Go applications to enforce sandbox policies in-process, receive structured execution results, or supply custom interactive network gates (such as prompting a human when an agent attempts undeclared network egress).

### Minimal Example

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/whiskeyjimbo/bento/backend"
	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/manifest"
)

func main() {
	// Dispatch sandbox re-exec stage before any other initialization
	backend.DispatchReexec()

	ctx := context.Background()

	// 1. Load and parse the manifest file
	manifestPath := "fetch.py.manifest.yaml"
	f, err := os.Open(manifestPath)
	if err != nil {
		log.Fatalf("failed to open manifest: %v", err)
	}
	defer f.Close()

	pol, err := manifest.Load(f)
	if err != nil {
		log.Fatalf("invalid manifest policy: %v", err)
	}

	// 2. Anchor the policy's relative paths to the manifest's own directory. Kept out
	// of Load because it must run after any approval/fingerprint check, never before.
	if err := manifest.Resolve(pol, manifestPath); err != nil {
		log.Fatalf("path resolution failed: %v", err)
	}

	// 3. Resolve environment variables allowed by the manifest policy
	env, _, err := enforce.ResolveEnv(pol, nil, os.LookupEnv)
	if err != nil {
		log.Fatalf("env resolution failed: %v", err)
	}

	// 4. Create the platform backend enforcer
	e, err := backend.New()
	if err != nil {
		log.Fatalf("failed to instantiate enforcer: %v", err)
	}

	// 5. Run the target inside the sandbox
	proc := enforce.Process{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Env: env}
	res, err := enforce.Run(ctx, e, pol, proc, enforce.Options{})
	if err != nil {
		log.Fatalf("execution error: %v", err)
	}

	fmt.Printf("Exit Code: %d, Degraded: %v\n", res.ExitCode, res.Report.IsDegraded())
}
```

### Runnable Examples

Explore the [`examples/`](examples/) directory for complete, runnable reference code:

- **[`examples/embed`](examples/embed)**: In-process execution with an interactive `NetworkGate` supervisor that prompts human approval for undeclared egress.
- **[`examples/supervise`](examples/supervise)**: Full 2-act interactive wrapper demonstrating trial profiling for filesystem access and live proxy gating for network egress.

### Live Network Gates vs. Filesystem Approvals

When building a supervised wrapper (such as an editor agent or interactive CLI tool), Bento exposes two distinct interaction models:

- **Live Network Egress (`NetworkGate`)**: Outbound traffic is routed through Bento's host-side proxy, allowing your application to supply a live callback (`opts.NetworkGate`) that prompts or evaluates egress requests synchronously at connect time.
- **Pre-Run Filesystem Approvals**: File access is enforced directly inside the Linux kernel (Landlock and mount namespaces) and fails fast with `EACCES` without a userspace callback seam. Supervised wrappers implement filesystem policy by running a trial profiling pass (`backend.Profile`), prompting the user to approve/deny recorded file paths, and passing the resulting policy into the enforced run (`enforce.Run`).

---

## Development & Testing

Run tests and checks locally:

```sh
# Run tests (sandbox tests automatically skip if bwrap/userns are missing)
GOWORK=off go test ./...

# Run vet
GOWORK=off go vet ./...

# Audit denylist against upstream firejail reference definitions
./scripts/denylist-audit.sh

# The proxy's concurrency tests under the race detector, or `make check` for all gates
GOWORK=off CGO_ENABLED=1 go test -race ./internal/proxy/...
```

`-race` on `internal/proxy` is a gate, not extra credit: the proxy's
cross-connection properties - a gate or egress-guard verdict never landing on
another connection - rest on shared state whose narrower breakages pass hundreds
of plain runs and fail immediately under the race detector. It needs a C toolchain
(`-race` requires cgo).

The test suite executes real probes inside real bubblewrap sandboxes to verify that security boundaries strictly hold.

---

## License & Security

Bento is released under the [Apache 2.0 License](LICENSE).

For security architecture, threat boundaries, and architectural decision records, refer to [`docs/architecture.md`](docs/architecture.md), [`docs/threat-model.md`](docs/threat-model.md), and [`docs/adr/`](docs/adr/).

