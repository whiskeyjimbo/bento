<p align="center">
  <img src=".github/assets/bento-gopher.png" width="25%" alt="Bento Gopher Logo" />
</p>

# Bento

**Run untrusted scripts under strict, manifest-declared permissions.**

Bento is a lightweight, fail-closed sandbox for Linux that executes untrusted code (build scripts, CLI utilities, AI agent actions) with deny-by-default security. It shields host credentials even if a manifest includes broad read grants, isolates filesystem access, blocks unauthorized network egress, and prevents subprocess execution.

Bento surfaces any gap between what a manifest requests and what the host kernel can enforce, refusing to run under degraded security when `--strict` is enabled.

> **Status:** Fully implemented and verified on **Linux (amd64)** using bubblewrap, seccomp, Landlock, and systemd cgroups. Support for **Linux (arm64)** and **macOS** is planned. See [`docs/architecture.md`](docs/architecture.md) for architecture details and [`docs/threat-model.md`](docs/threat-model.md) for security boundaries.

---

## Why Bento?

Bubblewrap and Landlock do the isolation, and Bento uses both. These five are what it
adds on top:

- **Credentials stay shielded under a grant that covers them.** `read: "~"` does not expose `~/.ssh`, `~/.aws`, GPG and OS keyrings, environment-relocated secret stores, `.netrc`, shell histories, runtime sockets in `/run`, or persistence targets like `.git/hooks` and `.vscode`. The denylist is a maintained corpus, held to parity with firejail's and AppArmor's reference definitions by `make audit`, and it shields paths that do not exist on the host yet. Parity with those corpora is not completeness - both are desktop-application sandboxes, so developer token stores are still found by review.
- **Permissions you can attest, not just declare.** Policy lives in a readable `manifest.yaml`, and `bento approve` stamps a fingerprint over the policy fields. Edit the manifest afterwards and `bento run` refuses until a human re-reviews it. That is the answer to unreviewed permission creep in CI and autonomous agents, which is a likelier failure than an escape.
- **Egress decided per host, and decidable live.** Traffic is denied by default in an unshared network namespace; allowed hosts route through a host-side HTTP CONNECT proxy with hostname validation and IP pin checks. An embedder can supply a `NetworkGate` and approve or refuse a connection at connect time, so a wrapper can ask a human.
- **Discovery that never opens the paths it records.** `bento profile` watches a program under `ptrace`, reading the paths out of syscall registers rather than opening them, and the program runs sandboxed while it does. So drafting a manifest for code you do not trust is not its own exposure.
- **No quiet degradation.** `bento doctor` reports what this kernel actually enforces, layer by layer. A core guarantee that can only be partially enforced stops the run rather than silently becoming a weaker sandbox, and `--strict` extends that to the hardening tier.

---

## Requirements & Installation

### Requirements
- **OS:** Linux with `bubblewrap` (`bwrap`) installed and unprivileged user namespaces enabled.
- **Build Toolchain:** Go 1.26 or later.
- **Optional:** `systemd` user manager with delegated `memory`, `pids`, and `cpu` controllers for resource limits.

### Build from Source
```sh
make build                    # reproducible static binary (trimmed paths, source-derived stamp)
go build -o bento ./cmd/bento # plain build
```

A build for a target other than Linux succeeds by design and produces a working
binary - the tree carries a stub backend for it, so `bento validate` and `bento approve`
answer there and a manifest can be reviewed and stamped on a Mac. Anything that has to
build or probe a sandbox - `run`, `profile`, `doctor` - refuses at startup with a single
message naming the platform. There is no build-time error to catch this instead: Go has
no compile-time warning, and a `//go:build linux` guard on the command would take the two
commands that do work off Linux with it.

### Running Inside a Container

A stock container cannot run Bento: it builds its sandbox out of the same kernel
features the container runtime already restricts, so `bento doctor` reports the
core layers degraded or unavailable and runs are refused. On Docker, three
default restrictions are in the way, and all three have to be lifted:

```sh
docker run --security-opt seccomp=unconfined \
           --security-opt apparmor=unconfined \
           --security-opt systempaths=unconfined \
           ...
```

The image also has to carry `bubblewrap` itself. It is not in the stock
`ubuntu`, `debian`, or `alpine` images, and without it neither core layer is
enforced: the network layer is unavailable and the filesystem layer falls to
Landlock at best, with `doctor` naming the missing package. The flags above
change nothing until it is installed:

```dockerfile
RUN apt-get update && apt-get install -y bubblewrap   # Debian/Ubuntu
```

- `seccomp=unconfined` - the default profile blocks `unshare(CLONE_NEWUSER)` and
  `pivot_root` for a container without `CAP_SYS_ADMIN`, which is how bubblewrap
  builds its namespace and root.
- `apparmor=unconfined` - needed on hosts with
  `kernel.apparmor_restrict_unprivileged_userns=1` (Ubuntu 23.10 and later).
  Loading an AppArmor profile that permits `bwrap` is the narrower alternative,
  but it is a change to the *host*, which in CI you may not control.
- `systempaths=unconfined` - Docker masks paths under `/proc`, and bubblewrap
  cannot mount a fresh `procfs` over a masked one. Without it `doctor` reports
  the filesystem layer degraded - unavailable on a kernel with no Landlock to
  fall back to - and names this flag, and a run is refused rather than failing
  at setup with `Can't mount proc on /newroot/proc`.

Weigh this honestly: those flags loosen the *outer* container, so the isolation
the container gave you is traded for the isolation Bento gives you. That is a
reasonable trade when the container is a CI job runner whose purpose is to run
Bento, and a poor one when it is a shared multi-tenant sandbox. Running Bento
directly on the CI host - GitHub-hosted runners permit unprivileged user
namespaces - needs none of it.

Resource limits stay unavailable in a container without a systemd user manager;
that is a hardening layer, so runs proceed unless `--strict` is passed.

### In CI

The artifact CI consumes is the approved manifest, committed next to the script.
Profiling and approval happen once, on a developer's terminal; the pipeline only
checks the stamp is still good and runs under it. On a GitHub-hosted runner that
is the whole job - unprivileged user namespaces are permitted there, so none of
the container flags above apply:

```yaml
jobs:
  sandboxed:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get update && sudo apt-get install -y bubblewrap
      - run: go install github.com/whiskeyjimbo/bento/cmd/bento@latest
      - run: bento doctor
      - run: bento validate --strict ./fetch.py.manifest.yaml
      - run: bento run --env CI_TOKEN="$CI_TOKEN" ./fetch.py.manifest.yaml
        env:
          CI_TOKEN: ${{ secrets.CI_TOKEN }}
```

`validate --strict` is the gate: it fails the job if the manifest is unapproved
or was edited since approval, which is what stops permission creep landing in a
pipeline nobody re-reviewed. `run` needs no approval flags once the stamp is in
the repo - if it did, the gate would not mean anything. The `--env` above supplies
a secret's value, which is a separate thing from granting it: `CI_TOKEN` still has
to be in the manifest's `env:` list, and that list is inside the fingerprint.

---

## Quick Start Workflow

Bento follows a 4-step workflow: **Profile → Validate → Approve → Run**, with
`bento doctor` before all of it.

Run it against [`examples/probe`](examples/probe), a script that reports what the
sandbox actually lets it read, write, reach, and execute - so each step has
visible output rather than a silent success.

```sh
go build -o examples/probe/bento ./cmd/bento
cd examples/probe

./bento doctor                               # 0. what this host can actually enforce
./bento profile  ./probe.py                  # 1. observe what it touches, draft a manifest
./bento validate ./probe.py.manifest.yaml    # 2. check it, and read what it grants
./bento approve  ./probe.py.manifest.yaml    # 3. stamp a fingerprint over the permissions
./bento run      ./probe.py.manifest.yaml    # 4. execute under them
```

Run step 0 first on a host you have not run Bento on before. A core layer this
kernel cannot enforce is a refusal at step 4, and `doctor` is where you find
that out before drafting a manifest - a stock Ubuntu 24.04 install has no
`bubblewrap`, which is one `apt-get` away but only if you know to look.

Each step has a detail worth knowing before you rely on it:

**1. Profile** is a loop on a terminal, not one shot: each round asks per path
(`[y]es` / `[n]o` / `[a]ll` / `[q]uit`), mounts what you accept, and runs again until the
target stops finding new ones. With stdin not a terminal (a pipe, CI, `< /dev/null`) it
makes one non-interactive default-deny pass instead, granting nothing you were not asked
about - only a write directory the target died on is created for a second pass - so a
target that branches on a missing file under-reports, and you profile again with grants.
Egress is recorded but blocked by default; host credentials are never exposed during
profiling. Profiling again merges rather than replaces, so you end up with this run
unioned with whatever was already there. Profile says what it changed, including an exec
widened to `all` and an approval stamp the write drops.

**2. Validate** reports the approval state; `--strict` makes a missing or stale approval a
failure, so it belongs after step 3 (in CI), not here. It also reports whether this host
can start what the manifest names - an entrypoint that is not there, an interpreter not on
PATH - which `--strict` fails on too.

**3. Approve** prints the policy, calls out what deserves a second look, and asks. `--yes`
for CI; a stdin that is not a terminal (a pipe, a Makefile recipe) is refused rather than
answered, so an unreviewed stamp is something a caller asked for with `--yes`.

**4. Run** refuses if the manifest is unapproved or modified, unless `--allow-unapproved`
is passed.

Step 2 is where the work is. A profiled manifest describes what that one run
did, not what the script should be allowed to do: here it proposes `exec: all`,
a write grant over the whole example directory, and *both* hosts the probe
tried - including the one it was denied. Profiling drafts a manifest; approving
one is a judgement you make.

The credential shields are the headline feature and this sequence does not show them:
the probe demonstrates them against `BENTO_PROBE_HOME`, and a profiled manifest
allowlists only the variables the run actually read, so the shield probes report SKIPPED
here. Env does not cross into the sandbox unless the manifest names it - which is the
same lesson, arriving the hard way. The tour below runs them.

The probe example also ships hand-written manifests covering the deny-all floor,
narrow grants, a broad home grant with the credential shields still holding,
per-host egress, and the hardening tier. See its
[README](examples/probe/README.md) for a five-minute tour.

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
- **Directory-Granular Write Grants:** Write grants name directories, not individual files (preserving save-via-rename workflows like `os.replace` or `git`). Write grants covering shielded paths (e.g., `write: "~"`) are strictly refused, and so are write grants naming or inside one (`write: ~/.ssh`, `write: ~/.bashrc`) - by `validate --strict` and `approve` on a host that can resolve the grants, and by `run` in any case.
- **Explicit Shield Opt-In:** An explicit read grant naming an exact shield path (e.g., `read: ~/.ssh`) is honored as a deliberate, read-only exception with loud warnings. Write grants to shield paths remain forbidden.
- **Manifest Integrity Warnings:** `validate`, `approve`, and `run` inspect the manifest's own ownership and permissions - including POSIX ACLs, which the mode bits cannot show - and warn when someone other than you can rewrite it. An approval stamp only attests to what whoever can write the file left there.
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
  blocked-hosts: []             # Destinations bento's own egress guard refused to reach
```

A destination lands there only when the guard refused it because the name resolved into
space the sandbox must not reach - loopback, private ranges, cloud metadata - not because
a profiling run declined to forward it. A default `bento profile` forwards no egress at
all, so nothing is dialed and the list stays empty; it is populated only under
`--allow-network`.

The `blocked-hosts` list records how the manifest was drafted, not what it grants, so it
stays out of the `approves` fingerprint. `bento approve` calls out any `network:` rule
that matches one, so you are not asked to stamp egress bento itself would refuse.

### Environment variables

`env:` is an allowlist of names, not of values. A name on it passes through with
whatever value bento's own environment holds; everything else in that environment
stays out of the sandbox. For a value the calling environment does not carry - a CI
secret, most often - pass it to `bento run` on the command line:

```sh
bento run --env CI_TOKEN="$CI_TOKEN" ./fetch.py.manifest.yaml
```

`--env` supplies a value; it does not grant one. A name it names that is not in the
manifest's `env:` list is refused, so a secret reaching the sandbox is a reviewed and
stamped decision either way. An allowlisted name with no value anywhere says so at run
time rather than handing the script an empty string.

`--json`, `--interpreter` and `--out` are documented in `bento <command> --help`.

### Paths and `~`

Read and write paths may start with `~`. Bento replaces it with your home directory as
it builds the sandbox, so `read: [~/projects/api]` grants `/home/you/projects/api`.
Three details: quote a bare `"~"`, because unquoted YAML reads it as null; only your own
home expands, so spell out another user's (`/home/operator/...`); and a file whose name
really starts with a tilde needs a `./` prefix (`./~backup`).

Your script does not see that same home directory. Bento sets `HOME=/tmp` in the
sandbox to keep credential files under the real home out of reach, so a script that
expands `~` itself gets `/tmp/projects/api` and fails to open a file you granted. Either
have the script use the full path (`/home/you/projects/api`), or add `HOME` to the
manifest's `env:` list so the real value is passed through. `bento validate` prints the
`HOME` your script will see.

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

A core guarantee that can only be partially enforced stops the run by default. `--allow-degraded` overrides that, and it is the widest escape hatch Bento has: it also skips the credential-alias scan entirely, so aliased copies of shielded paths under a granted tree are exposed rather than acknowledged. Use `--accept-alias <path>` to acknowledge a specific tree instead.

---

## Architecture

Bento is architected around a platform-decoupled enforcement seam:

- **`enforce`**: Core `Enforcer` interface (`Probe` + `Run`) and degradation reporting (`Report`, enforcement tiers).
- **`policy`**: Domain model, manifest validation, host:port matching, and approval fingerprinting.
- **`internal/denylist`**: Platform-independent mandatory denylist data structures and rules.
- **`internal/linux`**: Linux implementation using bubblewrap, `internal/launcher`, `internal/observe` (ptrace profiler), seccomp, and Landlock.
- **`internal/proxy`**: Shared host-side egress HTTP CONNECT proxy.
- **`manifest`**: YAML manifest loader, serializer, and provenance tracker.
- **`profile`**: The `Observation` a profiling pass records, which `backend.Profile` returns and manifest synthesis consumes.
- **`backend`**: Backend selection logic and profiling synthesis.

---

## Embedding Bento (Go Library)

Bento can be imported directly into Go applications to enforce sandbox policies in-process, receive structured execution results, or supply custom interactive network gates (such as prompting a human when an agent attempts undeclared network egress).

### `DispatchReexec` is mandatory

Confining a target re-invokes the embedding binary as a hidden launch stage, so `backend.DispatchReexec()` must be the first statement in `main()` - before flag parsing, before any other initialization. **This applies to tests too:** any test package that performs an enforced or profiling run needs it at the top of `TestMain`, before the testing package parses flags. Without it the staged child runs the whole test suite again, which re-enters the sandbox and stages again.

```go
func TestMain(m *testing.M) {
	backend.DispatchReexec()
	os.Exit(m.Run())
}
```

A call that never happened is caught before any run starts: `backend.New` and `backend.Profile` return an error naming the missed call. They panic instead when the process they are called in is *itself* an undispatched stage, which is what stops the test-suite fork bomb.

A call made too late - after flag parsing, where the stage dies on its own argv before reaching it - still reaches neither guard, so the parent-side guarantee stands behind both: the stage writes what it applied before it dispatches the target, so a run whose stage stayed silent provably never ran the target, and `enforce.Run` returns an `*enforce.Refusal` saying so. The `log.Fatalf` on `err` in the example below catches every one of these; it will never report a clean exit 0 for a target that never started.

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

	fmt.Printf("Exit Code: %d, Degraded: %v\n", res.ExitCode, res.Report.HasDegradation())
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

This checkout is not part of the parent `go.work`, so every `go` command needs
`GOWORK=off`. The Makefile sets it for you - prefer the targets over raw commands.

```sh
make test      # unit and integration tests (sandbox tests skip if bwrap/userns are missing;
               # the denylist parity tests also want firejail and its apparmor profiles)
make vet
make lint      # golangci-lint, pinned
make audit     # denylist parity against upstream firejail reference definitions
make race      # the proxy's concurrency tests under the race detector (needs a C toolchain)
make examples  # each examples/*/verify.sh; the root go test does not reach them

make check     # every gate above - the bar before merging
```

`-race` on `internal/proxy` is a gate, not extra credit: the proxy's
cross-connection properties - a gate or egress-guard verdict never landing on
another connection - rest on shared state whose narrower breakages pass hundreds
of plain runs and fail immediately under the race detector.

The test suite executes real probes inside real bubblewrap sandboxes to verify that security boundaries strictly hold.

To exercise those boundaries by hand, [`examples/probe`](examples/probe) is a
Python script that runs inside the sandbox and reports what it can actually
read, write, reach, and execute, one line per probe. It ships with manifests
covering the deny-all floor, narrow grants, a broad home grant with the
credential shields still in place, per-host egress, and the hardening tier
(`none-strict`, memory and pid caps). Useful for checking a host's enforcement
after a kernel or bubblewrap change, and for seeing what a given manifest really
buys before approving it.

---

## License & Security

Bento is released under the [Apache 2.0 License](LICENSE).

For security architecture, threat boundaries, and architectural decision records, refer to [`docs/architecture.md`](docs/architecture.md), [`docs/threat-model.md`](docs/threat-model.md), and [`docs/adr/`](docs/adr/).

