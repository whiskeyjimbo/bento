<p align="center">
  <img src=".github/assets/bento-gopher.png" width="25%" alt="Bento Gopher Logo" />
</p>

# Bento

A polyglot script sandbox for Linux and macOS. Declare a script's
permissions in a YAML manifest; run it under kernel-enforced
isolation.

`bento` uses native OS sandboxing primitives (`sandbox-exec` on macOS,
`bubblewrap` on Linux) plus proxy-based network filtering. It can run
untrusted Python, Node, bash, Go, or other interpreter-driven scripts
without containers and without root.

> **Pre-1.0**
>
> The public API (`bento.Run`, `bento.Doctor`, options, manifest
> types) is unlikely to break in incompatible ways before 1.0 but
> small adjustments are possible. The macOS path compiles cleanly but
> has not been runtime-verified; structural parity with Linux is the
> design intent. Contributions welcome.

## Installation

```bash
# CLI
git clone https://github.com/whiskeyjimbo/bento
cd bento
make build                             # builds the launcher, fsshim, and bin/bento

# Option A — just try it out, no install:
./bin/bento doctor

# Option B — install system-wide:
sudo install bin/bento /usr/local/bin/
bento doctor

# Library
go get github.com/whiskeyjimbo/bento
```

The `bento doctor` step confirms the host has the sandboxing primitives
bento expects; if it reports something missing (e.g. an AppArmor profile
on Ubuntu 24.04+), `bento setup` will apply the fix where it can.

The examples below assume `bento` is on your `$PATH`; substitute
`./bin/bento` if you skipped the install step.

## Basic Usage

The fastest on-ramp: let `bento profile` record one trial run and write a
starter manifest you can review and trim.

```bash
# First-time check: does the host have what bento needs?
$ bento doctor
[PASS] bwrap binary — bubblewrap 0.9.0
[PASS] Landlock TCP — ABI=4
[PASS] mandatory-deny paths — 20 read-protect, 9 write-protect
all checks passed

# 1. Generate a manifest from a trial run (script's directory is auto-read;
#    network is permissive and observed so you can trim it).
$ bento profile ./fetch.py
[bento] profiling "./fetch.py" (permissive network)...
[bento] observed network:
  Host                              Port    Count
  api.example.com                   443     2
[bento] wrote fetch.manifest.yaml — review and trim before running with `bento run`

# 2. Inspect what bento will actually enforce.
$ bento validate fetch.manifest.yaml
manifest: /tmp/fetch.manifest.yaml — ok
interpreter: python3  →  /usr/bin/python3
script:      /tmp/fetch.py
read:
  - /tmp
network:
  - api.example.com:443
exec:        blocked (no subprocesses)

# 3. Run it.
$ bento run fetch.manifest.yaml

# Useful variations
$ bento run script.py                              # zero-config (no network)
$ bento run ./my-go-binary                         # ELF binary, no interpreter
$ bento run --timeout=30s --env ID=abc deploy.yaml
$ bento run --network-mode=bridge fetch.yaml       # kernel < 6.7 fallback
$ bento run --prompt fetch.yaml                    # interactive allowlist on misses
$ bento doctor --skip-network --fail-fast          # CI-friendly

# Bash and other shell scripts: zero-config blocks subprocess execve, so
# any script that runs `ls`, `grep`, `curl`, etc. (i.e. almost every bash
# script) will fail with "Operation not permitted" until you opt in.
# Profile with --allow-exec to capture a manifest with allow_exec: true:
$ bento profile --allow-exec ./deploy.sh           # writes deploy.manifest.yaml

# Per-subcommand flags
$ bento run --help                                 # full flag list for run
$ bento profile --help                             # full flag list for profile
```

### Sandbox conventions worth knowing up front

- **Host environment is not passed through.** This is the most common
  surprise. `$USER`, `$LANG`, `$PATH`, `$AWS_PROFILE`, `$NODE_ENV`, and
  every other host env var is stripped by default; scripts see a minimal
  env. A script that reads `$DATABASE_URL` will get an empty string and
  silently misbehave. To inherit specific vars, list them in the
  manifest's `env:` allowlist; to add new ones, use `--env KEY=VALUE` or
  `WithExtraEnv`.
- Inside the sandbox `cwd` is `/sandbox` and `$HOME` is `/sandbox`. Scripts
  that hard-code `$PWD` against the host directory will see a different
  path; reference the script's own location (`__file__`, `$0`) instead.
- The script is mounted at `/sandbox/script`; declared `read` and `write`
  paths keep their host paths.
- Zero-config (`bento run script.py`) gives the script no network at all.
  If a `urlopen()` or `curl` call fails with DNS errors, you almost
  certainly want `bento profile` to record the hosts and then run under
  the trimmed manifest.
- Zero-config also blocks subprocess execve. A `subprocess.run([...])`
  or backtick exec will fail with `Operation not permitted`. To allow
  subprocesses, set `allow_exec: true` in the manifest (or use
  `bento profile --allow-exec <script>` to generate one).
- Mandatory-deny shadows file *contents*, not file *existence*. A script
  with broad read access can `os.listdir("$HOME")` and see the names of
  protected files (`.ssh/`, `.bashrc`, `.aws/credentials`), but opening
  them returns `Permission denied`. Don't store secrets in filenames.
- If you're just trying bento out, you can run the local build directly
  without installing: after `make build`, use `./bin/bento doctor` etc.
  in place of `bento` in the snippets below.

## Overview

Bento provides a sandbox implementation usable as both a CLI tool and
a Go library. It's designed with a **secure-by-default** philosophy
for running untrusted scripts: every read, write, exec, and network
target must be explicitly allowed, and bento adds always-block
defaults for credentials and persistence vectors that users would
forget about.

**Key capabilities:**

- **Filesystem isolation**: deny-by-default reads and writes; bind-mount
  exactly the paths the script declares
- **Network isolation**: per-host allowlists enforced via local
  HTTP CONNECT + SOCKS5 proxies; static-binary bypass blocked at the
  kernel (Landlock) or via a fully isolated network namespace + socat
  bridge
- **Exec control**: seccomp filter blocks `execve` when the manifest
  forbids subprocess spawning
- **Resource limits**: `systemd-run` cgroup wrap for memory, CPU, and
  task ceilings
- **Mandatory defaults**: SSH keys, cloud creds, shell rc files, and
  `.git/hooks` are protected regardless of user config
- **Bypass-resistant**: host validation refuses `inet_aton` shorthand
  (`127.1` → `127.0.0.1`), null-byte allowlist tricks, and IPv6 zone-ID
  payloads
- **Two Linux network modes**: kernel-native Landlock TCP (modern
  kernels) or a socat unix-socket bridge (any kernel) — `auto`
  selects per environment

### Example Use Case: running an untrusted automation script

Imagine a script that ingests a webhook payload, parses some data,
and posts results to a specific API. You don't want it to read
arbitrary files or talk to arbitrary hosts.

**Without sandboxing:** the script can read your `~/.aws/credentials`,
write to `~/.bashrc`, and exfiltrate to anywhere. A bug or a
supply-chain compromise has full account access.

**With bento** (`fetch.yaml`):

```yaml
interpreter: python3
script: ./fetch.py
read:
  - /tmp/webhook-input.json
write:
  - /tmp/results
network:
  rules:
    - host: api.example.com
      port: "443"
limits:
  memory: "128M"
  cpu: "100%"
  tasks: 32
```

```bash
$ bento run fetch.yaml
```

The script can read its input file and write its output dir. It can
HTTPS to one host. It cannot read SSH keys. It cannot spawn
subprocesses. It dies if it allocates more than 128 MiB. A bug or
compromise is contained.

## How It Works

Bento uses OS-level primitives that apply to the entire process tree:

- **macOS**: dynamically generated SBPL (Seatbelt) profiles passed to
  `sandbox-exec`
- **Linux**: `bubblewrap` for filesystem/PID/mount namespacing, plus
  one of two network backends (see below) and a small `bento-launcher`
  shim that installs seccomp + Landlock rules after `execveat`-ing
  the interpreter

### Two-layer network filtering

| Layer | Catches | Mechanism |
|---|---|---|
| **HTTP CONNECT proxy** | curl, requests, `net/http`, urllib — anything that honors `HTTPS_PROXY` | Local proxy filters by Host header |
| **SOCKS5 proxy via LD_PRELOAD** | SMTP, postgres, redis — dynamically-linked binaries doing raw `connect()` | `proxychains4` intercepts libc `connect()` and routes through SOCKS5 |
| **Landlock TCP allowlist** OR **netns + socat bridge** | Static Go/Rust binaries doing raw `syscall.Connect` | Either kernel restricts ports (Landlock) or there's no route except through the bridge (netns) |

All layers enforce the same per-host allowlist defined in the manifest.

### Two filesystem isolation primitives

- **Linux**: bwrap bind-mounts grant exactly the declared paths
  (`--ro-bind` for reads, `--bind` for writes); `/dev/null` is mounted
  over always-blocked files; `.git/hooks` directories get re-bound
  read-only inside any writable workspace
- **macOS**: SBPL `(deny default)` + explicit `(allow file-read*
  (subpath ...))` and `(allow file-read* file-write* (subpath ...))`
  rules

### Mandatory deny

Two always-block lists ship in `internal/spec/dangerous.go`:

- **Read protection** — SSH private keys, `.aws/credentials`,
  `.config/gcloud/*`, `.kube/config`, `.netrc`, `.git-credentials`,
  `.npmrc`, etc. Prevents credential exfil even when the user grants
  blanket home-dir read.
- **Write protection** — shell rc files (`.bashrc`, `.zshrc`,
  `.profile`), `.gitconfig`, `.mcp.json`. Prevents
  persistence-via-rc-file even when the user grants home-dir write.
  Workspace-relative `.git/hooks` and `.git/config` are also shielded
  inside any user-declared writable workspace.

The user can't bypass these by adding the paths to their `read`/
`write` lists — the mandatory-deny binds are emitted AFTER user binds
and take precedence.

**Existing-files-only caveat.** The shadow is `--ro-bind /dev/null
<path>`, which requires the path to exist *at sandbox start*. If a
target file is absent on the host when bento runs, no shadow is
installed for it. A script with write access to the containing
directory could then *create* the path inside the sandbox without
hitting the shadow. In practice this matters in two cases:
(1) shell rc files that don't exist yet on a fresh user (e.g.
`~/.zshrc` on a bash-only user) — the persistence vector reopens if
the script can write `$HOME`; and (2) tools that initialize
credential stores on first use. `bento doctor` reports the
present/absent split for both lists (e.g. `20 read-protect (2
present)`) so you can see which entries are currently load-bearing.
The safe shape is to declare narrow `write:` paths rather than
blanket `$HOME`.

### Bypass-resistant host validation

The proxies refuse hosts that aren't already in canonical form before
matching against the allowlist:

- IP literals must be canonical (`127.0.0.1`, not `127.1` or
  `2852039166`). This blocks the `connect("2852039166", 443)` →
  169.254.169.254 (AWS IMDS) bypass.
- DNS-shaped strings must contain ≥1 letter in the last label (all-
  numeric labels are reserved by RFC 1123). Catches the same
  numeric-bypass class.
- No control characters (`\x00`, `\r`, `\n`) — defeats the
  `evil.com\x00.allowed.com` null-byte trick that bypasses naive
  `HasSuffix` matching.
- No `%` — defeats `::ffff:1.2.3.4%x.allowed.com` IPv6 zone-ID
  bypasses.
- Case-insensitive match (`EXAMPLE.com` matches rule `example.com`).

## Architecture

```
bento/
├── bento.go                    # public API (aliases + entry funcs)
├── doc.go                      # package docs
├── cmd/
│   ├── bento/                  # CLI entrypoint
│   └── bento-launcher/         # seccomp + Landlock shim binary (embedded)
└── internal/
    ├── spec/                   # manifest types + DangerousFiles
    ├── runner/                 # bwrap (Linux) + sandbox-exec (macOS)
    ├── proxy/                  # HTTP CONNECT + SOCKS5 + match logic
    ├── doctor/                 # environment health checks
    ├── sysprobe/               # find host binaries (bwrap, socat, ...)
    └── launcherbin/            # embedded launcher binary (regenerated by `make launcher`)
```

The `bento-launcher` is built as a separate `linux/amd64` binary and
embedded via `go:embed`. At runtime the parent process extracts it to
a temp file, bind-mounts it into the sandbox, and uses it as the
entrypoint. The launcher installs seccomp + Landlock rules, then
`execveat`s into the user's interpreter (using `execveat` so its own
final transition isn't blocked by the filter it just installed).

## Usage

### As a CLI tool

```bash
# bento run [flags] <manifest.yaml | script>
bento run check.yaml
bento run check.py                              # zero-config (no network)
bento run ./my-go-binary                        # ELF binary, no interpreter
bento run --timeout=30s check.yaml
bento run --env API_TOKEN=xyz --env DEPLOY_ID=42 check.yaml
bento run --network-mode=bridge check.yaml

# bento profile [flags] <script>   — record one trial run, emit a manifest
bento profile ./fetch.py                        # writes fetch.manifest.yaml
bento profile --out=mine.yaml --force ./fetch.py

# bento validate [-q] <manifest.yaml>           # print resolved view, or just "ok"
bento validate fetch.manifest.yaml

# bento doctor [flags]                          # host readiness
bento doctor
bento doctor --skip-network
bento doctor --fail-fast

# bento setup [--dry-run]                       # install host bits if needed
bento setup
```

`bento run` returns the script's exit code; a non-zero exit code does
NOT produce an error. Setup failures (interpreter missing, etc.) exit
with code 1.

### As a library

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/whiskeyjimbo/bento"
)

func main() {
    m := &bento.Manifest{
        Interpreter: "python3",
        Script:      "./fetch.py",
        Read:        []string{"/etc/hostname"},
        Write:       []string{"/tmp/results"},
        Network: &bento.NetworkPerm{
            Rules: []bento.NetworkRule{
                {Host: "api.example.com", Port: "443"},
                {Host: ".github.com", Port: "443"},
            },
        },
        Limits: &bento.Limits{Memory: "128M", CPU: "100%", Tasks: 32},
    }

    code, err := bento.Run(context.Background(), m,
        bento.WithLogger(log.New(os.Stderr, "", log.LstdFlags)),
        bento.WithTimeout(30*time.Second),
        bento.WithExtraEnv(map[string]string{"DEPLOY_ID": "abc123"}),
    )
    if err != nil {
        log.Fatal(err)
    }
    os.Exit(code)
}
```

#### Available exports

```go
// Types
type Manifest, NetworkPerm, NetworkRule, Limits
type Option, CheckOption, CustomCheck, CheckResult, Status, Logger
type NetworkMode  // NetworkModeAuto, NetworkModeLandlock, NetworkModeBridge

// Entrypoints
func Run(ctx, *Manifest, ...Option) (int, error)
func Doctor(io.Writer, ...CheckOption) bool
func Checks(...CheckOption) []CheckResult

// Run options
WithLogger(Logger), WithStdin, WithStdout, WithStderr
WithTimeout(time.Duration), WithExtraEnv(map[string]string)
WithNetworkMode(NetworkMode)

// Doctor options
WithSkipNetwork(), WithFailFast(), WithCheck(CustomCheck)
```

## Configuration

### Manifest format

```yaml
interpreter: python3        # resolved via $PATH
script: ./check.py          # relative to manifest, or absolute
args: ["--verbose"]         # appended after the script path

env:                        # host env vars to pass through (allowlist)
  - HOME
  - LANG

read:                       # paths the script can read
  - /etc/hostname
  - /tmp/data

write:                      # paths the script can write (implies read)
  - /tmp/output

network:                    # nil = no network at all
  rules:
    - host: api.example.com
      port: "443"
    - host: .github.com     # leading dot = suffix match
      port: "443"
    - host: "*"             # wildcard host
      port: "8000-9000"     # or port range

allow_exec: false           # true = let the script spawn arbitrary subprocesses
                            # (the seccomp+Landlock exec block is not installed).
                            # Default false = every execve fails with EPERM.
                            # NOTE: there is no per-binary allowlist today.
                            # The legacy `exec: [...]` field is accepted but
                            # deprecated — any non-empty value is treated as
                            # allow_exec: true; the list entries are not enforced.

limits:
  memory: "128M"            # systemd MemoryMax syntax
  cpu: "100%"               # systemd CPUQuota syntax
  tasks: 32                 # systemd TasksMax
```

### Common patterns

**Read-only script (analysis tool, formatter):**

```yaml
interpreter: python3
script: ./analyze.py
read:
  - .
# no write, no network, no exec — script must be pure
```

**Workspace + GitHub:**

```yaml
interpreter: python3
script: ./sync.py
read: ["."]
write: ["."]
network:
  rules:
    - host: ".github.com"
      port: "443"
```

**Webhook fetcher with timeout:**

```yaml
interpreter: python3
script: ./fetch.py
read: ["/tmp/webhook.json"]
write: ["/tmp/results"]
network:
  rules:
    - host: "api.example.com"
      port: "443"
limits:
  memory: "128M"
  tasks: 16
# CLI: bento run --timeout=30s webhook.yaml
```

### Error handling policy

`bento.Run` distinguishes hard errors from degraded modes:

- **Hard error** (`Run` returns non-nil) — required tool missing
  (`bwrap` on Linux, `sandbox-exec` on macOS); manifest interpreter
  not found; script file missing; proxy bind failure; symlink-escape
  detected on a write path.
- **Degraded mode** (`Run` proceeds, `[warn]` logged) —
  `libproxychains.so` missing (LD_PRELOAD layer disabled); Landlock
  TCP unavailable in `auto` mode (falls back to bridge);
  `systemd-run` missing (resource limits not enforced); launcher
  extraction failed (exec block disabled).

Pass `WithLogger` to observe warnings. Treating any warning as fatal
is the caller's choice; bento doesn't presume a security posture.

## Platform Support

| Platform | Status | Notes |
|---|---|---|
| Linux x86_64 | Supported | Both `landlock` and `bridge` network modes |
| Linux arm64 | Compiles, launcher build excluded | `bento-launcher` is `linux+amd64` only today; exec-block degrades |
| macOS | Compiles (untested) | sandbox-exec path; no cgroup limits yet |
| Windows | Not supported | bwrap and sandbox-exec are POSIX-only |

### Platform-specific dependencies

**Linux required:**
- `bubblewrap` (`apt install bubblewrap`)

**Linux optional (doctor warns if missing):**
- `socat` (`apt install socat`) — required only for bridge mode
- `proxychains4` (`apt install proxychains4`) — LD_PRELOAD layer
- `systemd-run` — resource limits

**Linux kernel/AppArmor:**
- Kernel ≥ 6.7 enables Landlock TCP path (otherwise bridge mode is
  used)
- Ubuntu 24.04+ requires an AppArmor profile for `bwrap` — see
  `testdata/bwrap.apparmor`; `bento doctor` reports the exact
  remediation command

**macOS:**
- ships with everything needed

## Development

```bash
# Build the launcher (regenerates embed target) + the CLI
make build

# Just the launcher
make launcher

# Run unit tests + e2e probes
make test

# Run e2e probes manually
./bin/bento run testdata/probe.manifest.yaml      # filesystem + network
./bin/bento run testdata/exec.manifest.yaml       # seccomp exec block
./bin/bento run testdata/membomb.manifest.yaml    # cgroup memory limit
./bin/bento run testdata/goprobe.manifest.yaml    # static-binary network bypass test
./bin/bento run testdata/dangerous.manifest.yaml  # mandatory-deny

# Test both network modes
./bin/bento run --network-mode=landlock testdata/probe.manifest.yaml
./bin/bento run --network-mode=bridge   testdata/probe.manifest.yaml
```

### Layout

The internal layout is detailed in [Architecture](#architecture)
above. Public surface: `bento.go` + `doc.go`.

## Implementation Details

### Network mode auto-selection

In `NetworkModeAuto`, bento inspects the kernel's Landlock ABI
(`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`)
and picks `landlock` if it's ≥ 4 (kernel 6.7+), else falls back to
`bridge`. An explicit `WithNetworkMode(NetworkModeBridge)` overrides.

### Landlock mode

- `bwrap --share-net` (script sees host network namespace)
- HTTP CONNECT proxy on ephemeral port; SOCKS5 proxy on ephemeral port
- `BENTO_ALLOW_PORTS=<httpPort>,<socksPort>` passed to launcher
- Launcher installs Landlock TCP rule allowing `connect()` only to
  those two ports
- Effect: static binaries doing `connect("anywhere", 443)` get
  EACCES from the kernel; they must use one of the proxy ports

### Bridge mode

- `bwrap --unshare-net` (full network namespace isolation; no route to
  anywhere)
- Host runs two socats per sandbox:
  `socat UNIX-LISTEN:/tmp/bento-http.sock TCP:localhost:<httpPort>`
- Sandbox runs two socats on fixed ports (3128/1080):
  `socat TCP-LISTEN:3128 UNIX-CONNECT:/tmp/bento-http.sock`
- HTTP_PROXY in the sandbox points to `127.0.0.1:3128`
- Effect: static binaries doing `connect("anywhere", 443)` get
  ENETUNREACH — there is no route except through the bridge

### Seccomp exec filter

The `bento-launcher` shim:

1. Opens the interpreter binary as an fd
2. Calls `prctl(PR_SET_NO_NEW_PRIVS)`
3. Installs a seccomp filter: deny `execve(2)` with EPERM, allow
   `execveat(2)` and everything else
4. Calls `execveat(fd, "", argv, envp, AT_EMPTY_PATH)` to become the
   interpreter — uses `execveat`, which the filter permits

After step 4 the interpreter is running with the filter active. Any
subsequent `subprocess.Popen` from the script returns `PermissionError`
because the underlying libc call uses `execve`, not `execveat`.

This indirection is necessary because bwrap's own `--seccomp FD`
mechanism installs the filter before bwrap's own final `execve` into
the interpreter — which would block bwrap. Doing it post-exec, in a
shim that itself uses `execveat`, works around that.

**Process visibility.** bwrap is invoked with `--unshare-pid`, so the
sandboxed process tree lives in its own PID namespace. After
`bento-launcher`'s `execveat`, the launcher process *becomes* the
interpreter (same PID); the script runs as PID 1 in the new namespace
with no sibling or parent visible. Single-binary sandboxes like `srt`
need a manual second-stage unshare to achieve the same isolation —
bento gets it from bwrap.

**Seccomp limitation: inherited file descriptors.** A seccomp filter
intercepts *syscalls*, not the file descriptors a process already
holds. When `allow_exec: true` lets a script spawn children, those
children inherit any open fds (sockets, pipes, files) the parent had.
Filtering at the syscall layer cannot revoke them: a child can `read`
or `write` an fd opened pre-fork even if it could not `open` the same
path itself. The same applies to fds passed via `SCM_RIGHTS` over a
Unix socket. If this matters for your threat model, the only mitigation
is to close sensitive fds before exec (or set `O_CLOEXEC` at open
time) and audit the parent's fd table.

### Mandatory deny paths (auto-protected)

**Read-protected** (`spec.DangerousFiles`):
`~/.ssh/id_{rsa,ed25519,ecdsa,dsa,identity}`, `~/.aws/credentials`,
`~/.aws/config`, `~/.config/gcloud/credentials.db`,
`~/.config/gcloud/application_default_credentials.json`,
`~/.config/gcloud/legacy_credentials`,
`~/.azure/accessTokens.json`, `~/.azure/azureProfile.json`,
`~/.kube/config`, `~/.docker/config.json`, `~/.git-credentials`,
`~/.netrc`, `~/.pypirc`, `~/.npmrc`, `~/.gem/credentials`,
`~/.password-store`.

**Write-protected** (`spec.DangerousWriteFiles`): `~/.bashrc`,
`~/.bash_profile`, `~/.zshrc`, `~/.zprofile`, `~/.profile`,
`~/.gitconfig`, `~/.gitmodules`, `~/.mcp.json`, `~/.ripgreprc`.

**Workspace-relative write protection** (any user-declared write
path): `.git/hooks/` (re-bound read-only — blocks creation of unborn
hook files like `post-checkout`), `.git/config`, `.vscode/tasks.json`,
`.vscode/launch.json`, `.idea/workspace.xml`.

### Symlink-escape rejection

Before any bind-mount setup, every component of every write path is
`lstat`'d. If any existing component is a symlink, the manifest is
rejected with a descriptive error. This prevents the attack where a
malicious workspace replaces `/tmp/out` with a symlink to `~/.ssh`
between the user's check and our bind.

Non-existent components are allowed — there's no symlink yet to
replace, and bwrap won't follow what doesn't exist.
