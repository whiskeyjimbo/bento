# bento

Run an untrusted script under the permissions declared in a manifest: deny-by-default
filesystem access, no network unless a rule allows it, no subprocesses unless asked.
bento enforces those permissions with the kernel (bubblewrap, seccomp, Landlock, cgroups
on Linux), and it reports every gap between what a manifest asks for and what the host can
actually enforce rather than quietly substituting a weaker sandbox.

> Status: this is the ground-up v2 rebuild. The Linux backend is implemented and tested.
> macOS is planned (see `docs/design.md` section 6.6) and not yet built. See the beads
> issue tracker (`bd ready`) for what is in flight.

## Why

Two properties define bento:

- **Isolation.** The script runs in a sandbox that can only see and touch what the manifest
  grants. Everything else is denied by default, and a mandatory deny-list shields
  credentials, SSH keys, cloud and CLI tokens, OS keyrings, crypto vaults, shell history,
  and startup/exec configs no matter what a broad grant would otherwise expose.
- **Declarative permissions.** The policy lives in a manifest, not in code. There is no
  runtime prompting: bento either runs within the declared permissions or refuses. That is
  what makes it usable unattended (CI, agents, Go embedders), where no human is present to
  answer a dialog. `run` also refuses a manifest whose approval is missing or stale (the
  permissions changed since it was approved), so an unreviewed change cannot run unattended;
  `--allow-unapproved` opts out for the profile-then-run inner loop.

When the host cannot enforce something a manifest declares, bento does not silently run a
weaker sandbox. It surfaces the shortfall in `bento doctor` and in the run output, and
`--strict` refuses rather than degrade.

## Requirements

- Linux with **bubblewrap** (`bwrap`) installed and **unprivileged user namespaces**
  enabled (bento skips or reports clearly when they are unavailable).
- Go 1.26 to build.
- Optional: a systemd user manager with delegated `memory`/`pids` (and `cpu`) controllers
  for resource limits.

## Build

```sh
go build -o bento ./cmd/bento
```

## Workflow

The manifest is tool-owned: you generate it by profiling, review it, approve it, then run.

```sh
# 1. Observe what the script actually does and propose a tight manifest.
#    Profiling runs the script; do it on code you would run unsandboxed. Egress is
#    recorded but not forwarded by default, so the script's data stays on the host.
bento profile ./fetch.py            # writes ./fetch.py.manifest.yaml
#   --interpreter python3           # override the interpreter guessed from the extension
#   --out ./fetch.yaml              # write the manifest somewhere other than <script>.manifest.yaml
#   --allow-network                 # forward egress for a faithful run of network-dependent code

# 2. Review the proposed permissions.
bento validate ./fetch.py.manifest.yaml
#   --strict                        # exit non-zero on a stale/missing approval (CI gate)
#   --json                          # emit the parsed policy as JSON

# 3. Approve it (stamps an approval fingerprint over the policy fields).
bento approve ./fetch.py.manifest.yaml

# 4. Run the script under the approved manifest. run refuses an unapproved or stale
#    manifest by default (pass --allow-unapproved to run one anyway).
bento run ./fetch.py.manifest.yaml
#   --strict                        # refuse unless every guarantee the policy needs is fully enforced
#   --allow-degraded                # run even when a core guarantee is only partially enforced
#   --env NAME=VALUE                # supply a value for an allowlisted env var (repeatable)
#   --json                          # emit a machine-readable result envelope instead of the streams

# At any time: what can this host actually enforce?
bento doctor
#   --json                          # emit the enforcement matrix as JSON
```

## The manifest

```yaml
entrypoint: ./fetch.py          # script or compiled binary
interpreter: python3            # optional; omit for a compiled binary
args: [--verbose]

env: [LANG, AWS_DEFAULT_REGION]  # allowlist of env var NAMES; values passed through if set

read:  [./data]                 # deny-by-default; paths relative to the manifest
write: [./out]                  # directory-granular (see note); a missing dir is created

network:                        # a list of rules; omitted/empty means all egress denied
  - host: api.github.com        # host + quoted port; suffix match with a leading dot
    port: "443"

exec: none                      # none (blocks execve) | none-strict (also fork/clone, threads ok; amd64) | all
limits: { memory: 128M, cpu: 100%, pids: 32 }

# Written by the tool, not by hand:
provenance:
  generated-by: bento profile
  generated-at: 2026-07-14T00:00:00Z
  approves: <sha-256 over the policy fields>   # attests the policy, not the code
```

**Write grants are directory-granular.** A `write:` entry names a directory, not a file.
This is forced by the enforcement mechanism: the sandbox can only make a directory writable
in a way that supports creating and renaming files inside it. Naming a file breaks
save-via-rename (editors, `os.replace`, git), so a write grant that names an existing file
is refused, and a granted directory that does not exist yet is created before the run.

A write grant that *contains* a shielded credential path is also refused: `write: ~`
(above `~/.ssh`) or `write: ~/.cargo` (above `~/.cargo/credentials`) would make the
shield's parent writable, so bento refuses it and asks you to grant a narrower directory.
A broad *read* grant over the same tree is fine - the deny-list keeps carving out the
credentials inside it.

A program that legitimately needs a shielded path (a deploy tool that reads `~/.ssh`) can
opt in by naming the shield's exact path in `read:`. That is honored as a deliberate,
caveat-emptor exception: the shield is skipped, the real content binds read-only, and the
exposure is surfaced in the run output (and `--json`). The opt-in is read-only and applies
only to bento's built-in credential shields: a *write* grant of a shield stays refused (the
key-planting vector), an embedder's own `denyPaths` stay shielded, and a broad enclosing
grant keeps carving rather than exposing the shield.

## What is enforced

bento reports capabilities in tiers. The **core tier** is the baseline both platforms aim
to provide; the **hardening tier** is Linux-only for now.

| Guarantee | Tier | Linux mechanism |
|---|---|---|
| Read only granted paths | core | bubblewrap read-only binds, deny-by-default root |
| Write only granted directories | core | bubblewrap read-write binds; root remounted read-only |
| Credentials/dotfiles always shielded | core | deny-list bind mounts (even for unborn paths) |
| No egress unless a rule allows it | core | empty network namespace (no route out) |
| Per-host:port egress | core | host-side SNI/CONNECT allowlist proxy behind the fence |
| No `execve` subprocesses | hardening | seccomp exec-block filter (`none-strict` also blocks fork/clone on amd64) |
| memory / pids / cpu limits | hardening | transient `systemd` scope |
| Filesystem backstop behind bubblewrap | hardening | Landlock (best-effort) |

If a hardening layer is unavailable on the host, `doctor` and `run` say so, and `--strict`
refuses. The Landlock backstop is best-effort: it warns and proceeds rather than making
bubblewrap's confinement contingent on it.

## Architecture

bento is layered behind one seam so a platform backend can be swapped without touching the
core.

- `enforce` - the `Enforcer` interface (`Probe` + `Run`) and the degradation
  reporting (`Report`, tiers, states, admission). A backend answers with what it actually
  enforced; no backend type appears in the core's signatures.
- `policy` - the `Policy` domain model, validation, host:port matching, and the
  approval `Fingerprint` (platform-independent).
- `internal/denylist` - the mandatory deny-list as platform-independent data; each backend
  decides how to enforce a rule.
- `manifest` - manifest load/marshal and provenance.
- `internal/proxy` - the egress allowlist CONNECT proxy, shared across platforms.
- `internal/linux` - the bubblewrap backend, with `internal/launcher` (the in-sandbox
  stage), `internal/observe` (the ptrace profiler), `internal/seccomp`, and
  `internal/landlock`.
- `backend` - selects the platform backend; `profile` synthesizes a
  manifest from an observed run.

The full design and rationale, including the macOS plan and the security model, live in
[`docs/design.md`](docs/design.md).

## Development

This module builds standalone; if you have a parent `go.work`, disable it for these
commands:

```sh
GOWORK=off go build ./...
GOWORK=off go vet ./...
GOWORK=off go test ./...        # the sandbox tests skip when bwrap/userns are unavailable
```

The tests run real probes inside real sandboxes and assert that the boundary actually
holds - a policy compiler that produces plausible arguments proves nothing about whether
the sandbox confines anything.

`scripts/denylist-audit.sh` cross-references bento's credential/exec deny-list against
firejail's upstream `disable-common.inc` and prints any secret- or exec-scope shield
bento is missing, so the list stays complete without hand-hunting. It needs network
access (firejail's data is fetched as a GPL reference, never vendored) and exits non-zero
when a gap is found, so it can gate CI; a failed fetch is reported and does not fail the
build. Run it after adding a tool that stores credentials, and classify each flagged path
into `internal/denylist/denylist.go`.

## Security notes

- Profiling runs the script under the same default-deny sandbox a real run gets: nothing
  under your home is mounted, so a probe of `~/.ssh` is recorded but never exposed. The
  proposal shows what the script *wants*; you grant it explicitly. Because nothing sensitive
  is bound, one run can under-report - grant what it shows and profile again to converge -
  so treat the proposed manifest as a proposal to review, not a guarantee.
- The approval fingerprint attests the *policy*, not the code. Re-approve after changing
  permissions; changing the script does not invalidate an approval.
- Known residual gaps are tracked in the issue tracker and documented in `docs/design.md`
  (for example, on Linux the exec-block is soft on `execveat`).
