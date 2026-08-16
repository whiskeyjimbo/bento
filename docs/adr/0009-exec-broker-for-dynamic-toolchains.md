# [ADR-0009] No exec broker for dynamically linked toolchains

* **Status:** Rejected
* **Date:** 2026-08-05
* **Authors:** whiskeyjimbo

## Context and Problem Statement

`ADR-0008` rejected a Landlock exec allowlist and named what remained: a broker. The job
class is unchanged and still unserved - a job whose filesystem legitimately holds a
compiler, a test runner or `git`, which therefore gets `exec: all` and unrestricted spawn
over that toolchain. That is also the case where model-generated code runs.

The design: the target keeps `exec: none`, so it executes nothing and the `PT_INTERP`
question that killed `ADR-0008` never arises for it. It writes a request to an inherited
socketpair; bento - a child forked before the filters, holding the sandbox's Landlock
ruleset - resolves the request against a reviewed policy table, spawns the binary inside
the target's namespaces with bento's own copy of the argv, and streams the result back.
A policy entry names an absolute binary; the target supplies arguments matched
whole-argument, with any `-` flag refused unless the entry names it exactly. The spawned
environment is composed by bento so the target cannot reach a shell through `GIT_PAGER`
and friends. A caller-supplied gate, on `NetworkGate`'s shape, decides requests the static
table does not admit, so a supervising wrapper can prompt a human.

That design is rejected. Two independent findings kill it, and a third bounds what would
have been left.

## Decision Drivers

* `ADR-0006`'s bar: an exec gate is admissible only if a mechanism that fails closed
  without it remains the enforcer, and the gate only widens.
* The dynamic-linking wall `ADR-0008` hit twice must not reappear.
* The result has to serve a job class someone can name, or it should not be built.

## Considered Options

* The broker as described above, as a containment boundary.
* The broker as an approval and observability boundary only, conceding it does not contain
  the toolchain case.
* No broker; serve the need with filesystem grants and the existing observation seam.

## Decision Outcome

Chosen option: **build no broker**.

### 1. It does not contain the job class it was written for

A toolchain is by design an arbitrary-code executor over the files it is pointed at.
`go test ./...` compiles and runs the target's own source; `make` runs recipe lines;
`cargo` runs `build.rs`; `npm` runs lifecycle scripts; `git` runs hooks out of
`.git/hooks`. The agent writes a test file into the workspace it is already granted, asks
for the one entry that was carefully reviewed, and its own code executes - the table
honored exactly, and nothing bought.

The broker's containment value is exactly the disjointness between what the brokered
binary reads as input and what the target can write. For the motivating case those are the
same directory, so it is nil. That leaves only the narrower case - inputs outside the write
grants, `git log` on a read-only repo, a linter over read-only sources - and finding 2
takes that one too.

### 2. The target can hijack the brokered process, so the broker grants arbitrary exec

The repo had already worked this out, for the bridge. `internal/launcher/launcher.go:825`:

> an untrusted target could PTRACE_ATTACH the bridge (a descendant, permitted under yama
> ptrace_scope<=1) and inject an execve, spawning a subprocess in violation of exec: none

Every word applies to the broker and to each process it spawns. After the launcher
execveats the target, the broker is a child of the target's pid and the brokered binary is
its grandchild - descendants, attachable at yama scope 0 and 1 alike. `ptrace` is not
filtered in the bwrap tier: `BlockExec` is `DefaultAction: ActionAllow` with one group for
`execve` (`internal/seccomp/seccomp_linux.go:78-82`), and `BlockProcessReach` is installed
only in the degraded tier (`internal/launcher/degraded.go:176`).

**The bridge's defense does not transfer.** `PR_SET_DUMPABLE(0)` protects the bridge only
because the bridge never execs again - `launcher.go:177` states the rule, execve resets
dumpable. A brokered binary execs by definition. There is no pre-exec trick that survives
it.

So one approved `git log` hands the target a same-uid, ptrace-attachable process that is
not under the exec filter: attach, inject execve, done. The broker is not an approval
boundary with residual containment; it is a switch that converts `exec: none` into
`exec: all` on request. This is what removes the read-only-inputs case that finding 1 left
standing.

Closing it is not one line. `BlockProcessReach` on the target is plausible - the target is
under `exec: none` and has no legitimate use for ptrace, and the broker forks before the
filter so the toolchain is unaffected - but `/proc/<pid>/mem` is an open-and-write, not a
syscall to filter, and `/proc` is in `sandboxWritableMounts` (`internal/linux/args.go:421`).
Both halves have to land, and the `/proc` narrowing has to not break the toolchains the
feature exists for.

### 3. Even winning that, no safe entry could be named

The environment must be composed by bento, because `git log` pipes through a pager run
under `/bin/sh`. But the scrub does not cover configuration on disk: `git` reaches
execution through `core.pager`, `core.hooksPath`, `diff.external`, `*.textconv`,
`core.fsmonitor` and aliases, read from `$GIT_DIR/config`, `~/.gitconfig`, `/etc/gitconfig`
and `.gitattributes`. bento already treats this as a threat - `gitDirShields`
(`internal/linux/args.go:876`) shields `.git/hooks`, `config` and each linked worktree's
`config.worktree`. Note what that costs: hundreds of lines for one tool, and it is
opt-out-able (`args.go:272`). There is no equivalent for `cargo`, `make`, `eslint`,
`npm`, `pre-commit` or `pytest`+`conftest.py`, and a linter loading plugins from the
workspace is doing so by design.

Asked to name one entry that survives that audit, we could not. A feature whose safe
configuration nobody can instance is not a feature.

### Also wrong in the draft, recorded so it is not repeated

* The ordering rationale claimed `setns` does not lift Landlock. Nothing in the design
  calls `setns`; the broker is a fork and inherits the domain. The real constraint is the
  bridge's, stated at `launcher.go:9-10`: starting a child uses execve, which the filter
  denies.
* The claim that the target "executes nothing" under `exec: none` overstates it.
  `docs/threat-model.md:388` records that the mode does not block `execveat`, "an
  execution-policy convenience rather than a complete system-call boundary." The
  directional point is what matters and it cuts against the broker: today a bypass needs a
  hand-rolled `execveat`; with a broker it needs one approved invocation plus a ptrace
  attach - ordinary, portable, library-supported operations. The broker is not additive
  over the filter the way `NetworkGate` is additive over the proxy. It lowers the cost of
  defeating it.
* Claim: no brokered process outlives its request. Not achievable as designed - orphaned
  grandchildren reparent to bwrap's init (`launcher.go:750-756`), so a double-forking
  build tool escapes the broker's kill entirely. It would need `PR_SET_CHILD_SUBREAPER`
  plus a process-group kill, and `setsid` still escapes that.
* Approval caching was presented as parity with `NetworkGate`. It is not: that gate's
  approved unit (host:port) *is* the granted unit, whereas one approved pattern here buys
  an unbounded number of distinct argv.

### The shape that remains

**Do not add an exec-capable process to the sandbox.** The containment lever for this need
is the filesystem, not exec - which is where bento is already strong, and which finding 1
identified before the design was attacked.

* For the audit trail: `exec: all` plus the existing observation seam. `ADR-0006` reached
  this conclusion already - the observability half "is better served by `run --observe`
  over the existing ptrace seam, which carries no fail-open risk and was always the better
  fit for it." A broker would be a second mechanism for a job one already does, and this
  one is an exec engine.
* For the read-only-inputs case, if it is ever wanted: tighten grants and add shields in
  the `gitDirShields` mold. That serves it without opening an exec channel to relitigate
  what the write grants already decide.

### Positive Consequences

* `exec` keeps three modes that each mean what they say. Three mechanisms have now been
  measured against `ADR-0006`'s bar with the same answer.
* The rejection is grounded in an in-tree fact with a comment already explaining it
  (`launcher.go:825`), so it is checkable rather than arguable.
* The finding generalizes past this design: **any** future mechanism that puts a process
  inside the sandbox and lets it exec inherits finding 2. The bridge is safe only because
  it never execs again, and that is now written down as the reason rather than as a
  detail of the bridge.

### Negative Consequences / Trade-offs

* A job needing a real toolchain still gets `exec: all`. Three attempts have failed to
  close that, and this one establishes the gap is not closable by an exec gate at all
  while the target can ptrace what bento spawns.
* The supervised-wrapper story (prompting a human before a toolchain invocation) has no
  home. It was the strongest remaining motivation and it is not enough on its own.
