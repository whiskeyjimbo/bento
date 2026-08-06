# [ADR-0011] Exec-only ptrace records what an enforced run ran

* **Status:** Accepted, unimplemented
* **Date:** 2026-08-06
* **Authors:** whiskeyjimbo

## Context and Problem Statement

An enforced run produces no record of what the target executed, and the profiler cannot
supply one: the two are mutually exclusive by construction. `internal/launcher/launcher.go`
refuses a config setting both `ObserveFD` and `AppliedFD` - the observation and the
applied-layer report travel the same inherited descriptor, which the host places at fd 3 -
and `Config.ObserveFD`'s own contract is that `runObserve` traces the target INSTEAD of
enforcing: no seccomp and no Landlock are applied, so that what the target does is fully
observed.

So the choice today is an observe-only run with full visibility and no enforcement, or an
enforced run with no exec record. `ADR-0006` closed the exec-gate question by naming
`run --observe` as the cheaper answer to the half of it that was about diagnostics -
"denial reporting stays the exit-126 heuristic ... that is a separate problem with a
separate and cheaper answer (`run --observe` over the existing ptrace seam), which carries
no fail-open risk". True, but that seam does not run under enforcement, so the conclusion
was not cashable. Anywhere an audit trail is offered as the answer to "what did `exec: all`
actually run", it assumes both at once.

`exec: none` runs have little to record by design. This is about `exec: all` - the mode the
toolchain job class `ADR-0008` and `ADR-0009` both failed to serve any other way, and the
mode where model-generated code runs.

## Decision Drivers

* The record is a diagnostic. It must not become a control, and nothing about its presence,
  absence or failure may change what is enforced.
* No second long-lived process, and no descriptor the host has to place.
* The enforced run's existing cost and its report contract are not to be disturbed.
* A record that can be silently incomplete is worse than none, because it reads as complete.

## Considered Options

* **Exec-only ptrace** on the supervise path: `PTRACE_O_TRACEEXEC` with `PTRACE_CONT`, no
  syscall stops.
* **The full observer** (`observe.Trace`) under enforcement, lifting the `ObserveFD` /
  `AppliedFD` exclusion.
* **`SECCOMP_RET_USER_NOTIF` on `execve`** as a pure recorder rather than a gate.
* **`LD_PRELOAD`** over the `exec*` family.
* **fanotify `FAN_OPEN_EXEC`** or the kernel audit subsystem.
* **No record.** Accept the gap and say so.

## Decision Outcome

Chosen option: **exec-only ptrace on the `exec: all` supervise path, reported through the
applied-report channel as a second, separately marked section.**

### The mechanism, verified

A standalone spike ran a target under `PTRACE_O_TRACEEXEC | TRACECLONE | TRACEFORK |
TRACEVFORK | EXITKILL`, resumed with `PTRACE_CONT` rather than `PTRACE_SYSCALL`, with
`no_new_privs` and a live seccomp filter already installed and inherited by the tracee
across its exec. Every exec in the tree, grandchildren included, produced one stop naming
the image and its argv:

```
EXEC pid=… exe=/usr/bin/true  argv="/bin/true"
EXEC pid=… exe=/usr/bin/ls    argv="/bin/ls\0/tmp"
EXEC pid=… exe=/usr/bin/dash  argv="/bin/sh\0-c\0/bin/echo"
EXEC pid=… exe=/usr/bin/echo  argv="/bin/echo"
total wait stops=29  elapsed=7.8ms
```

Four properties decide it.

**It is exec-only, so it is nearly free.** The cost is one stop per exec plus the
fork/clone and exit events, not one per syscall - 29 stops for that whole tree. `ADR-0005`'s
register-decoding machinery is not needed at all: `/proc/<pid>/exe` and
`/proc/<pid>/cmdline` are read at the `PTRACE_EVENT_EXEC` stop, after the exec retired, so
there is no pathname to fetch out of tracee memory and nothing to resolve against a dirfd.
`/proc/<pid>/exe` is the kernel's own answer, so symlinks are already resolved (`/bin/sh`
reads back as `/usr/bin/dash`) and a `PATH` search cannot be misattributed.

**It needs no new process.** On `exec: all`, `runTarget` dispatches to `superviseTarget`,
so the launcher is already the target's supervising parent for the whole run. The tracer is
that process.

**The target cannot hide an exec from it.** `TRACECLONE`/`TRACEFORK`/`TRACEVFORK` attach a
descendant at fork, before it runs a single instruction, and a tracee has exactly one
tracer - so the target cannot claim its own children first. This is the property
`LD_PRELOAD` does not have (a static binary, or one that `syscall`s directly, ignores it)
and the one `USER_NOTIF` does not have either: `ADR-0006`'s finding 2 is that the pathname
in a notification is a pointer the target may rewrite after the supervisor reads it, so a
`USER_NOTIF` recorder logs what it was shown rather than what ran, which is a record that
can lie. A record that can lie is worse than no record.

**It does not touch enforcement.** The tracee keeps the filters it inherited (the spike
confirms the filter is live in the tracee), Landlock is unaffected, and ptrace grants the
tracer nothing the parent did not already have over its own child.

### Where it does not apply

**The degraded tier cannot have it.** `internal/launcher/degraded.go:176` installs
`seccomp.BlockProcessReach`, which denies `ptrace` with EPERM, process-wide and before
`runTarget` - so the launcher's own attach is refused by its own filter. That filter is
load-bearing there: with no PID namespace the target shares the host's process table.
Loosening it to let the launcher trace is not on the table for a diagnostic, so the degraded
tier reports no exec record and says so.

**`exec: none` cannot have it, and does not need it.** When the exec block is installed,
`runTarget` calls `seccomp.Exec`, which execveats the target over the launcher - there is no
supervisor left to be the tracer. That mode has nothing to record by design.

**Yama `ptrace_scope` 3 disables ptrace outright.** Tracing one's own child is permitted at
scope 0 and 1, and scope 2 restricts attaching to CAP_SYS_PTRACE but leaves a parent's
`PTRACE_TRACEME` child intact; scope 3 refuses everything. A host at scope 3 gets no record.

### Why the full observer was rejected

Lifting the `ObserveFD`/`AppliedFD` exclusion would put every syscall of an enforced run
through two stops and a register read, on the path whose cost is a user's build. It also
buys nothing here: what is wanted is the exec tree, and the observer's open-path decode is
the expensive part. `runObserve` additionally installs `BlockIoUring` to keep its
observation complete, which is a filter the enforced run does not otherwise install. The
two remain separate; the exclusion stays.

fanotify `FAN_OPEN_EXEC` needs `CAP_SYS_ADMIN` on the host, and audit needs root and a
system-wide subscription. Both are out of reach for an unprivileged sandbox.

### The report channel

The record goes to the **applied report**, in a second write phase with its own marker,
after the existing marker and section.

The alternative shapes were a third descriptor beside `ObserveFD`/`AppliedFD` and appending
into the existing section. A third descriptor makes the host place another fd for a
diagnostic, and the applied report is already the enforced run's report - there is nothing
for a second channel to separate. Appending into the existing section is worse than either:
`applied.write()` fires BEFORE the target is reached, and the degraded tier's comment states
the invariant that depends on it - "a report that reaches its marker is itself the proof
that all of them are in place". Exec records arrive during the run, so folding them into
that write would trade a fail-closed proof for a diagnostic. A separately marked second
section keeps the first write, the first marker, and its meaning exactly as they are; a
report that ends after the first marker is a run whose fences held and whose exec record
was not produced.

That last case is why the channel matters: whether the recorder was installed is itself a
line in the report, in the `AppliedYes`/`AppliedNo`/`AppliedAbsent` vocabulary the layers
already use - `Absent` for the degraded tier and for `exec: none`, `No` with the error for a
failed attach. A run that produced no records because none happened is then distinguishable
from one that produced none because nothing was watching, which is the same distinction
`Dropped` makes for the observer.

### Positive Consequences

* `ADR-0006`'s answer to the diagnostic half becomes cashable: an `exec: all` run can say
  what it ran, without an exec gate and without the fail-open risk one carries.
* The exec tree is complete and unforgeable by the target, which no cheaper mechanism gives.
* Enforcement, the report's existing contract, and the `ObserveFD`/`AppliedFD` exclusion are
  all unchanged.

### Negative Consequences / Trade-offs

* The record exists in the bwrap tier under `exec: all` and nowhere else. Three modes have
  to be reported as absent rather than empty, and the frontend has to say which.
* The launcher's supervise path grows a wait loop: the tracer must be pinned to one OS
  thread (`runtime.LockOSThread`, as `observe.Trace` already does), must forward delivered
  signals, must reap auto-attached descendants, and must keep the target's exit code and
  signal plumbing exactly as `superviseTarget` reports them today. That machinery already
  exists in `internal/observe`; the implementation should factor the stop loop rather than
  write a second one, and the exec-only mode is a smaller loop than the decoder's, not a
  larger one.
* The root exec is not recorded - it retires before the tracer sets its options, the same
  structural gap `internal/observe/execimage_linux_amd64.go` documents. The launcher knows
  the target by construction, so the record is seeded with it rather than left short.
* A target that runs thousands of short-lived processes pays a stop each. The cost is
  proportional to execs, not to work, but it is not zero on a `make -j` workload.
