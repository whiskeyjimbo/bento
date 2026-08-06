# [ADR-0011] Exec-only ptrace records what an enforced run ran

* **Status:** Accepted
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
applied-report channel as a second, separately marked section, and off unless the run asks
for it.**

Opt-in is not caution about the mechanism; it is forced by the one thing tracing does take
away from the target - see "What the recorder costs the target" below. A run that did not
ask for a record is byte-for-byte the run it is today.

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

The one place tracing does change kernel behavior is a setuid or setgid exec, which the
kernel degrades to an ordinary one while the process is traced. That cannot matter here:
every filter bento installs sets `PR_SET_NO_NEW_PRIVS` first, which already degrades a
setuid exec for the whole run, so the recorder removes nothing that was still there. It is
worth stating rather than leaving for a reader to raise, because a mechanism that quietly
weakened a privilege transition would fail this ADR's first driver.

### What the recorder costs the target

A tracee has exactly one tracer, and `TRACECLONE` gives every process in the run one before
it executes an instruction. That is the property that makes the record complete, and it has
a price: nothing inside the sandbox can ptrace anything any more. `strace`, `gdb`, a test
harness that attaches to its own child, `rr`, a crash handler that reads its sibling's
state - all get EPERM or EBUSY that they do not get today, because the bwrap tier does not
otherwise filter ptrace (`BlockProcessReach` is degraded-tier only, and `BlockExec` denies
only `execve`).

This is the one way the record's presence changes what the target can do, and it lands
squarely on the `exec: all` toolchain case the feature is for - a debugger is a plausible
member of the toolchain the job was granted. It is why the recorder is opt-in rather than
on by default. The alternative - accept the change and document it - was rejected because a
run that is subtly different when observed is the thing observability is supposed to avoid,
and the flag costs one field.

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

**Yama `ptrace_scope` 2 already forbids it, not only 3.** Tracing one's own child is
permitted at scope 0 and 1 - the tracee is a descendant, which is exactly what scope 1
restricts to. Scope 2 requires `CAP_SYS_PTRACE` "either with `PTRACE_ATTACH` or through
children calling `PTRACE_TRACEME`", and `TRACEME` is the route here: `exec.Command` with
`SysProcAttr{Ptrace: true}` has the child call it before its exec. Scope 3 refuses
everything.

The capability is not available to fall back on, and the reason is worth stating so it is
not reasoned away later: `yama_ptrace_traceme` checks the capability against the child's
user namespace, and bento's launcher is inside one bwrap created - but `namespaceFlags`
passes `--cap-drop ALL` (`internal/linux/args.go`), deliberately, so the bounding set inside
that namespace is empty. Both hardened scopes therefore yield a failed attach, which is
reported rather than fatal: the record is a diagnostic, and a host that will not permit it
still gets its run.

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

  **The implementation did not factor it, deliberately.** Measured against the built loop,
  what `internal/observe` and `internal/launcher/execrecord.go` share is knowledge, not
  code: the event message carries the tid an `execve` retired, every signal but `SIGTRAP`
  is forwarded, a child is tracked at the fork event rather than at its own first stop.
  Everything else in the observer's loop is the decoder's - `nativeSyscall`, `inspect`,
  `dropOnce`, the `held`/`lastOp`/`drops` maps, and the drop accounting that makes up most
  of `forgetRetiredTid`, which collapses here to a single `delete`. Parameterizing a
  1462-line profiler for a second caller that wants none of that would have coupled the
  enforced path to the profiling one to avoid duplicating roughly forty lines. The three
  shared facts are stated in comments at the exec-only loop instead, which is what the
  concern behind this bullet - not rediscovering the quirks - actually asked for.
* **No `PTRACE_O_EXITKILL`, unlike the observer.** The spike set it, and it must not survive
  into the implementation: it makes a bug in the wait loop SIGKILL the entire enforced run,
  which is a diagnostic killing a run that would otherwise have succeeded - the first
  driver, exactly inverted. `observe.Trace` sets it for the opposite reason (a profiling run
  IS the trace, so an abandoned tracee is a leak with nothing left to reap it), and that
  reasoning does not carry over to a run whose point is the target. A tracer that dies
  detaches instead, the tracees continue, and the record ends where it ended - which is why
  the record's own section needs a marker of its own, so a truncated one is legible as
  truncated rather than as a run that stopped exec'ing.
* The wait loop inherits `ptrace(2)`'s multithreaded-exec quirk: an `execve` by a non-leader
  thread reports `PTRACE_EVENT_EXEC` under the thread-group leader's pid and the non-leader's
  pid disappears with no exit event. `internal/observe` already handles this
  (`forgetRetiredTid`), which is another reason to factor its loop rather than write a
  second one that has to rediscover it.
* Only what ran is recorded, not what was attempted: a denied exec produces no event. That
  is a different question - the exit-126 heuristic `ADR-0006` named - and this does not
  answer it.
* The root exec is not recorded - it retires before the tracer sets its options, the same
  structural gap `internal/observe/execimage_linux_amd64.go` documents. The launcher knows
  the target by construction, so the record is seeded with it rather than left short.
* A target that runs thousands of short-lived processes pays a stop each. The cost is
  proportional to execs, not to work, but it is not zero on a `make -j` workload.
