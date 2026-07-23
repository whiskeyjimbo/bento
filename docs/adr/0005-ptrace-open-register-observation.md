# [ADR-0005] Ptrace Syscall Register Observation for Safe Profiling

* **Status:** Accepted
* **Date:** 2026-07-14

## Context and Problem Statement

Profiling an untrusted script to generate a manifest requires discovering which files and host paths the script attempts to access. However, if profiling mounted sensitive host directories to observe access, an untrusted script could read credentials during the profiling phase.

## Decision Drivers

* Profiling must execute under the exact same default-deny filesystem sandbox as a production run.
* Zero exposure of sensitive host file contents during manifest generation.
* Accurately recording path access attempts even when the target path does not exist inside the sandbox.

## Decision Outcome

Chosen Option: **Ptrace Syscall Register Inspection without Reading File Content**.

1. `bento profile` launches the target script inside an unprivileged default-deny sandbox (no home directory bind-mounts).
2. The observer (`internal/linux/internal/observe`) attaches via `ptrace` and inspects `open`/`openat` syscall registers and memory parameters *before* the kernel processes the call.
3. The observer records the exact host path requested by the tracee, regardless of whether the call subsequently returns `ENOENT` or succeeds.
4. The observer never inspects file handles, buffer contents, or return data.

### Positive Consequences

* Untrusted code cannot read host secrets during profiling because sensitive paths remain unmounted.
* Accurately captures attempted access paths even for unmounted or non-existent files.

### Negative Consequences / Trade-offs

* Programs that branch on missing files (taking an early error exit when a config file returns `ENOENT`) require iterative re-profiling until all access paths converge.
