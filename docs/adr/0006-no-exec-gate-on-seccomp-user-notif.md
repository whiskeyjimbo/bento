# [ADR-0006] No ExecGate on SECCOMP_RET_USER_NOTIF

* **Status:** Rejected
* **Date:** 2026-08-02

## Context and Problem Statement

`internal/seccomp/seccomp_linux.go` blocks `execve` with `seccomp.ActionErrno`: a blind
filter that denies every exec without seeing what was being run. `SECCOMP_RET_USER_NOTIF`
would instead hand each `execve` to a supervising process that can read the attempted argv
path out of the notification and decide, returning EPERM or allowing the call.

The motivation worth considering was never diagnostics. It was symmetry with
`enforce.Options.NetworkGate`: a supervising wrapper could prompt a human at exec time
("agent.sh wants to run /usr/bin/git, allow?") the way `examples/supervise` already prompts
on egress, closing the asymmetry `examples/embed/README.md` names under "What is not here:
filesystem prompts". Two questions had to be answered before any code: what happens when
the supervisor dies, and whether `ExecGate` joins `NetworkGate` as a public
`enforce.Options` field.

## Decision Drivers

* The exec block is a fail-closed control. Nothing may replace it with one that is not.
* `NetworkGate`'s contract, which any second gate should match rather than merely resemble.
* Security budget: a new long-lived supervisor process is itself a target.

## Considered Options

* A `USER_NOTIF` filter on `execve` with a second `ActionErrno` filter stacked beneath it
  as a fail-closed floor. This was the shape proposed when the work was deferred.
* A `USER_NOTIF` filter on `execve` with no floor, relying on the kernel's own behaviour
  when the listener goes away.
* Keep `ActionErrno` and build no exec gate.

## Decision Outcome

Chosen option: **keep `ActionErrno` and build no exec gate**. Three facts decide it, two of
them fatal to the proposal as written.

**1. The floor cannot exist.** `<linux/seccomp.h>` orders the return values "from least
permissive to most" and composes stacked filters with a `min_t` over their results, so the
numerically smaller action wins: `SECCOMP_RET_ERRNO` is `0x00050000` and
`SECCOMP_RET_USER_NOTIF` is `0x7fc00000`. An `ActionErrno` filter stacked beneath a
notifier always outranks it, and the notification is never delivered. The two cannot
coexist on the same syscall; a design must pick one.

**2. The kernel says the notifier is not a security mechanism.** The same header, on
`SECCOMP_USER_NOTIF_FLAG_CONTINUE`: "It should be absolutely clear that this means that
the seccomp notifier _cannot_ be used to implement a security policy", because the target
can rewrite pointer arguments while it waits for the supervisor's answer. `execve`'s
pathname is exactly such a pointer. Since fact 1 rules out keeping `ActionErrno` beneath
it, adopting the notifier means replacing a control that fails closed by construction with
one whose own documentation disclaims the job.

**3. The fail-open risk that prompted the deferral is not real.** When the supervisor dies,
the kernel fails the target's syscall with ENOSYS rather than hanging or permitting it
(`seccomp_unotify(2)`, and the same for a notification already outstanding when the
listener is released). Supervisor death is fail-closed for free; no watchdog is needed.
This answers the question that was blocking the design, and it is the one answer that came
back favourable. It does not rescue the proposal, because facts 1 and 2 do not depend on it.

### On whether ExecGate joins NetworkGate in enforce.Options

No, and the reason generalizes past this particular mechanism. `NetworkGate` is purely
additive over a control that enforces on its own: the egress proxy denies by default, the
gate is consulted only for a host the manifest does not allow, and a nil gate denies
everything undeclared. Nothing about the gate's presence, absence, or slowness can weaken
what the proxy enforces; a gate that never answers stalls one connection and admits
nothing.

An `execve` notifier inverts that. There is no fail-closed layer left underneath for it to
widen, because fact 1 removed it - the gate would BE the enforcement. A field named
`ExecGate` sitting beside `NetworkGate` in `enforce.Options` would read as the same kind of
seam and would not be one, which is a worse outcome than not having it.

This gives the bar any future proposal has to clear, whatever mechanism it uses: **an exec
gate is admissible only if a mechanism that fails closed without it remains the enforcer,
and the gate only widens.** Nothing available on Linux today provides that for `execve`.

### Positive Consequences

* The exec block stays a filter with no liveness dependency and no supervisor process.
* `enforce.Options` keeps one meaning for "gate": an additive seam over a control that
  already denies.
* The fail-open question is answered rather than left open, so this does not have to be
  re-derived if the motivation returns.

### Negative Consequences / Trade-offs

* The asymmetry `examples/embed/README.md` names stands: an embedder can prompt on egress
  and cannot prompt on exec.
* Denial reporting stays the exit-126 heuristic in `cmd/bento/render.go`. That is a
  separate problem with a separate and cheaper answer (`run --observe` over the existing
  ptrace seam), which carries no fail-open risk and was always the better fit for it.
* The exec block remains soft by construction - `execveat` stays open, see
  `docs/threat-model.md` - and this decision does not improve it. Trading a soft control
  for one the kernel disclaims is not an improvement either.
