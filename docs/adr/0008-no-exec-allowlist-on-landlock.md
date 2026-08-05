# [ADR-0008] No exec allowlist on Landlock's execute right

* **Status:** Rejected
* **Date:** 2026-08-05
* **Authors:** whiskeyjimbo

## Context and Problem Statement

`policy.ExecMode` offers `none`, `none-strict` and `all`. An orchestrator running one
agent per job class wants a middle setting: a job that may run a fixed set of binaries and
nothing else. Today such a job gets `exec: all`, so the filesystem and network grants are
enforced while subprocess spawning is effectively advisory.

Part of that need is already met without a bento change. What a target can spawn is bounded
by what its read grants make reachable, so `exec: all` over a deliberately thin filesystem
is a de facto binary allowlist. The case that remains is a job whose filesystem legitimately
holds a real toolchain - a compiler, a test runner, `git` - and which therefore gets genuine
unrestricted spawn over it. That is also the case where model-generated code runs, so it is
the one worth solving.

The mechanism proposed was Landlock's `LANDLOCK_ACCESS_FS_EXECUTE`. go-landlock's read
helpers include the execute right, so under today's `Restrict` every readable file is
executable; the design was to withhold execute from the broad read and write rules and grant
it back on the allowlisted files alone. `ADR-0006` had already rejected the other candidate
mechanism, a `SECCOMP_RET_USER_NOTIF` gate on `execve`, so Landlock was what was left.

## Decision Drivers

* An allowlist that silently becomes `exec: all` is worse than no feature. The mode would
  install no exec-block filter, so nothing fails closed underneath it.
* The bar `ADR-0006` set for any exec gate: it is admissible only if a mechanism that fails
  closed without it remains the enforcer.
* Whatever ships has to serve a job class someone can name.

## Considered Options

* Withhold execute from the read/write rules and grant it on the allowlisted files.
* The same, plus execute on the dynamic loader, so dynamically linked entries can run.
* The same, restricted to statically linked allowlist entries.
* Build no allowlist mode; keep `none`/`none-strict`/`all`.

## Decision Outcome

Chosen option: **build no allowlist mode**. The ruleset works exactly as designed and still
cannot express the feature, for two reasons found by spike rather than by reading. Both were
reproduced on kernel 6.8 (Landlock ABI 4) with go-landlock v0.9.0.

**1. Granting the loader execute is the allowlist undone.** The kernel executes a
dynamically linked binary's `PT_INTERP`, so an allowlisted dynamic binary does not run
unless the loader also carries execute - allowlisting only `/usr/bin/echo` denies
`/usr/bin/echo`. Grant the loader, and the loader run directly as a command takes any
readable ELF as its argument:

```
ruleset: read-no-execute on /, read-write-no-execute on /tmp,
         execute on /usr/bin/echo, execute on ld-linux-x86-64.so.2

/usr/bin/echo                  -> allowed, the allowlist entry
ld.so /usr/bin/id              -> RAN. not on the allowlist
ld.so /tmp/<self-written elf>  -> RAN. never on the host at all
```

The third line is the one that decides it. The payload was copied into a path the write
grants make writable, so the bypass is not even bounded by what is installed on the host.
And because this mode installs no exec-block filter, it is reachable through any language's
ordinary subprocess call - unlike `exec: none`, whose documented residual needs a raw
`execveat`.

Stripping read as well does not rescue it. The bypass needs the loader executable AND the
payload readable, and `sandboxWritableMounts` (`/tmp`, `/dev`, `/proc`) plus the write grants
are readable on every run by construction. The only way to close it is to deny the loader
execute, which forces statically linked entries.

**2. Static-only does not survive either.** Reason 1 is the load-bearing one; this is what
it costs once obeyed. Under this mode `Block` is false - the target has to be able to `execve` at all - so
`launcher.runTarget` takes `superviseTarget`, an ordinary `exec.Command`, and that runs
after `applyLayers` has installed the ruleset. The target's own `argv[0]` therefore needs
execute under the very ruleset that withholds it, and `command()` in `internal/linux/args.go`
returns the interpreter when there is one and the entrypoint when there is not. A process
that restricts itself and then execs a dynamic binary is denied - that is the same fact as
reason 1, applied to the launcher.

So the mode would additionally require the entrypoint and interpreter to be statically
linked. Any script under an interpreter is out: `python3`, `/bin/sh`, and every real
interpreter is dynamic. What is left is a static entrypoint with no interpreter spawning
static allowlisted binaries - a static Go binary that spawns other static Go binaries.
That is neither the toolchain case that motivated the bead nor the fixed-script case it was
later narrowed to, and no job class was named for it.

The launcher ordering is not itself the obstacle, and a reader should not stop there: a
static shim that applied the ruleset after being exec'd would move the problem without
solving it, because every binary in the chain still has to be static. The ceiling is what
reason 1 leaves behind, not where the ruleset happens to be installed today.

Landlock governs filesystem paths; the exec allowlist is a question about which program the
kernel loads. The two only coincide for binaries that need nothing loaded on their behalf.

### The shape that remains

A broker. The target keeps `exec: none` - seccomp-blocked, so the loader question never
arises - and asks bento to spawn an approved binary on its behalf over a channel; bento runs
it outside the filter with a fixed argv. The allowlist becomes a broker-side table rather
than a filesystem right, so what is permitted is an entry in the reviewed policy rather than
whatever the loader can reach.

That also clears `ADR-0006`'s bar, which neither rejected mechanism did: the exec-block
filter still fails closed on its own, and the broker only widens it, along a channel bento
controls rather than by re-running a syscall against pointers the target can rewrite.

### Positive Consequences

* `exec` keeps three modes that each mean what they say, and none of them rests on a
  mechanism that can be argued around.
* The bar `ADR-0006` set now has a second mechanism measured against it, and the same
  answer: an exec control is only worth having if something fails closed underneath it.
* The negative result is executable. `internal/landlock` keeps `RestrictExecAllowlist` and
  its probe, whose `execallow_loader=DENIED` arm is the assertion that says why granting the
  loader cannot be the fix. Nothing in a policy reaches it - it exists so this ADR's central
  claim can be re-run rather than re-argued.

### Negative Consequences / Trade-offs

* A job that needs a real toolchain present still gets `exec: all`, which is the gap this
  work set out to close and did not.
* `internal/landlock` carries a mechanism no run uses. That is a real cost, accepted because
  the alternative is a paragraph asserting a kernel behaviour with nothing to check it
  against.
* One observation was recorded and deliberately not built on: on ABI 4, shared objects
  mapped `PROT_EXEC` needed no execute right - granting the loader alone was enough, and
  `libc` was not. Landlock has an `mmap` hook and this is version-sensitive. It is noted
  because it would matter to any future variant, not because anything here depends on it.
