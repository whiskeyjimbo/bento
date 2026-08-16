# [ADR-0007] Cross-Language Service Surface

* **Status:** Proposed
* **Date:** 2026-08-02

## Context and Problem Statement

Bento is embeddable today, but only from Go. `enforce.Run` takes an `Enforcer`, a
`*policy.Policy`, a `Process`, and `Options`, and returns a `Result`
(`enforce/run.go:72`); `examples/embed/main.go:183` and `examples/supervise/main.go:287`
are working callers. A harness written in Python, TypeScript, or Rust has no equivalent -
it must shell out.

Shelling out is not nothing. `bento run --json` already emits NDJSON: one object per
stdout/stderr chunk, base64-encoded and stream-tagged, then exactly one terminal
`verdict`, `refusal`, or `failed` object, with refusals emitted as objects too so stdout
is never empty (`cmd/bento/run.go:150-233,368-416`). `validate`, `doctor`, and `profile`
have `--json` as well. For a non-interactive caller *whose target needs no input*, that is
the whole API - `--json` sets `proc.Stdin = nil` (`cmd/bento/run.go:127`).

Two capabilities do not survive the process boundary:

* **The network gate.** `enforce.NetworkGate` is `func(ctx, host, port) bool`, consulted
  synchronously in the connection's own goroutine, mid-run, and permitted to block while
  it prompts a human (`enforce/enforce.go:93-99`). A CLI invocation has nowhere to put
  that callback, and a unary `Run(manifest) -> Result` RPC cannot express it either.
* **Stdin**, per above.

The target embedder for this decision is **arbitrary callers, any language** - a
published, versioned surface, not a single first-party wrapper.

### Why the Terraform provider analogy does not transfer

Terraform's gRPC plugin surface exists so that Terraform, the host, can drive plugins
other people wrote; the process boundary is simultaneously a lifecycle and trust
boundary the core controls. What is wanted here is the inverse - other languages driving
bento. That is "bento as a service," a different shape with a different threat model.
The literal go-plugin analogy would only apply to a *pluggable* `Enforcer` or
`NetworkGate` implemented outside Go, which is a real but much smaller feature and is
out of scope here.

## Decision Drivers

* Cross-language callers, without each one reimplementing the NDJSON contract.
* The network gate must remain reachable, or its loss must be explicit.
* **The approval check must not be routed around** - and must not be over-claimed either.
* A long-lived service that spawns sandboxes for callers is a confused deputy by
  construction, in a project whose thesis is fail-closed.

## The approval problem

`bento approve` stamps a fingerprint of the policy fields into the manifest's
`provenance.approves` (`manifest/manifest.go:58-60`, `cmd/bento/approve.go:92-99`).
`bento run` recomputes it and refuses when the manifest was edited after review
(`requireApproval`, `cmd/bento/run.go:489`, via `checkApproval`,
`cmd/bento/validate.go:167`). `--allow-unapproved` (`cmd/bento/run.go:144`) opts out for
the profile-then-run loop.

**What the stamp is, precisely.** It is unkeyed local drift detection, *not*
authentication - the code says so in both places (`cmd/bento/run.go:482-486`,
`cmd/bento/approve.go:36-39`). It records that the permissions match what was stamped,
never who stamped them. Anyone who can write the file can restamp it, and
`policy.Fingerprint()` is a plain digest anyone can compute. Calling it "attestation" -
as an earlier draft of this ADR did - overstates it and would mislead the design.

What actually approximates "only the reviewer could have changed this" is the trust
inspection in `cmd/bento/trust.go`: it walks the manifest file's ownership, mode bits,
POSIX ACLs, the directory chain above it, and symlink ownership
(`trust.go:21-135,304-430`), and refuses non-regular files (`trust.go:226`). Two
properties of it decide this ADR:

* On the **run** path it is only advisory - `warnStampAtRisk` prints and does not refuse
  (`trust.go:484-502`: "The read commands do not refuse on one"). Only `approve` refuses
  (`requireApprovableLocation`, `approve.go:295`). The enforced check on a run is the
  fingerprint comparison alone.
* It judges every flaw against `os.Geteuid()` (`trust.go:154,296,488`). In a daemon that
  is the *daemon's* uid, not the caller's, which silently answers a different question
  than the one being asked.

Neither check lives in `enforce` - `enforce.Run` never sees the manifest or its
provenance, only a `*policy.Policy`. So: **any RPC layer built directly on `enforce`
skips approval entirely by default.** That is correct as a finding and is the reason
step 2 below exists.

### The two ways a caller can supply policy

**A. Caller names a pre-approved manifest.** The request carries a path (and optionally
the fingerprint it expects); the daemon loads it and runs the same checks the CLI runs.
The property being relied on is still a file on disk with an owner, a mode, and a
directory chain - something `trust.go` can evaluate. But A is only worth anything if the
service, unlike the CLI, makes it load-bearing:

1. trust flaws must be **fatal**, not advisory, on the service path; and
2. `foreignOwner` must be judged against the **RPC peer's** uid (SO_PEERCRED), not the
   daemon's.

Without both, A degrades to "any caller who can write a path the daemon will load may
author and self-stamp any policy" - which is option B with extra steps.

**B. Caller sends policy inline.** There is no file, no owner, no mode, no directory
chain, so `trust.go` has nothing to evaluate at all and the fingerprint check becomes
circular (the caller supplied both the policy and the stamp over it). It relocates the
trust boundary wholly onto the daemon's own authorization: whoever may call may grant
themselves any permission bento can enforce.

Recommendation: **A, with the two conditions above stated as requirements**, and B only
over a socket whose peer credentials match the daemon's own uid, if at all - and under a
distinct method name so an audit log can tell the two apart. Whether `--allow-unapproved`
has any wire equivalent is the same question and should be answered with it (default: no).

## Considered Options

* **1. Do nothing; document the `--json` contract as the cross-language API.**
  No daemon and no long-lived privilege surface. Loses the gate and stdin. Each language
  reimplements the envelope. Note this is *not* "zero compatibility commitment" - the
  NDJSON envelope is already the published machine contract.

* **2. `--json` plus a duplex control channel.**
  Keep the process-per-run model; add a channel (inherited fd, or a UDS the caller
  passes) on which the run emits a `gate` request and blocks for a reply, and optionally
  carries stdin frames. No daemon, approval untouched because the path is still
  `cmd/bento run` with all its checks. Smallest change that restores the missing
  capabilities, and it validates the wire shape of a gate exchange before anything is
  frozen in a proto.

* **3. `bento serve`: a long-lived daemon with a bidi-streamed gRPC surface.**
  One `Run` stream: client opens with a manifest reference, server streams stdout,
  stderr, gate requests, and the verdict; client streams stdin and gate replies.
  Generated clients for every language, one versioned proto. The full answer to the
  question asked - and the one that must answer who may call, and how the approval check
  still means something.

* **4. go-plugin-shaped pluggable gates/enforcers.**
  Bento stays the host and calls out to a gate written in another language. Solves a
  different problem (custom approval UIs) and does not make bento embeddable.

## Decision Outcome

Not yet decided. The sequencing that makes sense:

1. **Settle the identity question.** Not "file path vs inline" but: *who could have
   written this stamp, and against whose identity is the trust walk judged?* That is a
   prerequisite for 2 and 3 alike and belongs in this ADR before any `.proto` is written.
2. **Extract the approval and trust checks out of `cmd/bento`** into a package both the
   CLI and any service surface call. Extract the trust walk with the observing identity
   as a **parameter**, and with fatality as a caller decision - otherwise the shared
   package bakes in the CLI's advisory-and-euid answer and step 1 has been decided by
   accident. Worth doing on its own merits even if no service is ever built.

   Done: package `trust`. `Inspect`/`InspectNew` gather the facts, `Flaws(euid)` and
   `LocationFlaws(euid)` judge them against an identity the caller names, and `Flaw.Fatal`
   is data nothing in the package acts on. `CheckApproval` is the fingerprint comparison.
   The CLI's answer - advisory on a read, fatal on an approve, `os.Geteuid()` throughout -
   now lives in `cmd/bento` (`trustwarn.go`, `requireApprovableLocation`), so step 1 is
   still open rather than decided.
3. **Ship option 2.** Acceptance criteria beyond "the gate works":
   * **Stdin disposition** is stated - carried on the channel, or interactive targets are
     declared out of scope. `Process.AllowNetworkStdio` (`enforce/enforce.go:114-124`) is
     deliberately Go-caller-only and must never gain a wire equivalent.
   * **The target cannot reach or forge on the channel, on every tier.** A caller-supplied
     UDS path is unreachable from a full bwrap run, but the degraded tier has no mount
     namespace (`enforce/enforce.go:56-64`), so a degraded-tier target could connect to it
     and inject. An inherited fd is safer only if the backend provably does not pass it in.
     `host`/`port` in a gate request are attacker-chosen bytes - the framing must not be
     smuggle-able.
   * **Channel death denies, and teardown does not stall.** `stop()` blocks until
     `proxy.Serve` returns (`internal/linux/linux.go:716-726`) while handlers sit inside
     the gate; a peer that dies mid-prompt must resolve to deny on ctx, or run teardown
     hangs - exactly what `enforce/enforce.go:96-98` warns about. This is also the answer
     to option 3's lifetime question: client disconnect ⇒ ctx cancel ⇒ teardown.
4. **Reassess 3** once something is actually using 2. A daemon is a large, permanent
   security surface to add on a prediction.

### Negative Consequences / Trade-offs

* Option 3 makes bento a privilege boundary of its own. `docs/threat-model.md` has no
  adversary class for an RPC caller at all - its adversary is the sandboxed program and
  grants are "yours to grant". That is a rewrite, not an amendment.
* **Host probes are memoized per process** (`enforce/enforce.go:26-28`), so a long-lived
  daemon serves stale probe verdicts as the host changes - fail-open in direction if e.g.
  cgroup delegation degrades after startup. Resource limits also run through transient
  systemd scopes whose lifetimes a daemon owns across client disconnects.
* A wire contract must carry the `Refusal`/`Shortfall`/strict-shortfall distinctions and
  the 124/125 exit conventions (`cmd/bento/run.go:33-46,459-471`), or `--strict`
  semantics do not survive the boundary.
* A non-nil gate pulls `LayerNetwork` into the required layer set even for a zero-network
  manifest (`enforce/run.go:191-208`), so a surface that always wires a gate changes which
  hosts can run which manifests.
* The CONNECT proxy is per-run, per-socket (`internal/linux/linux.go:595-608`), so a
  daemon has no shared-proxy tenancy problem - but the cross-connection properties that
  only `make race` enforces carry higher stakes under concurrent runs.
