# embed - hosting bento in-process

A minimal program that runs a script under bento's sandbox by calling bento's public
Go API directly, instead of shelling out to the `bento` binary and parsing its output.
It is the reference for an embedder such as a supervising CLI wrapper.

It runs with the zero-value `enforce.Options`, which refuses only on a **core**-tier
shortfall: a hardening gap (exec-blocking unavailable, say, so the target can spawn
subprocesses) is reported but the run proceeds, and that report necessarily prints
*after* the target has run. That is the right default for a demo you want to run on any
host, and the wrong one for genuinely untrusted code - for that, set `Strict: true`,
which refuses up front unless every layer, hardening included, is enforced.

It does three things worth studying:

1. **In-process enforcement.** Load a manifest to a `policy.Policy`, get an
   enforcer from `backend.New()`, call `enforce.Run(...)`, and read a structured
   `enforce.Result` (exit code, degradation report, egress accounting).
2. **Interactive supervision.** Supply a `NetworkGate` that prompts a human to
   admit egress the manifest did not declare, and remembers the answer for the
   run - the model an editor agent uses. bento provides the seam and the honesty
   accounting; the prompt and the session memory are the wrapper's, and they live
   in the `supervisor` type in `main.go`.
3. **Surfacing every honesty field.** A `Result` carries what the run could not
   guarantee and what it exposed anyway - degradations, the shields that engaged,
   gate-admitted egress, granted credential paths, unshieldable paths, credential
   aliases read past a shield, and the egress count. An embedder who reads only some
   of them ships a frontend that is silent about the rest, so this example reads them
   all, including the ones that stay empty under its own options (see "Every honesty
   surface").

## Prerequisites

- Linux with `bwrap` (bubblewrap) and unprivileged user namespaces.
- Go (to build).
- `curl` for the demo script below.

## Build

```sh
go build -o embed .
```

This module is intentionally separate (its own `go.mod`), so Go's internal-package
rule turns any import of `bento/internal/...` into a compile error. If it
builds, bento's public packages are self-sufficient for an embedder.

## The demo

`demo/reach.yaml` is a manifest that declares **no** network rules, and
`demo/reach.sh` tries to reach `example.com`. So that egress is *undeclared*: what
happens to it depends entirely on the gate. Run these from this directory.

### 1. Declarative box - undeclared egress is denied

```sh
./embed demo/reach.yaml
```

```
reaching example.com ... HTTP 000blocked
```

No gate, no terminal: bento behaves as the non-interactive box. The connection
never leaves the sandbox.

### 2. Supervised, unattended - pre-approve the host

```sh
BENTO_GATE_ALLOW=example.com ./embed demo/reach.yaml
```

```
reaching example.com ... HTTP 200 (reached)
embed: gate admitted undeclared egress to "example.com" port 443
```

`BENTO_GATE_ALLOW` seeds the gate's "already decided" set, so the host is admitted
without a prompt. The second line is the honesty surface: `Result.GateAdmitted`
lists what the gate let out beyond the manifest.

### 3. Supervised, interactive - get prompted

Run it attached to a terminal, with no pre-approval:

```sh
./embed demo/reach.yaml
```

```
bento: allow egress to "example.com" port 443? [y/N] y
reaching example.com ... HTTP 200 (reached)
embed: gate admitted undeclared egress to "example.com" port 443
```

Answer `y` and it is admitted; answer anything else and it is denied. The answer
is cached for the run, so the same host is asked only once. The hostname is quoted
before display because it is attacker-controlled (the sandboxed target chose it), and
the prompt is read from and written to `/dev/tty` rather than the target's own stdin and
stderr, so the dialogue is on no descriptor the confined program holds. Redirect or
capture the target's output - what an embedder wrapping this does - and it cannot reach
the dialogue at all. Share a bare terminal with it, as this demo does, and it can still
print convincing lines to the same screen through its inherited stderr; what it cannot
do is read your keystrokes or inject into the terminal, since the sandbox starts a new
session.

## The honesty loop

`GateAdmitted` is what makes "run permissively, then tighten" possible. A wrapper
collects the hosts a human waved through, and can offer to persist them into the
manifest via bento's normal `approve`/fingerprint path - turning ad-hoc runtime
approvals back into declared, attested policy. After that the host is in the
manifest and the gate is never consulted for it again. That maps onto an editor
agent's "allow once / allow for session / always allow":

| Editor agent    | Here                                                        |
| --------------- | ----------------------------------------------------------- |
| Allow once      | gate returns true for this connection only                  |
| Allow session   | the `supervisor`'s session cache, remembered for the run    |
| Always allow    | persist the host into the manifest (approve/fingerprint)    |

## Every honesty surface

`writeResult()` reads all of these from one `enforce.Result`, in this order. Most stay
empty on a healthy host with an ordinary manifest; every one of them is read, so an
embedder who copies this file inherits the warning rather than the silence:

| Field                | What its absence would hide                                            |
| -------------------- | ---------------------------------------------------------------------- |
| `Report.Degradations()` | a layer the host could only partly enforce                           |
| `Shields`            | *(positive evidence)* that the boundary engaged, and for how many paths |
| `GateAdmitted`       | egress a human waved through beyond the manifest                       |
| `ShieldedGrants`     | a credential store the manifest granted, so the target could read it   |
| `AcceptedAliases`    | a credential read under a second name, past its shield                 |
| `Exposed`            | what a full run would shield but this tier could not                   |
| `EgressConnections`  | a proxy bypass: a network run that reached nothing through the proxy    |

Each line prints only when it has something to say - an empty list prints nothing, and
the last row is a count read in context rather than a list. `Shields` being empty is
not proof nothing sensitive was in scope: the degraded tier shields nothing at all and
reports that through the report instead.

Two more come from outside the `Result`: the names `enforce.ResolveEnv` reports as
allowed-but-unset (a manifest that permits `GITHUB_TOKEN` on a host that does not set
it), and `enforce.Refusal`'s `Short`, which is what names *which* layer fell short -
printing `Reason` alone gives a generic posture string. Printing `%v` on the error
covers both parts.

`enforce.Shortfall` is the one an embedder is likeliest to mishandle. It means the
target **ran** and then a guarantee `Strict` required lapsed, so the `Result` is
complete and must not be discarded like a failure - but its exit code is no longer the
answer. It is unreachable under this example's options and handled anyway, because
setting `Strict: true` is exactly what a copyist does first.

## What is *not* here: filesystem prompts

The gate is network-only, on purpose. A denied file read is refused inside the
kernel (Landlock / the mount set) and the box never learns what was attempted, so
there is no per-access callback to hang a prompt on. The box-native way to do
interactive filesystem is the batch loop: `bento profile` (observe a permissive
run) then `bento approve`. [`examples/supervise`](../supervise/README.md) works through
the full rationale under "The two models (and why they differ)", and builds both halves.

## Code map

- `main.go` `run()` - the in-process enforcement flow, end to end.
- `main.go` `supervisor` - the interactive layer: prompt, session cache, ctx-aware
  cancellation, hostname sanitization.
- `main.go` `writeResult()` - every honesty field of a `Result`, in one place.
- `supervisor_test.go` - proves prompt-once-per-host, pre-approval, and that a
  prompt returns (as a denial) when the run's context is cancelled.
- `result_test.go` - proves every honesty field reaches the output, that host-supplied
  paths are quoted, and - the guard that matters for a template - fails if a new field
  is added to `enforce.Result` and left unprinted here.
- `verify.sh` - the check that keeps this example honest: it greps for any
  `bento/internal/...` import (which its separate `go.mod` already makes a compile
  error), then builds, vets, and tests. If it passes, bento's public packages are
  self-sufficient for an embedder.
