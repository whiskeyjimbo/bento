# embed - hosting bento in-process

A minimal program that runs an untrusted script under bento's sandbox by calling
bento's public Go API directly, instead of shelling out to the `bento` binary and
parsing its output. It is the reference for an embedder such as a supervising CLI
wrapper.

It does two things worth studying:

1. **In-process enforcement.** Load a manifest to a `policy.Policy`, get an
   enforcer from `backend.New()`, call `enforce.Run(...)`, and read a structured
   `enforce.Result` (exit code, degradation report, egress accounting).
2. **Interactive supervision.** Supply a `NetworkGate` that prompts a human to
   admit egress the manifest did not declare, and remembers the answer for the
   run - the model an editor agent uses. bento provides the seam and the honesty
   accounting; the prompt and the session memory are the wrapper's, and they live
   in the `supervisor` type in `main.go`.

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
embed: gate admitted undeclared egress to example.com:443
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
embed: gate admitted undeclared egress to example.com:443
```

Answer `y` and it is admitted; answer anything else and it is denied. The answer
is cached for the run, so the same host is asked only once. The hostname is quoted
before display because it is attacker-controlled (the sandboxed target chose it).

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

## What is *not* here: filesystem prompts

The gate is network-only, on purpose. A denied file read is refused inside the
kernel (Landlock / the mount set) and the box never learns what was attempted, so
there is no per-access callback to hang a prompt on. The box-native way to do
interactive filesystem is the batch loop: `bento profile` (observe a permissive
run) then `bento approve`. See `docs/network-gate-seam.md` for the full rationale.

## Code map

- `main.go` `run()` - the in-process enforcement flow, end to end.
- `main.go` `supervisor` - the interactive layer: prompt, session cache, ctx-aware
  cancellation, hostname sanitization.
- `supervisor_test.go` - proves prompt-once-per-host, pre-approval, and that a
  prompt returns (as a denial) when the run's context is cancelled.
