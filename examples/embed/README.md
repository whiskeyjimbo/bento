# embed - hosting bento in-process

A minimal program that runs a script under bento's sandbox by calling bento's public
Go API directly, rather than shelling out to the `bento` binary and parsing its output.
It is the reference for a Go embedder such as a supervising CLI wrapper.

A harness written in Python, Node or Rust cannot call that API at all. Its path is the
`bento` binary itself, and it is a genuinely smaller surface - see "Driving bento from
another language" below for what it gives up.

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

## Calling `DispatchReexec` first

Building the sandbox is not something bento can do from within your process: it re-runs
your binary, and that second run - the launcher - is what sets up the confinement and
execs the target. `backend.DispatchReexec()` is how the launcher takes over. It looks at
`os.Args[1]`, and either recognizes itself and never returns, or returns and lets your
program start normally.

That is why it must be the *first* statement in `main()`, ahead of flag parsing and any
other setup. Flags bento passes to the launcher are not your program's flags, so a parser
that runs first will reject them and exit. The same applies to test binaries: put the call
at the top of `TestMain`, before `m.Run()` parses the testing flags, or the launcher will
run your whole test suite again - which starts another sandbox, which runs it again.

```go
func TestMain(m *testing.M) {
	backend.DispatchReexec()
	os.Exit(m.Run())
}
```

`main.go` and `main_test.go` here both do this. If you forget, `backend.New` and
`backend.Profile` return an error naming the missed call rather than letting the program
hang or quietly misbehave - and when the process they run in is itself an undispatched
stage, they name it on stderr and exit 125, which is what stops a test suite forking
itself. The root README's embedding section has the rest.

One consequence worth knowing: every `init()` in your binary runs again in the launcher,
under an environment bento constructed rather than the one you were started with. Keep
package init cheap and free of environment-dependent side effects.

## Prerequisites

- Linux with `bwrap` (bubblewrap) and unprivileged user namespaces.
- Go (to build).
- `curl` for the demo script below.

## Build

```sh
go build -o bentoembed .
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
./bentoembed demo/reach.yaml
```

```
reaching example.com ... HTTP 000blocked
```

No gate, no terminal: bento behaves as the non-interactive box. The connection
never leaves the sandbox.

### 2. Supervised, unattended - pre-approve the host

```sh
BENTO_GATE_ALLOW=example.com ./bentoembed demo/reach.yaml
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
./bentoembed demo/reach.yaml
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
| `ShieldedGrants`     | a store the manifest granted past its shield, and what it held         |
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

## Driving bento from another language

Everything above is Go-only. A harness in Python, Node or Rust runs the `bento` binary
as a subprocess and reads `bento run --json`, which puts the same run on stdout as
line-delimited JSON: the target's own output as it arrives, then exactly one object
naming the outcome. Run these from this directory, with `bento` on your `PATH`.

```sh
bento run --json --allow-unapproved demo/reach.yaml
```

```
{"event":"stdout","data":"cmVhY2hpbmcgZXhhbXBsZS5jb20gLi4uIA=="}
{"event":"stdout","data":"SFRUUCAwMDA="}
{"event":"stdout","data":"YmxvY2tlZAo="}
{"event":"verdict","exit_code":0,"egress_connections":0,"report":{"layers":[{"layer":"filesystem","tier":"core","state":"enforced","detail":"Landlock backstop active"}],"fully_enforced":true}}
```

That is case 1 above - no gate, so the undeclared egress is denied and the target prints
`blocked`. A run bento declines never reaches the target and ends the stream with a
`refusal` object instead, so stdout is never empty:

```sh
bento run --json demo/reach.yaml
```

```
{"event":"refusal","reason":"refusing to run: the manifest is not approved; review it and run `bento approve`, or pass --allow-unapproved","report":{"layers":[],"fully_enforced":false}}
```

Read the stream by switching on `event`:

- `stdout` / `stderr` - one chunk of the target's output. `data` is **base64**: the
  target is untrusted and may print bytes that are not UTF-8, so it is transported as
  bytes and must be decoded (`base64.b64decode`, `Buffer.from(d,'base64')`). A chunk is
  whatever the pipe delivered, **not** a line - concatenate per stream before splitting.
- `verdict` - the run completed. `exit_code` is the target's own.
- `refusal` - bento declined; the target never started.
- `failed` - the run could not be finished. Distinct from `refusal` because a caller may
  retry a refusal (a different host, an approval) and must not retry this. It does not
  say whether the target got to run: bento cannot tell on that path, and does not guess.

Exactly one of the last three arrives, always last. `reason` on the two error events is
prose for a human, not a stable code - branch on `event`, never on the text.

Three rules a subprocess consumer gets wrong:

- **A stream with no terminal object is a failure**, even if it parsed cleanly. If bento
  cannot finish writing stdout it says so on stderr and exits 125 rather than leaving a
  truncated run that reads as a complete one. A consumer that only checks "did the JSON
  parse" would accept the truncation.
- **125 is bento's own failure code**, not the target's, and `--strict` adds 124 for a
  run whose posture lapsed. Every other code is the target's, passed through untouched,
  so a process exit status alone cannot tell a bento verdict from a script that happened
  to exit 125 - that is what `event` is for.
- **`strict_shortfall`** (`--strict` only) means the target ran and then a guarantee
  lapsed. `exit_code` in the verdict is still the target's own there; it is the process
  status that becomes 124. Ignore the field and a run whose posture did not hold reads
  as an ordinary clean run.

The verdict object is the honesty surface above, rendered as JSON. Same obligation: read
all of it, or ship a frontend silent about the rest.

| `Result` field          | In the verdict object                          |
| ----------------------- | ---------------------------------------------- |
| `Report.Degradations()` | `report.layers[].state` / `.detail`, and `report.fully_enforced` |
| `ExitCode`, `Signal`    | `exit_code`, and `signal` only where a signal is known |
| `Shields`               | `shields`                                      |
| `ShieldedGrants`        | `shielded_grants`, each with `holds` and, where the path bound differs from the spelling that granted it, `on_host` |
| `AcceptedAliases`       | `accepted_aliases`                             |
| `Exposed`               | `exposed`                                      |
| `ChangedAutoExec`       | `changed_auto_exec`, the auto-executing files the run changed |
| `EgressConnections`     | `egress_connections`                           |
| `Denied`, `GuardBlocked` | `egress_denied` and `guard_blocked`, naming what the count does not |
| `GateAdmitted`          | *nothing* - see below                          |
| `Setup`                 | *nothing* - which stage died is not reported here |

One field goes the other way: `missing_read_grants` has no `Result` counterpart. It is
the pre-run verdict on read grants that name nothing on this host, which the human path
prints on stderr.

### What does not survive the process boundary

**The network gate.** `enforce.NetworkGate` is a Go callback consulted mid-connection
and allowed to block while it asks a human. There is nowhere to put that on a command
line, so a subprocess caller has no gate: undeclared egress is simply denied, and there
is no `gate_admitted` to report. Everything this README says about supervision,
"allow once / allow for session", and the honesty loop is in-process only. A harness
that needs a host admitted must put it in the manifest and `bento approve`.

**Stdin.** `--json` gives the target none: the stream mode exists to keep the target's
own bytes off bento's stdout, and it does not carry a channel back the other way. A
target that reads from stdin will see EOF.

Also note that `bento profile --json` answers with a single indented document rather
than this per-line event stream, and so does a refusal from it. The two shapes cannot be
parsed by the same code.

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
