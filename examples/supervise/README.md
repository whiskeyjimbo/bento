# supervise - interactive supervision, editor-agent style

A small wrapper that runs an untrusted script under bento the way an editor agent
does: discover what the script wants, ask a human to approve it, then run it
enforced - prompting live for anything it reaches at runtime that you did not
declare. It uses only bento's public packages (no `internal/` imports), so it also
proves the public surface is enough to build a real supervisor.

## The two models (and why they differ)

bento supports two honest interaction models, and this example shows both. They
differ because the kernel enforces network and filesystem differently:

- **Network is gated live.** During the enforced run bento consults a callback for
  every host the manifest did not declare, in the connection's own goroutine. So
  you are prompted *at connect time*, and a denial blocks that connection in real
  time - exactly the "allow piratesite.com? [y/n]" moment.

- **Filesystem is approved from a trial run.** A denied read is refused inside the
  kernel (Landlock / the mount set); the box never learns what was attempted, so
  there is no per-access callback to prompt on mid-read. Instead, a **trial pass**
  runs the script permissively under observation, records every file it reads and
  writes (nothing leaves the host), and you approve paths *before* the enforced
  run. The enforced run then denies anything you did not approve.

So filesystem approval happens up front, network approval can happen live. That is
not a limitation this example papers over - it is how bento works, and the demo is
built to make the difference visible.

## Prerequisites

- Linux with `bwrap` (bubblewrap) and unprivileged user namespaces.
- Go, and `curl` (the demo agent uses it to make requests).

## Build

```sh
go build -o supervise .
```

## Walkthrough

```sh
./supervise run demo/agent.sh
```

`demo/agent.sh` reads two files from `../vault`, writes a log, and reaches two
hosts. Nothing is declared up front, so you decide everything.

### Act 1 - trial run, approve what it wants

The script runs permissively under observation, then you approve each access with
**[y]es / [n]o / [A]ll** (A approves this and everything after it):

```
== trial run: watching agent.sh (permissive, nothing leaves the host) ==
  read   ~/.../vault/data.csv     [y/n/A] y
  read   ~/.../vault/secret.txt   [y/n/A] n     <- keep the secret out
  write  ~/.../demo               [y/n/A] y
  exec   run subprocesses         [y/n/A] y
  reach  ads.tracker.example:443  [y/n/A] n     <- decline the tracker
  reach  example.com:443          [y/n/A] y
```

Your answers become the manifest the enforced run is held to. You may also see a
couple of incidental reads the trial caught - `curl` opening its own TLS config,
say (`/etc/gnutls/config`, `~/.curlrc`); the exact set depends on your `curl`
build. Decline them: the request still works without them, and that is the point
of reviewing what a permissive run actually touched. The wrapper does drop the
sandbox's own scratch (`/tmp`, `/dev`, `/proc`) before asking, since granting
those is meaningless.

### Act 2 - enforced run, live gate for the rest

```
== enforced run: agent.sh under your approvals ==
[agent] read  vault/data.csv       -> ok
[agent] read  vault/secret.txt     -> DENIED (kernel)     <- refused inside the kernel
[agent] write out.log              -> ok
[agent] reach example.com          -> HTTP 200            <- declared, no prompt
[agent] reach ads.tracker.example

[gate] agent.sh is reaching "ads.tracker.example" port 443 now - allow? [y/n/A] n
                                   -> blocked              <- live gate, denied in real time
```

`secret.txt` is denied by the kernel because you never granted it - no prompt, it
just fails. `ads.tracker.example` was not declared, so the live gate prompts you at
the moment the script reaches it. Answer `y` or `A` and it is admitted, and the run
reports it:

```
supervise: the live gate admitted egress beyond the manifest:
  ads.tracker.example:443   (a real wrapper would offer to add this to the manifest)
```

## The honesty loop

`Result.GateAdmitted` is what a run permits beyond its declared manifest, surfaced
so nothing is laundered into looking declared. A real wrapper collects these and
offers to persist them into the manifest via bento's `approve`/fingerprint path -
turning ad-hoc runtime approvals back into attested policy. That is the "always
allow" of an editor agent:

| Editor agent  | Here                                                       |
| ------------- | ---------------------------------------------------------- |
| Allow once    | gate returns true for this connection                      |
| Allow session | remembered for the run (the gate's session cache)          |
| Always allow  | persist the host into the manifest (approve/fingerprint)   |

## Code map

- `run()` - the two acts: `backend.Profile` (trial) then `enforce.Run` with a
  `NetworkGate` (enforced).
- `approve()` - walks the synthesized proposal and builds the policy from y/n/A.
- `supervisor.gate` - the live network gate: prompt, session cache, ctx-aware
  cancellation, hostname sanitization.
- `prompter` - reads y/n/A from the controlling terminal, ctx-aware so a pending
  prompt cannot stall run teardown.
- `main_test.go` - proves approval, allow-all, and the gate's per-host memory.

For the design rationale (why network but not filesystem), see
`docs/network-gate-seam.md`. For a stripped-down non-interactive embedder, see
`examples/embed`.
