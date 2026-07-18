# supervise - interactive supervision, editor-agent style

A small wrapper that runs an untrusted script under bento the way an editor agent
does: discover what the script wants, ask a human to approve it, then run it
enforced - prompting live for anything it reaches at runtime that you did not
declare. It **remembers your answers**, so a second run of the same script is
silent. It uses only bento's public packages (no `internal/` imports), so it also
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

The script runs permissively under observation, then you approve each access.
**[y]es** and **[n]o** are remembered for this script; **[o]nce** allows just this
run without remembering; **[A]ll** allows this and everything after it (for this
run). Attacker-chosen paths are quoted, since a filename can carry terminal escapes.

```
== trial run: watching agent.sh (permissive, nothing leaves the host) ==
  read   "~/.../vault/data.csv"     [y]es/[n]o/[o]nce/[A]ll y
  read   "~/.../vault/secret.txt"   [y]es/[n]o/[o]nce/[A]ll n   <- keep the secret out
  write  "~/.../demo"               [y]es/[n]o/[o]nce/[A]ll y
  exec   run subprocesses           [y]es/[n]o/[o]nce/[A]ll y
  reach  "ads.tracker.example":443  [y]es/[n]o/[o]nce/[A]ll n   <- decline the tracker
  reach  "example.com":443          [y]es/[n]o/[o]nce/[A]ll y
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

[gate] agent.sh is reaching "ads.tracker.example" port 443 now - allow? [y]es/[n]o/[o]nce n
                                   -> blocked              <- live gate, denied in real time
```

`secret.txt` is denied by the kernel because you never granted it - no prompt, it
just fails. `ads.tracker.example` was not declared, so the live gate prompts you at
the moment the script reaches it (unless the store already remembers it, in which
case it applies silently and a remembered *deny* is printed). Answer `y` and it is
admitted, and the run reports it:

```
supervise: the live gate admitted egress beyond the manifest:
  ads.tracker.example:443   (a real wrapper would offer to add this to the manifest)
```

## Remembering decisions

Your answers are kept in a permission store at
`$XDG_CONFIG_HOME/bento-supervise/permissions.json` (default
`~/.config/bento-supervise/`), so **a second run of the same script is silent** -
every access shows `(remembered)` and applies without a prompt:

```
== trial run: watching agent.sh (permissive, nothing leaves the host) ==
  read   "~/.../vault/data.csv"     allow (remembered)
  read   "~/.../vault/secret.txt"   deny (remembered)
  ...
```

The store is the wrapper's own memory - bento never sees it. A few properties
worth knowing:

- **Keyed by the script's content hash.** Change the script and it re-prompts;
  identical code shares the same decisions wherever it lives. This is launcher
  identity, not behavior identity (a script that `curl | sh`s more code keeps its
  key), so it is convenience memory, not a security boundary.
- **The store shields itself from the trial.** The permissive trial grants
  `Read:["/"]`, so the wrapper passes its own store directory to `backend.Profile`
  as a deny path - the untrusted script cannot read your saved decisions.
- **A grant that would expose the store is refused** outright (you cannot approve
  `read ~/.config` when the store lives under it).
- **Deny wins.** A remembered deny overrides an allow, and a stored deny that fires
  is printed so a silent block is never a mystery.

### Inspecting and editing the store

`perms` reads and edits the store without hand-editing JSON. It is also the escape
hatch for the deny-wins footgun: a stored deny applies silently to a later run with
no prompt, so you need a way to see it and clear it.

```sh
supervise perms list                        # the effective decisions, global rules first
supervise perms forget app <handle>         # drop one app's decisions (handle from list)
supervise perms forget global [host:port]   # drop one global rule, or all of them
supervise perms reset                       # clear the whole store (asks to confirm)
```

`list` prints the *effective* decision - a network host is resolved through the
deny-wins lattice, and one blocked by a global rule is marked `(global)` so you
know it is the global layer to clear, not the app's. Every host and path is quoted,
since a key can be a name the sandboxed target chose.

`forget app` clears the whole app record, not one path or host inside it; re-running
the script re-prompts for everything. Global rules are the finer-grained layer, so
`forget global` can drop a single `host:port` rule (that is the footgun to clear).

Not yet built (tracked as follow-ups): exporting the store to a `bento run`
manifest, and global (cross-script) read/write/exec rules.

## The honesty loop

`Result.GateAdmitted` is what a run permits beyond its declared manifest, surfaced
so nothing is laundered into looking declared - the store never touches it. The
model maps onto an editor agent's allow choices:

| Editor agent  | Here                                                            |
| ------------- | --------------------------------------------------------------- |
| Allow once    | `[o]nce` - admitted for this run, not remembered                |
| Allow session | `[y]es` - remembered for this script across runs                |
| Always allow  | export the store to a bento manifest, then `bento run` (planned) |

## Code map

- `run()` - the two acts: `backend.Profile` (trial, with the store dir as a deny
  path) then `enforce.Run` with a `NetworkGate` (enforced), then saves the store.
- `approve()` - walks the synthesized proposal, consults the store per item
  (auto-apply remembered / prompt unknown / persist), refuses store-covering grants.
- `supervisor.gate` - the live network gate: store lookup first, then prompt;
  session cache, ctx-aware cancellation, hostname quoting.
- `store.go` - the permission store: XDG location, atomic save under a lockfile,
  the SHA app key, the deny-wins lattice, host/path key matching.
- `prompter` - reads the controlling terminal, ctx-aware so a pending prompt cannot
  stall run teardown.
- `*_test.go` - the store lattice/longest-prefix, the run-twice-silent loop, the
  store-covering-grant refusal, path quoting, and the gate's per-host memory.

For the design rationale (why network but not filesystem), see
`docs/network-gate-seam.md`. For a stripped-down non-interactive embedder, see
`examples/embed`.
