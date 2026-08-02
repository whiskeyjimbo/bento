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
  runs the script under a default-deny sandbox that mounts only the script's own
  directory, records every file it tries to read or write (nothing leaves the host),
  and you approve paths *before* the enforced run. The enforced run then denies
  anything you did not approve.

So filesystem approval happens up front, network approval can happen live. That is
not a limitation this example papers over - it is how bento works, and the demo is
built to make the difference visible.

## Prerequisites

- Linux with `bwrap` (bubblewrap) and unprivileged user namespaces.
- Go, and `curl` (the demo agent uses it to make requests).
- A terminal on stdin. Every access the trial finds is a question for a human, so
  `supervise run` refuses rather than answer them itself; `supervise perms` is the
  scriptable half.

## Build

```sh
go build -o supervise .
```

## Walkthrough

```sh
./supervise run demo/agent.sh
```

`demo/agent.sh` reads two files from `../vault`, writes a log, and reaches two hosts
outright plus a third it only learns about once a fetch succeeds. Nothing is declared
up front, so you decide everything.

### Act 1 - trial run, approve what it wants

The script runs under default-deny observation, then you approve each access with
three keys: **[y]es** allows it and remembers that for this script, **[n]o** denies
and remembers, **[o]nce** allows just this run without remembering. That is the whole
per-access choice - a standing rule for *every* script is a deliberate `perms global`
act (below), never a keystroke away from a routine yes. Attacker-chosen paths are
quoted, since a filename can carry terminal escapes, and the whole dialogue is read
from and written to `/dev/tty` rather than the target's own stdin and stderr, so it is on
no descriptor the confined script holds - redirect the script's output and it cannot
reach the dialogue at all, while on a shared bare terminal it can still print convincing
lines to the same screen but can never read your keystrokes. The run's banners and
summary stay on stderr, so `2>log` keeps the report and leaves the dialogue on screen. Output is colorized on a terminal
(the access kind, a `✓`/`✗` verdict); set `NO_COLOR` or pipe it for plain text.

```
trial run · agent.sh  (default-deny - nothing leaves the host)
  approve what the trial touched  ·  y allow (this script) · n deny · o once
    read  "~/.curlrc"               [y]es [n]o [o]nce › n   <- incidental, decline it
    read  "~/.../demo"              [y]es [n]o [o]nce › y   <- the script's own directory
    read  "~/.../vault/data.csv"    [y]es [n]o [o]nce › y
    read  "~/.../vault/secret.txt"  [y]es [n]o [o]nce › n   <- keep the secret out
    write "~/.../demo"              [y]es [n]o [o]nce › y
    exec  run subprocesses          [y]es [n]o [o]nce › y
    reach "ads.tracker.example":443 [y]es [n]o [o]nce › n   <- decline the tracker
    reach "example.com":443         [y]es [n]o [o]nce › y
```

Your answers become the manifest the enforced run is held to. The script's own
directory is asked about like anything else - the trial mounts it so the script can
be read and run, but reading and writing files inside it is still a grant you give.
The reads above it (the walk down to `demo`) are not asked about, since a yes to one
of those would grant a whole tree the script never named.

The exact set of incidental reads depends on your `curl` build - `~/.curlrc` here,
perhaps `/etc/gnutls/config` too. Decline them: the request still works without them,
and that is the point of reviewing what the trial run actually touched. The wrapper
does drop the sandbox's own scratch (`/tmp`, `/dev`, `/proc`) before asking, since
granting those is meaningless.

### Act 2 - enforced run, the gate on every undeclared host

```
enforced run · agent.sh  (a live gate prompts for any undeclared host)
[agent] read  vault/data.csv
  -> ok
[agent] read  vault/secret.txt
  -> DENIED (kernel)                                      <- refused inside the kernel
[agent] write out.log
  -> ok
[agent] reach example.com
  -> HTTP 200                                             <- declared, no prompt
[agent] reach example.org (learned from the response)
  net agent.sh is reaching "example.org" port 443 now
      allow? [y]es [n]o [o]nce [B]lock-everywhere › y     <- the live gate, stopped mid-connection
  -> HTTP 200
[agent] reach ads.tracker.example
  ✗ agent.sh reaching "ads.tracker.example" port 443 - denied by the permission store
  -> blocked

the sandbox shielded 5 credential/host-service path(s) from the script

the live gate admitted egress beyond the manifest:
  "example.org" port 443   (a real wrapper would offer to add this to the manifest)

egress to these destinations was refused: no network rule covers them, and none was admitted
  "ads.tracker.example" port 443 (the target saw only a 403 from the proxy)
```

`secret.txt` is denied by the kernel because you never granted it - no prompt, it
just fails. `ads.tracker.example` goes through the live gate, but it does not prompt:
you already answered `n` for it in Act 1, and the gate applies a remembered decision
without asking, printing the line above so a silent block is never a mystery.

`example.org` is the one host the trial never surfaced, and it is where the
gate actually prompts - the connection is stopped in its own goroutine while it waits
for you. It stays undecided through Act 1 for a structural reason, not a scripted one:
`agent.sh` only reaches for it after `example.com` returns, and the trial runs
default-deny, so in the trial that fetch fails and the follow-up never happens. The
host is therefore absent from the trial's recorded set, which is exactly how a real
agent discovers a destination its operator never declared.

## Remembering decisions

Your answers are kept in a permission store at
`$XDG_CONFIG_HOME/bento-supervise/permissions.json` (default
`~/.config/bento-supervise/`), so **a second run of the same script is silent** -
every access shows `(remembered)` and applies without a prompt:

```
trial run · agent.sh  (default-deny - nothing leaves the host)
  ✓ read  "~/.../vault/data.csv"    allowed (remembered)
  ✗ read  "~/.../vault/secret.txt"  denied (remembered)
  ...
```

The store is the wrapper's own memory - bento never sees it. A few properties
worth knowing:

- **Keyed by the script's content hash.** Change the script and it re-prompts;
  identical code shares the same decisions wherever it lives. This is launcher
  identity, not behavior identity (a script that `curl | sh`s more code keeps its
  key), so it is convenience memory, not a security boundary.
- **The store is shielded from the trial.** The trial runs default-deny, mounting only
  the script's own directory. The store lives under the config dir, so a script placed
  in or beside it (say, under a dev-set `XDG_CONFIG_HOME`) could reach it through that
  script-dir grant; the wrapper passes the store directory to `backend.Profile` as a
  trial deny path, so the untrusted script cannot read or tamper with your saved
  decisions wherever the script lives.
- **A grant that would expose the store is refused** outright (you cannot approve
  `read ~/.config` when the store lives under it).
- **Deny wins.** A remembered deny overrides an allow, and a stored deny that fires
  is printed so a silent block is never a mystery.
- **It fails closed, never quietly.** A store that cannot be read or parsed - or that
  a newer build wrote - stops the run rather than being replaced with an empty one; a
  wrongly-forgotten deny is worse than a refusal. Writes are atomic and flushed, and
  the run persists what it recorded even when it fails partway, so an answer you gave
  is never lost to a later error. Ctrl-C is part of that: it cancels the run - stopping
  the remaining prompts and killing the sandboxed child - and still saves the answers
  you had already given.
- **Two layers, deny-wins across both.** Per-app decisions live under the script's
  hash; global decisions apply to every app and survive a code change, since a fresh
  hash still sees them. Global rules are set deliberately - `perms global ...`, or
  `[B]lock-everywhere` at the live gate - not from the routine approval prompt. A broad
  global deny beats a more-specific per-app allow, the whole point of a standing
  denylist. `perms list` marks a decision `(global)` when a global deny is why it is
  blocked, so you clear the right layer.

### Inspecting and editing the store

`perms` reads and edits the store without hand-editing JSON. It is also the escape
hatch for the deny-wins footgun: a stored deny applies silently to a later run with
no prompt, so you need a way to see it and clear it.

```sh
supervise perms list                        # the effective decisions, global rules first
supervise perms global deny net ads.x:443   # set a standing rule for every script
supervise perms global allow read /etc/hosts
supervise perms forget app <handle>         # drop one app's decisions (handle from list)
supervise perms forget global [host:port]   # drop one global rule, or all of them
supervise perms reset                       # clear the whole store (asks to confirm)
supervise perms import <manifest.yaml>      # seed an app's approvals from a manifest
```

`import` is how a headless caller gets a store to run against: `run` needs a terminal
and refuses without one, so seed the decisions first from a manifest you already
attested, then run. It is `export` backwards.

`list` prints the *effective* decision - a network host is resolved through the
deny-wins lattice, and one blocked by a global rule is marked `(global)` so you
know it is the global layer to clear, not the app's. Every host and path is quoted,
since a key can be a name the sandboxed target chose.

`forget app` clears the whole app record, not one path or host inside it; re-running
the script re-prompts for everything. Global rules are the finer-grained layer, so
`forget global` can drop a single `host:port` rule (that is the footgun to clear).

### Graduating to an attested manifest

`export` turns an app's remembered approvals into a bento manifest, so the same
script can run under plain `bento run` once you attest it:

```sh
supervise perms export <handle>            # writes <script>.manifest.yaml
bento approve <script>.manifest.yaml       # a deliberate human attestation
bento run <script>.manifest.yaml           # now runs declared, no wrapper
```

Export writes the *effective* policy: a host a global rule denies never reaches the
allowlist, and it refuses outright if a deny is nested under an allowed dir - a
manifest is a pure allowlist and cannot express that. Like `bento profile` it leaves
the provenance unattested; graduating store memory into a declared policy is honest,
but `bento approve` is the separate step that attests it.

`import` runs the loop backwards, seeding an app's approvals from an existing
manifest. It hashes the entrypoint's *current* bytes and asks you to confirm, since
bento's fingerprint attests the policy, not the code - the file may not be what the
manifest was written for. A remembered deny is kept (only `forget` clears a deny),
and a wildcard or port-range rule is skipped, since the store holds only literal
`host:port` keys; those stay runtime prompts.

### Drift between the store and a manifest

When a `<script>.manifest.yaml` exists next to a script you `supervise run`, the
wrapper warns up front about any place the manifest and the store disagree - so you
notice that plain `bento run` would enforce something different from what supervise
remembers. It walks the store's own allow/deny decisions and flags each the manifest
resolves the other way, naming the direction (`bento run` more permissive, or
supervise more permissive). A manifest entry the store has no opinion on is *not*
drift: supervise would prompt for it, which is not silent. Network rules are matched
through the manifest's wildcards and ranges, so a concrete host the manifest covers
via `.example` is not a false alarm. Only fields both sides express are compared;
`args`, `env`, and `limits` are the store's blind spots.

## The honesty loop

`Result.GateAdmitted` is what a run permits beyond its declared manifest, surfaced
so nothing is laundered into looking declared - the store never touches it. The
model maps onto an editor agent's allow choices:

| Editor agent  | Here                                                            |
| ------------- | --------------------------------------------------------------- |
| Allow once    | `[o]nce` - admitted for this run, not remembered                |
| Allow session | `[y]es` - remembered for this script across runs                |
| Always allow  | `perms export` to a bento manifest, `bento approve`, then `bento run` |

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

The design rationale (why network but not filesystem) is under "The two models (and why
they differ)" above. For a stripped-down non-interactive embedder, see
[`examples/embed`](../embed/README.md).
