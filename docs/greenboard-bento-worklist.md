# Bento work for greenboard

Derived from `greenboard-conformance-2026-08-07.md`. Bento-side only - anything that lands
in the greenboard or tack tree is listed in §6 of that document instead.

Ordered by what blocks greenboard's §8 first cut (Build and Review lanes, monitored auth,
single worker, PRs only).

---

## Blocking the first cut

### 1. Decide how the runner invokes a sandbox, and make that path complete

Greenboard §2 step 6 says `bento run bento.yaml`. Greenboard §6 wants a `NetworkGate` that
logs every connect attempt with the card id. Those two are incompatible today:
`NetworkGate` is a Go callback consulted mid-run in the connection's own goroutine
(`enforce/enforce.go:128-152`) and does not survive a process boundary - `ADR-0007` says so
directly and is still **Proposed**.

Three ways out, and bento only owes work on two of them:

- Runner embeds in Go the way `examples/supervise/` does. No bento change. Cheapest for
  the first cut and it is the path the exec-layer doc already cites for sandboxing a lane.
- Land `ADR-0007` so a non-Go runner gets a gate. Real work, and only needed if the runner
  is not Go.
- Runner shells out and gives up the gate. Then §6's connect logging degrades to what
  `--json` already reports post-hoc: `GateDenied`, `Denied`, `GuardBlocked`, `Untunneled`
  (`cmd/bento/run.go:467`). Card-visible, just not live. No bento change.

**Decide this first** - items 4 and 5 read differently depending on the answer, and it is a
one-way door for the runner's language.

### 2. Answer what happens when Claude Code refreshes its OAuth token in-sandbox

Monitored auth (§4) grants `read: ["~/.claude/.credentials.json"]` and the exact-literal
opt-in exposes it **read-only** - a write grant to a credential store is never opt-in-able,
by design (`internal/linux/shields.go:566-597`, read grants only). Claude Code writes that file
on token refresh.

Nothing in the conformance check established how it degrades. Measure it: run a lane past a
refresh and see whether Claude Code retries, re-auths, or dies. Then bento owes one of:

- Nothing, and the docs say monitored mode is for runs shorter than a token lifetime.
- A narrow, named exception - and that is a deny-list design decision, not a greenboard
  convenience, because it is the key-planting shape the rule exists to stop.

This is the single most likely way an overnight first cut fails at 3am.

---

## Wanted before the board runs unattended

### 3. Close shield-parity Gap A

Greenboard §7.5 wants lane manifests under a CI check, which means `bento validate` is
load-bearing for them. `credentialLinkShields` is runtime-only, so a write grant at the
target of a symlinked entry in a credential store validates clean and the run refuses it
(`docs/rewrite-assessment-2026-08-06.md` §2). Gap B is the reverse and lower confidence.

The real fix is the `internal/shield` subsystem rewrite that assessment recommends - three
consumers of one rule engine, mirrors deleted. Until then a green `validate` on a lane
manifest is not a promise the lane starts, so the runner has to smoke-run each manifest
once, which is a workaround greenboard should not have to keep.

### 4. Confirm a grant can bind a unix socket file

§9 leaves "where the socket lives" open and calls it cheap either way: inside the worktree
under a relative grant, or an embedder hook that binds one. The first needs no bento
change *if* a grant binds a socket - bwrap will, and bento already bind-mounts its own
proxy socket at a fixed interior path (`internal/linux/args.go:375-404`), so the pattern is
proven - but a grant naming a socket is untested in-tree.

Test it. If it works, §9's socket question is answered with zero bento work, and it is also
what decides whether Plan and Review can run at `exec: none` (a socket the lane calls costs
no exec; a client it spawns costs `exec: all`).

Note the constraint that makes this safe: the netns fence does not cover AF_UNIX and
`connect()` succeeds through a read-only bind (`args.go:278-283`), which is exactly why
`denylist.Runtime` shields the host runtime directory whole. Broker mode must refuse the
degraded tier for the same reason - `run --strict` already expresses that, no change
needed.

### 5. Decide whether the credential opt-in should count as a pinned path

`bento validate --relocatable` flags `~/.claude/.credentials.json` as a `pinned_path`
(`manifest.NonAnchoring`, `manifest/manifest.go:342-344`), so a monitored-auth lane manifest
cannot pass the CI gate §7.5 asks for - and monitored auth is what §8's first cut runs.

Both behaviours are individually right: the grant genuinely does pin the manifest to one
user's home. The question is whether the one `~` path the design blesses deserves an
exemption, or whether greenboard runs `--relocatable` over unattended manifests only and
accepts that its first-cut manifests are ungated. Small either way; decide it rather than
discover it in CI.

---

## Already served - no work, listed so it is not re-opened

- **Exec allowlist (greenboard §7 item 1).** Will not be built. `ADR-0006`, `ADR-0008` and
  `ADR-0009` measure three mechanisms against the same bar with the same answer, and
  `ADR-0009` establishes the gap is not closable by an exec gate at all while the target
  can ptrace what bento spawns. Build keeps `exec: all`. Point greenboard's issue at the
  ADR and close it.
- **Cgroup identity (§7 item 4).** `RunOptions.RunID` (`enforce/enforce.go:105-125`). The
  runner mints the id, derives the scope name before spawning, writes it to the inflight
  lockfile, and kills the scope on orphan recovery. Nothing to add.
- **Relocatable manifest lint (§7 item 2).** `bento validate --relocatable`, reporting
  `relocatable` and `pinned_paths` (`cmd/bento/validate.go:307-340`).
- **Fingerprint-before-resolve.** Holds, and is pinned by `cmd/bento/approve_test.go:61-79`.
  Do not let a future change move resolution earlier - that test is the guard, and every
  lane manifest in every worktree depends on it.
- **Post-run signals the runner should read rather than the exit code:**
  `ChangedAutoExec` (a lane that wrote a git hook or workflow file),
  `Shields`/`Exposed` (which grant was missing when a lane coded around an absent file),
  `ExecRecord` under `--record-exec` (the audit trail that stands in for the allowlist
  bento will not build).
