# Greenboard conformance check - bento-v2 at `80222c0`

**Question:** do the changes in bento-v2 still line up with what
`greenboard-execution-layer.md` (2026-08-03) says Bento has to provide?

Scoped to the substrate surface the exec-layer doc actually asks Bento for - manifests,
approval stamp, shields, exec, network, run identity. Not board semantics.

**Verdict:** the load-bearing property holds and is regression-tested; two of the five §7
asks have since landed; one §9 assumption is now contradicted by an ADR written after the
doc; and there are two concrete manifest-level conflicts to resolve before the §8 first
cut.

---

## 1. The property everything rests on: holds

§3 depends on `bento run` checking the approval fingerprint *before* resolving relative
paths, so one lane manifest fingerprints identically in every worktree.

- `cmd/bento/run.go:85-93` - `requireApproval(doc, ...)` runs, then `manifest.Resolve`,
  with the ordering stated in the comment.
- `manifest/manifest.go:276-280` - `Resolve` is deliberately not part of `Load`, for the
  reason the doc quotes, verbatim and unchanged.
- `cmd/bento/approve_test.go:61-79` pins the ordering as a test, asserting that
  `manifest.Resolve` *must* change the fingerprint "else the check ordering would not
  matter".
- The manifest is parsed once and the same bytes are approval-checked and executed
  (`run.go:79-82`), closing a swap between two opens.

Four days of path-resolution churn after the doc was written (`eb946f4`, `76dc55d`) is all
in the autoexec/hooksPath reporting path, not the policy pipeline. Nothing moved
resolution earlier. **"Approve five manifests once, use them for every card forever" is
still true.**

Also checked, since it is new: the exec record added in `be81219`/`606ed84`/`e28071b` is
provenance, not permission, and does not shift the stamp (`approve_test.go:474`).

## 2. §7 asks: two landed, one closed as rejected, two open

| § | Ask | State |
|---|---|---|
| 7.1 | Exec allowlist so Review can run `dod.sh` and nothing else | **Closed, rejected.** See §3 below |
| 7.2 | A lint refusing absolute paths in a reusable manifest | **Built.** `bento validate --relocatable` |
| 7.3 | NetworkGate observability - destination, run identity, refusal distinguishable | **Adequate, conditional on §2 step 6** |
| 7.4 | Cgroup identity out of `bento run` | **Built, better than asked** |
| 7.5 | Lane manifests under a CI check | **Available**, greenboard-side work |

**7.2 is done and its rationale is greenboard's own use case.** `pinnedPaths`
(`cmd/bento/validate.go:307-340`) reads the manifest's own spelling, flags any entrypoint,
interpreter, read or write grant that is absolute or `~`-anchored, and reports
`relocatable` / `pinned_paths` in `--json`. The doc comment describes "a fleet approving
one manifest per agent class and reusing it in every worktree" - that is the runner. It is
opt-in and does not need `--strict`, so the greenboard CI check (§7.5) is
`bento validate --relocatable --strict` per lane manifest.

**7.4 landed as `RunOptions.RunID`** (`enforce/enforce.go:105-125`), and the rationale is
§5's argument word for word: under `exec: all` the target has children, so a supervisor
that recorded bento's pid can call a card dead while a test runner still holds the
checkout - the tree, not the pid, is the thing to kill. It is better than §5 asked for: the
caller *supplies* the id and derives the systemd scope name in advance, so there is no
window between the target starting and the runner learning the handle. That matters for a
card that hangs immediately. `enforce.Run` refuses a run whose id could not get a scope, so
this fails closed.

Runner consequence: §5 says "add the cgroup path to the lockfile". Under this shape the
runner mints the id, so it can write it to the lockfile *before* spawning, and orphan
recovery is `systemctl --user kill <derived scope>`.

**7.3.** The gate stays `func(ctx, host, port) bool` (`enforce/enforce.go:152`) - no card
id in the signature, but the runner constructs the gate per run, so attribution is by
closure. Refusals are distinguishable from ordinary connection failure on the Result:
`GateDenied`, `Denied`, `GuardBlocked`, `Untunneled`, all surfaced through
`bento run --json` (`cmd/bento/run.go:467`). §6's "turn a silent EPERM into a board-visible
event" is buildable today with no bento change.

## 3. §9's broker: the assumption has changed under it

`docs/adr/0009-exec-broker-for-dynamic-toolchains.md` (2026-08-05, **Rejected**) is
untracked and post-dates the exec-layer doc. It rejects an in-sandbox exec broker, and two
of its findings reach §9.

The rejected design is not §9's design - ADR-0009 kills a broker *inside* the sandbox;
greenboard already chose brokered-not-nested with the exec happening on the runner's side.
So the core of §9 survives. But:

- **ADR-0009 finding 2 generalizes explicitly:** "any future mechanism that puts a process
  inside the sandbox and lets it exec inherits finding 2". A target can `PTRACE_ATTACH` a
  same-uid descendant and inject an `execve` - `ptrace` is unfiltered in the bwrap tier
  (`internal/seccomp/seccomp_linux.go:78-82`), `BlockProcessReach` is degraded-tier only
  (`internal/launcher/degraded.go:176`). The tack thin client is a process inside the lane's
  sandbox. It does not exec (it writes to a socket), which is what keeps it safe - and that
  is now a *load-bearing* property of the client, not an implementation detail. Write it
  down on the tack side: **the broker client must never exec.**
- **§9's "Plan and Review can plausibly reach `exec: none` this way" holds only if the
  client is not a subprocess.** If the lane invokes `tack gh pr create` by spawning it,
  that is an exec and the lane needs `exec: all` - there is no allowlist between them
  (`policy/policy.go:63-72` still has exactly `none`, `none-strict`, `all`, and ADR-0008 and
  ADR-0009 both rejected adding one). If instead the lane speaks to the broker socket
  directly - an MCP server over AF_UNIX rather than a spawned binary - `exec: none` is
  reachable, and the in-tree mechanics support it: `internal/linux/args.go:278-283` records
  that the netns fence does not cover AF_UNIX, a path-named socket is scoped by the
  filesystem, and `connect()` succeeds even through a read-only bind. §9 already leaves
  "where the socket lives" open; **the exec-column claim depends on that answer, so decide
  the two together.** Same note applies to the per-verb `plugin.yaml` framing: a plugin the
  lane *runs* costs `exec: all`; a verb the lane *calls* does not.
- **§7 item 1 does not shrink to one lane.** It stays as written in §3's table: three lanes
  at `exec: all`. The recovery §9 offers is real but partial - a thin filesystem does bound
  what is reachable - and it is now the *only* recovery, because an exec gate has been
  measured against ADR-0006's bar three times and failed each time.
- §9's degraded-tier caveat ("broker mode must refuse to run degraded") is confirmed
  correct and is now doubly motivated: `BlockProcessReach` is installed *only* in the
  degraded tier, so degraded is simultaneously where the socket boundary is decorative and
  where the ptrace filter exists. Refuse degraded, do not inherit `--allow-degraded`.

`docs/adr/0007-cross-language-service-surface.md` (Proposed) is not a conflict but is worth
tracking: it makes the same point §9 needs, that `NetworkGate` does not survive a process
boundary. A runner that shells out to `bento run` cannot supply a gate; §6's connect
logging therefore wants either the Go embedding path (`examples/supervise/`) or ADR-0007
landing. **This is a real decision for §2 step 6, which currently says `bento run`.**

## 4. Two manifest-level conflicts to settle before the first cut

**a. Monitored auth cannot pass `--relocatable`.** §4 monitored mode requires the credential
store named exactly:

```yaml
read: [".", "~/.claude/.credentials.json"]
```

`NonAnchoring` (`manifest/manifest.go:342-344`) is `~`-prefix or absolute, so that grant is
a `pinned_paths` entry and the manifest fails `--relocatable`. The two §7 asks greenboard
made are individually satisfied and jointly unsatisfiable for monitored mode.

Not a bug in either - the grant genuinely does pin the manifest to one user's home. The
resolution is greenboard's: run `--relocatable` in CI over the **unattended** manifests
only, and treat monitored mode as the deliberately-pinned variant. Which is consistent with
§4's own framing ("solo, watched, first cut") - but §8's first cut chooses monitored auth,
so the CI gate §7.5 asks for does not cover the manifests §8 actually runs. Pick one.

**b. Monitored auth is a read-only exposure, and OAuth refreshes.** `explicitShieldOptIns`
(`internal/linux/shields.go:566-597`) opts in on **read grants only** - a write grant to a
credential store "is the key-planting threat the deny-list exists to stop, so it is never
an opt-in and stays refused". Claude Code writes `~/.claude/.credentials.json` on token
refresh. Inside the sandbox that write is refused, and no grant makes it not be. Whether
Claude Code retries, re-auths, or dies there is unknown - nothing in this check inspected
it. It is the first thing the first cut should measure, before anything runs long enough to
cross a refresh.

## 5. Changes since the doc that greenboard should use

- **`Result.ChangedAutoExec`** (`enforce/enforce.go:477-497`) names files under a write
  grant that auto-execute on the host after the run. A Build lane writing a git hook or a
  workflow file is exactly the escape that survives teardown, and this is now card-visible.
  Wire it into the runner's post-run transition. Note the field carries bytes a prior run
  chose - quote it before rendering.
- **`--record-exec` / `Result.ExecRecord`** (`enforce/enforce.go:282-352`,
  `cmd/bento/run.go:449-467`). Off by default. This is the audit trail ADR-0009 points to
  as the answer for `exec: all`, and it is the closest thing the three coarse lanes get to
  the allowlist §7.1 wanted. The Build and Verify lanes should run with it on.
- **`Result.Shields` / `Exposed`** (`ShieldApplied`, `enforce.go:500-511`) are what §3's
  "a missing grant looks like a missing file" recovery needs, and now carry `Source` -
  which environment variable relocated the shield. Still the argument for reading the
  Report rather than the exit code.
- `docs/rewrite-assessment-2026-08-06.md` records a known divergence between the three
  sites that answer "does this grant land inside a shield" (runtime, validate gate, profile
  clamp). It diverges in **both** directions, so neither surface substitutes for the other.
  Gap A: a write grant at the target of a symlinked entry in a credential store validates
  clean and the run refuses it (`credentialLinkShields` is runtime-only). Gap B: where a
  shield rule resolves onto a home, the gate keeps a rule the runtime drops and flags every
  grant inside that home, which the run honors - the gate refusing what a run accepts, the
  direction `render.go:461` asserts cannot happen. Consequence for greenboard: smoke-run
  every lane manifest, and treat a validate refusal on one as a claim to check rather than a
  verdict. Gap B is exotic host state and lower confidence; Gap A is not.

## 6. What to change, on which side

Greenboard side:
1. Settle §9's open "where the socket lives" together with its exec column: a spawned
   broker client costs `exec: all`, a socket the lane calls does not.
2. Decide §2 step 6: `bento run` (no gate, per ADR-0007) or embed via `examples/supervise/`
   (gate, but Go). §6 depends on the answer.
3. Resolve 4a - which manifests the `--relocatable` CI gate covers.
4. Fold `RunID` into §5: mint before spawn, into the lockfile, kill the scope.

Tack side:
5. The broker client must never exec (ADR-0009 finding 2), and broker mode refuses degraded.

Bento side: nothing blocking. §7.1 is answered as "will not build" with three ADRs behind
it; §7.2 through §7.5 are served.
