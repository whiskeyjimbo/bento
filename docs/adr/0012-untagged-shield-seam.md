# [ADR-0012] One shield verdict behind an untagged seam

* **Status:** Accepted
* **Date:** 2026-08-06
* **Authors:** whiskeyjimbo

## Context and Problem Statement

Three call sites independently answer "does this grant land inside a shield", and they
are required to agree:

| site | how it answers | when |
| --- | --- | --- |
| the Linux backend | `checkNotShielded`, `checkWriteNotUnderReadOnlyShield`, `checkWriteNotAboveShield` over `appliedShields(sb)` | at run time, authoritative |
| the validate gate | `shieldedReadProblems`, `writeShieldProblem` over `resolvedShieldRules()` | in CI, before a manifest is approved |
| the profiler clamp | `clampShieldedGrants`, `clampWriteShieldedGrants` over its own anchor walk | when a draft manifest is proposed |

They have diverged. The differential corpus (`internal/shieldcorpus`, landed red on
purpose) measures it: on a host where `~/.ssh/known_hosts` is a symlink into a dotfile
farm, the backend refuses a write to the target and the other two honor it, so the
profiler proposes the grant, the gate green-lights it, and the run hard-refuses at its
first step. The reverse also happens: where a shield's symlink resolves onto the home
anchor the backend deliberately does not shield it at all, and the other two refuse what
the run allows. Three comments in `cmd/bento/render.go` assert the gate is a strict subset
of the runtime. All three are wrong.

The mirroring is forced, not careless. `internal/linux` is `//go:build linux` and
`cmd/bento` is not, so `cmd/bento` cannot import the answer. That constraint is the design
problem; the code motion is not.

## Decision Drivers

* One answer, or the divergence recurs the next time a rule shape is added.
* The backend keeps its fake-based tests. Its grant checks are testable today against a
  hypothetical filesystem, and a seam that forces a real host into those tests is a worse
  design than three copies.
* No backend type in the shared package's signatures. A seam shaped like the sandbox is
  the sandbox's API under another name, and `cmd/bento` would then be coupled to a type it
  cannot even import.
* The five distinct refusal sentences survive. The wording is deliberate and tested; a
  shared boolean would collapse them.
* The read opt-in stays read-only. Reads can lift a literally-named built-in shield;
  writes never can, because a write to a credential store is the plant the deny-list
  exists to stop.

## Considered Options

* **Export a verdict from `internal/linux`.** `cmd/bento` can reach it from a
  `//go:build linux` test file, and a build-tagged file does not affect the portable
  build. Rejected: it does nothing for the non-test build, which is where the gate and
  the clamp actually run, so the mirrors would stay.
* **Move the rule assembly into `internal/denylist`.** Rejected: that package is rule
  DATA, consumed as data by `cmd/denylist-audit` and `internal/credhunt`. Assembly needs a
  filesystem; giving the data package one gives every data consumer one.
* **A new untagged `internal/shield` with its own fs seam.** Chosen.

## Decision Outcome

`internal/shield`, untagged, layered on `internal/denylist`:

* `shield.go` - `FS`, the host access the shield logic needs, as three function fields:
  `IsDir`, `Resolve`, `ListDir`. Named for what the shield logic asks, not for what any
  caller provides. `Host()` is the real-filesystem implementation the gate and the clamp
  pass; the backend passes its sandbox's own seams, so its fakes keep working unchanged.
* `rules.go` - `Assemble(fs, homes, runtimeDir, extraDeny) Set`. Home rules, the
  relocation expansion over the whole anchor set, the runtime rules, the caller's denies,
  and the symlinked-credential expansion, each resolved to where it would really mount and
  dropped where it would mount nowhere.
* `verdict.go` - `Set.Contains(grant, kind, optIns, workspace) (Rule, Verdict)` and
  `Set.OptIns(literalReads)`.

Three decisions inside that are load-bearing:

**`Verdict` is an enum, not a sentence.** `InsideShield`, `InsideCallerShield`,
`UnderWriteShield`, `AboveShield`, `Honored`, each returned with the rule that raised it.
The refusal wording stays in `internal/grantrefusal` where the frontend owns it. This is
what lets one verdict serve a runtime that refuses, a gate that predicts, and a clamp that
answers keep-or-drop.

**Workspace shields stay a per-call argument.** A checkout's git hooks and editor task
files are derived from the write grants being judged, so they are an input to
`Contains`, not part of the assembled set. That narrowing is deliberate: consulted in the
inside direction only, because a self-derived shield sits strictly under its own grant and
checking the other direction would refuse every project write grant there is.

**`Set` keeps the built-in rules alongside the applied ones.** An opt-in is matched on the
path the deny-list built; a refusal is decided at the path that rule lands on. One slice
cannot answer both, and collapsing them silently changes which shields a policy can name.

The corpus is the check. `internal/shield`'s own test runs every case and must produce the
verdict the backend produces - asserted against the backend's own table, not against
expectations this package wrote for itself.

### Positive Consequences

* The two gaps close by construction rather than by being noticed: the gate and the clamp
  inherit the symlink expansion and the moved-onto-home drop because they are asking the
  same function.
* `internal/shieldcorpus` becomes the regression harness. A future rule shape is added
  once and all three sites move together, or the corpus goes red.
* The three wrong parity comments have nothing left to be wrong about, because there is no
  second set to be in parity with.

### Negative Consequences / Trade-offs

* A fourth package in the shield story. Justified only because the build tag makes three
  copies the alternative.
* `FS` duplicates two small host helpers (`IsDir`, `ListDir`) that also exist in
  `internal/linux`. The backend keeps its own because they are wired into its sandbox; the
  duplication is two four-line functions, against a shared verdict of several hundred
  lines.
* The clamp will not become a pure delegation. It answers keep-or-drop and departs from
  the run in two documented places - it withholds an opt-in read from a draft manifest,
  and it keeps a grant that merely contains a shield. Both stay, carried as fields on the
  corpus case rather than as unexplained divergence.
