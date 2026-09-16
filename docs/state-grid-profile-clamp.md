# State grid: profiler proposal path vs run refusals

Area: `profile.Synthesize` (profile/profile.go), `clampProposal` and its clamps
(cmd/bento/clamp.go), judged against `gate.Refusals` (gate/gate.go) and the backend's
`checkGrants` / `checkShieldsCarvable` / `checkWriteNotAboveWriteShield`
(internal/linux/grants.go, shields.go, linux.go, degraded.go).

## Phase 0 - fit

Good fit. Two strong signals: a mirror pair (proposal clamp vs gate vs backend, with
internal/shieldcorpus existing precisely because they diverged) and a long run of one-at-a-time
`fix(profile)` / `fix(clamp)` commits. The invariant is one-sided:

> A synthesized, clamped proposal may withhold grants the run would honor, but must never keep
> a grant the gate or backend refuses, and must never quietly widen past what was observed.

`FuzzProfileSynthesize` asserts only non-nil. The refusal half is a per-input oracle, but it
needs clampProposal (package main), so as a fuzz assertion it can only be
`gate.Refusals(clampProposal(Synthesize(obs))) == empty`, which inherits every gate-vs-backend
gap below. The widening half is fully checkable inside package profile (see the end).

Key structural fact: `withholdRunRefused` routes through `gate.Refusals`, so the proposal agrees
with the gate by construction (pinned by TestClampProposalProposesNothingTheRunRefuses). Every
forbidden-direction cell is therefore a place where the BACKEND refuses and the gate does not.
The gate's "miss a refusal rather than invent one" narrowing is the allowed direction for the
gate and the forbidden direction for the profiler.

## Phase 1 - grids

Access class splits cleanly: exec and egress do not interact with landing, so they live in the
widening grid.

### Grid A - write grant (after collapse to directory) x landing

| # | Landing | Run check that could refuse |
|---|---------|-----------------------------|
| A1 | filesystem root "/" | checkWriteNotRoot |
| A2 | system tree (/etc, /var, /usr, /opt ...) | floors / carve |
| A3 | home container or foreign home itself | none (floored) |
| A4 | own home itself | AboveShield |
| A5 | at/inside DenyAll home shield | InsideShield |
| A6 | at/inside DenyWrite home shield | UnderWriteShield |
| A7 | above DenyAll home shield | AboveShield |
| A8 | above DenyWrite home shield | AboveWriteShield (degraded only) |
| A9 | at/inside a static workspace shield (.git/hooks, .vscode ...) | UnderWriteShield (workspace) |
| A10 | at/inside a discovered gitdir shield (.git/modules/X/hooks, worktrees/*/config.worktree) | UnderWriteShield (gitDirShields) |
| A11 | checkout whose workspace shield path is symlink-redirected | checkWorkspaceShieldNotRedirected |
| A12 | existing dir this uid cannot write (not a system tree) | checkShieldsCarvable (workspace mount points) |
| A13 | grant creating a home-shield mount point under an unwritable parent | checkShieldsCarvable (home rules) |
| A14 | resolves to a regular file | WriteIsFile |
| A15 | unstattable (EACCES on parent) | WriteUnstattable |
| A16 | symlink loop | Looped |
| A17 | resolves to managed mount (/tmp, /dev/shm) or /proc/<pid> | ManagedMount / Process |
| A18 | spelled via symlink landing in any of A1-A10 | same, on resolved path |
| A19 | shield set cannot anchor (no usable home) | run refuses wholesale |
| A20 | case-folding mount containing a shield | FoldedShield |

### Grid B - read grant x landing

| # | Landing | Run check |
|---|---------|-----------|
| B1 | at a DenyAll shield exactly | honored as opt-in |
| B2 | strictly inside a DenyAll shield | InsideShield |
| B3 | above a shield (read: ~) | honored |
| B4 | inside a DenyWrite shield | honored |
| B5 | system tree | honored |
| B6 | root / top-level / own home | honored |
| B7 | managed mount / process path | ManagedMount / Process |
| B8 | symlink loop | Looped |
| B9 | caller deny-list | InsideCallerShield |
| B10 | case-folding shield | FoldedShield |
| B11 | spelled through symlink into B2/B7 | resolved check |
| B12 | unix socket | none (bind confers the peer) |

### Grid C - widening (observed -> proposed)

| # | Observed | Proposed |
|---|----------|----------|
| C1 | write to a file | write grant of its directory |
| C2 | write named at a directory entry (mkdir/unlink) | write grant of the parent |
| C3 | read of a file | read grant of that file |
| C4 | directory opened for readdir only | read grant of the whole directory (recursive bind) |
| C5 | probe-only ancestors of entrypoint | nothing |
| C6 | exec attempted, not executed | exec none |
| C7 | one exec executed | exec: all |
| C8 | egress host:port | exact rule |
| C9 | egress refused by upstream guard (Blocked) | exact rule, recorded as BlockedHosts |
| C10 | untunneled / unparseable destination | nothing |
| C11 | relative observed path | nothing |

Total: 20 + 12 + 11 = 43 cells.

## Phase 2 - verdicts

Forbidden-direction violations first.

### WRONG (proposal keeps a grant the backend refuses)

- **A12 - write grant on an existing directory this uid cannot write.** WRONG.
  VERIFIED BY SPIKE. Clamp keeps `write: <tmp>/ro` (mode 0555); `gate.Refusals` returns empty;
  backend `checkShieldsCarvable` (internal/linux/shields.go:517) with host seams refuses with
  ShieldNotCarvable naming `<ro>/.git/hooks`. Cause: gate's `ShieldCarveProblems` mounts only
  `set.Rules()` (home rules), while the backend's `createdShields` uses `shieldRules(sb, writes)`,
  which adds workspace rules for every directory grant. Reachable from profiling because the
  observer records attempted writes even when denied. The gate half is open as bv2-kxv8p; the
  profiler inherits it through withholdRunRefused, so fixing the gate fixes this cell.
- **A10 - write at/inside a discovered gitdir shield** (observed write to
  `<repo>/.git/modules/sub/hooks/pre-commit`). WRONG. VERIFIED BY SPIKE. Clamp keeps
  `<repo>/.git/modules/sub/hooks`; backend `checkWriteNotUnderReadOnlyShield` (grants.go:155)
  refuses via `gitDirShields`. clamp.go:141 documents skipping the gitdir scan as a residual
  "matching what the gate already misses" - allowed for the gate, forbidden here. The linked
  worktree `config.worktree` half is VERIFIED BY READING only. No open tracker item.
- **A11 - write over a checkout whose workspace shield is symlink-redirected.** WRONG.
  Clamp half VERIFIED BY SPIKE (keeps `write: proj` with `proj/.vscode -> ../real`); backend
  refusal VERIFIED BY READING (grants.go:210) and carried as the `WorkspaceRedirected` verdict in
  internal/shieldcorpus, documented there as the one divergence no site reproduces. Known and
  documented, still forbidden-direction. No open tracker item on the profiler side.
- **A8 - write above a DenyWrite shield (write: ~/.pyenv).** WRONG on the degraded tier only, by
  design: kept and REPORTED via aboveWriteShieldGrants (clamp.go:113) because the tier is
  unknown. VERIFIED BY READING (degraded.go:61, clamp.go:327). Not silent; lowest priority.

### Widening

- **C4 - readdir-only directory becomes a recursive read grant.** UNHANDLED (quiet widening).
  VERIFIED BY READING in Synthesize: canonical observed reads are emitted verbatim
  (profile.go:304); only probe-only strict entrypoint ancestors are dropped (profile.go:243), and
  that comment says an enumerated directory "keeps its grant". `ls ~/Documents` proposes read of
  all of ~/Documents. Grant grammar has no list-only form; isBroadDir only catches /, top-level
  dirs, own home and containers. The observer hop (opendir recorded as a read) is UNVERIFIED -
  settle it by reading parseObservations in internal/linux/profile.go or a profiling run of `ls`.
- **C1/C2 - file write collapses to its directory.** HANDLED, deliberate documented widening
  (profile.go:247-275, bwrap rename-safety); floors and clamps screen the widened dir.
- **C7 - one executed spawn becomes exec: all.** HANDLED, documented widening (profile.go:308);
  exec grammar has no per-binary form, and converge gates it on consent.

### HANDLED (VERIFIED BY READING unless noted)

| Cell | Where |
|------|-------|
| A1 | flooredWrite "/" (profile.go:522); RootWriteProblems via withholdRunRefused |
| A2 | FlooredWrite / isSystemWriteDir + isSystemPath (profile.go:501, 357) |
| A3 | isForeignHomeTree (profile.go:566); isBroadDir containers (clamp.go:435) |
| A4 | isBroadDir own anchors (clamp.go:438), reported as broad |
| A5 | clampShieldedGrants (clamp.go:45), both spellings; gate InsideShield backstop |
| A6 | clampWriteShieldedGrants (clamp.go:84) |
| A7 | gate AboveShield via withholdRunRefused (gate.go writeShieldProblem) |
| A9 | clampWriteShieldedGrants with workspaceShields union (clamp.go:85, 146) |
| A13 | gate ShieldCarveProblems via withholdRunRefused (home rules) |
| A14, A15, A16 | gate FileWriteGrantProblems / LoopedGrantProblems via withholdRunRefused; pinned by TestClampProposalProposesNothingTheRunRefuses |
| A17 | ScratchWrite (profile.go:511), resolvesIntoProc, MountGrantProblems via withhold |
| A18 | every clamp and floor asks both spellings through pathresolve.Existing |
| A20 | clampShieldedGrants drops any non-Honored read verdict, including FoldedShield |
| B1 | withheld though honored (allowed narrowing, clamp.go:33) |
| B2, B9, B10, B11 | clampShieldedGrants + gate ShieldedReadProblems |
| B3, B4, B5 | kept; run honors |
| B6 | partitionBroad withholds and reports (allowed narrowing) |
| B7, B8 | isSystemPath /proc,/dev; gate MountGrantProblems / Looped via withhold |
| B12 | Socket() drop (profile.go:443), reported |
| C3, C5, C6, C8, C10, C11 | Synthesize exact or dropped (profile.go:181, 243, 308, 318; Untunneled never enters Hosts) |
| C9 | proposed and recorded in BlockedHosts, flagged for approve (cmd/bento/profile.go:325, 740). Gate and backend accept the rule; the proxy guard refuses the connection. Reported, not silent. |

Per-grant attribution in withholdRunRefused was checked for cross-grant refusals: opt-ins only
ever remove problems, so probing a grant alone is at least as strict as the whole policy.
VERIFIED BY READING.

### IMPOSSIBLE

- **A19** - no anchors: clamp skips its shield clamp (clamp.go:316) and gate.Refusals uses an
  empty set, but the run refuses the whole policy first, so no grant-level disagreement exists.
  VERIFIED BY READING. Coupling note: nothing ties the clamp's skip to that wholesale refusal.

### Cells not walked

None. A10's worktree half and C4's observer hop are READING / UNVERIFIED as stated. HANDLED cells
were read, not re-spiked.

## Phase 2 re-open pass (history read after the grid)

- `2dd8bc9 fix(clamp): withhold the grants run refuses` fixed the gate-known families by routing
  through gate.Refusals. The row was not carried to backend-only refusals: A10, A11, A12 remain.
- `ff5e7ba fix(clamp): derive the checkout shields under a write grant` fixed A9 (static Workspace
  rules) and stopped; the gitDirShields half of the same row (A10) was left as a residual.
- `2eb9ec4` / `e069c77` report A8 rather than drop it; consistent with the verdict above.
- Open tracker: bv2-kxv8p is the gate side of A12. Nothing open for A10 or A11 on the profiler side.

## Fuzz oracle handoff

Widening half, per input, inside package profile for FuzzProfileSynthesize: each `p.Read[i]` is
`filepath.Clean` of an absolute `obs.Reads` entry; each `p.Write[i]` is
`filepath.Dir(filepath.Clean(w))` for an absolute `obs.Writes` entry; `p.Exec == ExecAll` iff
`obs.Execed`; every network rule equals some `obs.Hosts` entry and validates. The refusal half
cannot be asserted there (clampProposal is package main).

Permanent corpus seeds: A10 (gitdir hooks write), A11 (redirected .vscode), A12 (0555 dir write).
