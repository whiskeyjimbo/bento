# State grid: build-tag stubs vs their real counterparts

Worktree base 924e291 (branch docs/state-grids). Host: linux/amd64, kernel 7.0.0-28.
Non-amd64 and non-Linux arms were checked by cross-compiling (`go vet`, `go test -c`) and by
feeding each stub's answer to the platform-neutral consumer logic on amd64.

## Phase 0 - fit

Good fit. Signal: mirror pairs selected by build tag. Every stub has a real counterpart that
must agree with it on the one-sided question "is this fence held". Invariant: a stub never lets
a fence or check read as held; it reports unsupported and the consumer marks the layer not
Enforced (or the gate answer Partial/Unknown), or the run refuses.

## Phase 1 - dimensions (from code)

Stub files (`find . -name '*_other.go'` plus `//go:build !linux` / `!amd64`):

- internal/seccomp: egress, strict, terminal, foreignarch `*_linux_other.go` (linux && !amd64) vs
  `*_linux_amd64.go`; seccomp_other.go (!linux) vs seccomp_linux.go.
- internal/landlock/landlock_other.go (!linux) vs landlock_linux.go.
- internal/observe/observe_other.go (!(linux && amd64)).
- trust/trust_other.go (!linux) vs trust_linux.go.
- gate/alias_other.go, gate/carve_other.go (!unix) vs `*_unix.go`.
- backend/backend_other.go (darwin), cmd/bento/platform_other.go (!linux).
- cmd/bento/tty_other.go, examples/supervise/tty_other.go: terminal plumbing, no fence. Out of scope.

Platforms: linux/amd64 (real), linux/arm64 (and other 64-bit non-amd64, e.g. riscv64: same
stubs, builds), linux/386 and linux/arm (32-bit), darwin, windows.

Reachability facts that collapse cells:

- Every consumer of internal/seccomp and internal/landlock is `//go:build linux`
  (internal/linux/*, internal/launcher/*, internal/landlock/internal/probe/main.go:1). So the
  `!linux` seccomp and landlock stubs have no caller on darwin/windows.
- linux/386 and linux/arm do not compile: internal/launcher/verify.go:36 passes
  `Statfs_t.Type` (int32 there) to `isTmpfs(int64)`. No bento binary exists for those targets.
- windows: cmd/bento does not build (backend_other.go:3-8), but gate and enforce do, so gate's
  `!unix` stubs are reachable by an embedder.
- darwin: backend.New refuses (backend_other.go:28), checkPlatform refuses sandbox commands
  (platform_other.go:22). validate and approve still run and reach trust's stubs.

## Phase 2 - verdicts

### internal/seccomp (consumers: internal/linux/probe.go, internal/launcher)

| # | Stub answer | Platform | Consumer verdict | Verdict | Where / why | Stamp |
|---|---|---|---|---|---|---|
| 1 | foreignArchSupported=false, so Supported()=false | linux/arm64 | exec-block and exec-strict layers | HANDLED | seccomp_linux.go:30 folds foreignArch into Supported; probe.go:161-172 reports both Unavailable; args.go:468 clears Block/StrictBlock so the launcher installs nothing and records AppliedExecNone | VERIFIED BY SPIKE |
| 2 | blockForeignArch errors | linux/arm64 | BlockExec / BlockExecStrict / BlockProcessReach / BlockIoUring | HANDLED | seccomp_linux.go:79, :129, iouring_linux.go:42 return its error first; every launcher call site is fatal (launcher.go:420, degraded.go:206-227) | VERIFIED BY READING |
| 3 | StrictExecSupported=false | linux/arm64 | exec-strict layer, launcher filter choice | HANDLED | probe.go reports exec-strict Degraded (the execve block still installs); launcher.go:891-900 falls back to execve-only and returns AppliedExecBasic, which reconcile reports as the same Degraded | VERIFIED BY SPIKE |
| 4 | EgressSupported=false | linux/arm64 | degraded tier offer | HANDLED | probe.go:51 degradedFencesOK; probe.go:260-269 Filesystem Unavailable, not Degraded | VERIFIED BY SPIKE |
| 5 | EgressSupported=false | linux/arm64 | degraded launcher | HANDLED | degraded.go:168 degradedPrerequisites refuses (degraded.go:124) | VERIFIED BY SPIKE |
| 6 | TerminalInjectionSupported=false | linux/arm64 | degraded tier offer and launcher | HANDLED | probe.go:51 and degraded.go:127 | VERIFIED BY SPIKE |
| 7 | BlockProcessReach (no predicate of its own) | linux/arm64 | degraded launcher | HANDLED | covered by seccompSupported() in probe.go:51 (foreignArch) and fatal at degraded.go:216 | VERIFIED BY READING |
| 8 | all `*_linux_other.go` | linux/386, linux/arm | any | IMPOSSIBLE | internal/launcher/verify.go:36 does not compile on 32-bit targets | VERIFIED BY EXECUTION |
| 9 | seccomp_other.go | darwin, windows | any | IMPOSSIBLE | no non-Linux importer; every consumer is `//go:build linux` | VERIFIED BY READING + EXECUTION (GOOS=darwin vet clean) |
| 10 | seccomp_other.go lacks TerminalInjectionSupported | darwin | compile surface | IMPOSSIBLE (latent) | a non-Linux caller would fail to compile: safe direction | VERIFIED BY READING |
| 11 | observe.Supported=false; BlockIoUring errors | linux/arm64 | profile | HANDLED | profile.go refuses on !observeSupported before launching; launcher.go:420 would also refuse | VERIFIED BY READING (profile_test.go:170 fakes it) |

### internal/landlock/landlock_other.go

| # | Stub answer | Platform | Consumer verdict | Verdict | Where / why | Stamp |
|---|---|---|---|---|---|---|
| 12 | Available / *Restricted = false | darwin, windows | Filesystem layer | IMPOSSIBLE | only caller internal/linux is linux-tagged; backend.New refuses first on darwin | VERIFIED BY READING |
| 13 | Restrict, RestrictTo return nil (fail-open) | darwin, windows | bwrap-tier Landlock backstop | IMPOSSIBLE (latent, forbidden direction if reached) | callers launcher.go:303 via degraded.go:106 and internal/landlock/internal/probe, all linux-tagged. RestrictDegraded and RestrictExecAllowlist already refuse off Linux; these two do not | VERIFIED BY READING |
| 14 | RestrictDegraded, RestrictExecAllowlist error | darwin, windows | degraded tier | IMPOSSIBLE | same linux-only callers | VERIFIED BY READING |

### trust/trust_other.go

| # | Stub answer | Platform | Consumer verdict | Verdict | Where / why | Stamp |
|---|---|---|---|---|---|---|
| 15 | manifestLocation = ErrLocationUnknown | darwin | Inspect | HANDLED | trust.go:200 located=false; LocationFlaws trust.go:295 Fatal flaw | VERIFIED BY SPIKE |
| 16 | same | darwin | approve | HANDLED | approve.go:62 requireApprovableLocation refuses on Fatal (approve.go:401-408) | VERIFIED BY SPIKE (flaw) / READING (refusal) |
| 17 | same | darwin | validate | HANDLED | warns via Flaws; stamps nothing | VERIFIED BY READING |
| 18 | same | darwin | profile write | HANDLED | profile.go:293 checks Located() | VERIFIED BY READING |
| 19 | pathDirs = ErrLocationUnknown | darwin | InspectNew | HANDLED | trust.go:219 returns the error | VERIFIED BY READING |
| 20 | ACLNamedWrite errors | darwin | journal privacy | HANDLED | journal.go:279 returns it; :141 journalUntrusted; :219 refuses the write | VERIFIED BY READING |

### gate `!unix` stubs

| # | Stub answer | Platform | Consumer verdict | Verdict | Where / why | Stamp |
|---|---|---|---|---|---|---|
| 21 | credentialAliases nil, partial=true | windows (embedder) | CredentialAliasesPartial | HANDLED | gate.go:146; validate.go:302, examples/embed/main.go:329 | VERIFIED BY READING + EXECUTION (GOOS=windows test -c) |
| 22 | writableDir = true | windows (embedder) | ShieldCarveProblems | HANDLED (by package rule) | gate.go:486 skips. The refusal predicts a loud bwrap mkdir failure, not a confinement hole; gate forbids inventing refusals; no bwrap backend on windows. Only stub answer shaped "clean" rather than "unknown" | VERIFIED BY READING |
| 23 | both | darwin, linux | - | IMPOSSIBLE | `!unix` excludes them | VERIFIED BY READING |

### backend / cmd platform stubs

| # | Stub answer | Platform | Consumer verdict | Verdict | Where / why | Stamp |
|---|---|---|---|---|---|---|
| 24 | backend.New, Profile error | darwin | run, profile | HANDLED | backend_other.go:28, :33 | VERIFIED BY READING |
| 25 | checkPlatform errors | darwin | sandbox commands | HANDLED | platform_other.go:22 | VERIFIED BY READING |
| 26 | no backend file | windows, BSDs | any | IMPOSSIBLE | cmd/bento does not compile there (backend_other.go:3-8) | VERIFIED BY READING |

### Admission of a stub-driven Unavailable hardening layer

| # | Stub answer | Platform | Consumer verdict | Verdict | Where / why | Stamp |
|---|---|---|---|---|---|---|
| 27 | exec-block / exec-strict Unavailable (cell 1) | linux/arm64 | enforce admission, default posture, `exec: none` manifest | HANDLED (invariant holds; see O1) | run.go:426-431 requires the layers, but report.go:62 makes them TierHardening and admit (run.go:469-472) refuses only core shortfalls, so the run is admitted with no exec block. Reported Unavailable; render.go:2015 writeDegradations prints it after the run. --strict refuses (run.go:453) | VERIFIED BY SPIKE |

27 cells, all walked.

Adversarial re-check of HANDLED cells: cell 7 holds only because Supported() includes
foreignArchSupported; a future arch with foreignArch but no process-reach filter would still
refuse at degraded.go:216 at run time (loud, not open). Cell 3 relies on the host reading
AppliedExecBasic as a downgrade; it is a distinct value from AppliedExecStrict. Cell 22 is the
only "clean" shaped stub answer, and it guards no fence.

## Findings

No WRONG or UNHANDLED cell. Nothing breaks the forbidden direction on a platform bento builds for.

Latent / non-forbidden:

- L1 (cell 13) landlock_other.go Restrict and RestrictTo return nil off Linux: a future non-Linux
  caller would get the bwrap-tier backstop reported applied while restricting nothing. Unreachable
  today. Their siblings RestrictDegraded and RestrictExecAllowlist already refuse for this reason.
  VERIFIED BY READING.
- L2 (cell 8) linux/386 and linux/arm do not build: internal/launcher/verify.go:36
  `isTmpfs(st.Type)` with Statfs_t.Type int32. Safe direction, but the `linux && !amd64` stubs are
  therefore exercised only on 64-bit non-amd64. VERIFIED BY EXECUTION.
- O1 (cell 27) On linux/arm64 an `exec: none` / `none-strict` manifest runs by default with no exec
  block, disclosed only after the run. Allowed branch of the invariant (layer not Enforced), same as
  an amd64 kernel without seccomp BPF, but the stub turns a per-host gap into a whole-architecture
  one. Design question, not a bug. VERIFIED BY SPIKE.
  RESOLVED 2026-09-20: the default now refuses. `enforce.admit` calls `undeliverableExecBlock`,
  so a manifest asking to block exec on a platform that cannot install the filter is refused
  before the target runs, waivable with `--allow-degraded`. Cell 27's reading describes the
  code at this grid's base, not the code now.

## Rejected findings

- seccomp_other.go missing TerminalInjectionSupported: compile failure is the safe direction, and
  no non-Linux caller exists (darwin vet clean).
- gate writableDir=true on windows: not a fence; see cell 22.
- degradedFencesOK does not name BlockProcessReach: covered by seccompSupported() and the fatal
  install at degraded.go:216.

## Spikes (deleted)

Throwaway tests on linux/amd64 in internal/linux (execLayers, execBlockFlags, filesystemLayer,
degradedFencesOK with stub answers), internal/launcher (degradedPrerequisites, installExecFilter
strict fallback), enforce (admit with exec-block Unavailable: default admits, strict refuses) and
trust (unlocated Manifest yields a Fatal flaw). All passed. Cross-compiles: GOARCH=arm64
`go vet ./...` and `go test -c` on internal/linux, internal/seccomp, internal/launcher, enforce
clean; GOOS=darwin `go vet ./...` clean; GOOS=windows `go test -c ./gate/` clean; GOARCH=386 and
GOARCH=arm fail at internal/launcher/verify.go:36. Spike files removed; worktree clean.

## Re-open pass (head 5a98897)

- f21e1bd and 686226d change internal/linux/probe.go only from line 284 down (the degraded
  Consequences clauses). degradedFencesOK (:50), execLayers (:148-182) and the
  `landlockAvail && !degradedFencesOK` arm (:260) are unmoved, so cells 1, 3, 4, 6 and 27 keep
  their cites and verdicts. landlock_other.go is untouched, so L1 stands.
- enforce/run.go gained 8 lines above requiredLayers and admit (Result.Degraded, and run-id limits
  in postRunShortfall). Cell 27 cites shifted to run.go:426-431, :453, :469-472. The tier logic is
  unchanged (report.go:62), so O1 stands.
- Open bd: bv2-zmay1 (MPTCP pin) and bv2-z69p3 (SetTierPreset hybrid) change no cell here.
- Landlock ABI grid follow-ups bv2-vnic2, bv2-ivg7h, bv2-688em: judging by that grid's findings
  (cells 6, 10, 21), they are about Landlock residuals disclosed on Linux degraded hosts. None of
  them overlaps L1 (a non-Linux Landlock stub with no caller) or O1 (exec layers admitted as
  hardening tier on arm64). I read the grid, not the tracker, so the ID-to-cell mapping is inferred.
