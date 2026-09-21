# State grid: remedy screening at refusal time

## Phase 0 - fit

Signals: four consecutive fixes to one function (715ec11, 4490bd7, fa78083, 7ca549e), each
closing one cell. One decision (is this remedy live?) is answered in two places: enforce's
`screenRemedies` and the frontend's `writeRefusalRemedy`, which picks what to print. The
invariant is one-sided. A refusal may withhold a remedy that would have worked. It must never
print one that admission refuses once it is taken. Fit: good.

Dimensions, taken from the code rather than from the brief:

- **Remedy kind.** Four remedies reach the reader:
  (W) the `--allow-degraded` waiver, printed when `Waivable` (render.go:1085-1101).
  (E) the "drop `limits:`" manifest edit, printed when Short is limits-only (render.go:1071-1075, :1098).
  (L) a lever quoted in the Reason text: admitRunID's "drop the run id" and the "the run id is" suffix that screenRemedies adds (run.go:612-613).
  (N) no remedy at all.
  JSON carries only W (`allow_degraded_would_admit`, cmd/bento/run.go:484).
- **Refusal cause.** Every pre-run Refusal that `enforce.Run` can return: ValidateRunID
  (:535), admitEnv (:558), admit strict (:451), admit allow-degraded core (:457), admit default
  core (:474), admit default exec (:487, Waivable), admit default limits (:500, Waivable),
  admitRunID no-limits (:752), admitRunID limits (:762), admitTier no-netns (:669), and admitTier
  degraded-tier deny/gate/rules (:700-712). The post-run silent-stage refusal (:247) is included.
  A backend Refusal from inside e.Run (internal/linux/limits.go:593/596) has an empty Short, so
  it only reaches N.
- **Cause behind.** Whether composedAdmission (run.go:623) would refuse the remedied run for
  another reason: none, admitRunID, or admitTier.

## Grid 1 - remedy printed per cause (frontend x enforce)

| # | cause | remedy printed | verdict |
|---|---|---|---|
| 1 | ValidateRunID / admitEnv (no Short) | N from writeRefusalRemedy. The Reason's own "add the name to `env:`" is the cause's own fix | HANDLED for W/E (render.go:1071 returns when there are no limits). See 1b |
| 1b | admitEnv reason lever with a probe cause behind (a core shortfall) | L: "add the name to `env:`". The run then refuses on the probe | UNHANDLED (low). admitEnv runs before the probe (run.go:121), so nothing screens its advice. Taking it clears this cause and exposes a different one, so the reader is not sent back to the same refusal |
| 2 | admit strict, Short has a non-limits layer | N | HANDLED (render.go:1071). Withholds W, which strict rejects (cmd/bento/run.go:71) |
| 3 | admit strict, limits-only, run id set | E screened away, NoRemedy | HANDLED for E (run.go:608-614, TestAWithdrawnManifestEditNamesTheLiveLever). Its L is WRONG, see Grid 2 |
| 4 | **admit strict, limits-only, no run id, probed network U with filesystem E** | **E printed. The edited run is refused by admitTier's no-netns check** | **WRONG**, forbidden direction. The edit screen at run.go:608 calls `admitRunID` alone, not composedAdmission, so admitTier is never consulted. 7ca549e widened only the waiver half of the screen to composedAdmission |
| 5 | admit allow-degraded core Unavailable | N | HANDLED (not Waivable, non-limits Short) |
| 6 | admit default core | N | HANDLED. This withholds W on a Degraded core layer where W would work. That is the documented narrowing (run.go:822-826 comment) |
| 7 | admit default exec U (Waivable) | W + exec cost | HANDLED (the waiver screen at run.go:585-594 runs composedAdmission, so admitRunID and admitTier are both covered; TestNoWaivableRefusalMeetsARefusalOfTheTier) |
| 8 | admit default limits Degraded (Waivable), no run id | W + E | HANDLED. Only W is screened, but E is equivalent here: a Waivable limits refusal implies filesystem E (the core bar at run.go:473 runs first), so the waived and the edited runs meet the same admitTier. VERIFIED BY SPIKE (inverted) |
| 9 | admit default limits (Waivable), run id set | W and E withdrawn, NoRemedy | HANDLED for W/E (admitRunID refuses the waived run at run.go:589). Its L is WRONG, see Grid 2 |
| 10 | admitRunID no-limits | N | HANDLED (no Short). The Reason's "set a limit or drop the run id" is the cause's own fix |
| 11 | admitRunID limits (default Unsampled, or allow-degraded Degraded/U) | E withdrawn, NoRemedy; L "drop the run id" / "the run id is" | HANDLED (TestARunIDLimitsRefusalWithdrawsTheManifestEdit; L admitted, see Grid 2) |
| 12 | admitTier no-netns / degraded-tier deny, gate, rules | N | HANDLED (no Short) |
| 13 | silent stage | NoRemedy | HANDLED (run.go:255, TestASilentStageRefusalOffersNoRemedy) |
| 14 | exec Waivable + limits also short | W, with only the exec cost named | HANDLED. admit returns one refusal at a time (exec before limits at run.go:486), and W waives both. The cost line under-reports "unbounded", which is the allowed direction |
| 15 | Waivable + degraded-tier refusal behind (deny, gate, rules) | W withdrawn | IMPOSSIBLE today: a Waivable refusal requires filesystem E (run.go:473), so degradedTier is false. Screening still covers it (TestNoWaivableRefusalMeetsARefusalOfTheTier) |

Row 4 on the Linux backend: IMPOSSIBLE there, because network U forces filesystem short.
That is enforced in another package (internal/linux probe) and pinned by
TestAnUnavailableNetworkLayerNeverLeavesFilesystemEnforced. admitTier's own comment
(run.go:657-661) says the refusal must not rest on one backend's probe, and the edit screen
does rest on it.

## Grid 2 - levers quoted in the Reason (L)

screenRemedies appends the blocker's reason. admitRunID's limits reason says "drop the run id".
The edit branch then adds "- so the manifest is not the lever here, the run id is". Neither
lever is screened.

| posture / limits state, run id set | lever printed | dropping the run id alone | verdict |
|---|---|---|---|
| strict, limits U (or D, Unsampled) | "the run id is" the lever (edit branch) | still refused: strict refuses the limits layer | **WRONG**, forbidden direction |
| default, limits Degraded (Waivable, W withdrawn) | "--allow-degraded does not admit it either: ... drop the run id" | still refused: admit's default limits bar, which is Waivable again | **WRONG**, forbidden direction. The next refusal does offer a working W, so the damage is one wasted round |
| default, limits Unsampled | "drop the run id" + "the run id is" | admitted | HANDLED |
| allow-degraded, limits D/U | same | admitted | HANDLED |

Note that the cmd test TestARefusalOnlyNamesRemediesAdmissionWouldAccept (cmd/bento/run_test.go:1459)
asserts that "drop the run id" IS printed in the strict case. That test pins the defect.

## Adversarial re-review of HANDLED cells

- Row 8's equivalence rests on the ordering in admit (core, then exec, then limits). If exec
  moved after limits, a Waivable limits refusal could leave exec U standing. W would still be
  screened, but E would not be. Coupling gap, one line, and nothing pins it.
- Rows 3/11: NoRemedy rests on the reason text alone. The frontend prints nothing more,
  which is correct.
- JSON `allow_degraded_would_admit` reads the screened Waivable, so it agrees with human output.

## Re-open pass

- 7ca549e (screen remedies over all of admission): fixed W against admitTier. The E half of the
  same row, run.go:608, still calls admitRunID only, so the fix was not carried along the row. That gap is row 4.
- fa78083 (name the live lever): added L without screening it. That is Grid 2.
- 4490bd7 / 715ec11: E and W withdrawal. Carried.
- bd open: nothing on remedies. bv2-ujyy2 (Unsampled bars) touches limitsBar but does not change these cells.

## Findings (ranked by blast radius)

1. **WRONG**: the lever "drop the run id" / "the run id is" is printed under strict (every limits
   state) and under the default posture with limits Degraded, and taking it is refused again.
   This happens on a real Linux host (cgroup not delegated plus --run-id). VERIFIED BY SPIKE:
   Run refuses again with RunID cleared, in both cells.
   Possible fix: screen the run-id drop through composedAdmission like E and W, and word the suffix on the result.
2. **WRONG**: under strict with limits-only Short and no run id, the "drop `limits:`" edit is
   printed while admitTier refuses the edited run (probe: network U, filesystem E). VERIFIED BY
   SPIKE in enforce (fakeEnforcer): Run refuses the edited policy with the no-netns reason, 3 mem
   states. The render half is VERIFIED BY READING (render.go:1071-1075). Unreachable on the Linux backend by
   the probe coupling. Possible fix: run.go:608 should call composedAdmission on the unlimited policy.
3. UNHANDLED (low): admitEnv's reason-embedded edit is not screened against the probe causes behind it. UNVERIFIED (reading only).

Inverted dismissals: over posture {default, strict, allow-degraded} x run id {"", job} x
fs/net/mem in {E, Unsampled, D, U}, every printed W is admitted, and every printed E is admitted
except the row-4 cells. VERIFIED BY SPIKE.

## Cells not walked

- Doctor's `--allow-degraded` hints (doctor.go:111-123) are a remedy printed outside refusal
  time and are out of this area.
- Backend refusals after admission (grantrefusal under the degraded tier, and the scope creation at linux/limits.go:596)
  are not admission. They only reach N here.
- Profile prints no remedy (preflightHost). Not traced further.
