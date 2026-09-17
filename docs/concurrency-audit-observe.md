# Concurrency audit: internal/observe

Scope: internal/observe at 0abf849, with internal/launcher and internal/linux where they
share state with it. Everything below was run from the worktree with `GOWORK=off`.

## The shape of the concurrency here

internal/observe has almost no in-process concurrency, and that is the headline fact.
The trace loop is a single goroutine: it dequeues stops with `Wait4(-1)`, decodes them,
and mutates `seen`, `drops`, `held`, `lastOp`, `execSpawn`, `tracees` and `res` with no
other goroutine in sight. None of those maps can data-race.

The interleavings that matter are of two kinds, and only one of them is a data race:

1. **In-process, detector-visible.** Exactly three pieces of state: the `traceCalls`
   mutex (observe_linux_amd64.go:157), the `exec.Cmd` copier goroutine that only
   `cmd.Wait` joins (observe_linux_amd64.go:210), and the package-level test hooks
   `waitTracee` / `reapTracees` (:705, :732).
2. **Tracee-side, detector-blind.** Six threads racing inside the traced process.
   `-race` says nothing at all about this; the tracer is one goroutine and the tracee is
   another process. Only assertions can catch it.

That split is what the rest of this report turns on.

## Tests that CAN fail - proved by removing the protection

### TestTraceCapturesOutputThroughANonFileWriter - PROPERTY, strong teeth
VERIFIED BY SPIKE. Deleted `defer func() { _ = cmd.Wait() }()` (observe_linux_amd64.go:210)
and ran `go test -count=5 -run TestTraceCapturesOutputThroughANonFileWriter
./internal/observe/`: 5/5 FAIL, each on the named assertion
("a write arrived after Trace returned"), under plain `go test`, no detector needed.
Restored, and it passes.

This is the model the rest of the package should copy. The `latchedBuffer` makes the leak
*observable* (a write timestamped after the caller took ownership) rather than
detector-only, and the 20ms per-write delay guarantees the copier still has work at the
moment Trace returns, so the failure is deterministic instead of the ~1-in-13 the comment
measured for the short-read symptom.

### TestConcurrentTracesDoNotStealEachOthersStops - PROPERTY, strong teeth
VERIFIED BY SPIKE. Removed `traceCalls.Lock()` / `defer traceCalls.Unlock()` from Trace
and ran `go test -count=5 -run TestConcurrentTracesDoNotStealEachOthersStops`: FAIL on the
first iteration, via the 30s deadline path, printing the named message and exiting 1.
Plain `go test`, no detector. Restored, and it passes in 0.08s.

Two sub-questions this settles:

- **Do the goroutines overlap?** Yes - VERIFIED BY SPIKE, not by reading. bv2-8updn's
  complaint (no start barrier) is formally correct: the loop does an `os.WriteFile` and a
  `wg.Go` per iteration with no release gate. But the unlocked run failed on the first
  iteration, which is only possible if at least two Traces were in `Wait4(-1)` at the same
  time. The spawn cost is microseconds against a ~20ms trace, so the window is wide. A
  barrier would make the overlap guaranteed rather than merely reliable; it is a hardening,
  not a fix for a test that cannot fail.
- **Does the a48ac8e deadline work?** Yes. The `os.Exit(1)` path fired exactly as designed
  and named the failure instead of burying it in a suite timeout. bv2-nobuv (the hang) is
  addressed: the regression now costs 30s and one clear line. The stale part is the
  comment claiming the passing case "takes about a second" - it is 0.08s here.

Note the residual the mutex does *not* cover, in "State with no concurrent test" below.

### TestTraceAttributesConcurrentOpensPerThread - PROPERTY for tid confusion, STRUCTURAL for the rest
VERIFIED BY SPIKE, with a caveat worth stating precisely.

The tracee side is the best-built concurrency fixture in the repo: six openers each
`runtime.LockOSThread`, report ready on one WaitGroup, and park on a second until all six
are up (observe_tracee_linux_amd64_test.go:64-88). That is a real start barrier at the
contended call, plus a decoy file to catch stale-buffer reads. The overlap is by
construction, not by luck.

What it catches:
- Decoding the wrong tid's registers: FAILS. Changed `inspect(wpid, ...)` to
  `inspect(root, ...)` at observe_linux_amd64.go:426; `go test -count=3` gave 3/3 FAIL,
  recording one file and missing five.

What it does NOT catch, contrary to its own docstring:
- "a decoder that keys the read on anything but the tid that stopped": I removed the pid
  from `stopKey` (observe_linux_amd64.go:813-815), so all six threads - same call site,
  same `Orig_rax`, same `Rip` - collide on one key. `go test -count=5`: 5/5 PASS.
- Sharing `lastOp` across tids (`lastOp[pid]` to `lastOp[0]` in `nativeSyscall`):
  5/5 PASS.

The reason is structural, not a test defect: the openat pathname is read and recorded
inside `inspect` from the stopping pid's own registers within a single stop. It never
crosses a map, so `stopKey` and `lastOp` are not on its path - they serve `dropOnce` and
the existence-syscall `held` pathnames. The docstring describes a failure mode the current
design cannot have, which makes the test read stronger than it is. Grade it PROPERTY for
wrong-tid decode and STRUCTURAL insurance against a future refactor that introduces a
shared decode buffer. The docstring is the thing to fix.

**The tid discriminator itself is not uncovered.** VERIFIED BY SPIKE: I re-applied the
pid-less `stopKey` and ran the *whole* package plain (`go test -count=1
./internal/observe/`): FAIL, eight tests red, among them
TestAnUnreadableStopCountsItsHeldProbeOnce ("held has 1 entries, want 0 - releasing more
than this pid's pair would drop a probe that is still live"),
TestForgetExitedTidLeavesNothingForAReusedTid ("recorded [\"/etc/shadow\"] for a tid the
kernel reused"), TestForgetRetiredTidKeepsTheLivePid, and both exec-recording tests. So
the per-tid keying of `drops` and `held` is well guarded - by single-goroutine unit tests
over those maps, which is the right place for it, since the tracer loop is one goroutine.
This downgrades the item from a coverage gap to a docstring correction: the concurrent
test does not enforce the tid key, but the package does.

Also worth recording: the over-attribution direction - the one the docstring calls the one
that matters, because the manifest is what the user consents to - never fired in any of
my three mutations. The under-attribution loop caught all of them first. I have no spike
that makes the over-attribution assertion go red on its own. UNVERIFIED; what would settle
it is a mutation that records a path against a tid that did not open it, e.g. having
`inspect` record the last *other* tid's held pathname.

## The race-detector gate: wired correctly

VERIFIED BY EXECUTION and BY READING. The premise in the brief - that the Makefile's race
target names internal/proxy only - is out of date. Makefile:137 is:

    go test -race -count=1 ./internal/proxy/... ./internal/observe/

internal/observe runs *whole* under the detector, not by name, with the reasoning written
out at Makefile:125-134. `make race` is in `make check` (Makefile:302) and CI runs
`make check` (.github/workflows/gate.yml:73).

Every gate defect this skill looks for is already closed here, and by someone who has been
bitten:
- The `-run`-matches-nothing no-op: guarded. Makefile:139-142 runs `go test -list` and
  fails loudly when a name in `RACE_LINUX_TESTS` no longer exists. observe sidesteps it
  entirely by running the package whole.
- The skip-is-also-green hole: closed. `BENTO_REQUIRE_TEST_DEPS=1` is set on both legs,
  with the reason written down - observe's two concurrency tests need a real `sh` and
  would otherwise skip to a green gate. This is the defect the `-list` guard cannot see,
  and it is explicitly handled.
- Cache replay: `-count=1` on both legs.
- Scope drift: `RACE_LINUX_TESTS` carries a stated rule for widening ("Add a name here
  when another concurrent structure lands there").

I ran `GOWORK=off CGO_ENABLED=1 BENTO_REQUIRE_TEST_DEPS=1 go test -race -count=3
./internal/observe/`: ok, 77.3s, no races. That is 3 full passes of the package, and it
confirms the Makefile's own 24s-per-pass estimate.

**The honest verdict on value, though:** the detector buys less on this package than on
internal/proxy. Both observe concurrency tests already fail under plain `go test` when
their protection is removed (proved above), and the decode maps are single-goroutine. What
`-race` actually guards is the mutex itself and the copier-join window. That is real but
narrow, and it is 24s per run. The Makefile makes exactly this argument at :125-127 and
decides the simplicity of running the package whole is worth it - a defensible call, and
the comment says so rather than pretending the coverage is broader than it is.

One thing the detector does earn its place for: `waitTracee` and `reapTracees` are
package-level vars that tests reassign (observe_test.go:178-183, :219, :866-874;
observe_tracee_linux_amd64_test.go:1084) while Trace reads them under no lock. No test in
the package calls `t.Parallel` (grepped: zero hits), so this is safe today. The moment
someone adds `t.Parallel` to a test that swaps a hook, it is a data race - and because the
package runs whole under `-race`, the gate will catch it. That is the case for the current
scoping.

## Shared state with no concurrent test

Ranked by blast radius.

### 1. Trace's Wait4(-1) reaps the embedder's unrelated children
The `traceCalls` mutex serializes Trace against *other Traces*. It does nothing about a
concurrent `exec.Command(...).Wait()` elsewhere in the same process: a `-1` wait consumes
any child's status, so the sibling's `Wait` gets ECHILD and its exit code is lost. Trace
documents this (observe_linux_amd64.go:162-166) and the launcher claims to satisfy it by
running the trace in a dedicated in-sandbox stage (launcher.go:423).

Property: while Trace runs, no other child of the calling process may be reaped by it - or
if that cannot be guaranteed, the launcher stage must provably have no other live child.
No test asserts either half. UNVERIFIED. What would settle it: a test that starts a
long-running `exec.Command`, calls Trace, and asserts the sibling's `Wait` still returns
its true exit code - it should fail today, which is the point, and the fix is a documented
precondition check rather than a mutex. Cheaper alternative: assert in the launcher stage
that no other child is live at the call.

This is the one genuine hole. Severity is not "two goroutines interleave": a misattributed
or lost exit status feeds the synthesized manifest the user consents to.

### 2. recordedEgress has no concurrency test, and is outside the race gate
internal/linux/profile.go:220-233. Its own comment says it "locks for the same reason" as
`egressCollector`: observe runs on each connection's own goroutine. Its sibling
`egressCollector` has both a concurrency test
(TestEgressCollectorKeepsVerdictsApartUnderConcurrency, gate_test.go:171) *and* a named
slot in `RACE_LINUX_TESTS`. `recordedEgress` has three single-goroutine tests
(profile_test.go:443, :467, :492), no concurrent test, and no race-gate entry.

Property: concurrent `observe` calls must not cross a decision between connections, and
`unnamed` / `unproposable` must not be lost. VERIFIED BY READING that the gap exists;
the crossing itself is UNVERIFIED. What would settle it: the existing egressCollector
concurrency test ported to `recordedEgress`, plus its name added to `RACE_LINUX_TESTS` -
where the Makefile's own comment already says a new concurrent structure in internal/linux
should go.

### 3. Lifecycle overlap: stopProxy before rec.into
profile.go:205-213 orders `stopProxy()` before `rec.into(&obs)` so a connection recorded
during teardown is not lost to a still-running handler. That ordering is the invariant and
nothing enforces it beyond the comment. No test drives a connection arriving during
teardown. VERIFIED BY READING. This is the WHEN-axis cell worth handing to state-grid
rather than solving here.

### 4. enforce's result assembly - examined, no gap
VERIFIED BY READING. There is no `internal/enforce` package (`ls internal/`:
credhunt, denylist, grantrefusal, i386, landlock, launcher, linux, observe, pathresolve,
proxy, seccomp, shield, shieldcorpus). The recent `docs(enforce)` commits refer to the
exec-record path in internal/launcher: `execrecord.go` and `applied.go`'s
`writeExecRecord`. `execrecord.go` (280 lines) contains no `sync.`, no `chan`, and no
`go func`; `ExecRecord.Complete` and the `Dropped` count it derives from are assembled
from `res` after `observe.Trace` returns, on the single launcher goroutine
(launcher.go:423 onward). Nothing is shared with a second goroutine, so no concurrent
test is owed. The conservatism `Complete` documents is a decode-completeness property,
not an interleaving one, and it belongs to state-grid.

### 5. Not a gap, recorded so it is not re-opened
`seen`, `drops`, `held`, `lastOp`, `execSpawn`, `tracees`, `res` - all confined to the
single trace-loop goroutine. No concurrent test is owed, and adding one would prove
nothing. Their correctness is an ordering question about tracee stops, which is what
TestTraceAttributesConcurrentOpensPerThread and the tracee-fixture tests already cover.

## Test inventory: closed by goroutines, not only by names

VERIFIED BY READING. `grep -n 'go func\|wg\.Go\|errgroup' internal/observe/*_test.go`
finds seven spawn sites beyond the two concurrency tests. None of them is a second
concurrent user of observe's state, so none is owed a grade:

- observe_test.go:388, observe_test.go:821, observe_tracee_linux_amd64_test.go:200 and
  :277 - watchdog wrappers. One Trace off the test goroutine with a `select` on a
  deadline, so a livelock is a named failure instead of a suite timeout. The comment at
  :812 states this explicitly.
- execimage_linux_amd64_test.go:213 - the same wrapper around `execImage` on a FIFO,
  which blocks if the resolver opens it.
- observe_tracee_linux_amd64_test.go:1446 - a unix-socket accept loop fixture.
- observe_tracee_linux_amd64_test.go:72 - the six-thread tracee openers, graded above.

So "which tests can fail" is answered over the complete set of goroutine-spawning tests,
not just the ones whose names say Concurrent.

## What I ran

    go test -count=1 -run 'TestConcurrentTracesDoNotStealEachOthersStops|TestTraceCapturesOutputThroughANonFileWriter' -v ./internal/observe/     (pass, 0.62s)
    [mutex removed]  go test -count=5 -run TestConcurrentTracesDoNotStealEachOthersStops ./internal/observe/     (FAIL, iteration 1)
    [cmd.Wait removed] go test -count=5 -run TestTraceCapturesOutputThroughANonFileWriter ./internal/observe/    (FAIL, 5/5)
    [stopKey pid dropped] go test -count=5 -run TestTraceAttributesConcurrentOpensPerThread ./internal/observe/  (PASS, 5/5 - the finding)
    [lastOp shared]       go test -count=5 -run TestTraceAttributesConcurrentOpensPerThread ./internal/observe/  (PASS, 5/5 - the finding)
    [inspect(root)]       go test -count=3 -run TestTraceAttributesConcurrentOpensPerThread ./internal/observe/  (FAIL, 3/3)
    [stopKey pid dropped] go test -count=1 ./internal/observe/    (FAIL, 8 tests - the tid key IS guarded, just not there)
    CGO_ENABLED=1 go test -race -count=3 ./internal/observe/     (ok, 77.3s, no races)

All with `GOWORK=off BENTO_REQUIRE_TEST_DEPS=1`. Every mutation was reverted from a
pristine copy; `git status` is clean and no spike files remain in the tree.

Read but not executed: internal/linux/profile.go, internal/launcher/launcher.go,
internal/launcher/execrecord.go, the Makefile race target, .github/workflows/gate.yml.

## Concrete changes, in order of value

1. Add the sibling-child test for Trace's `Wait4(-1)`, or a precondition check in the
   launcher stage. This is the only property with no coverage at all.
2. Port TestEgressCollectorKeepsVerdictsApartUnderConcurrency to `recordedEgress` and add
   it to `RACE_LINUX_TESTS`.
3. Fix TestTraceAttributesConcurrentOpensPerThread's docstring: it claims to catch
   key-on-the-wrong-tid, and it does not. Say what it does catch - wrong-tid register
   reads - and that the stale-buffer direction is insurance against a refactor.
4. Add the start barrier to TestConcurrentTracesDoNotStealEachOthersStops (bv2-8updn) as
   hardening, and correct its "about a second" comment to 0.08s. Low priority: the test
   demonstrably fails today without it.
