//go:build linux

package linux

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

func TestWrapWithLimitsNoLimitsIsPassthrough(t *testing.T) {
	exe, args := wrapWithLimits("bwrap", []string{"--die-with-parent"}, policy.Limits{}, "")
	if exe != "bwrap" || len(args) != 1 || args[0] != "--die-with-parent" {
		t.Errorf("no limits should pass the command through unchanged; got %s %v", exe, args)
	}
}

// requireMemPidsLimits skips unless this host can actually bind a memory or pids cap.
// canCreateScope answers only whether a scope can be created; since the delegation
// split it no longer implies the host-safety controllers are delegated, so a test that
// asserts a real memory kill has to ask for both or it fails on a host that delegates
// cpu alone.
func requireMemPidsLimits(t *testing.T) {
	t.Helper()
	if ok, reason := canCreateScope(t.Context()); !ok {
		t.Skip("no usable systemd user scope on this host: " + reason)
	}
	ctrls, known := delegatedControllers(t.Context())
	for _, c := range []string{"memory", "pids"} {
		if state, reason := hostSafetyDelegationState(ctrls, known, c); state != enforce.Enforced {
			t.Skip("memory/pids limits cannot bind on this host: " + reason)
		}
	}
}

// The probe's contract is that a nil return means systemd applied the limits. Zero
// limits create no scope at all, so the only honest answer there is an error - a nil
// would be the fail-open direction the whole delegation check exists to refuse.
func TestScopeProbeRefusesZeroLimits(t *testing.T) {
	if err := runScopeProbe(t.Context(), policy.Limits{}, nil); err == nil {
		t.Error("runScopeProbe returned success for zero limits, which create no scope")
	}
}

// Probe runs on the hot path of every Run and every doctor, and two of its three
// subprocess probes used to derive their 5s bound from context.Background(): a caller
// that had already given up was held for ~10s more, serially, measuring a host nobody
// was waiting on. Both now layer their bound under the caller's context.
//
// The cache is the sharp edge. A probe abandoned mid-flight measured nothing, so it must
// leave no verdict behind - one cancelled run would otherwise pin the limits layers
// Unavailable for the lifetime of the process, which under --allow-degraded runs targets
// unbounded on a host whose caps bind. That is the same fail-safe cacheProbe already
// makes for a busy user manager, extended to the caller giving up.
func TestTheLimitsProbesHonorTheCallersContext(t *testing.T) {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("systemd-run is not installed, so these probes never reach a subprocess")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	start := time.Now()
	if err := runScopeProbe(ctx, policy.Limits{Memory: "64M"}, nil); err == nil {
		t.Error("a cancelled probe must not report that the limits will bind")
	}
	if _, known := measureDelegatedControllers(ctx); known {
		t.Error("a cancelled delegation probe must not report a reading it never took")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("the probes took %v on a cancelled context; they are bounded by their own 5s deadline, not the caller's", elapsed)
	}

	v, answered := measureScope(ctx)
	if answered {
		t.Error("a cancelled scope probe must leave no verdict to cache; one cancelled run would pin the limits layers Unavailable for the process")
	}
	if !strings.Contains(v.reason, "did not finish") {
		t.Errorf("reason = %q, want it to name the abandonment rather than blame the user manager", v.reason)
	}
}

func TestWrapWithLimitsBuildsScope(t *testing.T) {
	exe, args := wrapWithLimits("bwrap", []string{"--proc", "/proc"}, policy.Limits{
		Memory: "128M", CPU: "100%", PIDs: 32,
	}, "")
	if exe != "systemd-run" {
		t.Fatalf("exe = %q, want systemd-run", exe)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--user --scope --quiet",
		"MemoryMax=128M", "MemorySwapMax=0", // swap must be pinned so memory can't escape
		"CPUQuota=100%",
		"TasksMax=32",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("scope args missing %q; got %q", want, joined)
		}
	}
	// The wrapped command must follow the -- separator, intact.
	found := strings.Contains(joined, " -- ")
	if !found || !strings.HasSuffix(joined, "-- bwrap --proc /proc") {
		t.Errorf("wrapped command not appended after --: %q", joined)
	}
}

func TestWrapWithLimitsOnlySetsWhatIsAsked(t *testing.T) {
	_, args := wrapWithLimits("bwrap", nil, policy.Limits{PIDs: 8}, "")
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "MemoryMax") || strings.Contains(joined, "CPUQuota") {
		t.Errorf("only TasksMax was requested; got %q", joined)
	}
	if !strings.Contains(joined, "TasksMax=8") {
		t.Errorf("TasksMax not set; got %q", joined)
	}
}

// A memory-limited target that tries to allocate far past its cap must be killed,
// not allowed to allocate. The control (no limit) proves the allocation itself
// succeeds when unbounded, so the kill is the limit and not a broken script.
func TestMemoryLimitEnforced(t *testing.T) {
	requireSandbox(t)
	requireMemPidsLimits(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}

	dir := t.TempDir()
	bomb := filepath.Join(dir, "bomb.py")
	src := "buf=[]\n" +
		"for _ in range(400):\n" +
		"    buf.append(bytearray(1024*1024))\n" +
		"print('ALLOCATED')\n"
	if err := os.WriteFile(bomb, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	run := func(l policy.Limits) string {
		p := &policy.Policy{Entrypoint: bomb, Interpreter: "python3", Read: []string{dir}, Exec: policy.ExecAll, Limits: l}
		var out strings.Builder
		// A non-zero exit is expected under the limit, so the error is not fatal
		// here - the assertion is on whether the allocation completed.
		_, _ = sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, enforce.RunOptions{})
		return out.String()
	}

	if got := run(policy.Limits{}); !strings.Contains(got, "ALLOCATED") {
		t.Fatalf("control run without a limit should allocate; got %q", got)
	}
	if got := run(policy.Limits{Memory: "24M"}); strings.Contains(got, "ALLOCATED") {
		t.Fatalf("a 24M memory limit should have killed a 400M allocation; got %q", got)
	}
}

func TestDelegatedControllers(t *testing.T) {
	ctrls, ok := delegatedControllers(t.Context())
	if !ok {
		t.Skip("could not create a probe scope to measure delegation on this host")
	}
	// A systemd user session delegates at least memory and pids by default; those
	// are the host-safety controllers the probe's LayerLimitsMemory capability depends on.
	if !ctrls["memory"] || !ctrls["pids"] {
		t.Errorf("expected memory and pids delegated, got %v", ctrls)
	}
}

// The delegation reading gates whether bento claims resource limits are enforced.
// The decision must FAIL CLOSED: an unreadable delegated set (known=false) cannot
// confirm the caps bind, so it must report unavailable, never enforced - the
// fail-open bug was known=false taking the enforced/ok branch, letting a target run
// unbounded under a report that said the limit held.
func TestHostSafetyDelegationStateFailsClosed(t *testing.T) {
	cases := []struct {
		name       string
		controller string
		ctrls      map[string]bool
		known      bool
		wantState  enforce.State
		wantReason string // a substring that distinguishes the diagnosis
	}{
		{"unknown fails closed", "memory", nil, false, enforce.Unavailable, "could not read"},
		{"memory delegated", "memory", map[string]bool{"memory": true}, true, enforce.Enforced, ""},
		{"pids delegated", "pids", map[string]bool{"pids": true}, true, enforce.Enforced, ""},
		{"memory missing", "memory", map[string]bool{"pids": true}, true, enforce.Unavailable, "the memory controller is not delegated"},
		{"pids missing", "pids", map[string]bool{"memory": true}, true, enforce.Unavailable, "the pids controller is not delegated"},
		// The other host-safety controller is a separate layer's business now, as cpu
		// already was: a pids-only manifest must not be refused over memory delegation,
		// which is a Delegate= step it never needed.
		{"memory undelegated does not move the pids verdict", "pids", map[string]bool{"pids": true}, true, enforce.Enforced, ""},
		{"pids undelegated does not move the memory verdict", "memory", map[string]bool{"memory": true}, true, enforce.Enforced, ""},
		{"cpu undelegated is irrelevant here", "memory", map[string]bool{"memory": true, "pids": true}, true, enforce.Enforced, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, reason := hostSafetyDelegationState(tc.ctrls, tc.known, tc.controller)
			if state != tc.wantState {
				t.Errorf("state = %v, want %v", state, tc.wantState)
			}
			// The unknown case must be diagnosed as unreadable, not misdiagnosed as an
			// undelegated controller (which would tell the user to run a Delegate= step
			// that does not address an unreadable path).
			if !strings.Contains(reason, tc.wantReason) {
				t.Errorf("reason = %q, want it to contain %q", reason, tc.wantReason)
			}
			// The REMEDY must name only what is actually missing - the clause before it
			// names both because the layer covers both, and that stays true. Telling an
			// admin to delegate a controller they already have sends them to change a
			// setting that is already correct.
			remedy, _, _ := strings.Cut(reason[max(strings.Index(reason, "Delegate="), 0):], " on user@")
			for c, delegated := range tc.ctrls {
				if delegated && strings.Contains(remedy, c) {
					t.Errorf("the remedy %q names %q, which this host already delegates", remedy, c)
				}
			}
		})
	}
}

// The seam lets a test build the unknown-delegation host the pure functions cannot
// be reached through otherwise: with delegation unreadable, Probe must report the
// cpu limits layer Unavailable, never Enforced (the fail-open bug at the Probe
// level). The cpu layer is emitted only where a scope can be created, so guard on
// that: without one the whole limits layer is Unavailable and no cpu sub-layer is
// emitted at all.
func TestProbeCpuLayerFailsClosedOnUnknownDelegation(t *testing.T) {
	if ok, _ := canCreateScope(t.Context()); !ok {
		t.Skip("no usable systemd scope on this host; the cpu limits layer is not emitted")
	}
	orig := delegatedControllers
	delegatedControllers = func(context.Context) (map[string]bool, bool) { return nil, false }
	defer func() { delegatedControllers = orig }()

	r := New().Probe(context.Background())
	if got := r.StateOf(enforce.LayerLimitsCPU); got != enforce.Unavailable {
		t.Errorf("LayerLimitsCPU = %v with delegation unreadable, want Unavailable (fail closed)", got)
	}
}

// Admission is otherwise only ever exercised against a fake enforcer returning a
// synthetic Report, so nothing proved a REAL probe's output drives the refuse/run
// decision - the report could stop matching what admission expects and every existing
// test would stay green. This drives the real enforcer end to end: the delegation seam
// makes cpu delegation unreadable (the fail-closed case), and all three postures are
// pinned against that one real Report. Default and strict refuse a requested limit this
// host cannot enforce; --allow-degraded waives it and the target actually runs, because
// limits are hardening tier. That last asymmetry is the one a synthetic Report cannot
// vouch for, and it is what makes the two refusals meaningful rather than a host that
// simply never runs anything.
func TestRealProbeDrivesStrictAndDefaultRefusalAndDegradedRun(t *testing.T) {
	requireSandbox(t)
	ns, _ := usableNamespaces(context.Background())
	if ok, _ := canCreateScope(t.Context()); ns != namespacesUsable || !ok {
		t.Skip("no bwrap tier with a usable systemd scope on this host; the cpu limits layer is not emitted")
	}
	// Overriding AFTER the guard above is deliberate and load-bearing. canCreateScope
	// caches success and reads delegation before doing so, so the guard must run
	// first and cache a real scopeOK; the cpu sub-layer is then measured outside that
	// cache and does see this override. Move the override earlier and canCreateScope
	// refuses instead, limitsLayers emits no cpu sub-layer at all, and this test
	// silently SKIPS forever while still reporting PASS.
	orig := delegatedControllers
	delegatedControllers = func(context.Context) (map[string]bool, bool) { return nil, false }
	defer func() { delegatedControllers = orig }()

	dir := t.TempDir()
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte("echo RAN\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := sandboxEnforcer(t)
	run := func(opts enforce.Options) (string, error) {
		var out strings.Builder
		_, err := enforce.Run(context.Background(), e,
			&policy.Policy{
				Entrypoint:  script,
				Interpreter: "sh",
				Read:        []string{dir},
				Limits:      policy.Limits{CPU: "50%"},
			},
			enforce.Process{Stdout: &out, Stderr: &out}, opts)
		return out.String(), err
	}

	for name, opts := range map[string]enforce.Options{
		"default": {},
		"strict":  {Strict: true},
	} {
		t.Run(name+" refuses", func(t *testing.T) {
			out, err := run(opts)
			var refusal *enforce.Refusal
			if !errors.As(err, &refusal) {
				t.Fatalf("want a Refusal driven by the real probe, got err=%v out=%q", err, out)
			}
			named := false
			for _, l := range refusal.Short {
				if l.Layer == enforce.LayerLimitsCPU {
					named = true
				}
			}
			if !named {
				t.Errorf("the refusal must name the cpu limits layer that fell short; got %v", refusal.Short)
			}
			if strings.Contains(out, "RAN") {
				t.Error("a refused run must not execute the target")
			}
		})
	}

	t.Run("allow-degraded runs", func(t *testing.T) {
		out, err := run(enforce.Options{AllowDegraded: true})
		if err != nil {
			t.Fatalf("--allow-degraded must waive a hardening-tier limit and run: %v (out=%q)", err, out)
		}
		if !strings.Contains(out, "RAN") {
			t.Errorf("the target should have run under --allow-degraded; got %q", out)
		}
	})
}

func TestCpuDelegationStateFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		ctrls map[string]bool
		known bool
		want  enforce.State
	}{
		{"unknown fails closed", nil, false, enforce.Unavailable},
		{"cpu delegated", map[string]bool{"cpu": true}, true, enforce.Enforced},
		{"cpu undelegated", map[string]bool{"memory": true}, true, enforce.Unavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, reason := cpuDelegationState(tc.ctrls, tc.known)
			if state != tc.want {
				t.Errorf("state = %v, want %v", state, tc.want)
			}
			if state != enforce.Enforced && reason == "" {
				t.Error("a non-enforced state must carry a reason")
			}
		})
	}
}

// The delegation measurement must agree with reality: a controller it reports as
// delegated must actually bind a limit, and one it omits must not. This guards the
// subtle regression where reading a BARE probe scope's controllers under-reports cpu
// (systemd enables cpu only when a CPUQuota is requested), which would wrongly refuse
// a cpu limit this host can enforce. Ground truth = does the controller's cgroup
// interface file appear in a scope that requests that controller's limit.
func TestMeasuredDelegationMatchesActualBinding(t *testing.T) {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("systemd-run not available")
	}
	ctrls, known := measureDelegatedControllers(t.Context())
	if !known {
		t.Skip("no usable systemd user manager on this host")
	}

	binds := func(prop, iface string) bool {
		// Create a scope requesting the limit and check its own cgroup for the
		// controller's interface file - present only if the controller actually bound.
		script := "test -e /sys/fs/cgroup$(grep '^0::' /proc/self/cgroup | cut -d: -f3)/" + iface + " && echo BOUND || echo absent"
		out, err := exec.Command("systemd-run", "--user", "--scope", "--quiet", "--collect",
			"-p", prop, "--", "sh", "-c", script).Output()
		if err != nil {
			t.Fatalf("probe scope for %s: %v", prop, err)
		}
		return strings.Contains(string(out), "BOUND")
	}

	for _, tc := range []struct {
		ctrl  string
		prop  string
		iface string
	}{
		{"memory", "MemoryMax=64M", "memory.max"},
		{"pids", "TasksMax=64", "pids.max"},
		{"cpu", "CPUQuota=100%", "cpu.max"},
	} {
		if got := binds(tc.prop, tc.iface); ctrls[tc.ctrl] != got {
			t.Errorf("measured %s delegated=%v, but the limit actually binds=%v", tc.ctrl, ctrls[tc.ctrl], got)
		}
	}
}

// The two limits probes measure something a busy or restarting systemd user manager
// simply fails to report, so an unanswered probe must not be memoized: pinning one
// transient failure left the limits layers Unavailable for the process lifetime, and
// under --allow-degraded that runs the target unbounded on a host whose caps bind.
func TestCacheProbeMemoizesOnlyAnsweredMeasurements(t *testing.T) {
	calls := 0
	answers := []bool{false, false, true}
	probe := cacheProbe(func(context.Context) (int, bool) {
		i := calls
		calls++
		return i, answers[min(i, len(answers)-1)]
	})

	if _, ok := probe(t.Context()); ok || calls != 1 {
		t.Fatalf("first call: ok=%v calls=%d, want a failed measurement after 1 call", ok, calls)
	}
	if _, ok := probe(t.Context()); ok || calls != 2 {
		t.Errorf("second call: ok=%v calls=%d, want the failure re-measured", ok, calls)
	}
	v, ok := probe(t.Context())
	if !ok || v != 2 || calls != 3 {
		t.Fatalf("third call: v=%d ok=%v calls=%d, want the recovered answer", v, ok, calls)
	}
	// The capability, once proven, is stable: every later caller is free.
	if v, ok := probe(t.Context()); !ok || v != 2 || calls != 3 {
		t.Errorf("fourth call: v=%d ok=%v calls=%d, want the cached answer with no re-measure", v, ok, calls)
	}
}

func TestWrapWithLimitsNamesTheScopeForARunID(t *testing.T) {
	_, args := wrapWithLimits("bwrap", nil, policy.Limits{PIDs: 8}, "job_17")
	joined := strings.Join(args, " ")
	// The supervisor computes this name before the run starts and reaps through it, so
	// the spelling is the contract, not an implementation detail.
	if !strings.Contains(joined, "--unit bento-run-job_17.scope") {
		t.Errorf("scope not named for the run id; got %q", joined)
	}
}

func TestWrapWithLimitsLeavesTheScopeUnnamedWithoutARunID(t *testing.T) {
	_, args := wrapWithLimits("bwrap", nil, policy.Limits{PIDs: 8}, "")
	if joined := strings.Join(args, " "); strings.Contains(joined, "--unit") {
		t.Errorf("no run id should leave systemd to generate the name; got %q", joined)
	}
}

// measureScope answers scope creatability and nothing else, so an unreadable delegated
// set cannot turn its verdict into a non-answer. That independence is what keeps the
// probe cached on the containerized and hybrid-cgroup hosts the fail-closed path exists
// for: while the two were folded together, an unreadable delegation read left the
// verdict uncached and canCreateScope re-created a real transient scope on every call -
// three times on one run, from Probe, screenRunID, Run, the degraded path and Profile.
func TestScopeVerdictIsIndependentOfTheDelegationRead(t *testing.T) {
	if ok, _ := canCreateScope(t.Context()); !ok {
		t.Skip("no usable systemd scope on this host; measureScope cannot be exercised")
	}
	orig := delegatedControllers
	delegatedControllers = func(context.Context) (map[string]bool, bool) { return nil, false }
	defer func() { delegatedControllers = orig }()

	v, answered := measureScope(t.Context())
	if !answered || !v.ok {
		t.Errorf("measureScope = (%+v, %v) with delegation unreadable, want a cached yes: creatability does not depend on the delegated set", v, answered)
	}
}
