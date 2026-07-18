package linux

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/policy"
)

func TestWrapWithLimitsNoLimitsIsPassthrough(t *testing.T) {
	exe, args := wrapWithLimits("bwrap", []string{"--die-with-parent"}, policy.Limits{})
	if exe != "bwrap" || len(args) != 1 || args[0] != "--die-with-parent" {
		t.Errorf("no limits should pass the command through unchanged; got %s %v", exe, args)
	}
}

func TestWrapWithLimitsBuildsScope(t *testing.T) {
	exe, args := wrapWithLimits("bwrap", []string{"--proc", "/proc"}, policy.Limits{
		Memory: "128M", CPU: "100%", PIDs: 32,
	})
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
	_, args := wrapWithLimits("bwrap", nil, policy.Limits{PIDs: 8})
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
	if ok, reason := canCreateScope(); !ok {
		t.Skip("resource limits unavailable on this host: " + reason)
	}
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
		sandboxEnforcer(t).Run(context.Background(), p, enforce.Process{Stdout: &out, Stderr: &out}, nil)
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
	ctrls, ok := delegatedControllers()
	if !ok {
		t.Skip("cannot read delegated controllers on this host")
	}
	// A systemd user session delegates at least memory and pids by default; those
	// are the host-safety controllers the probe's LayerLimits capability depends on.
	if !ctrls["memory"] || !ctrls["pids"] {
		t.Errorf("expected memory and pids delegated, got %v", ctrls)
	}
}

// The delegation reading gates whether bento claims resource limits are enforced.
// The decision must FAIL CLOSED: an unreadable delegated set (known=false) cannot
// confirm the caps bind, so it must report unavailable, never enforced - the
// fail-open bug was known=false taking the enforced/ok branch, letting a target run
// unbounded under a report that said the limit held.
func TestHostControllersDelegatedFailsClosed(t *testing.T) {
	cases := []struct {
		name       string
		ctrls      map[string]bool
		known      bool
		wantOK     bool
		wantReason string // a substring that distinguishes the diagnosis
	}{
		{"unknown fails closed", nil, false, false, "could not read"},
		{"memory and pids delegated", map[string]bool{"memory": true, "pids": true}, true, true, ""},
		{"memory missing", map[string]bool{"pids": true}, true, false, "not delegated"},
		{"pids missing", map[string]bool{"memory": true}, true, false, "not delegated"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := hostControllersDelegated(tc.ctrls, tc.known)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			// The unknown case must be diagnosed as unreadable, not misdiagnosed as an
			// undelegated controller (which would tell the user to run a Delegate= step
			// that does not address an unreadable path).
			if !strings.Contains(reason, tc.wantReason) {
				t.Errorf("reason = %q, want it to contain %q", reason, tc.wantReason)
			}
		})
	}
}

// The seam lets a test build the unknown-delegation host the pure functions cannot
// be reached through otherwise: with delegation unreadable, Probe must report the
// cpu limits layer Unavailable, never Enforced (the fail-open bug at the Probe
// level). Guarded on the host being able to create a scope at all, since the cpu
// layer is only emitted then.
func TestProbeCpuLayerFailsClosedOnUnknownDelegation(t *testing.T) {
	if ok, _ := canCreateScope(); !ok {
		t.Skip("no usable systemd scope on this host; the cpu limits layer is not emitted")
	}
	orig := delegatedControllers
	delegatedControllers = func() (map[string]bool, bool) { return nil, false }
	defer func() { delegatedControllers = orig }()

	r := New().Probe(context.Background())
	if got := r.StateOf(enforce.LayerLimitsCPU); got != enforce.Unavailable {
		t.Errorf("LayerLimitsCPU = %v with delegation unreadable, want Unavailable (fail closed)", got)
	}
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
	ctrls, known := measureDelegatedControllers()
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
