//go:build linux

package launcher

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The degraded tier has no mount namespace behind Landlock and the seccomp egress
// block, so each is the ONLY fence of its kind: a host missing one must be refused,
// never run with the host filesystem or network reachable.
func TestDegradedPrerequisites(t *testing.T) {
	cases := []struct {
		name       string
		landlockOK bool
		egressOK   bool
		wantHas    string
	}{
		{"both present", true, true, ""},
		{"no landlock", false, true, "needs Landlock"},
		{"no egress filter", true, false, "needs the seccomp egress block"},
		{"neither", false, false, "needs Landlock"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := degradedPrerequisites(tc.landlockOK, tc.egressOK)
			if tc.wantHas == "" {
				if err != nil {
					t.Fatalf("refused a host that has both fences: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ran with a missing fence instead of refusing")
			}
			if !strings.Contains(err.Error(), tc.wantHas) {
				t.Errorf("refusal %q does not name the missing fence %q", err, tc.wantHas)
			}
		})
	}
}

// The confinement paths arrive from argv (--ro/--rw/--x), and in this tier the ruleset
// built from them is the whole filesystem fence - there is no mount namespace behind it.
// A relative one resolves against whatever working directory the stage started in, so it
// would confine the target to a tree the policy never granted. Target[0] in the same
// struct is refused for the same reason.
func TestRunDegradedRefusesRelativeConfinementPaths(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  DegradedConfig
	}{
		{"readable", DegradedConfig{Readable: []string{"etc"}}},
		{"writable", DegradedConfig{Writable: []string{"../elsewhere"}}},
		{"exec", DegradedConfig{ExecPaths: []string{"bin/sh"}}},
		// Same wire, same flag, and it becomes TMPDIR: a relative one sends every temp
		// file the target writes to a cwd-relative path the ruleset never granted.
		{"scratch", DegradedConfig{Scratch: "../tmp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.Target = []string{"/bin/true"}
			// The refusal is checked before anything is applied, so this returns without
			// confining or exec'ing anything in the test process.
			_, err := RunDegraded(cfg)
			if err == nil {
				t.Fatal("ran with a relative confinement path instead of refusing")
			}
			if !strings.Contains(err.Error(), "must be absolute") {
				t.Errorf("refusal %q does not name the relative path as the problem", err)
			}
		})
	}
}

// DegradedConfig says Scratch is "already in Writable", and the environment override
// below the check exports it as TMPDIR regardless. A scratch outside the write set is a
// TMPDIR Landlock refuses on the target's first temp file - fail-closed, but as a
// permission denied deep in the target rather than as the policy mismatch it is.
func TestRunDegradedRefusesAScratchOutsideTheWriteSet(t *testing.T) {
	cfg := DegradedConfig{
		Writable: []string{"/granted"},
		Scratch:  "/elsewhere",
		Target:   []string{"/bin/true"},
	}
	_, err := RunDegraded(cfg)
	if err == nil {
		t.Fatal("ran with a scratch the write set does not grant instead of refusing")
	}
	if !strings.Contains(err.Error(), "not in the write set") {
		t.Errorf("refusal %q does not name the ungranted scratch as the problem", err)
	}
}

// sentinelPrereq makes the test binary re-exec itself as the child half of the
// wiring test below.
const sentinelPrereq = "BENTO_TEST_DEGRADED_PREREQ"

// RunDegraded must consult the real capability checks, not the capabilities the
// developer's kernel happens to have. Only a host MISSING a fence exercises the
// refusal, so the check is swapped out to build that host.
//
// It runs in a child process on purpose. Past the guard, RunDegraded closes
// inherited descriptors, applies Landlock and execs the target - so a regression
// that dropped the guard would destroy an in-process test and could exec a target
// that exits 0, reading as a pass. The child is sacrificial, and the parent
// asserts on the refusal text it must print, which nothing but the guard produces.
//
// The three seccomp installs are covered here rather than by a predicate, and the report
// half is the point of them. None of the three has a line in the applied report, so the
// only thing attesting them to the host is that the marker was written at all. A failed
// install must therefore leave the report EMPTY: a run that got as far as the marker with
// one of them missing is reconciled into an enforced network layer for a tier that has
// neither a netns nor an egress filter.
func TestRunDegradedRefusesWithoutTheRealFences(t *testing.T) {
	if v := os.Getenv(sentinelPrereq); v != "" {
		runDegradedChild(v)
		return
	}
	for _, tc := range []struct {
		fence   string
		wantHas string
	}{
		{"landlock", "needs Landlock"},
		{"egress", "needs the seccomp egress block"},
		{"egress-install", "could not install the egress filter"},
		{"process-reach", "could not install the cross-process block"},
		{"terminal-injection", "could not install the terminal-injection block"},
		{"landlock-install", "could not apply the Landlock confinement"},
	} {
		t.Run(tc.fence, func(t *testing.T) {
			report := filepath.Join(t.TempDir(), "applied")
			f, err := os.Create(report)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()[:strings.Index(t.Name(), "/")]+"$")
			cmd.Env = append(os.Environ(), sentinelPrereq+"="+tc.fence)
			// Inherited as fd 3, the number the child passes as AppliedFD.
			cmd.ExtraFiles = []*os.File{f}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child failed: %v\n%s", err, out)
			}
			got := string(out)
			// The fence name carries the teeth: runDegraded prefixes ANY RunDegraded
			// error with "REFUSED: ", so a bypassed guard still prints one (the target
			// fails later, under Landlock). Only these strings are unique to the guard.
			if !strings.Contains(got, "REFUSED: ") || !strings.Contains(got, tc.wantHas) {
				t.Errorf("with %s absent the child printed %q; want a refusal naming %q - RunDegraded is not reading the check",
					tc.fence, got, tc.wantHas)
			}
			written, err := os.ReadFile(report)
			if err != nil {
				t.Fatal(err)
			}
			if len(written) > 0 {
				t.Errorf("with %s absent the child still wrote an applied report (%q); the host reconciles a marker-bearing report into enforced layers",
					tc.fence, written)
			}
		})
	}
}

// runDegradedChild loses one fence and reports what RunDegraded did. It prints
// nothing on the paths that must not happen (a nil error, or never returning at
// all because the target was exec'd), so the parent's assertion fails.
//
// It writes its applied report to the descriptor the parent passed as fd 3, so the parent
// can assert the report stayed empty as well as the refusal - which for the three installs
// below is the whole finding.
func runDegradedChild(fence string) {
	failed := func() error { return fmt.Errorf("kernel refused the filter") }
	switch fence {
	case "landlock":
		landlockAvailable = func() bool { return false }
	case "egress":
		seccompEgressSupported = func() bool { return false }
	case "egress-install":
		blockEgress = failed
	case "process-reach":
		blockProcessReach = failed
	case "terminal-injection":
		blockTerminalInjection = failed
	case "landlock-install":
		restrictDegraded = func([]string, []string, []string) error { return failed() }
	}
	if _, err := RunDegraded(DegradedConfig{AppliedFD: 3, Target: []string{"/bin/true"}}); err != nil {
		os.Stdout.WriteString("REFUSED: " + err.Error() + "\n")
	}
}
