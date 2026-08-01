//go:build linux

package launcher

import (
	"os"
	"os/exec"
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
	} {
		t.Run(tc.fence, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()[:strings.Index(t.Name(), "/")]+"$")
			cmd.Env = append(os.Environ(), sentinelPrereq+"="+tc.fence)
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
		})
	}
}

// runDegradedChild loses one fence and reports what RunDegraded did. It prints
// nothing on the paths that must not happen (a nil error, or never returning at
// all because the target was exec'd), so the parent's assertion fails.
func runDegradedChild(fence string) {
	switch fence {
	case "landlock":
		landlockAvailable = func() bool { return false }
	case "egress":
		seccompEgressSupported = func() bool { return false }
	}
	if _, err := RunDegraded(DegradedConfig{Target: []string{"/bin/true"}}); err != nil {
		os.Stdout.WriteString("REFUSED: " + err.Error() + "\n")
	}
}
