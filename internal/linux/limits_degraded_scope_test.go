//go:build linux

package linux

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

// A policy-declared variable must keep its policy value: it is neither overwritten
// with the host's nor named for stripping, which would delete it from the target's
// environment entirely.
func TestWithScopeBusVarsSkipsPolicyDeclared(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/host/bus")
	t.Setenv("XDG_RUNTIME_DIR", "/host/run")

	policyEnv := map[string]string{"XDG_RUNTIME_DIR": "/policy/run"}
	env, added := withScopeBusVars(envSlice(policyEnv), policyEnv)

	if want := []string{"DBUS_SESSION_BUS_ADDRESS"}; !slices.Equal(added, want) {
		t.Fatalf("added = %v, want %v (a policy-declared var must not be added or stripped)", added, want)
	}
	if !slices.Contains(env, "XDG_RUNTIME_DIR=/policy/run") || slices.Contains(env, "XDG_RUNTIME_DIR=/host/run") {
		t.Errorf("env = %v, want the policy value for XDG_RUNTIME_DIR", env)
	}
	if !slices.Contains(env, "DBUS_SESSION_BUS_ADDRESS=unix:path=/host/bus") {
		t.Errorf("env = %v, want the host bus address added", env)
	}
}

// A variable neither the policy nor the host sets is not invented.
func TestWithScopeBusVarsSkipsUnsetHostVars(t *testing.T) {
	for _, name := range scopeBusVars {
		// t.Setenv cannot unset, but it registers the restore this test needs: without
		// it the unset leaks into every later test in the package, and the ones that
		// create a real scope then fail to reach the user bus.
		t.Setenv(name, "")
		os.Unsetenv(name)
	}

	env, added := withScopeBusVars(nil, nil)
	if len(env) != 0 || len(added) != 0 {
		t.Fatalf("env = %v, added = %v, want nothing added when the host sets neither", env, added)
	}
}

// The reverted first attempt at degraded-tier limits ran systemd-run with the
// sanitized policy environment, which has no session bus: systemd-run died before the
// scope existed, the target never ran, and the report still said the limits were
// enforced. This drives the exact shape runDegraded uses - policy env plus only the
// added bus vars, NOT the host environment - and proves the scope is created, the
// target actually runs, and it sees the policy environment.
func TestScopedCommandRunsWithSanitizedPolicyEnv(t *testing.T) {
	if ok, reason := canCreateScope(); !ok {
		t.Skip("no usable systemd user scope: " + reason)
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "env.out")

	policyEnv := map[string]string{"PATH": "/usr/bin:/bin", "BENTO_TEST_VAR": "policy-value"}
	env, added := withScopeBusVars(envSlice(policyEnv), policyEnv)
	if len(added) == 0 {
		t.Skip("host sets no session bus variables; the sanitized-env case cannot be exercised")
	}

	exe, args := wrapWithLimits(shBinary(), []string{
		"-c", "env > " + marker,
	}, policy.Limits{Memory: "64M"})
	cmd := exec.Command(exe, args...)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scoped command failed with the sanitized policy env: %v: %s", err, out)
	}

	b, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("the target never ran under the scope: %v", err)
	}
	got := string(b)
	if !strings.Contains(got, "BENTO_TEST_VAR=policy-value") {
		t.Errorf("target environment lost the policy value: %q", got)
	}
	for _, name := range added {
		if !strings.Contains(got, name+"=") {
			t.Errorf("added bus var %s missing from the target environment; the launcher, not the enforcer, is what strips it", name)
		}
	}
}

// The added bus values must reach systemd-run through the environment only. Putting
// them (or any policy value) in argv would publish them in /proc/self/cmdline, which a
// same-uid host process can read - this tier has no PID namespace to hide it.
func TestScopeArgvCarriesNoEnvValues(t *testing.T) {
	exe, args := wrapWithLimits("/usr/bin/bento", []string{"--strip-env", "DBUS_SESSION_BUS_ADDRESS"}, policy.Limits{Memory: "64M"})
	line := exe + " " + strings.Join(args, " ")
	if strings.Contains(line, "unix:path=") || strings.Contains(line, "=/run/user") {
		t.Fatalf("argv carries an environment value: %q", line)
	}
	if !strings.Contains(line, "--strip-env DBUS_SESSION_BUS_ADDRESS") {
		t.Fatalf("argv should carry the variable NAME to strip: %q", line)
	}
}
