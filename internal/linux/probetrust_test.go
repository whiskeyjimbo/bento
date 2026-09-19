//go:build linux

package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// plantProbeCanary writes an executable named name in a directory this user owns and makes
// probeBinary hand it to the probes - the shim harness the canary tests are built on, moved
// off PATH now that what the probes resolve is trust-checked. Names it is not asked for
// still go through the real resolver, so a test that plants `true` does not also unvouch
// `sh`.
func plantProbeCanary(t *testing.T, name, script string) string {
	t.Helper()
	dir := t.TempDir()
	writeShim(t, dir, name, script)
	overrideProbeBinary(t, name, filepath.Join(dir, name), nil)
	return dir
}

// refuseProbeCanary makes probeBinary refuse name the way trustLauncherPath refuses a
// planted one, and returns the directory the refusal names. The probes' own reaction is
// what these tests are about, and it must not depend on this host having a plantable PATH.
func refuseProbeCanary(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	overrideProbeBinary(t, name, "", fmt.Errorf("refusing to run with %s as the canary: %s is writable by this user", filepath.Join(dir, name), dir))
	return dir
}

func overrideProbeBinary(t *testing.T, name, path string, refusal error) {
	t.Helper()
	real := probeBinary
	probeBinary = func(want, conventional, role string) (string, error) {
		if want == name {
			return path, refusal
		}
		return real(want, conventional, role)
	}
	t.Cleanup(func() { probeBinary = real })
}

func mustTrueBinary(t *testing.T) string {
	t.Helper()
	p, err := trueBinary()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustShBinary(t *testing.T) string {
	t.Helper()
	p, err := shBinary()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The probes execute their canaries before any preflight - measureScope's bare `true` on
// the host, and the delegated-controllers and namespace shells - so a planted one is code
// execution as this user rather than a forged verdict, and nothing downstream recovers from
// it. resolveBwrap and resolveScopeRunner already refuse a launcher this uid may replace;
// these are under the same check, for a strictly worse harm.
func TestTrustedProbeBinaryRefusesAUserWritableCanary(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, where every path is writable and the question is vacuous")
	}

	// The conventional location itself planted, which is what a writable / or /bin would
	// mean and what the check has to rule on whichever way the resolution went.
	t.Run("the conventional path", func(t *testing.T) {
		dir := t.TempDir()
		writeShim(t, dir, "sh", "#!/bin/sh\nexit 0\n")

		p, err := trustedProbeBinary("sh", filepath.Join(dir, "sh"), "probe shell")
		if err == nil {
			t.Fatalf("accepted a shell in a directory this user can write (%s)", p)
		}
		if !strings.Contains(err.Error(), dir) {
			t.Errorf("refusal = %q, want it to name the writable directory so the user can act on it", err)
		}
	})

	// With no conventional path present the resolution falls to PATH, which is the one a
	// sandboxed target with a write grant on a bin directory can plant in for the NEXT run.
	t.Run("the PATH fallback", func(t *testing.T) {
		dir := shimPATH(t, "sh", "#!/bin/sh\nexit 0\n")

		p, err := trustedProbeBinary("sh", filepath.Join(dir, "absent-on-purpose"), "probe shell")
		if err == nil {
			t.Fatalf("accepted a shell PATH resolved into a directory this user can write (%s)", p)
		}
		if !strings.Contains(err.Error(), dir) {
			t.Errorf("refusal = %q, want it to name the writable directory", err)
		}
	})
}

// The positive control, and the reason the resolution prefers the conventional path: a
// false refusal here breaks every run and every doctor on a working machine, which is worse
// than the hole it closes. A user-level shell ahead of /bin/sh - a Nix profile, a mise shim
// - is the ordinary shape, not an attack, and must not be reached at all where /bin/sh is.
func TestProbeCanariesAcceptTheHostsOwn(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, where every path is writable and the question is vacuous")
	}
	if got := mustShBinary(t); got != "/bin/sh" {
		t.Errorf("shBinary = %q, want /bin/sh: a host that has one must never consult PATH for its canary", got)
	}
	if got := mustTrueBinary(t); got != "/bin/true" {
		t.Errorf("trueBinary = %q, want /bin/true", got)
	}
}

// A resolver is worth nothing unless the probes consult it, and that is the half that was
// actually broken: trustLauncherPath already worked, these call sites never called it. Each
// probe has to reach its own fail-closed verdict from the refusal, not merely not execute.
func TestProbesRefuseARefusedCanary(t *testing.T) {
	t.Run("measureScope names the refusal rather than blaming the user manager", func(t *testing.T) {
		// A systemd-run that propagates its command's status drives measureScope onto the
		// branch that runs the canary bare - the one execution that is not even wrapped in
		// a scope.
		shimPATH(t, "systemd-run", "#!/bin/sh\nfor a in \"$@\"; do last=$a; done\nexec \"$last\"\n")
		dir := refuseProbeCanary(t, "true")

		v, answered := measureScope(context.Background())
		if answered {
			t.Fatal("measureScope reached a verdict from a probe whose canary was refused")
		}
		if !strings.Contains(v.reason, dir) {
			t.Errorf("reason = %q, want the refusal and the writable directory, not a user-manager diagnosis", v.reason)
		}
	})

	t.Run("delegated controllers fail closed", func(t *testing.T) {
		shimPATH(t, "systemd-run", "#!/bin/sh\necho '"+controllersMarker+"'\necho 'memory pids cpu'\nexit 0\n")
		refuseProbeCanary(t, "sh")

		ctrls, known := measureDelegatedControllers(context.Background())
		if known {
			t.Errorf("known=true with ctrls=%v from a reading whose shell was refused; every one of those would be reported enforced", ctrls)
		}
	})

	// The namespace probe is the unconditional one: it runs on every Probe, so this is the
	// canary a plant reaches with no limits in the manifest at all. The verdict has to be
	// UNKNOWN, which refuses - blocked is the permissive one that offers the Landlock-only
	// tier, and a canary nothing vouched for is not a host that refused a namespace.
	t.Run("usableNamespaces lands on unknown", func(t *testing.T) {
		if _, notInstalled, err := resolveBwrap(); err != nil || notInstalled {
			skipMissingDep(t, "no usable bwrap: %v", err)
		}
		dir := refuseProbeCanary(t, "sh")

		got, reason := usableNamespaces(t.Context())
		if got != namespacesUnknown {
			t.Fatalf("verdict = %v, want namespacesUnknown; blocked would offer the degraded tier on a probe whose canary was never vouched for (reason %q)", got, reason)
		}
		if !strings.Contains(reason, dir) {
			t.Errorf("reason = %q, want the refusal to name the writable directory", reason)
		}
	})
}
