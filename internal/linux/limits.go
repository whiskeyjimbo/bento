package linux

import (
	"os"
	"os/exec"
	"strconv"

	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

// Resource limits are enforced by running bwrap inside a transient systemd user
// scope with the limits set as scope properties.
//
// Direct cgroup-v2 writes are the theoretically cleaner path, but on a normal
// login session the process's own cgroup is a session scope that systemd does
// not delegate: it is not writable and child cgroups cannot be created there.
// systemd, which owns the hierarchy, will create a delegated, limited scope for
// us unprivileged — and a scope applies its limits before the command starts, so
// there is no window in which the target runs unbounded. When no systemd user
// manager is reachable, limits cannot be enforced unprivileged, and that is
// reported rather than silently ignored (v1's actual failure).

// limitsAvailable reports whether resource limits can be enforced on this host,
// with a reason when they cannot.
func limitsAvailable() (bool, string) {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return false, "systemd-run is not installed, so resource limits cannot be enforced unprivileged"
	}
	// A reachable user manager is required to create the scope. Its runtime
	// directory is the cheapest reliable signal without spawning a probe unit.
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		if _, err := os.Stat(dir + "/systemd"); err == nil {
			return true, ""
		}
	}
	return false, "no systemd user manager is reachable (no lingering user session), so resource limits cannot be enforced unprivileged"
}

// wrapWithLimits prepends a transient systemd user scope carrying the policy's
// limits. With no limits set it returns the command unchanged, so the scope is
// only paid for when a manifest asks for it.
func wrapWithLimits(exe string, args []string, l policy.Limits) (string, []string) {
	if l.IsZero() {
		return exe, args
	}
	// --collect garbage-collects the transient scope even when the target exits
	// non-zero (e.g. an OOM kill); without it, failed scope units linger in the
	// user manager forever.
	scope := []string{"--user", "--scope", "--quiet", "--collect"}
	if l.Memory != "" {
		// MemorySwapMax=0 stops a memory-limited target from escaping the cap into
		// swap.
		scope = append(scope, "-p", "MemoryMax="+l.Memory, "-p", "MemorySwapMax=0")
	}
	if l.CPU != "" {
		scope = append(scope, "-p", "CPUQuota="+l.CPU)
	}
	if l.PIDs > 0 {
		scope = append(scope, "-p", "TasksMax="+strconv.Itoa(l.PIDs))
	}
	scope = append(scope, "--", exe)
	return "systemd-run", append(scope, args...)
}
