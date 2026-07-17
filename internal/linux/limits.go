package linux

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/whiskeyjimbo/bento-v2/policy"
)

// Resource limits are enforced by running bwrap inside a transient systemd user
// scope with the limits set as scope properties.
//
// Direct cgroup-v2 writes are the theoretically cleaner path, but on a normal
// login session the process's own cgroup is a session scope that systemd does
// not delegate: it is not writable and child cgroups cannot be created there.
// systemd, which owns the hierarchy, will create a delegated, limited scope for
// us unprivileged - and a scope applies its limits before the command starts, so
// there is no window in which the target runs unbounded. When no systemd user
// manager is reachable, limits cannot be enforced unprivileged, and that is
// reported rather than silently ignored (v1's actual failure).

var (
	scopeOnce   sync.Once
	scopeOK     bool
	scopeReason string
)

// canCreateScope reports whether this host can create a transient user scope at
// all. It answers by actually creating a throwaway one - a stat of a runtime
// directory does not prove the manager will answer - and caches the result,
// which is stable for the life of the process.
func canCreateScope() (bool, string) {
	scopeOnce.Do(func() {
		if _, err := exec.LookPath("systemd-run"); err != nil {
			scopeReason = "systemd-run is not installed, so resource limits cannot be enforced unprivileged"
			return
		}
		if err := runScopeProbe(policy.Limits{Memory: "64M"}); err != nil {
			scopeReason = "no usable systemd user manager for resource limits: " + err.Error()
			return
		}
		// A scope can be *created*, but systemd-run silently accepts a property for
		// an undelegated controller without enforcing it. memory and pids are the
		// host-safety controllers (an uncapped memory bomb can OOM the host) and are
		// delegated by default; if they are not, limits genuinely cannot protect the
		// host, so report unavailable here - that is what lets admission refuse a
		// requested memory limit rather than run unbounded. cpu, which commonly needs
		// a Delegate=cpu drop-in, is reported separately by the probe as its own
		// LayerLimitsCPU layer, so a requested cpu limit is likewise refused (not run
		// unenforced) without gating scope creation on cpu delegation.
		if ctrls, known := delegatedControllers(); known && (!ctrls["memory"] || !ctrls["pids"]) {
			scopeReason = "the memory/pids controllers are not delegated to your systemd user manager, so resource limits cannot be enforced (a one-time admin step: Delegate=memory pids on user@.service)"
			return
		}
		scopeOK = true
	})
	return scopeOK, scopeReason
}

// preflightLimits verifies the exact requested limits can be applied, by creating
// a throwaway scope carrying them. This turns a run-time scope-creation failure
// into a clear error up front, instead of letting systemd-run's own exit code
// masquerade as the target's when the scope never starts.
func preflightLimits(l policy.Limits) error {
	if l.IsZero() {
		return nil
	}
	if err := runScopeProbe(l); err != nil {
		return fmt.Errorf("systemd could not apply the requested resource limits: %w", err)
	}
	return nil
}

// runScopeProbe creates a transient scope with the given limits running /bin/true
// and returns whether it succeeded.
func runScopeProbe(l policy.Limits) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	exe, args := wrapWithLimits(trueBinary(), nil, l)
	out, err := exec.CommandContext(ctx, exe, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return err
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func trueBinary() string {
	if p, err := exec.LookPath("true"); err == nil {
		return p
	}
	return "/bin/true"
}

// cpuUndelegatedReason explains why a requested cpu limit cannot be enforced.
// systemd-run *accepts* a CPUQuota even when the cpu controller is not delegated
// (the common default - it needs a one-time admin `Delegate=cpu` drop-in), then
// silently does not enforce it, so the probe reports LayerLimitsCPU unavailable and
// admission refuses a requested cpu limit rather than running it unenforced.
const cpuUndelegatedReason = "the cpu controller is not delegated to your systemd user manager, so a requested cpu limit cannot be enforced (a one-time admin step: Delegate=cpu on user@.service)"

// delegatedControllers reads the cgroup-v2 controllers systemd has delegated to
// this user's manager, under which `systemd-run --user --scope` creates scopes.
// A controller absent here is accepted but not enforced.
func delegatedControllers() (map[string]bool, bool) {
	uid := os.Getuid()
	path := fmt.Sprintf("/sys/fs/cgroup/user.slice/user-%d.slice/user@%d.service/cgroup.controllers", uid, uid)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	set := make(map[string]bool)
	for _, c := range strings.Fields(string(b)) {
		set[c] = true
	}
	return set, true
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
