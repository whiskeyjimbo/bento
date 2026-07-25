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

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
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
		if err := runScopeProbe(policy.Limits{Memory: "64M"}, nil); err != nil {
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
		if ok, reason := hostControllersDelegated(delegatedControllers()); !ok {
			scopeReason = reason
			return
		}
		scopeOK = true
	})
	return scopeOK, scopeReason
}

// hostControllersDelegated reports whether the memory and pids controllers - the
// host-safety caps - are confirmed delegated, and why not otherwise.
//
// Unknown fails CLOSED. When the delegated set could not be read (known is false),
// bento cannot confirm the caps will bind, so it reports them unavailable rather
// than claim an enforcement it cannot verify. Returning ok there was the fail-open
// bug: systemd-run accepts a MemoryMax for an undelegated controller without
// enforcing it, so the target would run unbounded under a report saying the limit
// held. Reporting unavailable instead lets admission refuse a requested memory/pids
// limit (or proceed under --allow-degraded), which is the loud-degradation contract.
func hostControllersDelegated(ctrls map[string]bool, known bool) (bool, string) {
	if !known {
		return false, "could not read which cgroup controllers your systemd user manager delegates, so resource limits cannot be confirmed to protect the host (a non-standard, containerized, or hybrid-cgroup layout); they are reported unavailable rather than claimed enforced"
	}
	if !ctrls["memory"] || !ctrls["pids"] {
		return false, "the memory/pids controllers are not delegated to your systemd user manager, so resource limits cannot be enforced (a one-time admin step: Delegate=memory pids on user@.service)"
	}
	return true, ""
}

// preflightLimits verifies the exact requested limits can be applied, by creating
// a throwaway scope carrying them. This turns a run-time scope-creation failure
// into a clear error up front, instead of letting systemd-run's own exit code
// masquerade as the target's when the scope never starts.
//
// env is the environment the real run will hand systemd-run, or nil to inherit the
// enforcer's. Passing the real one matters on the degraded tier, whose command env is
// the sanitized policy env: systemd-run needs the session bus variables to reach the
// user manager, and a probe that inherited the host env would pass while the real run
// died with the scope never created and the target never started.
func preflightLimits(l policy.Limits, env []string) error {
	if l.IsZero() {
		return nil
	}
	if err := runScopeProbe(l, env); err != nil {
		return fmt.Errorf("systemd could not apply the requested resource limits: %w", err)
	}
	return nil
}

// runScopeProbe creates a transient scope with the given limits running /bin/true
// and returns whether it succeeded.
func runScopeProbe(l policy.Limits, env []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	exe, args := wrapWithLimits(trueBinary(), nil, l)
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
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

// cpuDelegationState maps the delegated-controllers reading to the LayerLimitsCPU
// state. Like hostControllersDelegated, unknown fails CLOSED: an unreadable
// delegated set cannot confirm a cpu limit will bind, so it is Unavailable, not
// Enforced - previously known==false took the Enforced branch and admission then
// admitted a cpu limit the host silently ignored.
func cpuDelegationState(ctrls map[string]bool, known bool) (enforce.State, string) {
	if !known {
		return enforce.Unavailable, "could not read which cgroup controllers your systemd user manager delegates, so a requested cpu limit cannot be confirmed to bind (a non-standard, containerized, or hybrid-cgroup layout)"
	}
	if !ctrls["cpu"] {
		return enforce.Unavailable, cpuUndelegatedReason
	}
	return enforce.Enforced, ""
}

// cpuUndelegatedReason explains why a requested cpu limit cannot be enforced.
// systemd-run *accepts* a CPUQuota even when the cpu controller is not delegated
// (the common default - it needs a one-time admin `Delegate=cpu` drop-in), then
// silently does not enforce it, so the probe reports LayerLimitsCPU unavailable and
// admission refuses a requested cpu limit rather than running it unenforced.
const cpuUndelegatedReason = "the cpu controller is not delegated to your systemd user manager, so a requested cpu limit cannot be enforced (a one-time admin step: Delegate=cpu on user@.service)"

// delegatedControllers reports which cgroup controllers a transient scope actually
// gets, so the fail-closed decision knows whether a limit will bind. It is a var so
// a test can construct the unknown-delegation host the decision hinges on, which the
// real, systemd-dependent implementation cannot otherwise reach in-package. The
// result is process-stable, so it is measured once.
var delegatedControllers = sync.OnceValues(measureDelegatedControllers)

// measureDelegatedControllers creates a throwaway scope that REQUESTS every
// controller's limit and reads that scope's own cgroup.controllers, so it measures
// delegation at the exact cgroup a real limited scope will live in.
//
// This is more faithful than reading a fixed host path (the user manager's
// user@.service cgroup): that path is wrong on a containerized, nested, or hybrid
// systemd layout, where it is unreadable and the whole limits layer then falsely
// reports unavailable. It is also more faithful than reading a *bare* scope's
// controllers - systemd enables a controller on a scope only when something needs
// it, so a bare scope omits cpu even where a CPUQuota would bind; requesting the
// limits makes systemd enable exactly the controllers it can, and the ones it cannot
// (undelegated) are silently absent - which is the very fact this measures.
//
// Bundling all three properties into one scope is safe on a partially-delegated host
// (the common cpu-not-delegated default): systemd-run accepts a property for an
// undelegated controller without erroring the scope - the same behavior that made the
// original fail-open bug possible - so requesting CPUQuota where cpu is undelegated
// still yields a running scope whose controllers report memory and pids. A cpu quirk
// cannot sink the host-safety reading (verified: requesting an undelegated
// controller's property exits 0 and merely omits it from the read).
//
// known is false only when the probe scope could not be created or read at all
// (no systemd user manager, or the read failed): that is the fail-closed signal.
func measureDelegatedControllers() (map[string]bool, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Read the scope's own cgroup.controllers - the set systemd actually enabled on
	// the scope. The path is derived from the unified (v2) line of /proc/self/cgroup
	// (the "0::" line), which is what makes this work on a containerized or nested
	// systemd where the scope's cgroup is not at a fixed location. Every failure mode
	// is closed: on a cgroup-v1-only host there is no "0::" line, so the guard exits
	// nonzero rather than falling back to catting the v2 root's controllers (which
	// would over-report); on a legacy-hybrid host the v2 hierarchy is mounted under
	// /sys/fs/cgroup/unified, so the derived path is wrong and the cat fails. Either
	// way the scope exits nonzero and known is false.
	const readControllers = `p=$(grep '^0::' /proc/self/cgroup | cut -d: -f3); [ -n "$p" ] || exit 1; cat /sys/fs/cgroup$p/cgroup.controllers`
	args := []string{
		"--user", "--scope", "--quiet", "--collect",
		"-p", "MemoryMax=64M", "-p", "TasksMax=64", "-p", "CPUQuota=100%",
		"--", shBinary(), "-c", readControllers,
	}
	out, err := exec.CommandContext(ctx, "systemd-run", args...).Output()
	if err != nil {
		return nil, false
	}
	set := make(map[string]bool)
	for c := range strings.FieldsSeq(string(out)) {
		set[c] = true
	}
	return set, true
}

func shBinary() string {
	if p, err := exec.LookPath("sh"); err == nil {
		return p
	}
	return "/bin/sh"
}

// scopeBusVars are the variables systemd-run reads to find the systemd user manager.
// A command run with a sanitized environment has none of them and systemd-run fails
// with "No medium found" before the scope exists.
var scopeBusVars = []string{"DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"}

// withScopeBusVars returns env with the host's session-bus variables added, plus the
// names it added. A variable the policy itself declares is left alone: the target must
// see the policy's value, so it is neither overwritten here nor stripped later.
//
// The added values are for systemd-run only, which is why the names come back: the
// launcher drops exactly them before exec, so the target still sees only the policy
// environment. They travel in the environment rather than in argv because this tier has
// no PID namespace, and a same-uid host process can read another's /proc/self/cmdline.
func withScopeBusVars(env []string, policyEnv map[string]string) (out []string, added []string) {
	out = env
	for _, name := range scopeBusVars {
		if _, declared := policyEnv[name]; declared {
			continue
		}
		v, ok := os.LookupEnv(name)
		if !ok {
			continue
		}
		out = append(out, name+"="+v)
		added = append(added, name)
	}
	return out, added
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
