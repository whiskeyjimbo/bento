//go:build linux

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

// Resource limits are enforced by running the tier's own top-level command - bwrap on
// the full tier, the bento launcher on the degraded one - inside a transient systemd
// user scope with the limits set as scope properties.
//
// Direct cgroup-v2 writes are the theoretically cleaner path, but on a normal
// login session the process's own cgroup is a session scope that systemd does
// not delegate: it is not writable and child cgroups cannot be created there.
// systemd, which owns the hierarchy, will create a delegated, limited scope for
// us unprivileged - and a scope applies its limits before the command starts, so
// there is no window in which the target runs unbounded. When no systemd user
// manager is reachable, limits cannot be enforced unprivileged, and that is
// reported rather than silently ignored (v1's actual failure).

// scopeProbeTimeout bounds each systemd-run subprocess probe. It is a backstop against a
// user manager that never answers, not a pacing knob, and it is layered UNDER the
// caller's context rather than over a fresh one: Probe runs on the hot path of every Run
// and every doctor, and a caller that has already given up must not be held for the full
// bound of each remaining probe.
const scopeProbeTimeout = 5 * time.Second

// probeWaitDelay is what makes the deadlines above actually bound anything. Every probe
// here reads its command's output, and that read waits for the output PIPE to close, not
// for the process to die: killing systemd-run on the deadline leaves the scope's own
// command alive and still holding the descriptor it inherited, which is precisely the busy
// user manager scopeProbeTimeout exists to survive. WaitDelay makes exec close the pipe
// itself shortly after the kill, so the probe returns an error - the fail-closed
// direction - instead of blocking admission indefinitely. Which error it is varies:
// exec reports ErrWaitDelay only where Wait would otherwise have succeeded, and here it
// usually reports the kill instead, so nothing may key on the one shape.
const probeWaitDelay = time.Second

// cacheProbe memoizes a host measurement, but only once it has ANSWERED: measure's
// bool reports whether the probe reached a verdict, not whether the verdict was yes,
// and a probe that reached none is re-run on the next call.
//
// That distinction is the whole point. Both limits probes below measure something a
// systemd user manager that is busy, restarting, or slower than the 5s bound simply
// fails to report - and one such failure memoized for the process lifetime pinned the
// limits layers Unavailable forever on a host where the limits bind, which under
// --allow-degraded means running the target unbounded. A definitive answer, yes or
// no, is a fact about the host and is cached either way, so the host with no
// systemd-run and the host with undelegated controllers both pay one probe, not one
// per call.
func cacheProbe[T any](measure func(context.Context) (T, bool)) func(context.Context) (T, bool) {
	var (
		mu       sync.Mutex
		val      T
		answered bool
	)
	return func(ctx context.Context) (T, bool) {
		mu.Lock()
		defer mu.Unlock()
		if !answered {
			val, answered = measure(ctx)
		}
		return val, answered
	}
}

// canCreateScope reports whether this host can create a transient user scope at
// all, and why not otherwise.
//
// It answers only that. Which controllers the manager delegates is a separate reading
// (hostSafetyDelegationState, cpuDelegationState) because the three limits layers rest
// on different ones: folding a controller check in here made every caller refuse a
// manifest over a delegation it never depended on, and sent the operator to a Delegate=
// drop-in for controllers the manifest never named.
func canCreateScope(ctx context.Context) (bool, string) {
	v, answered := scopeProbe(ctx)
	if !answered {
		return false, v.reason
	}
	return v.ok, v.reason
}

var scopeProbe = cacheProbe(measureScope)

// scopeVerdict is what measureScope concluded. It is separate from cacheProbe's
// answered bool because a definitive NO - no systemd-run on this host, controllers the
// manager does not delegate - is as cacheable as a yes; only a probe that could not
// reach either is re-run.
type scopeVerdict struct {
	ok     bool
	reason string
}

// measureScope answers by actually creating a throwaway scope - a stat of a runtime
// directory does not prove the manager will answer.
func measureScope(ctx context.Context) (scopeVerdict, bool) {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return scopeVerdict{reason: "systemd-run is not installed, so resource limits cannot be enforced unprivileged"}, true
	}
	if err := runScopeProbe(ctx, policy.Limits{Memory: "64M"}, nil); err != nil {
		// A caller that gave up measured nothing about this host, and must not leave a
		// verdict behind that says it did: the reason names the abandonment rather than
		// blaming the user manager, and nothing is cached either way.
		if ctx.Err() != nil {
			return scopeVerdict{reason: "the resource-limit probe did not finish (" + ctx.Err().Error() + "), so whether this host can enforce limits is unknown"}, false
		}
		// A scope propagates its command's exit status, so the failure above is equally a
		// scope that was never created and a canary that would not run - and the second is
		// the rare cause the common wording hides, sending an operator to debug a user
		// manager that is fine. Running the canary bare separates them, and only here: this
		// is the failure path, so a healthy host pays nothing for it.
		canary := trueBinary()
		if cerr := exec.CommandContext(ctx, canary).Run(); cerr != nil {
			return scopeVerdict{reason: "the resource-limit probe's canary (" + canary + ") does not run on this host, so whether limits can be enforced was never measured: " + cerr.Error()}, false
		}
		// The scope could not be created, which is the failure a busy or restarting user
		// manager produces transiently: no verdict, so nothing is cached.
		return scopeVerdict{reason: "no usable systemd user manager for resource limits: " + err.Error()}, false
	}
	return scopeVerdict{ok: true}, true
}

// hostSafetyDelegationState maps the delegated-controllers reading to the state of one
// host-safety limits layer - controller is "memory" or "pids", each its own layer.
//
// Unknown fails CLOSED, like cpuDelegationState. When the delegated set could not be
// read (known is false), bento cannot confirm the caps will bind, so it reports them
// unavailable rather than claim an enforcement it cannot verify. Returning Enforced
// there was the fail-open bug: systemd-run accepts a MemoryMax for an undelegated
// controller without enforcing it, so the target would run unbounded under a report
// saying the limit held. Reporting unavailable instead lets admission refuse a
// requested memory/pids limit (or proceed under --allow-degraded), which is the
// loud-degradation contract.
func hostSafetyDelegationState(ctrls map[string]bool, known bool, controller string) (enforce.State, string) {
	if !known {
		return enforce.Unavailable, "could not read which cgroup controllers your systemd user manager delegates, so a requested " + controller + " limit cannot be confirmed to protect the host (a non-standard, containerized, or hybrid-cgroup layout); it is reported unavailable rather than claimed enforced"
	}
	if !ctrls[controller] {
		return enforce.Unavailable, "the " + controller + " controller is not delegated to your systemd user manager, so a requested " + controller + " limit cannot be enforced (a one-time admin step: Delegate=" + controller + " on user@.service)"
	}
	return enforce.Enforced, ""
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
func preflightLimits(ctx context.Context, l policy.Limits, env []string) error {
	if l.IsZero() {
		return nil
	}
	if err := runScopeProbe(ctx, l, env); err != nil {
		return fmt.Errorf("systemd could not apply the requested resource limits: %w", err)
	}
	return nil
}

// runScopeProbe creates a transient scope with the given limits running /bin/true
// and returns whether it succeeded.
//
// Zero limits are an error, not a pass: wrapWithLimits returns the command unchanged
// when there is nothing to apply, so a zero-limit probe would run /bin/true bare,
// never contact systemd, and report success - "the limits will bind" from a call that
// proved nothing, in the seam the fail-closed limits story rests on.
func runScopeProbe(ctx context.Context, l policy.Limits, env []string) error {
	if l.IsZero() {
		return fmt.Errorf("internal: the scope probe was asked to prove zero limits, which creates no scope")
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, scopeProbeTimeout)
	defer cancel()

	// Deliberately unnamed even when the run it preflights has an id: this scope and
	// that one would hold the same unit name, and the probe running first would either
	// take the name the run then fails to claim or - once --collect has reaped it - hand
	// the supervisor a window in which the name exists but belongs to /bin/true.
	exe, args := wrapWithLimits(trueBinary(), nil, l, "")
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Env = env
	cmd.WaitDelay = probeWaitDelay
	out, err := cmd.CombinedOutput()
	noteProbeDeadline(parent, ctx)
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
// real, systemd-dependent implementation cannot otherwise reach in-package.
//
// Only a reading that answered is cached (see cacheProbe): known==false means the
// probe scope could not be created or read at all, which a busy or restarting user
// manager causes transiently.
var delegatedControllers = func(ctx context.Context) (map[string]bool, bool) {
	// Screened first so the host class that can never answer stops paying for a scope
	// per call: cacheProbe deliberately does not memoize a non-answer, and here the
	// non-answer is permanent.
	if !unifiedCgroupReadable() {
		return nil, false
	}
	return cachedDelegatedControllers(ctx)
}

var cachedDelegatedControllers = cacheProbe(measureDelegatedControllers)

// unifiedCgroupReadable reports whether readControllers below could reach a scope's
// cgroup.controllers at all. It answers, from the host and before any scope is created,
// the two structural failures that snippet has which are visible without one: no unified
// ("0::") line in /proc/self/cgroup on a cgroup-v1-only host, and a v2 hierarchy mounted
// somewhere other than /sys/fs/cgroup on a legacy-hybrid one. Both are permanent facts
// about the layout, so a run does not re-measure them; keep this and readControllers in
// step.
//
// It is deliberately a subset, not a mirror: a cgroup-namespaced container whose root
// cgroup.controllers is readable but whose scope subtree is not mounted also fails
// readControllers permanently, and cannot be told apart from the transient case without
// creating the scope. That host keeps re-probing, which is the fail-safe direction - it
// costs a scope per call, where the alternative would cache a busy manager's silence as
// a fact about the host.
var unifiedCgroupReadable = sync.OnceValue(func() bool {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return false
	}
	unified := false
	for line := range strings.SplitSeq(string(b), "\n") {
		if strings.HasPrefix(line, "0::") {
			unified = true
		}
	}
	if !unified {
		return false
	}
	_, err = os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
})

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
func measureDelegatedControllers(ctx context.Context) (map[string]bool, bool) {
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, scopeProbeTimeout)
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
	//
	// The snippet announces itself before the cat, and only what follows that line is
	// read: the exit status alone is no oracle for WHERE the output came from, and the
	// whole fail-closed limits story rests on this one reading - anything else printed on
	// stdout would otherwise become a delegated controller and report a cap the host will
	// not enforce as Enforced. The marker is proof the snippet ran and reached its read,
	// which is a different question from whether the scope exited 0.
	const readControllers = `p=$(grep '^0::' /proc/self/cgroup | cut -d: -f3); [ -n "$p" ] || exit 1; echo ` + controllersMarker + `; cat /sys/fs/cgroup$p/cgroup.controllers`
	args := []string{
		"--user", "--scope", "--quiet", "--collect",
		"-p", "MemoryMax=64M", "-p", "TasksMax=64", "-p", "CPUQuota=100%",
		"--", shBinary(), "-c", readControllers,
	}
	cmd := exec.CommandContext(ctx, "systemd-run", args...)
	cmd.WaitDelay = probeWaitDelay
	out, err := cmd.Output()
	noteProbeDeadline(parent, ctx)
	if err != nil {
		return nil, false
	}
	_, read, found := strings.Cut(string(out), controllersMarker+"\n")
	if !found {
		return nil, false
	}
	set := make(map[string]bool)
	for c := range strings.FieldsSeq(read) {
		set[c] = true
	}
	return set, true
}

// controllersMarker is what readControllers prints immediately before the controller
// read, so the reading has an oracle beyond the scope's exit status. It is spelled
// unlike any cgroup controller name, and matched with its newline, so a controller list
// cannot contain it.
const controllersMarker = "bento-delegated-controllers:"

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
// A policy that declares one of these keeps its own value, which systemd-run then
// reads: a bogus bus address there fails the preflight and refuses the run, loudly,
// rather than silently overriding what the manifest asked the target to see.
//
// The added values are for systemd-run only, which is why the names come back: the
// launcher drops exactly them before exec, so the target still sees only the policy
// environment. They travel in the environment rather than in argv because this tier has
// no PID namespace: a same-uid host process can read another's /proc/pid/cmdline, while
// the launcher's PR_SET_DUMPABLE(0) makes its /proc/pid/environ root-owned. That matters
// less for the bus address than for the policy values sharing the same channel.
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

// scopeUnitName is the transient scope's unit name for a run the caller identified.
// The derivation is one-way and part of the enforce.RunOptions.RunID contract: a
// supervisor computes it before the run starts and reaps through it without reading
// anything back. enforce.Run has already screened the id to letters, digits and
// underscore, none of which systemd escapes or reads as a separator, so what it names
// here is what the supervisor spelled.
func scopeUnitName(runID string) string { return "bento-run-" + runID + ".scope" }

// screenRunID re-runs, at this entry point, both halves of the run-id contract
// enforce.Run applies - the spelling and the promise that a scope will exist to be
// reaped through. Run is exported and an embedder can call it directly, and unlike the
// policy checks above it neither half fails loudly on its own: an unscreened id reaches
// --unit unvalidated, and an id whose run gets no scope at all (no limits are set, or
// this host cannot create one) leaves the supervisor holding a unit name that never
// comes into existence, learning so only when its kill does nothing to a still-running
// target. The screen is enforce's so there is one spelling of the id, not two.
//
// All three refusals are a *enforce.Refusal, the category a supervisor must not retry:
// each is a mistake in what the caller asked for, and a frontend that sorts refusals
// from failures would otherwise file two of them under the runs that failed for reasons
// out of the caller's hands. The Report is empty because nothing has been probed yet.
func (e *Enforcer) screenRunID(ctx context.Context, p *policy.Policy, runID string) error {
	if runID == "" {
		return nil
	}
	if err := enforce.ValidateRunID(runID); err != nil {
		return err
	}
	if p.Limits.IsZero() {
		return &enforce.Refusal{Reason: "a run id asks for a reapable scope, but this manifest sets no resource limits and a run without them is not wrapped in one; set a limit (memory, cpu, or pids) or drop the run id"}
	}
	if ok, reason := canCreateScope(ctx); !ok {
		return &enforce.Refusal{Reason: "a run id asks for a reapable scope, but this host cannot create one, so there would be nothing to reap through: " + reason}
	}
	return nil
}

// wrapWithLimits prepends a transient systemd user scope carrying the policy's
// limits. With no limits set it returns the command unchanged, so the scope is
// only paid for when a manifest asks for it. runID, when set, names the scope so a
// supervisor can kill the tree; empty leaves systemd to generate a name.
func wrapWithLimits(exe string, args []string, l policy.Limits, runID string) (string, []string) {
	if l.IsZero() {
		return exe, args
	}
	// --collect garbage-collects the transient scope even when the target exits
	// non-zero (e.g. an OOM kill); without it, failed scope units linger in the
	// user manager forever. Under a named unit it stops being hygiene and becomes
	// load-bearing: a failed unit that lingered would hold the name, and the next run
	// the supervisor gave the same id to would fail to start rather than run unnamed.
	scope := []string{"--user", "--scope", "--quiet", "--collect"}
	if runID != "" {
		scope = append(scope, "--unit", scopeUnitName(runID))
	}
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
