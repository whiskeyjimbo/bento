package linux

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/landlock"
	"github.com/whiskeyjimbo/bento/internal/seccomp"
)

// The kernel capability checks this package's fail-closed decisions read. They are
// vars so a test can construct the host that lacks a capability: these are direct
// kernel and compile-time queries with no override, so on a host that HAS the
// capability - which is every host bento is developed on - the branch that reports
// the layer unavailable and refuses the run is otherwise unreachable. Testing the
// pure decision functions is not a substitute: it proves the decision, not that
// this call site consults the probe at all, so a site that hardcoded availability
// would still pass.
var (
	landlockAvailable             = landlock.Available
	landlockTruncateRestricted    = landlock.TruncateRestricted
	landlockIoctlDevRestricted    = landlock.IoctlDevRestricted
	landlockResolveUnixRestricted = landlock.ResolveUnixRestricted
	seccompSupported              = seccomp.Supported
	seccompStrictExecSupported    = seccomp.StrictExecSupported
	seccompEgressSupported        = seccomp.EgressSupported
)

// Probe reports what this host can actually enforce.
//
// It reports what it can prove, not what it hopes: the filesystem layer is only
// Enforced if bwrap is present and the namespaces and base mounts the run makes can
// really be built here, which is checked by building them rather than by inspecting
// sysctls. Ubuntu's
// AppArmor restriction, container policies, and kernel builds all interact, and
// the only trustworthy answer is an empirical one.
func (e *Enforcer) Probe(ctx context.Context) enforce.Report {
	var r enforce.Report

	// bwrap's filesystem and network confinement both depend on standing up an
	// unprivileged user namespace here; probe that once and report both layers
	// against it, so neither claims a guarantee bwrap cannot deliver on this host.
	ns, nsReason := usableNamespaces(ctx)
	// The reduced-confinement tier stands in for the missing netns and PID namespace
	// with a seccomp egress and cross-process block, so its viability - not just
	// Landlock's - decides whether a degraded run is offered.
	degradedFencesOK := seccompSupported() && seccompEgressSupported()
	fsState, fsDetail := filesystemLayer(ns, nsReason, landlockAvailable(), landlockTruncateRestricted(), landlockIoctlDevRestricted(), landlockResolveUnixRestricted(), degradedFencesOK)
	r.Add(enforce.LayerFilesystem, fsState, fsDetail)

	// Egress is enforced by the network namespace (nothing leaves except through our
	// proxy) plus the host-side allowlist proxy. The guarantee that matters - nothing
	// reaches a non-allowlisted host - holds fully and unprivileged, but only where the
	// namespace can be created: without it there is no netns to fence egress into, so
	// the layer is unavailable, not enforced. (The one nuance where it IS enforced: a
	// program that ignores the proxy environment fails closed rather than being
	// transparently redirected; transparent redirect needs the one-time `bento setup`.
	// That is an availability nuance for uncooperative clients, not a containment gap.)
	//
	// The netns fences IP, not AF_UNIX: a path-named unix socket is scoped by the
	// filesystem, and connect() to one succeeds even through a read-only bind. A host
	// daemon reached that way has its own network access, so a socket the mount
	// namespace exposes is a way out regardless of this layer. That is why the
	// deny-list shields the host's runtime directory whole (see denylist.Runtime), and
	// why the residual it documents - a service socket somewhere else that a grant
	// exposes - is an egress hole as much as a filesystem one.
	if ns == namespacesUsable {
		r.Add(enforce.LayerNetwork, enforce.Enforced, "")
	} else {
		r.Add(enforce.LayerNetwork, enforce.Unavailable, nsReason)
	}

	for _, ls := range execLayers(seccompSupported(), seccompStrictExecSupported()) {
		r.Add(ls.Layer, ls.State, ls.Reason)
	}

	scopeOK, scopeReason := canCreateScope()
	// Default Unavailable, not the zero value (Enforced): cpuState is measured only when
	// a scope is creatable, and a host whose cpu delegation was never measured must not
	// report the cpu limit as enforced - admission would then admit an unenforceable
	// CPUQuota. Today limitsLayers reads this only on the same nsOK && scopeOK path, so
	// the default is belt-and-suspenders against that coupling drifting.
	cpuState := enforce.Unavailable
	var cpuReason string
	if scopeOK {
		// cpu delegation is separate from scope creation: a scope can be created
		// (memory/pids delegated) while systemd-run silently ignores a CPUQuota
		// because the cpu controller is not delegated. Report it so admission can
		// refuse a requested cpu limit this host cannot actually enforce.
		cpuState, cpuReason = cpuDelegationState(delegatedControllers())
	}
	for _, ls := range limitsLayers(scopeOK, scopeReason, cpuState, cpuReason) {
		r.Add(ls.Layer, ls.State, ls.Reason)
	}

	return r
}

// execLayers decides the exec and exec-strict layers. exec-strict (none-strict's
// fork/vfork/clone blocking) needs both seccomp and the architecture-specific
// filter; off amd64 it degrades to the execve-only block rather than silently
// claiming the stricter guarantee.
func execLayers(seccompOK, strictOK bool) []enforce.LayerStatus {
	var out []enforce.LayerStatus
	if seccompOK {
		out = append(out, enforce.LayerStatus{Layer: enforce.LayerExec, State: enforce.Enforced})
	} else {
		out = append(out, enforce.LayerStatus{
			Layer: enforce.LayerExec, State: enforce.Unavailable,
			Reason: "this kernel does not support seccomp BPF, so subprocess-blocking cannot be enforced",
		})
	}
	switch {
	case !seccompOK:
		out = append(out, enforce.LayerStatus{
			Layer: enforce.LayerExecStrict, State: enforce.Unavailable,
			Reason: "this kernel does not support seccomp BPF",
		})
	case !strictOK:
		out = append(out, enforce.LayerStatus{
			Layer: enforce.LayerExecStrict, State: enforce.Unavailable,
			Reason: "fork/vfork/process-clone blocking is not implemented for this architecture; none-strict blocks only execve here",
		})
	default:
		out = append(out, enforce.LayerStatus{Layer: enforce.LayerExecStrict, State: enforce.Enforced})
	}
	return out
}

// limitsLayers decides the resource-limit layers. Both tiers wrap their command in a
// systemd scope (see wrapWithLimits), so the only question is whether a scope can be
// created; the cpu sub-layer additionally needs the cpu controller delegated. The
// tier does not enter into it: a scope is a cgroup, applied by systemd before the
// command starts and independent of the user namespace the degraded tier lacks.
func limitsLayers(scopeOK bool, scopeReason string, cpuState enforce.State, cpuReason string) []enforce.LayerStatus {
	switch {
	case !scopeOK:
		// No scope at all: the cpu gap is subsumed by the whole limits layer being
		// unavailable, which already refuses a cpu-limit policy. A separate
		// LayerLimitsCPU here would only duplicate the refusal with the same reason.
		return []enforce.LayerStatus{{Layer: enforce.LayerLimits, State: enforce.Unavailable, Reason: scopeReason}}
	default:
		return []enforce.LayerStatus{
			{Layer: enforce.LayerLimits, State: enforce.Enforced},
			{Layer: enforce.LayerLimitsCPU, State: cpuState, Reason: cpuReason},
		}
	}
}

// filesystemLayer decides the filesystem-confinement state from namespace and
// Landlock availability, the two independent capabilities it rests on:
//
//   - userns OK: bwrap gives full confinement (fresh rootfs, mount namespace, the
//     deny-list binds); Landlock, when present, is a second kernel backstop behind it.
//   - no usable namespace (blocked, or bwrap absent) but Landlock present: the
//     Landlock-only degraded tier - path
//     read/write/exec rules and nothing else. No mount namespace means no rootfs, no
//     hidden /proc, and critically no deny-list binds, so it is materially weaker
//     than the full sandbox, not the same thing by another mechanism (design 6.2).
//   - neither: nothing confines the filesystem, so the layer is unavailable and a
//     run refuses outright rather than offering a degraded mode that enforces nothing.
//   - the probe could not answer: unavailable, never degraded. Substituting the weaker
//     tier here would act on a measurement that was never taken - the host may well run
//     bwrap fine - and would hand the user a weaker sandbox with a wrong reason. Like
//     the delegated-controller readings in limits.go, unknown fails closed.
//
// The network layer is deliberately NOT three-stated the same way: without a user
// namespace there is no netns to fence egress, so it stays Unavailable, which is
// what makes a network manifest refuse even under --allow-degraded.
func filesystemLayer(ns namespaceProbe, nsReason string, landlockAvail, truncateRestricted, ioctlDevRestricted, resolveUnixRestricted, degradedFencesOK bool) (enforce.State, string) {
	switch {
	case ns == namespacesUsable && landlockAvail:
		return enforce.Enforced, "Landlock backstop active"
	case ns == namespacesUsable:
		return enforce.Enforced, "no Landlock backstop on this kernel; bwrap alone confines"
	case ns == namespacesUnknown:
		return enforce.Unavailable, nsReason
	case landlockAvail && !degradedFencesOK:
		// Landlock confines the filesystem, but the reduced-confinement tier also
		// substitutes a seccomp egress block and cross-process block for the netns and
		// PID namespace it lacks - and those need an amd64 kernel with seccomp BPF.
		// Without them the tier cannot run at all, so report it unavailable rather than
		// offer a --allow-degraded that would only refuse at launch.
		return enforce.Unavailable, joinReason(nsReason,
			"and the reduced-confinement fallback needs a seccomp egress and cross-process "+
				"block (an amd64 kernel with seccomp BPF) to stand in for the missing namespaces, "+
				"unavailable here")
	case landlockAvail:
		// Leads with nsReason rather than a hardcoded userns clause: this branch is
		// reached whenever bwrap cannot give a namespace, which includes bwrap simply
		// not being installed. Asserting "user namespaces are blocked" there sends a
		// reader to enable a namespace the host already permits.
		return enforce.Degraded, joinReason(nsReason,
			"confinement falls back to Landlock path rules plus a seccomp egress block. This is materially "+
				"weaker than the full sandbox: no mount namespace (the deny-list cannot carve a credential out of "+
				"an allowed tree, and any granted /proc is the host's), no PID namespace (the target shares the "+
				"host process table, so it can see and signal same-user processes - though seccomp blocks the "+
				"cross-process memory read/write and ptrace injection that would let it take one over - and a "+
				"background process it leaves is swept only best-effort by killing the run's process group, which "+
				"a setsid() escapes and which also stops a target that reads an interactive terminal), and no "+
				"network namespace "+
				"(seccomp blocks IP egress but not netlink interface enumeration, nor "+
				unixSocketClause(resolveUnixRestricted)+"). It confines filesystem "+
				"read/write/exec, nothing more"+
				truncateResidual(truncateRestricted)+ioctlDevResidual(ioctlDevRestricted)+
				resolveUnixResidual(resolveUnixRestricted))
	default:
		return enforce.Unavailable, joinReason(nsReason,
			"and this kernel has no Landlock, so no filesystem confinement is available at all")
	}
}

// joinReason continues a probe reason with the clause the calling branch concludes
// from it. The trailing period matters: classifyUnshare's sysctl diagnoses close with
// an instruction to the reader ("Set it to 1 to allow them."), and joining that to a
// clause raw produces "...to allow them.; confinement falls back to".
func joinReason(reason, clause string) string {
	return strings.TrimRight(reason, ".") + "; " + clause
}

// truncateResidual is the degraded-tier disclosure clause for a kernel whose Landlock
// ABI (< 3) cannot restrict truncate: a read-granted file can still be zeroed, since
// Landlock leaves an unhandled right unrestricted and this tier has no mount namespace
// behind it. It is empty when truncate is restricted.
func truncateResidual(truncateRestricted bool) string {
	if truncateRestricted {
		return ""
	}
	return ". Additionally this kernel's Landlock ABI is below 3, which cannot restrict truncate, so a " +
		"read-only granted file can still be truncated (zeroed) - an integrity gap this tier cannot close"
}

// ioctlDevResidual is the degraded-tier disclosure clause for a kernel whose Landlock
// ABI (< 5, i.e. before 6.10) cannot restrict ioctl on device files. Landlock leaves an
// unhandled right unrestricted, so every ioctl on every granted device node is available
// - and this tier grants /dev/urandom, /dev/random, /dev/zero and /dev/null to every run.
// seccomp's terminal-injection block covers the tty ioctls that matter most but not the
// rest, so the gap is disclosed rather than treated as closed. Empty from 6.10 on.
func ioctlDevResidual(ioctlDevRestricted bool) string {
	if ioctlDevRestricted {
		return ""
	}
	return ". This kernel's Landlock ABI is also below 5, which cannot restrict ioctl on device files, so " +
		"any ioctl on a granted device node (/dev/urandom, /dev/random, /dev/zero, /dev/null) is available " +
		"beyond the terminal-injection set seccomp blocks"
}

// unixSocketClause is the unix-socket half of the degraded tier's "no network namespace"
// disclosure. What the target can reach over AF_UNIX depends on the Landlock ABI, so the
// sentence cannot be fixed text: from ABI 9 the degraded ruleset handles resolve_unix and
// grants it only on the write set, so a pathname socket outside the grants is denied and
// only the abstract namespace - which no file grant governs - is left. Below it no
// pathname socket is governed at all.
//
// /dev/log is named because it is the one denial with no visible symptom: glibc's
// syslog(3) discards the message and reports nothing, so a target that logs through it
// goes quiet rather than failing, and an operator has no thread to pull. The other
// sockets this denies (nscd, systemd-resolved, dbus, X11) error visibly, and losing them
// is the trade the tier is for.
func unixSocketClause(resolveUnixRestricted bool) string {
	if resolveUnixRestricted {
		return "an abstract-namespace unix socket to a host daemon, which no file grant governs " +
			"(a pathname one outside the write grants is denied by Landlock's resolve_unix right - " +
			"including /dev/log, whose denial is silent, since glibc's syslog(3) drops the message " +
			"without an error)"
	}
	return "a unix socket to a host daemon, including an abstract-namespace one no grant is needed to reach"
}

// resolveUnixResidual is the degraded-tier disclosure clause for a kernel whose Landlock
// ABI (< 9) cannot restrict connect(2) and sendmsg(2) on pathname AF_UNIX sockets. The
// degraded ruleset handles that right and grants it on the write set, so from ABI 9 the
// file grants govern which sockets the target may reach; below it the right is unhandled
// and every socket path on the host stays connectable. That is an egress residual as much
// as a filesystem one - the daemon on the other end has its own network access - which is
// why it is named here rather than left to the filesystem grants to imply.
func resolveUnixResidual(resolveUnixRestricted bool) string {
	if resolveUnixRestricted {
		return ""
	}
	return ". This kernel's Landlock ABI is also below 9, which cannot restrict connect(2) on pathname " +
		"unix sockets, so the target can reach any host daemon socket its path names regardless of the " +
		"grants - and that daemon's own network access with it"
}

// namespaceProbe is what the user-namespace probe could establish. The third state
// is the point of the type: an unanswered probe - the canary reaped under memory
// pressure, the context expired, bwrap itself failing to start - is not the same
// finding as a host that refused the namespace, and collapsing the two selects the
// Landlock-only tier on a host where bwrap works fine, telling the user to go flip
// AppArmor sysctls that were never the problem.
type namespaceProbe int

const (
	namespacesUsable namespaceProbe = iota
	namespacesBlocked
	namespacesUnknown
)

// usableNamespaces reports whether bwrap is installed and can build here the
// namespaces and base mounts its filesystem and network confinement depend on,
// with a reason a user can act on when it cannot.
func usableNamespaces(ctx context.Context) (namespaceProbe, string) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		// Cause only, no verdict: every caller leads with this string and each one
		// reaches a different conclusion from it - the network layer is unavailable,
		// but the filesystem layer may still have Landlock to fall back on. A reason
		// asserting "no confinement is possible" contradicts the degraded tier that
		// then describes itself in the same sentence.
		// The remedy closes the sentence like classifyUnshare's sysctl diagnoses do, so
		// joinReason continues from it the same way: this is the one probe finding a user
		// can fix with a single command, and without it the reason names a binary they
		// have no reason to know is packaged as "bubblewrap".
		return namespacesBlocked, "bubblewrap (bwrap) is not installed, so it cannot isolate anything. " +
			"Install it with your package manager (Debian/Ubuntu: sudo apt install bubblewrap; " +
			"Fedora: sudo dnf install bubblewrap; Arch: sudo pacman -S bubblewrap)."
	}
	if err := canUnshare(ctx, bwrap); err != nil {
		return classifyUnshare(err)
	}
	return namespacesUsable, ""
}

// canUnshare reports whether the sandbox's namespaces and base mounts can be built
// here, by asking bwrap to build them.
func canUnshare(ctx context.Context, bwrap string) error {
	// Bound the probe like every sibling (runScopeProbe, measureDelegatedControllers):
	// it runs on the hot path of every Run, and a bwrap that hangs - a wedged canary, a
	// stuck mount - would otherwise stall admission for as long as the caller's context
	// allows, which for the CLI is forever. The deadline is a probe failure, not a host
	// finding, and classifyUnshare reports it as one.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Exercise the same namespace and capability flags the real run uses (namespaceFlags),
	// not a hand-copied subset: a host that permits user+net namespaces but rejects one of
	// the others - most plausibly --unshare-cgroup on a pre-4.6 kernel, or --cap-drop on an
	// old bwrap - would otherwise pass this probe, report the filesystem layer Enforced, and
	// then fail at launch with a bwrap exit code indistinguishable from the target's. Probing
	// the shared set surfaces that at admission instead. --unshare-net is probed too (the run
	// adds it for the network layer); --bind / / makes the canary reachable for the check.
	// The canary is resolved on $PATH, not hardcoded to /bin/true: bwrap sets the
	// namespaces up FIRST and only then execs, so on a host with no /bin/true (NixOS,
	// a minimal image) the namespaces would succeed and only the exec fail - and this
	// probe cannot tell the two apart. It would report userns blocked, refuse every
	// network manifest, and downgrade the run to the Landlock-only tier while sending
	// the user off to flip AppArmor sysctls on a host where userns works. limits.go's
	// trueBinary resolves it the same way for the same reason.
	// The pseudo-filesystem mounts are exercised for the same reason and from the same
	// shared list (pseudoFSFlags): mounting a fresh procfs into the namespace is a
	// permission separate from creating it, and a container that masks paths under
	// /proc grants the second and refuses the first. --dev and --tmpfs are probed
	// alongside it because the run makes them too; unlike the procfs refusal they have
	// no known host remedy to name, so classifyUnshare reports them as a mount the host
	// refused and stops there.
	args := append([]string{}, namespaceFlags...)
	args = append(args, "--unshare-net", "--bind", "/", "/")
	args = append(args, pseudoFSFlags...)
	args = append(args, trueBinary())
	cmd := exec.CommandContext(ctx, bwrap, args...)
	// Killing bwrap on the deadline is not enough on its own: CombinedOutput waits for
	// the output pipe to close, and any descendant still holding it keeps the probe
	// blocked for as long as it lives - which is the stall the deadline exists to stop.
	// WaitDelay makes exec close the pipe itself shortly after the kill.
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &usernsError{output: string(out), err: err, ctxErr: ctx.Err()}
	}
	return nil
}

type usernsError struct {
	output string
	err    error
	// ctxErr is the probe context's error read after the command returned. It is
	// captured here because exec reports a cancelled command as the kill signal it
	// sent ("signal: killed"), which is indistinguishable from the canary being
	// reaped by anything else - and a probe that ran out of time has measured
	// nothing about this host.
	ctxErr error
}

func (e *usernsError) Error() string { return e.err.Error() }

// classifyUnshare turns a failed sandbox-base probe into a verdict about the host
// plus a reason a user can act on. The bare bwrap message ("No permissions to create
// a new user namespace") tells a user nothing about why or what to do, and on current
// Ubuntu the cause is a specific, fixable AppArmor policy.
//
// Only output naming a namespace refusal, or one of the base mounts the sandbox root
// needs, counts as "blocked": that is the host answering. Everything else - the probe
// timing out, bwrap failing to start, an exit whose output names no such failure (a
// reaped canary, EAGAIN under load) - leaves the question open, and saying "userns
// blocked" there costs the user the full sandbox on a host that supports it. The match
// is on bwrap's message, so a "Permission denied" naming neither still reads as
// blocked; that is the pre-existing reading, and it errs toward the tier that confines
// less rather than toward claiming a guarantee.
func classifyUnshare(err error) (namespaceProbe, string) {
	var out string
	var ue *usernsError
	if errors.As(err, &ue) {
		out = ue.output
		if ue.ctxErr != nil {
			return namespacesUnknown, "the user-namespace probe did not finish (" + ue.ctxErr.Error() +
				"), so whether bubblewrap can isolate anything on this host is unknown; it is reported unavailable rather than guessed"
		}
	}
	// Checked before both matches below, and matching every base mount rather than only
	// proc: the host did answer here, and with a fact worth stating on its own - the
	// namespace was granted and the mount inside it was not. Falling through, a refusal
	// worded "Operation not permitted" would read as an unclassified probe failure and
	// one worded "Permission denied" would borrow base's "cannot create an unprivileged
	// user namespace", which is false on this host. Only proc carries a remedy, because
	// masking paths under /proc is the one cause established for this class.
	if strings.Contains(out, "Can't mount ") {
		reason := "bubblewrap can create a user namespace here but cannot mount the pseudo-filesystems " +
			"the sandbox's root filesystem needs, so it cannot isolate anything: " + strings.TrimSpace(out)
		if strings.Contains(out, "Can't mount proc") {
			reason += ". The usual cause is a container runtime masking paths under /proc, " +
				"which docker does by default; there --security-opt systempaths=unconfined lifts it."
		}
		return namespacesBlocked, reason
	}
	const base = "cannot create an unprivileged user namespace, so bubblewrap cannot isolate anything"
	const unknownBase = "the user-namespace probe failed for a reason that is not a namespace refusal, so whether " +
		"bubblewrap can isolate anything on this host is unknown; it is reported unavailable rather than guessed"

	if !strings.Contains(out, "user namespace") && !strings.Contains(out, "Permission denied") {
		if out != "" {
			return namespacesUnknown, unknownBase + ": " + strings.TrimSpace(out)
		}
		return namespacesUnknown, unknownBase + ": " + err.Error()
	}
	if restricted("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "1") {
		return namespacesBlocked, base + ": AppArmor restricts unprivileged user namespaces on this host " +
			"(kernel.apparmor_restrict_unprivileged_userns=1). Install an AppArmor profile permitting bwrap, " +
			"or set it to 0 to allow them system-wide."
	}
	if restricted("/proc/sys/kernel/unprivileged_userns_clone", "0") {
		return namespacesBlocked, base + ": unprivileged user namespaces are disabled " +
			"(kernel.unprivileged_userns_clone=0). Set it to 1 to allow them."
	}
	return namespacesBlocked, base + ": " + strings.TrimSpace(out)
}

// restricted reports whether a sysctl file holds the given value.
func restricted(path, value string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == value
}
