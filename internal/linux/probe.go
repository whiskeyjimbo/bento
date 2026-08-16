//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
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
	seccompTerminalSupported      = seccomp.TerminalInjectionSupported
	landlockScopedIPCRestricted   = landlock.ScopedIPCRestricted
	landlockNetTCPRestricted      = landlock.NetTCPRestricted
)

// degradedFencesOK reports whether this host can supply every fence the reduced-
// confinement tier substitutes for the namespaces it lacks: a seccomp egress block for
// the missing netns, a cross-process block for the missing PID namespace, and a
// terminal-injection block for the missing --new-session. It must name the same terms
// the launcher's degradedPrerequisites refuses on, or the probe offers a tier the
// launcher can only refuse at run time.
//
// A function rather than the local it used to be, called from both this package's
// probe paths: the term was written out twice, which is how the two answers drift.
func degradedFencesOK() bool {
	return seccompSupported() && seccompEgressSupported() && seccompTerminalSupported()
}

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
	// The reduced-confinement tier stands in for the missing namespaces with seccomp
	// fences, so its viability - not just Landlock's - decides whether a degraded run
	// is offered.
	r.AddStatus(filesystemLayer(ns, nsReason, landlockAvailable(), landlockTruncateRestricted(), landlockIoctlDevRestricted(), landlockResolveUnixRestricted(), landlockScopedIPCRestricted(), landlockNetTCPRestricted(), degradedFencesOK()))

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
		r.AddStatus(ls)
	}

	scopeOK, scopeReason := canCreateScope(ctx)
	// Default Unavailable, not the zero value (Enforced): delegation is measured only
	// when a scope is creatable, and a host whose controllers were never read must not
	// report a limit as enforced - admission would then admit an unenforceable cap.
	per := []enforce.LayerStatus{
		{Layer: enforce.LayerLimitsMemory, State: enforce.Unavailable},
		{Layer: enforce.LayerLimitsPIDs, State: enforce.Unavailable},
		{Layer: enforce.LayerLimitsCPU, State: enforce.Unavailable},
	}
	if scopeOK {
		// Delegation is separate from scope creation, and separate per controller: a
		// scope can be created while systemd-run silently ignores a property whose
		// controller the manager does not delegate. Report each so admission can refuse
		// exactly the limits this host cannot actually enforce.
		ctrls, known := delegatedControllers(ctx)
		per[0].State, per[0].Reason = hostSafetyDelegationState(ctrls, known, "memory")
		per[1].State, per[1].Reason = hostSafetyDelegationState(ctrls, known, "pids")
		per[2].State, per[2].Reason = cpuDelegationState(ctrls, known)
	}
	for _, ls := range limitsLayers(scopeOK, scopeReason, per) {
		r.AddStatus(ls)
	}
	r.AddStatus(autoExecReportLayer())

	return r
}

// autoExecReportLayer reports whether this host can answer where a write grant's
// checkout runs its hooks, which is hookRunnerDir's `git rev-parse` and so needs git on
// PATH. Every other binary this package shells to is probed here; this one was the
// dependency nobody asked about, and its absence is invisible from the run's own report -
// each grant simply comes back unresolved, which is also what one bad checkout looks like.
//
// LookPath rather than running git: the per-call handling already treats a git that
// answers wrongly as an unresolved grant, and what is missing is only the host-level
// statement, which the presence of the binary settles.
func autoExecReportLayer() enforce.LayerStatus {
	if _, err := exec.LookPath("git"); err != nil {
		return enforce.LayerStatus{
			Layer: enforce.LayerAutoExecReport, State: enforce.Unavailable,
			Reason: "git is not on this host's PATH, and bento asks git where a write grant's checkout runs its hooks.",
			Consequences: "Every run's auto-exec report comes back short here: a grant's hook directory is never resolved, so it is listed as unresolved and any file planted in it goes unnamed. " +
				"The shields are unaffected - nothing is less confined for it - but the hint an operator is told to read cannot be trusted as a clean one. Install git to restore it.",
		}
	}
	return enforce.LayerStatus{Layer: enforce.LayerAutoExecReport, State: enforce.Enforced}
}

// execLayers decides the exec and exec-strict layers. exec-strict (none-strict's
// fork/vfork/clone blocking) needs both seccomp and the architecture-specific
// filter; off amd64 it degrades to the execve-only block rather than silently
// claiming the stricter guarantee.
func execLayers(seccompOK, strictOK bool) []enforce.LayerStatus {
	var out []enforce.LayerStatus
	if seccompOK {
		// Enforced with a standing seam: the filter denies execve, never execveat, which
		// the launcher itself needs to reach the target. validate says the same thing over
		// a manifest that blocks exec; a reader who only ever runs doctor would otherwise
		// come away believing the block is total.
		out = append(out, enforce.LayerStatus{
			Layer: enforce.LayerExec, State: enforce.Enforced,
			Consequences: "execve covers effectively every real subprocess (fork+exec, os/exec, system). " +
				"execveat stays open by construction - the launcher needs it - so a program written to " +
				"spawn through execveat is not stopped.",
		})
	} else {
		out = append(out, enforce.LayerStatus{
			Layer: enforce.LayerExec, State: enforce.Unavailable,
			Reason: "this host cannot install the exec-block filter - either the kernel has no seccomp BPF support, or the filter is not implemented for this architecture - so subprocess-blocking cannot be enforced",
		})
	}
	switch {
	case !seccompOK:
		out = append(out, enforce.LayerStatus{
			Layer: enforce.LayerExecStrict, State: enforce.Unavailable,
			Reason: "this host cannot install the exec-block filter - either the kernel has no seccomp BPF support, or the filter is not implemented for this architecture",
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
// systemd scope (see wrapWithLimits), so each layer needs a creatable scope plus its
// own controllers delegated. The tier does not enter into it: a scope is a cgroup,
// applied by systemd before the command starts and independent of the user namespace
// the degraded tier lacks.
//
// Every layer is always emitted, including when no scope can be created at all. Each
// is required only by a policy that asks for the limit it covers, so a cpu-only
// manifest whose report omitted LayerLimitsCPU would reach admission with nothing
// limits-related to refuse and run unbounded on exactly the host that can enforce
// least.
//
// No creatable scope is one verdict about all of them - there is no cgroup to carry any
// property - so it overwrites the per-controller states rather than being folded into
// each.
func limitsLayers(scopeOK bool, scopeReason string, per []enforce.LayerStatus) []enforce.LayerStatus {
	if scopeOK {
		return per
	}
	out := make([]enforce.LayerStatus, 0, len(per))
	for _, l := range per {
		out = append(out, enforce.LayerStatus{Layer: l.Layer, State: enforce.Unavailable, Reason: scopeReason})
	}
	return out
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
//     than the full sandbox, not the same thing by another mechanism.
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
//
// The degraded tier is the one layer whose disclosure splits: what is broken on this
// host and how to fix it is the Reason, and the enumeration of what the fallback tier
// does not confine - the same paragraph on every degraded host - is Consequences. A
// refusal prints the first and sends the reader to a fuller report for the second;
// doctor prints both. Nothing is dropped, only moved out from on top of the remedy.
func filesystemLayer(ns namespaceProbe, nsReason string, landlockAvail, truncateRestricted, ioctlDevRestricted, resolveUnixRestricted, scopedIPCRestricted, netTCPRestricted, degradedFencesOK bool) enforce.LayerStatus {
	status := func(state enforce.State, reason string) enforce.LayerStatus {
		return enforce.LayerStatus{Layer: enforce.LayerFilesystem, State: state, Reason: reason}
	}
	switch {
	case ns == namespacesUsable && landlockAvail:
		return status(enforce.Enforced, "Landlock backstop active")
	case ns == namespacesUsable:
		return status(enforce.Enforced, "no Landlock backstop on this kernel; bwrap alone confines")
	case ns == namespacesUnknown:
		return status(enforce.Unavailable, nsReason)
	case landlockAvail && !degradedFencesOK:
		// Landlock confines the filesystem, but the reduced-confinement tier also
		// substitutes a seccomp egress block and cross-process block for the netns and
		// PID namespace it lacks - and those need an amd64 kernel with seccomp BPF.
		// Without them the tier cannot run at all, so report it unavailable rather than
		// offer a --allow-degraded that would only refuse at launch.
		return status(enforce.Unavailable, joinReason(nsReason,
			"and the reduced-confinement fallback needs a seccomp egress and cross-process "+
				"block (an amd64 kernel with seccomp BPF) to stand in for the missing namespaces, "+
				"unavailable here"))
	case landlockAvail:
		// Leads with nsReason rather than a hardcoded userns clause: this branch is
		// reached whenever bwrap cannot give a namespace, which includes bwrap simply
		// not being installed. Asserting "user namespaces are blocked" there sends a
		// reader to enable a namespace the host already permits.
		l := status(enforce.Degraded, joinReason(nsReason,
			"confinement falls back to restricting which paths the program can reach and blocking its "+
				"network access (Landlock path rules plus a seccomp egress block). This is materially "+
				"weaker than the full sandbox."))
		l.Consequences = "It confines filesystem read/write/exec, nothing more: no mount namespace (the deny-list " +
			"cannot carve a credential out of an allowed tree, and any granted /proc is the host's), no PID " +
			"namespace (the target shares the host process table, so it can " + signalClause(scopedIPCRestricted) +
			" - though seccomp blocks the cross-process memory read/write and ptrace injection " +
			"that would let it take one over - and a background process it leaves is swept only best-effort by " +
			"killing the run's process group, which a setsid() escapes and which also stops a target that reads " +
			"an interactive terminal), and no network namespace (" + netFenceClause(netTCPRestricted) +
			unixSocketClause(resolveUnixRestricted, scopedIPCRestricted) + ")" +
			truncateResidual(truncateRestricted) + ioctlDevResidual(ioctlDevRestricted) +
			resolveUnixResidual(resolveUnixRestricted)
		return l
	default:
		return status(enforce.Unavailable, joinReason(nsReason,
			"and this kernel has no Landlock, so no filesystem confinement is available at all"))
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
// ABI (< 5, i.e. before 6.10) cannot restrict ioctl on device files. From 6.10 the tier
// grants the right on its own grants, so a granted device node is ioctl-able either way
// and the disclosure is about the rest: Landlock leaves an unhandled right unrestricted,
// so below 5 an ioctl on any device node the target can open is available, and with no
// mount namespace that is the host's whole /dev. seccomp's terminal-injection block
// covers the tty ioctls that matter most but not the rest, so the gap is disclosed rather
// than treated as closed. Empty from 6.10 on.
func ioctlDevResidual(ioctlDevRestricted bool) string {
	if ioctlDevRestricted {
		return ""
	}
	return ". This kernel's Landlock ABI is also below 5, which cannot restrict ioctl on device files, so " +
		"any ioctl on any device node the target can open - the host's whole /dev, since this tier has no " +
		"mount namespace - is available beyond the terminal-injection set seccomp blocks"
}

// netFenceClause is the IP half of the degraded tier's "no network namespace"
// disclosure, up to the unix-socket clause that follows it. Landlock has no network
// access set before ABI 4, where BestEffort downgrades the tier's net domain to an empty
// config that restricts nothing - so on every Landlock kernel from 5.13 to 6.6 the
// seccomp egress filter is the whole fence, and the residual it structurally cannot
// close stays open. That residual is the reason the domain exists: the filter governs
// socket CREATION, so it cannot revoke an AF_INET descriptor the target is handed over
// SCM_RIGHTS, while Landlock's connect(2) hook evaluates the calling task's domain and
// denies it whatever its origin.
func netFenceClause(netTCPRestricted bool) string {
	if netTCPRestricted {
		return "seccomp blocks IP egress and Landlock denies TCP connect on a descriptor the filter " +
			"cannot revoke, but neither reaches netlink interface enumeration, nor "
	}
	return "seccomp blocks IP egress, but this kernel's Landlock ABI is below 4 and cannot restrict TCP " +
		"connect, so an already-created AF_INET descriptor passed to the target over SCM_RIGHTS stays " +
		"usable - the filter governs socket creation, not use, and has nothing behind it here. Nor does " +
		"it reach netlink interface enumeration, or "
}

// unixSocketClause is the unix-socket half of the degraded tier's "no network namespace"
// disclosure. What the target can reach over AF_UNIX depends on the Landlock ABI, so the
// sentence cannot be fixed text, and two independent facilities narrow it. From ABI 9 the
// degraded ruleset handles resolve_unix and grants it only on the write set, so a pathname
// socket outside the grants is denied; below it no pathname socket is governed at all.
// From ABI 6 the tier's IPC scoping denies an abstract-namespace socket, which nothing
// else covers - it lives in the network namespace this tier does not have, no file grant
// reaches it at any ABI, and the seccomp egress filter sees only AF_UNIX at socket(2).
//
// /dev/log is named because it is the one denial with no visible symptom: glibc's
// syslog(3) discards the message and reports nothing, so a target that logs through it
// goes quiet rather than failing, and an operator has no thread to pull. The other
// sockets this denies (nscd, systemd-resolved, dbus, X11) error visibly, and losing them
// is the trade the tier is for.
func unixSocketClause(resolveUnixRestricted, scopedIPCRestricted bool) string {
	// Below ABI 6 nothing scopes the abstract namespace, and resolve_unix (ABI 9) is out
	// of reach too, so this one sentence covers every unrestricted kernel.
	if !scopedIPCRestricted {
		return "a unix socket to a host daemon, including an abstract-namespace one no grant is needed to reach"
	}
	const pathnameDenied = "a pathname one outside the write grants is denied by Landlock's resolve_unix right - " +
		"including /dev/log, whose denial is silent, since glibc's syslog(3) drops the message without an error"
	if resolveUnixRestricted {
		return "a unix socket a write grant exposes, which is all that stays reachable (" + pathnameDenied +
			", and an abstract-namespace one by Landlock's IPC scoping)"
	}
	return "a pathname unix socket to a host daemon, which this kernel's Landlock (ABI < 9) does not govern " +
		"(an abstract-namespace one is denied by Landlock's IPC scoping)"
}

// signalClause is the degraded-tier disclosure for the signalling the missing PID
// namespace leaves open. Landlock's signal scope (ABI 6) closes it - the domain may
// still signal within itself, which is where the target's own children are - so above
// that ABI the shared process table is a visibility residual rather than a reach one.
func signalClause(scopedIPCRestricted bool) string {
	if scopedIPCRestricted {
		return "see same-user processes but not signal them, which Landlock's IPC scoping denies"
	}
	return "see and signal same-user processes"
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
	// allows, which for the CLI is forever. Layered UNDER the caller's context, as the
	// siblings are, so a caller that has already given up is not held for the bound of
	// each remaining probe. The deadline is a probe failure, not a host finding, and
	// classifyUnshare reports it as one.
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Exercise the same namespace and capability flags the real run uses (namespaceFlags),
	// not a hand-copied subset: a host that permits user+net namespaces but rejects one of
	// the others - most plausibly --unshare-cgroup on a pre-4.6 kernel, or --cap-drop on an
	// old bwrap - would otherwise pass this probe, report the filesystem layer Enforced, and
	// then fail at launch with a bwrap exit code indistinguishable from the target's. Probing
	// the shared set surfaces that at admission instead. --unshare-net is probed too (the run
	// adds it for the network layer); --bind / / makes the canary reachable for the check.
	// The canary is resolved on $PATH, not hardcoded to /bin/sh: bwrap sets the
	// namespaces up FIRST and only then execs, so on a host with no /bin/sh (NixOS,
	// a minimal image) the namespaces would succeed and only the exec fail - and this
	// probe cannot tell the two apart. It would report userns blocked, refuse every
	// network manifest, and downgrade the run to the Landlock-only tier while sending
	// the user off to flip AppArmor sysctls on a host where userns works. limits.go's
	// shBinary resolves it the same way for the same reason.
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
	args = append(args, shBinary(), "-c", namespaceCanary)
	cmd := exec.CommandContext(ctx, bwrap, args...)
	// Killing bwrap on the deadline is not enough on its own: CombinedOutput waits for
	// the output pipe to close, and any descendant still holding it keeps the probe
	// blocked for as long as it lives - which is the stall the deadline exists to stop.
	// See probeWaitDelay, which the limits probes share.
	cmd.WaitDelay = probeWaitDelay
	out, err := cmd.CombinedOutput()
	noteProbeDeadline(parent, ctx)
	if err != nil {
		return &usernsError{output: string(out), err: err, ctxErr: ctx.Err()}
	}
	if !strings.Contains(string(out), namespaceProof) {
		// Deliberately not a *usernsError, which is the type classifyUnshare reads a HOST
		// verdict out of: nothing here is a refusal, so the fall-through's unknown is the
		// right landing. Unknown refuses outright where blocked would offer the degraded
		// tier, and offering a tier on a bwrap that proved nothing is the fail-open half.
		return fmt.Errorf("bubblewrap exited successfully but the canary inside it did not report a user namespace, so nothing proves the namespaces were built (%q)", forReason(string(out)))
	}
	return nil
}

// namespaceProof is what the canary prints once it has confirmed, from inside, that it is
// in a user namespace of its own. namespaceCanary is the confirmation: /proc/self/uid_map
// maps exactly one uid in a namespace bwrap built, where the host's own init namespace maps
// the whole range (4294967295). It is read with shell builtins alone, so the check needs no
// binary the sandbox root might not carry.
//
// Exit status is no oracle on its own. It cannot tell "bwrap built the namespaces" from
// "something named bwrap exited 0", and the shapes that produce the second have no attacker
// in them: a Nix or distro wrapper, a container entrypoint, or a bwrap older than one of the
// flags in namespaceFlags, any of which can swallow an unrecognised flag and exit 0. Run
// then resolves the same name and execs it, so the target would run with no mount namespace
// and no netns while the report called the filesystem and network layers Enforced.
//
// What it does not catch: bento itself already running inside a namespace that maps one uid,
// under a bwrap that builds nothing. That needs the wrapper AND the nesting, and the
// deliberate version of it needs write access to a host $PATH directory, which is the same
// premise the threat model already excludes.
const namespaceProof = "bento-namespace-built"

// Every step is checked, and the range is checked for BEING something as well as for not
// being the host's: a read that fails leaves n empty, and "not the whole range" alone would
// take that for proof - which is the fail-open direction this exists to close.
const namespaceCanary = `read _ _ n < /proc/self/uid_map || exit 1; [ -n "$n" ] || exit 1; [ "$n" != 4294967295 ] || exit 1; echo ` + namespaceProof

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
// blocked" there costs the user the full sandbox on a host that supports it. What counts
// as naming a refusal is usernsRefused's business, and it needs both a namespace word and
// a refusal errno: bwrap words exhaustion with the same words it words a refusal, and it
// words a canary that would not exec with the same errno.
// containerUsernsRemedy is the container half of every userns-blocked diagnosis, and
// is carried by all of them rather than gated on detecting a container: podman, k8s and
// nerdctl all defeat a /.dockerenv-style probe, and the reader who most needs this
// clause is the one a detection miss would silently deny it. It names the first two flags
// because the refusal cannot tell them apart - docker's default seccomp profile blocks
// unshare(CLONE_NEWUSER) and its AppArmor profile restricts the namespace, and either
// alone produces the same bwrap message. The host remedies the diagnoses lead with are
// a sysctl a CI engineer usually cannot set; these are the ones they can.
//
// The third is named though it is blocking nothing yet, and says so: docker also masks
// paths under /proc, so a container that lifts the first two reaches the namespace and
// fails on the mount instead - the "Can't mount proc" branch below, one build-and-run
// cycle later. The reader here is fixing a container image and the image needs all
// three, which is what the README's container section already lists together.
// It closes the sentence with a period, like the sysctl diagnoses it extends, so
// joinReason's trailing-period trim still leaves a clean continuation.
const containerUsernsRemedy = " If bento is running inside a container, the host sysctl may be out of " +
	"reach and the container runtime's own policy is blocking the namespace too; with docker, " +
	"--security-opt seccomp=unconfined --security-opt apparmor=unconfined lift it. Lifting those " +
	"two exposes a third restriction rather than removing it, so grant --security-opt " +
	"systempaths=unconfined alongside them: docker masks paths under /proc that the sandbox's " +
	"root filesystem has to mount once the namespace is granted."

// usernsRefused reports whether bwrap's output is the host REFUSING the namespace, as
// opposed to any other way the probe can fail. It takes both halves of each of bwrap's
// three refusal shapes, because neither half alone is the answer.
//
// A namespace word alone is not: bwrap words exhaustion the same way it words a refusal
// ("Creating new namespace failed: nesting depth or /proc/sys/user/max_*_namespaces
// exceeded (ENOSPC)", or an EAGAIN under load), and that is transient rather than a fact
// about the host - unless the allowance is zero, which is a permanent refusal wearing the
// exhaustion wording, and is classified before this is consulted. An errno alone is not either: canUnshare execs a canary INSIDE the
// sandbox, so a noexec mount, mode 000 or an AppArmor exec denial yields "bwrap: execvp
// true: Permission denied", which says nothing about the namespace at all.
//
// Getting it wrong in this direction is expensive: blocked is the PERMISSIVE verdict -
// filesystemLayer offers the Landlock-only tier for it and refuses outright for
// unanswered - so every miss hands the user reduced confinement plus AppArmor remediation
// for a sysctl that was never the problem.
func usernsRefused(out string) bool {
	// bwrap's two unconditional refusals, both die() with no errno appended: the kernel
	// forbids unprivileged user namespaces, or it has none at all. Matched on their own
	// wording, since there is no errno to pair with.
	if strings.Contains(out, "No permissions") || strings.Contains(out, "likely because the kernel does not") {
		return true
	}
	// The errno-carrying shapes. "setting up uid map" is the second half of creating a
	// namespace: it exists, the host refused the map write, and the sandbox has no usable
	// identity in it either way.
	named := strings.Contains(out, "namespace") || strings.Contains(out, "setting up uid map")
	return named && (strings.Contains(out, "Permission denied") || strings.Contains(out, "Operation not permitted"))
}

// maxUserNamespaces is the per-user-namespace ucount limiting how many user namespaces
// a uid may create. A hardened CI runner sets it to zero, and it can also be written
// inside a nested user namespace, which scopes the zero to that namespace alone.
const maxUserNamespaces = "/proc/sys/user/max_user_namespaces"

// exhaustedAllowanceReason returns the diagnosis for a probe bwrap failed with ENOSPC on
// a host whose namespace allowance is zero, or "" when this is not that. The allowance is
// what separates the two things bwrap words identically: at zero the kernel refuses every
// user namespace this uid asks for and there is a sysctl to name, while a nonzero
// allowance exhausted by nesting depth or by load is transient and measures nothing about
// the host - which is why that case falls through to the unknown verdict rather than
// costing a user the full sandbox on a machine that supports it.
func exhaustedAllowanceReason(out string, allowanceZero bool) string {
	if !allowanceZero || !strings.Contains(out, "ENOSPC") || !strings.Contains(out, "namespace") {
		return ""
	}
	return ": this user's namespace allowance is zero (user.max_user_namespaces=0), so the kernel " +
		"refuses every one it is asked for. Raise it - sysctl -w user.max_user_namespaces=15000, or " +
		"user.max_user_namespaces=15000 in /etc/sysctl.d to persist it."
}

// probeOutputCap bounds how much of bwrap's own words reach a reason. Its refusals are one
// short line; anything past this is not the diagnosis, and the reason travels into the
// doctor report, a run's refusal message, and whatever collects those.
const probeOutputCap = 400

// envAssignment matches the shape a leaked environment entry has in a tool's output. Case
// is not part of the shape: the proxy pair (http_proxy, no_proxy) is conventionally
// lowercase and carries a URL with credentials in it, which is the most realistic leak of
// the class. It still requires a name-shaped word with a value attached, because bwrap's and
// systemd-run's own messages carry paths and errnos and a wider scrub would take the
// diagnosis with it.
//
// The value is taken to the next whitespace, so a value that contains a space keeps its
// tail. The cap below is what bounds that residue.
var envAssignment = regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9_]{2,}=\S+`)

// forReason is bwrap's output made safe to put in a user-facing reason: capped, and with
// environment-shaped assignments stripped of their values. A misconfigured host can have
// bwrap echo environment content, and the reason it lands in is unbounded in both length
// and content.
//
// It is applied ONLY to what is shown. Every classification below matches on the raw
// output, and must keep doing so: a cap applied before the match can truncate past
// "No permissions" or "ENOSPC" and turn a host that answered into an unknown verdict,
// which refuses outright where blocked would have offered the degraded tier.
func forReason(out string) string {
	return capOutput(envAssignment.ReplaceAllStringFunc(out, func(kv string) string {
		name, _, _ := strings.Cut(kv, "=")
		return name + "=[redacted]"
	}))
}

// capOutput is the length half alone, for a tool whose output is bounded by nothing but
// whose assignments are the diagnosis rather than a leak: systemd-run answers a refused
// property by echoing it ("Unknown assignment: NoSuchProperty=1"), and redacting the value
// there would take the clue with it.
func capOutput(out string) string {
	s := strings.TrimSpace(out)
	if len(s) > probeOutputCap {
		s = strings.ToValidUTF8(s[:probeOutputCap], "") + "... (truncated)"
	}
	return s
}

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
	if strings.Contains(out, "Can't mount ") || strings.Contains(out, "Can't bind mount ") {
		// Worded for mounts in general rather than for the pseudo-filesystems: the probe
		// binds the host root as well, and a refused --bind is not a procfs problem.
		diagnosis := "bubblewrap can create a user namespace here but cannot set up the mounts " +
			"the sandbox's root filesystem needs, so it cannot isolate anything: " + forReason(out)
		if strings.Contains(out, "Can't mount proc") {
			// This reason is the head of a block that runs past twenty lines once the
			// degraded tier's consequences follow it, and a flag held to its fifth sentence
			// is one a CI engineer scanning that block does not reach at all, so the remedy
			// goes ahead of the diagnosis it remedies. The bwrap line is parenthesised and
			// the sentence closed with a period, like the diagnoses above, so joinReason's
			// trim still leaves a clean continuation rather than running raw tool output
			// into the tier's clause.
			return namespacesBlocked, "bubblewrap cannot mount /proc here, and the usual cause is a " +
				"container runtime masking paths under it, which docker does by default; there " +
				"--security-opt systempaths=unconfined lifts it. The namespace itself was granted - " +
				"only the mount the sandbox's root filesystem needs was refused (" + forReason(out) + ")."
		}
		return namespacesBlocked, diagnosis
	}
	const base = "cannot create an unprivileged user namespace, so bubblewrap cannot isolate anything"
	const unknownBase = "the user-namespace probe failed for a reason that is not a namespace refusal, so whether " +
		"bubblewrap can isolate anything on this host is unknown; it is reported unavailable rather than guessed"

	// Checked before usernsRefused, which deliberately reads bwrap's ENOSPC wording as
	// transient exhaustion rather than as a fact about the host. With the allowance at
	// zero it is neither transient nor unknown: the kernel is declining, permanently and
	// for this user, the same way the AppArmor branch's sysctl declines.
	if reason := exhaustedAllowanceReason(out, restricted(maxUserNamespaces, "0")); reason != "" {
		return namespacesBlocked, base + reason + containerUsernsRemedy
	}
	if !usernsRefused(out) {
		if out != "" {
			return namespacesUnknown, unknownBase + ": " + forReason(out)
		}
		return namespacesUnknown, unknownBase + ": " + err.Error()
	}
	if restricted("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "1") {
		return namespacesBlocked, base + ": AppArmor restricts unprivileged user namespaces on this host " +
			"(kernel.apparmor_restrict_unprivileged_userns=1). Install an AppArmor profile permitting bwrap, " +
			"or set it to 0 to allow them system-wide." + containerUsernsRemedy
	}
	if restricted("/proc/sys/kernel/unprivileged_userns_clone", "0") {
		return namespacesBlocked, base + ": unprivileged user namespaces are disabled " +
			"(kernel.unprivileged_userns_clone=0). Set it to 1 to allow them." + containerUsernsRemedy
	}
	return namespacesBlocked, base + ": " + strings.TrimRight(forReason(out), ".") + "." + containerUsernsRemedy
}

// restricted reports whether a sysctl file holds the given value.
func restricted(path, value string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == value
}
