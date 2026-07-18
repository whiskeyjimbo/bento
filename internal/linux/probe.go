package linux

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/internal/landlock"
	"github.com/whiskeyjimbo/bento-v2/internal/seccomp"
)

// Probe reports what this host can actually enforce.
//
// It reports what it can prove, not what it hopes: the filesystem layer is only
// Enforced if bwrap is present and a user namespace can really be created here,
// which is checked by creating one rather than by inspecting sysctls. Ubuntu's
// AppArmor restriction, container policies, and kernel builds all interact, and
// the only trustworthy answer is an empirical one.
func (e *Enforcer) Probe(ctx context.Context) enforce.Report {
	var r enforce.Report

	// bwrap's filesystem and network confinement both depend on creating an
	// unprivileged user namespace here; probe that once and report both layers
	// against it, so neither claims a guarantee bwrap cannot deliver on this host.
	nsOK, nsReason := usableNamespaces(ctx)
	fsState, fsDetail := filesystemLayer(nsOK, nsReason, landlock.Available())
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
	if nsOK {
		r.Add(enforce.LayerNetwork, enforce.Enforced, "")
	} else {
		r.Add(enforce.LayerNetwork, enforce.Unavailable, nsReason)
	}

	if seccomp.Supported() {
		r.Add(enforce.LayerExec, enforce.Enforced, "")
	} else {
		r.Add(enforce.LayerExec, enforce.Unavailable,
			"this kernel does not support seccomp BPF, so subprocess-blocking cannot be enforced")
	}

	// exec-strict (none-strict's fork/vfork/clone blocking) needs both seccomp and
	// the architecture-specific filter; off amd64 it degrades to the execve-only
	// block rather than silently claiming the stricter guarantee.
	switch {
	case !seccomp.Supported():
		r.Add(enforce.LayerExecStrict, enforce.Unavailable,
			"this kernel does not support seccomp BPF")
	case !seccomp.StrictExecSupported():
		r.Add(enforce.LayerExecStrict, enforce.Unavailable,
			"fork/vfork/process-clone blocking is not implemented for this architecture; none-strict blocks only execve here")
	default:
		r.Add(enforce.LayerExecStrict, enforce.Enforced, "")
	}

	if ok, reason := canCreateScope(); ok {
		r.Add(enforce.LayerLimits, enforce.Enforced, "")
		// cpu delegation is separate from scope creation: a scope can be created
		// (memory/pids delegated) while systemd-run silently ignores a CPUQuota
		// because the cpu controller is not delegated. Report it so admission can
		// refuse a requested cpu limit this host cannot actually enforce.
		state, reason := cpuDelegationState(delegatedControllers())
		r.Add(enforce.LayerLimitsCPU, state, reason)
	} else {
		// No scope at all: the cpu gap is subsumed by the whole limits layer being
		// unavailable, which already refuses a cpu-limit policy. Emitting a separate
		// LayerLimitsCPU here would only duplicate the refusal with the same reason.
		r.Add(enforce.LayerLimits, enforce.Unavailable, reason)
	}

	return r
}

// filesystemLayer decides the filesystem-confinement state from namespace and
// Landlock availability, the two independent capabilities it rests on:
//
//   - userns OK: bwrap gives full confinement (fresh rootfs, mount namespace, the
//     deny-list binds); Landlock, when present, is a second kernel backstop behind it.
//   - userns blocked but Landlock present: the Landlock-only degraded tier - path
//     read/write/exec rules and nothing else. No mount namespace means no rootfs, no
//     hidden /proc, and critically no deny-list binds, so it is materially weaker
//     than the full sandbox, not the same thing by another mechanism (design 6.2).
//   - neither: nothing confines the filesystem, so the layer is unavailable and a
//     run refuses outright rather than offering a degraded mode that enforces nothing.
//
// The network layer is deliberately NOT three-stated the same way: without a user
// namespace there is no netns to fence egress, so it stays Unavailable, which is
// what makes a network manifest refuse even under --allow-degraded.
func filesystemLayer(nsOK bool, nsReason string, landlockAvail bool) (enforce.State, string) {
	switch {
	case nsOK && landlockAvail:
		return enforce.Enforced, "Landlock backstop active"
	case nsOK:
		return enforce.Enforced, "no Landlock backstop on this kernel; bwrap alone confines"
	case landlockAvail:
		return enforce.Degraded, "unprivileged user namespaces are blocked, so bubblewrap cannot run; " +
			"confinement falls back to Landlock path rules plus a seccomp egress block. This is materially " +
			"weaker than the full sandbox: no mount namespace (the deny-list cannot carve a credential out of " +
			"an allowed tree, and any granted /proc is the host's), no PID namespace (the target can see and " +
			"signal same-user processes, inject into them where ptrace is unrestricted, and leave a background " +
			"process running after the run - there is no namespace to tear one down), and no network namespace " +
			"(seccomp blocks IP egress but not netlink interface enumeration, nor a unix socket to a host " +
			"daemon, including an abstract-namespace one no grant is needed to reach). It confines filesystem " +
			"read/write/exec, nothing more (" + nsReason + ")"
	default:
		return enforce.Unavailable, nsReason +
			"; and this kernel has no Landlock, so no filesystem confinement is available at all"
	}
}

// usableNamespaces reports whether bwrap is installed and can create here the
// unprivileged user namespace its filesystem and network confinement depend on,
// with a reason a user can act on when it cannot.
func usableNamespaces(ctx context.Context) (bool, string) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return false, "bubblewrap (bwrap) is not installed; no filesystem or network confinement is possible"
	}
	if err := canUnshare(ctx, bwrap); err != nil {
		return false, usernsReason(err)
	}
	return true, ""
}

// canUnshare reports whether an unprivileged user namespace can be created here,
// by asking bwrap to create one.
func canUnshare(ctx context.Context, bwrap string) error {
	cmd := exec.CommandContext(ctx, bwrap, "--unshare-user", "--unshare-net", "--bind", "/", "/", "/bin/true")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &usernsError{output: string(out), err: err}
	}
	return nil
}

type usernsError struct {
	output string
	err    error
}

func (e *usernsError) Error() string { return e.err.Error() }

// usernsReason turns a failed namespace creation into something a user can act
// on. The bare bwrap message ("No permissions to create a new user namespace")
// tells a user nothing about why or what to do, and on current Ubuntu the cause
// is a specific, fixable AppArmor policy.
func usernsReason(err error) string {
	var out string
	if ue, ok := err.(*usernsError); ok {
		out = ue.output
	}
	const base = "cannot create an unprivileged user namespace, so bubblewrap cannot isolate anything"

	if !strings.Contains(out, "user namespace") && !strings.Contains(out, "Permission denied") {
		if out != "" {
			return base + ": " + strings.TrimSpace(out)
		}
		return base
	}
	if restricted("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "1") {
		return base + ": AppArmor restricts unprivileged user namespaces on this host " +
			"(kernel.apparmor_restrict_unprivileged_userns=1). Install an AppArmor profile permitting bwrap, " +
			"or set it to 0 to allow them system-wide."
	}
	if restricted("/proc/sys/kernel/unprivileged_userns_clone", "0") {
		return base + ": unprivileged user namespaces are disabled " +
			"(kernel.unprivileged_userns_clone=0). Set it to 1 to allow them."
	}
	return base + ": " + strings.TrimSpace(out)
}

// restricted reports whether a sysctl file holds the given value.
func restricted(path, value string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == value
}
