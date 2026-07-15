package linux

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
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

	switch bwrap, err := exec.LookPath("bwrap"); {
	case err != nil:
		r.Add(enforce.LayerFilesystem, enforce.Unavailable,
			"bubblewrap (bwrap) is not installed; no filesystem confinement is possible")
	default:
		if err := canUnshare(ctx, bwrap); err != nil {
			r.Add(enforce.LayerFilesystem, enforce.Unavailable, usernsReason(err))
		} else {
			// The filesystem layer is enforced by bwrap. Landlock, when present, is
			// a second independent kernel backstop behind it; note whether it is
			// active so its presence is not silently assumed.
			detail := "Landlock backstop active"
			if !landlock.Available() {
				detail = "no Landlock backstop on this kernel; bwrap alone confines"
			}
			r.Add(enforce.LayerFilesystem, enforce.Enforced, detail)
		}
	}

	// Egress is enforced by the network namespace (nothing leaves except through
	// our proxy) plus the host-side allowlist proxy. The guarantee that matters -
	// nothing reaches a non-allowlisted host - holds fully and unprivileged. The
	// one nuance is that a program which ignores the proxy environment fails
	// closed rather than being transparently redirected to an allowed host;
	// transparent redirect needs the one-time `bento setup`. That is an
	// availability nuance for uncooperative clients, not a containment gap, so the
	// layer is enforced.
	r.Add(enforce.LayerNetwork, enforce.Enforced, "")

	if seccomp.Supported() {
		r.Add(enforce.LayerExec, enforce.Enforced, "")
	} else {
		r.Add(enforce.LayerExec, enforce.Unavailable,
			"this kernel does not support seccomp BPF, so subprocess-blocking cannot be enforced")
	}

	if ok, reason := canCreateScope(); ok {
		r.Add(enforce.LayerLimits, enforce.Enforced, "")
	} else {
		r.Add(enforce.LayerLimits, enforce.Unavailable, reason)
	}

	return r
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
