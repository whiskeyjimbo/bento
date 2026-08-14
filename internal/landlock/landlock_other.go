//go:build !linux

package landlock

import "errors"

// Restrict is a no-op off Linux; there is no Landlock backstop to apply.
func Restrict(writable []string) error { return nil }

// RestrictTo is a no-op off Linux.
func RestrictTo(read, write []string) error { return nil }

// RestrictDegraded refuses off Linux rather than returning a nil no-op like the two
// above. Landlock is the degraded tier's ONLY filesystem confinement, so a nil here
// would report the primary fence applied while restricting nothing. The tier is
// Linux-only and its launcher is linux-tagged, so nothing reaches this - but a
// fail-open stub is the wrong thing to leave for whoever does.
func RestrictDegraded(read, write, exec []string) error {
	return errors.New("landlock: the degraded tier has no filesystem confinement off Linux")
}

// RestrictExecAllowlist refuses off Linux, on RestrictDegraded's reasoning rather than
// Restrict's: the allowlist ruleset is the whole mechanism, so a nil no-op would report
// execute withheld while withholding nothing. Its only caller is linux-tagged, so nothing
// reaches this today; it exists so a darwin caller fails to run rather than fails to
// compile.
func RestrictExecAllowlist(writable, execAllow []string) error {
	return errors.New("landlock: no exec allowlist off Linux")
}

// Available reports false: Landlock is Linux-only.
func Available() bool { return false }

// TruncateRestricted reports false: Landlock is Linux-only.
func TruncateRestricted() bool { return false }

// IoctlDevRestricted reports false: Landlock is Linux-only.
func IoctlDevRestricted() bool { return false }

// ResolveUnixRestricted reports false: Landlock is Linux-only.
func ResolveUnixRestricted() bool { return false }

// NetTCPRestricted reports false: Landlock is Linux-only.
func NetTCPRestricted() bool { return false }

// ScopedIPCRestricted reports false: Landlock is Linux-only.
func ScopedIPCRestricted() bool { return false }
