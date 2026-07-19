//go:build !linux

package landlock

// Restrict is a no-op off Linux; there is no Landlock backstop to apply.
func Restrict(writable []string) error { return nil }

// RestrictTo is a no-op off Linux.
func RestrictTo(read, write []string) error { return nil }

// RestrictDegraded is a no-op off Linux; the degraded tier is Linux-only and the
// caller gates on Available before relying on it.
func RestrictDegraded(read, write, exec []string) error { return nil }

// Available reports false: Landlock is Linux-only.
func Available() bool { return false }

// TruncateRestricted reports false: Landlock is Linux-only.
func TruncateRestricted() bool { return false }
