// Package installer implements bento's system initialization and package
// auto-installation setup flow.
package installer

// InitOption configures the package installer loop.
type InitOption func(*initOpts)

type initOpts struct {
	dryRun         bool
	distroOverride string // useful for testing
	skipAppArmor   bool
}

// WithDryRun specifies that bento init should only plan and print
// commands without modifying the system.
func WithDryRun() InitOption {
	return func(o *initOpts) { o.dryRun = true }
}

// WithDistroOverride overrides the auto-detected Linux distribution.
func WithDistroOverride(distro string) InitOption {
	return func(o *initOpts) { o.distroOverride = distro }
}

// WithSkipAppArmor skips generating and loading the AppArmor profile.
func WithSkipAppArmor() InitOption {
	return func(o *initOpts) { o.skipAppArmor = true }
}
