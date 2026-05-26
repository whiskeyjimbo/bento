// Package installer implements bento's system initialization and package
// auto-installation setup flow.
package installer

// InitOption configures the package installer loop.
type InitOption func(*initOpts)

type customPM struct {
	cmd            []string
	proxychainsPkg string
}

type initOpts struct {
	dryRun         bool
	distroOverride string // useful for testing
	skipAppArmor   bool
	customManagers map[string]customPM
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

// WithCustomPackageManager registers or overrides a package manager configuration
// for a given Linux distribution (distro name).
func WithCustomPackageManager(distro string, cmd []string, proxychainsPkg string) InitOption {
	return func(o *initOpts) {
		if o.customManagers == nil {
			o.customManagers = make(map[string]customPM)
		}
		o.customManagers[distro] = customPM{
			cmd:            cmd,
			proxychainsPkg: proxychainsPkg,
		}
	}
}
