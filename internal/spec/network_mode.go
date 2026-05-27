package spec

// NetworkMode selects how the Linux runner enforces network rules. Ignored on macOS.
type NetworkMode int

const (
	// NetworkModeAuto picks Landlock on kernel ≥6.7 (ABI ≥4), Bridge otherwise.
	NetworkModeAuto NetworkMode = iota

	// NetworkModeLandlock uses Landlock TCP rules on a shared netns. Requires kernel ≥6.7.
	NetworkModeLandlock

	// NetworkModeBridge --unshare-net + socat unix-socket bridge. Works on any kernel.
	NetworkModeBridge
)

func (m NetworkMode) String() string {
	switch m {
	case NetworkModeAuto:
		return "auto"
	case NetworkModeLandlock:
		return "landlock"
	case NetworkModeBridge:
		return "bridge"
	default:
		return "unknown"
	}
}

// ParseNetworkMode resolves a CLI-style string to a NetworkMode.
func ParseNetworkMode(s string) (NetworkMode, bool) {
	switch s {
	case "auto", "":
		return NetworkModeAuto, true
	case "landlock":
		return NetworkModeLandlock, true
	case "bridge":
		return NetworkModeBridge, true
	}
	return NetworkModeAuto, false
}
