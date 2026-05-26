package spec

// NetworkMode selects how the Linux runner enforces network rules.
//
// On macOS this is ignored — Seatbelt's network-outbound rules give
// per-host enforcement natively.
type NetworkMode int

const (
	// NetworkModeAuto picks Landlock when the kernel supports it
	// (ABI ≥ 4, kernel ≥ 6.7), otherwise Bridge. The default.
	NetworkModeAuto NetworkMode = iota

	// NetworkModeLandlock keeps the network namespace shared with the
	// host and uses Landlock TCP rules to restrict outbound connect()
	// to the proxy ports. Simpler at runtime; requires kernel ≥ 6.7.
	NetworkModeLandlock

	// NetworkModeBridge isolates the network namespace completely
	// (--unshare-net) and bridges to the host proxies via unix sockets
	// + socat. Works on any kernel but requires socat installed and
	// runs an extra process pair per sandbox.
	NetworkModeBridge
)

// String returns a human-readable name for logs and CLI output.
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

// ParseNetworkMode returns the mode for a CLI-style string.
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
