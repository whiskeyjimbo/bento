package spec

// Paths and env vars shared between the runner (host) and launcher (sandbox).
// Drift between the two silently breaks isolation.
const (
	SandboxRoot                = "/sandbox"
	SandboxScriptPath          = "/sandbox/script"
	SandboxLauncherPath        = "/sandbox/launcher"
	SandboxProxychainsConfPath = "/sandbox/proxychains.conf"

	// EnvAllowedPorts: comma-separated TCP ports for Landlock; empty → all TCP blocked.
	EnvAllowedPorts = "BENTO_ALLOW_PORTS"

	// EnvFDLimit: RLIMIT_NOFILE; needed because systemd-run --scope doesn't honor LimitNOFILE=.
	EnvFDLimit = "BENTO_FD_LIMIT"
)
