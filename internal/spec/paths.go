package spec

// Paths and env vars shared between the bento runner (which sets up the
// sandbox) and the bento-launcher (which runs inside it). Keep these in
// one place — drift between the two sides silently breaks isolation.
const (
	// SandboxRoot is the tmpfs root inside the sandbox; the script's
	// working directory.
	SandboxRoot = "/sandbox"

	// SandboxScriptPath is where the user's script appears inside the
	// sandbox (bind-mounted read-only).
	SandboxScriptPath = "/sandbox/script"

	// SandboxLauncherPath is where the bento-launcher binary appears
	// inside the sandbox when seccomp+Landlock enforcement is active.
	SandboxLauncherPath = "/sandbox/launcher"

	// SandboxProxychainsConfPath is where the proxychains config is
	// bind-mounted inside the sandbox.
	SandboxProxychainsConfPath = "/sandbox/proxychains.conf"

	// EnvAllowedPorts is the env var the launcher reads to learn which
	// TCP ports it should allow via Landlock. Comma-separated list.
	// Empty/unset → all TCP blocked.
	EnvAllowedPorts = "BENTO_ALLOW_PORTS"

	// EnvFDLimit is the env var the launcher reads to apply RLIMIT_NOFILE
	// via setrlimit(2) before exec'ing the interpreter. systemd-run
	// LimitNOFILE= isn't honored for --scope units; setrlimit is.
	EnvFDLimit = "BENTO_FD_LIMIT"
)
