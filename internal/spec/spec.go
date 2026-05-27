// Package spec defines the manifest types shared across internal packages.
package spec

// Manifest is the per-script permission declaration. Empty/nil fields mean "deny".
type Manifest struct {
	// Interpreter names the program used to execute the script (e.g. "python3",
	// "bash"). Omit for ELF binaries: when empty, LoadManifest sets it to
	// Script (the binary is its own interpreter).
	Interpreter string       `yaml:"interpreter,omitempty" json:"interpreter,omitempty"`
	Script      string       `yaml:"script,omitempty" json:"script,omitempty"`
	// Binary is an alias for Script intended for ELF binaries with no
	// interpreter: `binary: ./mytool` reads more naturally than
	// `script: ./mytool` for compiled programs. LoadManifest copies a
	// non-empty Binary into Script when Script is empty.
	Binary string `yaml:"binary,omitempty" json:"binary,omitempty"`
	Args        []string     `yaml:"args,omitempty" json:"args,omitempty"`
	Env         []string     `yaml:"env,omitempty" json:"env,omitempty"`
	Read        []string     `yaml:"read,omitempty" json:"read,omitempty"`
	Write       []string     `yaml:"write,omitempty" json:"write,omitempty"`
	Network     *NetworkPerm `yaml:"network,omitempty" json:"network,omitempty"`
	// AllowExec, when true, permits the script to spawn arbitrary subprocesses
	// (the seccomp+Landlock launcher is not installed). When false (default),
	// every execve attempt fails with EPERM.
	AllowExec bool `yaml:"allow_exec,omitempty" json:"allow_exec,omitempty"`
	// Exec is the deprecated legacy field. Any non-empty value is treated as
	// AllowExec=true at load time (the individual entries are not enforced;
	// per-binary allowlisting is not implemented). New manifests should use
	// allow_exec instead.
	Exec   []string `yaml:"exec,omitempty" json:"exec,omitempty"`
	Limits *Limits  `yaml:"limits,omitempty" json:"limits,omitempty"`

	// LegacyExecField is set by LoadManifest when the deprecated `exec:` key
	// was present in the source YAML. Callers (CLI) use it to emit a one-time
	// deprecation warning. Not serialized.
	LegacyExecField bool `yaml:"-" json:"-"`
}

// NetworkPerm describes allowed outbound traffic as a list of rules.
type NetworkPerm struct {
	Rules []NetworkRule `yaml:"rules" json:"rules"`
}

// NetworkRule is one host:port allowance. Host: literal, ".suffix", or "*".
// Port: literal, "lo-hi" range, or "*".
type NetworkRule struct {
	Host string `yaml:"host" json:"host"`
	Port string `yaml:"port" json:"port"`
}

// Limits is the per-script resource ceiling, enforced via systemd-run when available.
type Limits struct {
	Memory string `yaml:"memory,omitempty" json:"memory,omitempty"`
	CPU    string `yaml:"cpu,omitempty" json:"cpu,omitempty"`
	Tasks  int    `yaml:"tasks,omitempty" json:"tasks,omitempty"`
	FDs    int    `yaml:"fds,omitempty" json:"fds,omitempty"`     // RLIMIT_NOFILE
	Tmpfs  string `yaml:"tmpfs,omitempty" json:"tmpfs,omitempty"` // size cap on tmpfs mounts
}
