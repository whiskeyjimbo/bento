// Package spec defines the manifest types shared across bento's
// internal packages. Lives in internal/ so that both the runner and
// the proxies can depend on the types without creating an import
// cycle with the root bento package (which re-exports them as aliases).
package spec

// Manifest is the per-script permission declaration. Empty / nil fields
// mean "deny." A nil Network means no network access at all; a non-nil
// Network with no Rules means the same (but explicit).
type Manifest struct {
	Interpreter string       `yaml:"interpreter" json:"interpreter"`
	Script      string       `yaml:"script" json:"script"`
	Args        []string     `yaml:"args,omitempty" json:"args,omitempty"`
	Env         []string     `yaml:"env,omitempty" json:"env,omitempty"`
	Read        []string     `yaml:"read,omitempty" json:"read,omitempty"`
	Write       []string     `yaml:"write,omitempty" json:"write,omitempty"`
	Network     *NetworkPerm `yaml:"network,omitempty" json:"network,omitempty"`
	Exec        []string     `yaml:"exec,omitempty" json:"exec,omitempty"`
	Limits      *Limits      `yaml:"limits,omitempty" json:"limits,omitempty"`
}

// NetworkPerm describes allowed outbound traffic as a list of rules.
type NetworkPerm struct {
	Rules []NetworkRule `yaml:"rules" json:"rules"`
}

// NetworkRule is one host:port allowance. Host may be a literal hostname,
// ".suffix" (matches any subdomain), or "*". Port may be a literal,
// "lo-hi" range, or "*".
type NetworkRule struct {
	Host string `yaml:"host" json:"host"`
	Port string `yaml:"port" json:"port"`
}

// Limits is the per-script resource ceiling. Enforced via systemd-run
// when available.
type Limits struct {
	Memory string `yaml:"memory,omitempty" json:"memory,omitempty"`
	CPU    string `yaml:"cpu,omitempty" json:"cpu,omitempty"`
	Tasks  int    `yaml:"tasks,omitempty" json:"tasks,omitempty"`
	FDs    int    `yaml:"fds,omitempty" json:"fds,omitempty"`     // RLIMIT_NOFILE
	Tmpfs  string `yaml:"tmpfs,omitempty" json:"tmpfs,omitempty"` // size cap on /tmp and /sandbox tmpfs (e.g. "64M")
}
