// Package policy defines the validated permission model at the core of Bento.
//
// A Policy is the in-memory, already-validated permission declaration a script
// runs under. It is pure domain data: no I/O, no platform knowledge, no
// dependency on any enforcement backend. Backends (Linux, macOS) and frontends
// (CLI, JSON, library) all depend on this package; it depends on nothing of
// theirs. Empty/nil fields mean "deny".
package policy

// Policy is the validated permission declaration for a single script or binary.
type Policy struct {
	// Entrypoint is the script or compiled binary to run.
	Entrypoint string
	// Interpreter runs the entrypoint (e.g. "python3"). Empty means the
	// entrypoint is its own interpreter: a compiled ELF/Mach-O binary.
	Interpreter string
	// Args are fixed arguments passed to the entrypoint.
	Args []string
	// Env is an allowlist of host environment-variable NAMES passed through to
	// the sandbox when set. Values are never written in the manifest.
	Env []string
	// Read and Write are host paths granted read-only and read-write access.
	Read  []string
	Write []string
	// Network is the outbound egress allowlist. Nil or empty denies all egress.
	Network []NetworkRule
	// Exec is the subprocess-spawning policy. The zero value is ExecNone.
	Exec ExecMode
	// Limits are resource ceilings; the zero value imposes none.
	Limits Limits
}

// ExecMode is the subprocess-spawning policy.
type ExecMode string

const (
	// ExecNone (default) soft-blocks execve: it stops the exec paths glibc/musl
	// use (subprocess/fork+exec/os.system) but a raw execveat can still spawn.
	ExecNone ExecMode = "none"
	// ExecNoneStrict additionally blocks fork/vfork and process-creating clone
	// while permitting thread-creating clone. Not a total no-child guarantee:
	// execveat and io_uring remain reachable.
	ExecNoneStrict ExecMode = "none-strict"
	// ExecAll permits arbitrary subprocesses. It never relaxes filesystem or
	// network confinement.
	ExecAll ExecMode = "all"
)

// NetworkRule is one outbound allowance. There is exactly one rule form: a host
// and a port, both strings. A bare "host:port" string is deliberately not
// accepted (a heterogeneous scalar-or-mapping list reintroduces the v1 YAML
// shape trap), and Port is always a string so a single port and a range never
// differ in YAML type.
type NetworkRule struct {
	// Host is a literal hostname, a ".suffix" wildcard (matches subdomains, not
	// the bare domain), a canonical IP literal, or "*" (any host).
	Host string
	// Port is a literal port ("443"), an inclusive range ("8000-9000"), or "*".
	Port string
}

// Limits are per-run resource ceilings. Empty string / zero means unset.
type Limits struct {
	// Memory is a byte quantity (e.g. "128M", "1G").
	Memory string
	// CPU is a percentage quota (e.g. "100%", "50%").
	CPU string
	// PIDs caps the number of tasks (processes + threads).
	PIDs int
}
