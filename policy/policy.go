// Package policy defines the validated permission model at the core of Bento.
//
// A Policy is the permission declaration a script runs under. It is pure domain
// data and behavior: no I/O, no serialization format, no platform knowledge, and
// no dependency on any enforcement backend. Backends (Linux, macOS) and
// frontends (CLI, JSON, library) all depend on this package; it depends on
// nothing of theirs. Empty/nil fields mean "deny".
//
// Validate is the single gate on a well-formed Policy. Every construction path
// must pass through it - the YAML loader and Go library embedders alike - so an
// invalid Policy can never reach a backend.
package policy

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Policy is the permission declaration for a single script or binary.
type Policy struct {
	// Entrypoint is the script or compiled binary to run.
	Entrypoint string
	// Interpreter runs the entrypoint (e.g. "python3"). Empty means the
	// entrypoint is its own interpreter: a compiled ELF/Mach-O binary.
	Interpreter string
	// Args are fixed arguments passed to the entrypoint.
	Args []string
	// Env is an allowlist of host environment-variable NAMES passed through to
	// the sandbox when set. Values are never declared here.
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
// and a port, both strings. Port is a string so a single port and a range never
// differ in type.
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

// IsZero reports whether no limit is set.
func (l Limits) IsZero() bool { return l == Limits{} }

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Validate reports whether the policy is well-formed. It is the one gate every
// construction path passes through, so a Go embedder building a Policy directly
// gets the same guarantees as a manifest parsed from YAML.
func (p *Policy) Validate() error {
	if p == nil {
		return fmt.Errorf("policy: nil policy")
	}
	if p.Entrypoint == "" {
		return fmt.Errorf("policy: entrypoint is required")
	}
	// The path and argument fields are echoed verbatim by the frontends - the
	// validate summary, error messages naming a bad path - so a deceiving character in
	// one lets an untrusted manifest mislead the operator reading it: a control
	// character reprograms the terminal (ESC/OSC window spoofing, hidden text), a bidi
	// override reorders the display so a value reads as something other than what it
	// grants. No legitimate path or argument carries either. Rejecting here, at the
	// single gate every construction path passes through, closes it for the CLI and Go
	// embedders alike; the host field is already guarded separately.
	fields := append([]string{p.Entrypoint, p.Interpreter}, p.Args...)
	fields = append(append(fields, p.Read...), p.Write...)
	for _, f := range fields {
		if i := strings.IndexFunc(f, unsafeInField); i >= 0 {
			r, _ := utf8.DecodeRuneInString(f[i:])
			return fmt.Errorf("policy: value %q contains %s (U+%04X), which is not allowed in a path or argument", f, unsafeKind(r), r)
		}
	}
	for _, name := range p.Env {
		if !envNameRe.MatchString(name) {
			return fmt.Errorf("policy: invalid env name %q: must match [A-Za-z_][A-Za-z0-9_]* (env is an allowlist of variable names, not values)", name)
		}
	}
	if err := p.Exec.validate(); err != nil {
		return err
	}
	for i, r := range p.Network {
		if err := validateHostPattern(r.Host); err != nil {
			return fmt.Errorf("policy: network rule %d: %w", i, err)
		}
		if err := validatePort(r.Port); err != nil {
			return fmt.Errorf("policy: network rule %d: %w", i, err)
		}
	}
	return p.Limits.validate()
}

// unsafeInField reports whether r must not appear in a path or argument field: a
// control character, or a bidirectional formatting character. Both are ways an
// untrusted manifest deceives an operator reading the value - a control character
// reprograms the terminal, a bidi override reorders how the rest of the field is
// displayed - so a path renders as something other than what it grants.
func unsafeInField(r rune) bool {
	return isControl(r) || isBidiOverride(r)
}

// unsafeKind names the class of an unsafeInField rune for the error message.
func unsafeKind(r rune) string {
	if isBidiOverride(r) {
		return "a bidirectional formatting character"
	}
	return "a control character"
}

// isControl reports whether r is a C0 control, DEL, or a C1 control. These never
// appear in a legitimate path or argument, and each is a way for untrusted manifest
// content to reprogram the terminal it is later printed to (ESC begins every 7-bit
// ANSI/OSC sequence; U+009B and U+009D are the 8-bit CSI and OSC that some terminals
// honor directly).
func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// isBidiOverride reports whether r is a Unicode bidirectional embedding, override,
// or isolate control (U+202A-U+202E, U+2066-U+2069) - the "Trojan Source" class.
// These reorder how the surrounding text is displayed without changing its bytes, so
// a value renders as something other than what it grants (a path that reads as
// "/safe" but resolves to "/evil"). Legitimate right-to-left paths carry directional
// letters, which have inherent direction and are not these explicit format controls,
// so rejecting these does not reject real RTL filenames.
func isBidiOverride(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

func (m ExecMode) validate() error {
	switch m {
	case "", ExecNone, ExecNoneStrict, ExecAll:
		return nil
	default:
		return fmt.Errorf("policy: invalid exec mode %q: want one of none, none-strict, all", string(m))
	}
}

// validateHostPattern accepts a network-rule host: a literal hostname, a
// ".suffix" wildcard, a canonical IP literal, or "*". It rejects control
// characters, IPv6 zone ids, overlong names, and non-canonical IP shorthand
// (e.g. "127.1", "2852039166") that string-mismatches a rule but still resolves
// to a real address.
func validateHostPattern(host string) error {
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if strings.ContainsAny(host, "\x00\r\n\t %") {
		return fmt.Errorf("host %q contains control or reserved characters", host)
	}
	if host == "*" {
		return nil
	}
	if len(host) > 253 {
		return fmt.Errorf("host %q too long", host)
	}
	match := host
	if strings.HasPrefix(host, ".") {
		match = host[1:]
		if match == "" {
			return fmt.Errorf("host %q: suffix wildcard needs a domain after the dot", host)
		}
	}
	if ip := net.ParseIP(match); ip != nil {
		if ip.String() != match {
			return fmt.Errorf("host %q is not canonical (write it as %s)", match, ip.String())
		}
		return nil
	}
	if isIPShorthand(match) {
		return fmt.Errorf("host %q is not a canonical IP address (write a full dotted-quad or a hostname)", match)
	}
	if !isHostname(match) {
		return fmt.Errorf("host %q is not a valid hostname", host)
	}
	return nil
}

// isIPShorthand reports whether s is digits-and-dots only. Such a string that
// net.ParseIP already rejected is malformed IP shorthand (e.g. "127.1",
// "2852039166"), not a hostname.
func isIPShorthand(s string) bool {
	return strings.IndexFunc(s, func(c rune) bool {
		return (c < '0' || c > '9') && c != '.'
	}) < 0
}

func isHostname(h string) bool {
	if h == "" || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
		return false
	}
	labels := strings.Split(h, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '-' && i > 0 && i < len(label)-1:
			default:
				return false
			}
		}
	}
	// The rightmost label must contain a non-digit. An all-numeric final label
	// means the string is IP shorthand the libc resolver treats as an address,
	// not a name - rejecting it stops a rule that string-mismatches an allowlist
	// entry but still resolves to a real host.
	last := labels[len(labels)-1]
	return strings.IndexFunc(last, func(c rune) bool { return c < '0' || c > '9' }) >= 0
}

func validatePort(port string) error {
	if port == "" {
		return fmt.Errorf("empty port (use a number, a lo-hi range, or \"*\")")
	}
	if port == "*" {
		return nil
	}
	if lo, hi, ok := strings.Cut(port, "-"); ok {
		l, err := parsePortNum(lo)
		if err != nil {
			return err
		}
		h, err := parsePortNum(hi)
		if err != nil {
			return err
		}
		if l > h {
			return fmt.Errorf("port range %q is inverted", port)
		}
		return nil
	}
	_, err := parsePortNum(port)
	return err
}

func parsePortNum(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %q out of range 1-65535", s)
	}
	return n, nil
}

func (l Limits) validate() error {
	if l.PIDs < 0 {
		return fmt.Errorf("policy: limits.pids must not be negative")
	}
	if l.CPU != "" && !strings.HasSuffix(l.CPU, "%") {
		return fmt.Errorf("policy: limits.cpu %q must be a percentage (e.g. \"100%%\")", l.CPU)
	}
	if l.Memory != "" {
		if _, err := parseBytes(l.Memory); err != nil {
			return fmt.Errorf("policy: limits.memory: %w", err)
		}
	}
	return nil
}

// parseBytes parses a byte quantity with a K/M/G suffix (powers of 1024), or a
// bare byte count. Validate uses it to reject an unparseable Limits.Memory; the
// backend passes the original string to systemd, which parses it again.
func parseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'K', 'k':
		mult = 1 << 10
	case 'M', 'm':
		mult = 1 << 20
	case 'G', 'g':
		mult = 1 << 30
	}
	num := s
	if mult != 1 {
		num = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(num), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return n * mult, nil
}
