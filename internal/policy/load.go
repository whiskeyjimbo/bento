package policy

import (
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// manifest is the on-disk YAML shape. It is deliberately separate from Policy:
// the domain type carries no serialization concerns, and translation happens in
// one place (toPolicy) where every field is validated.
type manifest struct {
	Entrypoint  string         `yaml:"entrypoint"`
	Interpreter string         `yaml:"interpreter"`
	Args        []string       `yaml:"args"`
	Env         []string       `yaml:"env"`
	Read        []string       `yaml:"read"`
	Write       []string       `yaml:"write"`
	Network     []networkRule  `yaml:"network"`
	Exec        string         `yaml:"exec"`
	Limits      *manifestLimit `yaml:"limits"`
}

type networkRule struct {
	Host string `yaml:"host"`
	Port string `yaml:"port"`
}

type manifestLimit struct {
	Memory string `yaml:"memory"`
	CPU    string `yaml:"cpu"`
	PIDs   int    `yaml:"pids"`
}

// UnmarshalYAML rejects the bare "host:port" scalar form with a clear message
// instead of yaml.v3's cryptic "cannot unmarshal !!str into networkRule". A
// network rule is always a mapping with host: and port: keys.
func (r *networkRule) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("each network rule must be a mapping with `host:` and `port:` keys, not %s (e.g. `- {host: api.example.com, port: \"443\"}`)", yamlKindName(node.Kind))
	}
	type raw networkRule
	return node.Decode((*raw)(r))
}

func yamlKindName(k yaml.Kind) string {
	switch k {
	case yaml.ScalarNode:
		return "a single value"
	case yaml.SequenceNode:
		return "a list"
	default:
		return "that shape"
	}
}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Load parses a YAML manifest and returns a validated Policy. Unknown fields,
// malformed env names, ill-formed network rules, and bad limits are hard errors:
// the manifest is the machine-owned source of truth, so a shape mistake is
// caught here rather than reflected back through later surfaces.
func Load(r io.Reader) (*Policy, error) {
	if r == nil {
		return nil, fmt.Errorf("policy: nil reader")
	}
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var m manifest
	if err := dec.Decode(&m); err != nil && err != io.EOF {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return m.toPolicy()
}

func (m *manifest) toPolicy() (*Policy, error) {
	if m.Entrypoint == "" {
		return nil, fmt.Errorf("policy: `entrypoint` is required")
	}

	for _, name := range m.Env {
		if !envNameRe.MatchString(name) {
			return nil, fmt.Errorf("policy: invalid env name %q: must match [A-Za-z_][A-Za-z0-9_]* (env is an allowlist of variable names, not values)", name)
		}
	}

	exec, err := parseExecMode(m.Exec)
	if err != nil {
		return nil, err
	}

	rules := make([]NetworkRule, 0, len(m.Network))
	for i, nr := range m.Network {
		if err := validateHostPattern(nr.Host); err != nil {
			return nil, fmt.Errorf("policy: network rule %d: %w", i, err)
		}
		if err := validatePort(nr.Port); err != nil {
			return nil, fmt.Errorf("policy: network rule %d: %w", i, err)
		}
		rules = append(rules, NetworkRule{Host: nr.Host, Port: nr.Port})
	}

	p := &Policy{
		Entrypoint:  m.Entrypoint,
		Interpreter: m.Interpreter,
		Args:        m.Args,
		Env:         m.Env,
		Read:        m.Read,
		Write:       m.Write,
		Network:     rules,
		Exec:        exec,
	}
	if m.Limits != nil {
		p.Limits = Limits{Memory: m.Limits.Memory, CPU: m.Limits.CPU, PIDs: m.Limits.PIDs}
		if err := validateLimits(p.Limits); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func parseExecMode(s string) (ExecMode, error) {
	switch s {
	case "":
		return ExecNone, nil
	case string(ExecNone), string(ExecNoneStrict), string(ExecAll):
		return ExecMode(s), nil
	default:
		return "", fmt.Errorf("policy: invalid exec mode %q: want one of none, none-strict, all", s)
	}
}

// validateHostPattern accepts a network-rule host: a literal hostname, a
// ".suffix" wildcard, a canonical IP literal, or "*". It rejects control
// characters, IPv6 zone ids, overlong names, and non-canonical IP shorthand
// (e.g. "127.1", "2852039166") that string-mismatches a rule but resolves to a
// real address.
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
// "2852039166"), not a hostname — worth its own message.
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
	// means the string is IP shorthand (e.g. "127.1", "2852039166") that the
	// libc resolver treats as an address, not a name — rejecting it here stops
	// an allowlist rule that string-mismatches but resolves to a real host.
	last := labels[len(labels)-1]
	if strings.IndexFunc(last, func(c rune) bool { return c < '0' || c > '9' }) < 0 {
		return false
	}
	return true
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

func validateLimits(l Limits) error {
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
// bare byte count. It is intentionally small; the domain only needs a yes/no
// validity check plus the resolved value for enforcement.
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
