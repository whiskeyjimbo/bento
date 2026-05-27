package spec

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Validate checks the manifest's structural and semantic constraints,
// returning a descriptive error on the first failure.
func (m *Manifest) Validate() error {
	if m == nil {
		return fmt.Errorf("manifest: cannot be nil")
	}
	if m.Interpreter == "" {
		return fmt.Errorf("manifest.interpreter: required (e.g. \"python3\", \"bash\")")
	}
	if m.Script == "" {
		return fmt.Errorf("manifest.script: required (path to the script file)")
	}
	if m.Network != nil {
		for i, rule := range m.Network.Rules {
			if err := validateNetworkRule(rule); err != nil {
				return fmt.Errorf("manifest.network.rules[%d]: %w", i, err)
			}
		}
	}
	if m.Limits != nil {
		if err := validateLimits(m.Limits); err != nil {
			return fmt.Errorf("manifest.limits.%w", err)
		}
	}
	return nil
}

// dnsLabelCharset accepts DNS labels plus underscore (for _dmarc-style records).
var dnsLabelCharset = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// IsCanonicalHostPattern reports whether h is a valid host or host pattern
// for a NetworkRule: "*", ".suffix", a literal hostname, or a canonical IP.
// Non-canonical IP shorthand ("127.1", "2852039166", "0x7f.0.0.1") is
// rejected — those forms are used to bypass naive allowlist matching, and
// the runtime proxies refuse them at connect time. Validating up front
// surfaces the issue when the user writes the manifest, not at first run.
func IsCanonicalHostPattern(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if strings.ContainsAny(h, "\x00\r\n%") {
		return false
	}
	if h == "*" {
		return true
	}
	bare := strings.TrimPrefix(h, ".") // ".suffix" wildcard
	if bare == "" {
		return false
	}
	if strings.HasPrefix(bare, "[") && strings.HasSuffix(bare, "]") {
		bare = bare[1 : len(bare)-1]
	}
	if ip := net.ParseIP(bare); ip != nil {
		return ip.String() == bare
	}
	if !dnsLabelCharset.MatchString(bare) {
		return false
	}
	lastDot := strings.LastIndex(bare, ".")
	lastLabel := bare[lastDot+1:]
	return strings.ContainsAny(lastLabel, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

func validateNetworkRule(r NetworkRule) error {
	if r.Host == "" {
		return fmt.Errorf("host: required (e.g. \"example.com\", \".example.com\", \"*\")")
	}
	if !IsCanonicalHostPattern(r.Host) {
		return fmt.Errorf("host: %q is not a valid host pattern (use a hostname, .suffix wildcard, \"*\", or canonical IP — shorthand like \"127.1\" is rejected at runtime by the network proxies)", r.Host)
	}
	if r.Port == "" {
		return fmt.Errorf("port: required (e.g. \"443\", \"8000-9000\", \"*\")")
	}
	if r.Port != "*" {
		if loStr, hiStr, isRange := strings.Cut(r.Port, "-"); isRange {
			lo, errLo := strconv.Atoi(loStr)
			hi, errHi := strconv.Atoi(hiStr)
			if errLo != nil || errHi != nil {
				return fmt.Errorf("port: range %q must be lo-hi integers", r.Port)
			}
			if lo < 1 || lo > 65535 || hi < 1 || hi > 65535 || lo > hi {
				return fmt.Errorf("port: range %q out of bounds or inverted", r.Port)
			}
		} else {
			n, err := strconv.Atoi(r.Port)
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("port: %q is not a valid TCP port (1-65535)", r.Port)
			}
		}
	}
	return nil
}

func validateLimits(lim *Limits) error {
	if lim.Memory != "" {
		if _, err := ParseBytes(lim.Memory); err != nil {
			return fmt.Errorf("memory: %w", err)
		}
	}
	if lim.CPU != "" {
		if !strings.HasSuffix(lim.CPU, "%") {
			return fmt.Errorf("cpu: %q should end with %% (e.g. \"100%%\", \"50%%\")", lim.CPU)
		}
	}
	if lim.Tasks < 0 {
		return fmt.Errorf("tasks: cannot be negative")
	}
	if lim.FDs < 0 {
		return fmt.Errorf("fds: cannot be negative")
	}
	if lim.Tmpfs != "" {
		if _, err := ParseBytes(lim.Tmpfs); err != nil {
			return fmt.Errorf("tmpfs: %w", err)
		}
	}
	return nil
}
