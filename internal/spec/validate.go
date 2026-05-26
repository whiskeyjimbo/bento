package spec

import (
	"fmt"
	"strconv"
	"strings"
)

// Validate checks the manifest's structural and semantic constraints.
// Returns a descriptive error naming the offending field on the first
// failure, or nil if the manifest is well-formed.
//
// Validation runs BEFORE any sandbox setup. The intent is to surface
// "your manifest is broken" with a clear pointer rather than producing
// confusing Go-internal yaml.Unmarshal errors or bwrap arg failures.
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

func validateNetworkRule(r NetworkRule) error {
	if r.Host == "" {
		return fmt.Errorf("host: required (e.g. \"example.com\", \".example.com\", \"*\")")
	}
	if r.Port == "" {
		return fmt.Errorf("port: required (e.g. \"443\", \"8000-9000\", \"*\")")
	}
	// Port shape check: literal, range, or "*".
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
		// CPUQuota is "100%", "50%", etc. Loose validation.
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
