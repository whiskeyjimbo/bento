package policy

import (
	"math"
	"strings"
	"sync"
	"testing"
)

func TestAdversarialPolicyValidation(t *testing.T) {
	t.Parallel()

	validBase := func() Policy {
		return Policy{
			Entrypoint:  "/usr/bin/app",
			Interpreter: "python3",
		}
	}

	tests := []struct {
		name      string
		mutate    func(*Policy)
		errSubstr string
	}{
		{
			name: "reject_nil_policy",
			mutate: func(p *Policy) {
				// Handled in subtest directly
			},
			errSubstr: "policy: nil policy",
		},
		{
			name: "reject_empty_entrypoint",
			mutate: func(p *Policy) {
				p.Entrypoint = ""
			},
			errSubstr: "entrypoint is required",
		},
		{
			name: "reject_null_byte_in_entrypoint",
			mutate: func(p *Policy) {
				p.Entrypoint = "/bin/app\x00evil"
			},
			errSubstr: "control character",
		},
		{
			name: "reject_null_byte_in_args",
			mutate: func(p *Policy) {
				p.Args = []string{"--flag", "val\x00inject"}
			},
			errSubstr: "control character",
		},
		{
			name: "reject_null_byte_in_read_path",
			mutate: func(p *Policy) {
				p.Read = []string{"/tmp/read\x00file"}
			},
			errSubstr: "control character",
		},
		{
			name: "reject_null_byte_in_write_path",
			mutate: func(p *Policy) {
				p.Write = []string{"/tmp/write\x00file"}
			},
			errSubstr: "control character",
		},
		{
			name: "reject_ansi_escape_in_interpreter",
			mutate: func(p *Policy) {
				p.Interpreter = "python3\x1b[31m"
			},
			errSubstr: "control character",
		},
		{
			name: "reject_c1_control_in_path",
			mutate: func(p *Policy) {
				p.Read = []string{"/data\u009b31m"}
			},
			errSubstr: "control character",
		},
		{
			name: "reject_bidi_override_in_read_path",
			mutate: func(p *Policy) {
				p.Read = []string{"/home/user/\u202Eexe.bat"}
			},
			errSubstr: "bidirectional formatting character",
		},
		{
			name: "reject_zero_width_space_in_entrypoint",
			mutate: func(p *Policy) {
				p.Entrypoint = "/bin/\u200Bsh"
			},
			errSubstr: "zero-width or invisible",
		},
		{
			name: "reject_bom_in_write_path",
			mutate: func(p *Policy) {
				p.Write = []string{"\ufeff/tmp/out"}
			},
			errSubstr: "zero-width or invisible",
		},
		{
			name: "reject_invalid_env_name_empty",
			mutate: func(p *Policy) {
				p.Env = []string{""}
			},
			errSubstr: "invalid env name",
		},
		{
			name: "reject_invalid_env_name_digit_prefix",
			mutate: func(p *Policy) {
				p.Env = []string{"1ENV"}
			},
			errSubstr: "invalid env name",
		},
		{
			name: "reject_invalid_env_name_with_equals",
			mutate: func(p *Policy) {
				p.Env = []string{"FOO=BAR"}
			},
			errSubstr: "invalid env name",
		},
		{
			name: "reject_invalid_env_name_with_hyphen",
			mutate: func(p *Policy) {
				p.Env = []string{"FOO-BAR"}
			},
			errSubstr: "invalid env name",
		},
		{
			name: "reject_invalid_exec_mode_bogus",
			mutate: func(p *Policy) {
				p.Exec = ExecMode("root")
			},
			errSubstr: "invalid exec mode",
		},
		{
			name: "reject_network_empty_host",
			mutate: func(p *Policy) {
				p.Network = []NetworkRule{{Host: "", Port: "80"}}
			},
			errSubstr: "empty host",
		},
		{
			name: "reject_network_null_byte_host",
			mutate: func(p *Policy) {
				p.Network = []NetworkRule{{Host: "example\x00.com", Port: "80"}}
			},
			errSubstr: "control or reserved",
		},
		{
			name: "reject_network_newline_host",
			mutate: func(p *Policy) {
				p.Network = []NetworkRule{{Host: "example.com\n", Port: "80"}}
			},
			errSubstr: "control or reserved",
		},
		{
			name: "reject_network_overlong_host",
			mutate: func(p *Policy) {
				p.Network = []NetworkRule{{Host: strings.Repeat("a", 254), Port: "80"}}
			},
			errSubstr: "too long",
		},
		{
			name: "reject_network_wildcard_bare_dot",
			mutate: func(p *Policy) {
				p.Network = []NetworkRule{{Host: ".", Port: "80"}}
			},
			errSubstr: "suffix wildcard needs a domain",
		},
		{
			name: "reject_network_non_canonical_ip_octal",
			mutate: func(p *Policy) {
				p.Network = []NetworkRule{{Host: "127.0.0.01", Port: "80"}}
			},
			errSubstr: "not a canonical IP address",
		},
		{
			name: "reject_network_non_canonical_ip_shorthand",
			mutate: func(p *Policy) {
				p.Network = []NetworkRule{{Host: "127.1", Port: "80"}}
			},
			errSubstr: "not a canonical IP address",
		},
		{
			name: "reject_network_non_canonical_ip_integer",
			mutate: func(p *Policy) {
				p.Network = []NetworkRule{{Host: "2130706433", Port: "80"}}
			},
			errSubstr: "not a canonical IP address",
		},
		{
			name: "reject_network_host_all_numeric_tld",
			mutate: func(p *Policy) {
				p.Network = []NetworkRule{{Host: "foo.123", Port: "80"}}
			},
			errSubstr: "not a valid hostname",
		},
		{
			name: "reject_network_empty_port",
			mutate: func(p *Policy) {
				p.Network = []NetworkRule{{Host: "example.com", Port: ""}}
			},
			errSubstr: "empty port",
		},
		{
			name: "reject_network_port_zero",
			mutate: func(p *Policy) {
				p.Network = []NetworkRule{{Host: "example.com", Port: "0"}}
			},
			errSubstr: "out of range",
		},
		{
			name: "reject_network_port_over_max",
			mutate: func(p *Policy) {
				p.Network = []NetworkRule{{Host: "example.com", Port: "65536"}}
			},
			errSubstr: "out of range",
		},
		{
			name: "reject_network_port_negative",
			mutate: func(p *Policy) {
				p.Network = []NetworkRule{{Host: "example.com", Port: "-80"}}
			},
			errSubstr: "out of range",
		},
		{
			name: "reject_network_port_range_inverted",
			mutate: func(p *Policy) {
				p.Network = []NetworkRule{{Host: "example.com", Port: "443-80"}}
			},
			errSubstr: "inverted",
		},
		{
			name: "reject_network_port_range_out_of_bounds",
			mutate: func(p *Policy) {
				p.Network = []NetworkRule{{Host: "example.com", Port: "1-70000"}}
			},
			errSubstr: "out of range",
		},
		{
			name: "reject_limits_negative_pids",
			mutate: func(p *Policy) {
				p.Limits = Limits{PIDs: -1}
			},
			errSubstr: "pids must not be negative",
		},
		{
			name: "reject_limits_cpu_no_percent",
			mutate: func(p *Policy) {
				p.Limits = Limits{CPU: "100"}
			},
			errSubstr: "must be a percentage",
		},
		{
			name: "reject_limits_cpu_nan",
			mutate: func(p *Policy) {
				p.Limits = Limits{CPU: "NaN%"}
			},
			errSubstr: "plain decimal percentage",
		},
		{
			name: "reject_limits_cpu_inf",
			mutate: func(p *Policy) {
				p.Limits = Limits{CPU: "Inf%"}
			},
			errSubstr: "plain decimal percentage",
		},
		{
			name: "reject_limits_cpu_negative",
			mutate: func(p *Policy) {
				p.Limits = Limits{CPU: "-10%"}
			},
			errSubstr: "plain decimal percentage",
		},
		{
			name: "reject_limits_memory_invalid_unit",
			mutate: func(p *Policy) {
				p.Limits = Limits{Memory: "100MB"}
			},
			errSubstr: "invalid size",
		},
		{
			name: "reject_limits_memory_negative",
			mutate: func(p *Policy) {
				p.Limits = Limits{Memory: "-1G"}
			},
			errSubstr: "invalid size",
		},
		{
			name: "detect_integer_overflow_memory_limit",
			mutate: func(p *Policy) {
				p.Limits = Limits{Memory: "8000000000000000000K"}
			},
			errSubstr: "invalid size",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.name == "reject_nil_policy" {
				var nilP *Policy
				err := nilP.Validate()
				if err == nil || !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("expected error containing %q, got: %v", tc.errSubstr, err)
				}
				return
			}

			p := validBase()
			tc.mutate(&p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("expected validation failure containing %q, but Validate succeeded", tc.errSubstr)
			}
			if !strings.Contains(err.Error(), tc.errSubstr) {
				t.Fatalf("expected error containing %q, got: %v", tc.errSubstr, err)
			}
		})
	}
}

func TestAdversarialAllows(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rules     []NetworkRule
		host      string
		port      string
		wantAllow bool
	}{
		{
			name:      "reject_nil_rules",
			rules:     nil,
			host:      "example.com",
			port:      "443",
			wantAllow: false,
		},
		{
			name:      "reject_empty_rules",
			rules:     []NetworkRule{},
			host:      "example.com",
			port:      "443",
			wantAllow: false,
		},
		{
			name:      "deny_apex_domain_when_wildcard_specified",
			rules:     []NetworkRule{{Host: ".example.com", Port: "443"}},
			host:      "example.com",
			port:      "443",
			wantAllow: false,
		},
		{
			name:      "allow_subdomain_when_wildcard_specified",
			rules:     []NetworkRule{{Host: ".example.com", Port: "443"}},
			host:      "sub.example.com",
			port:      "443",
			wantAllow: true,
		},
		{
			name:      "deny_subdomain_mismatch",
			rules:     []NetworkRule{{Host: "sub.example.com", Port: "443"}},
			host:      "other.example.com",
			port:      "443",
			wantAllow: false,
		},
		{
			name:      "deny_port_mismatch",
			rules:     []NetworkRule{{Host: "example.com", Port: "443"}},
			host:      "example.com",
			port:      "80",
			wantAllow: false,
		},
		{
			name:      "deny_port_out_of_range",
			rules:     []NetworkRule{{Host: "example.com", Port: "80-100"}},
			host:      "example.com",
			port:      "101",
			wantAllow: false,
		},
		{
			name:      "deny_port_malformed_string",
			rules:     []NetworkRule{{Host: "example.com", Port: "443"}},
			host:      "example.com",
			port:      "443abc",
			wantAllow: false,
		},
		{
			name:      "deny_host_with_null_byte",
			rules:     []NetworkRule{{Host: "example.com", Port: "443"}},
			host:      "example.com\x00",
			port:      "443",
			wantAllow: false,
		},
		{
			name:      "handle_dns_trailing_dot_matching",
			rules:     []NetworkRule{{Host: "example.com", Port: "443"}},
			host:      "example.com.",
			port:      "443",
			wantAllow: true,
		},
		{
			name:      "handle_dns_case_insensitive_matching",
			rules:     []NetworkRule{{Host: "EXAMPLE.COM", Port: "443"}},
			host:      "example.com",
			port:      "443",
			wantAllow: true,
		},
		{
			name:      "handle_port_overflow_string",
			rules:     []NetworkRule{{Host: "example.com", Port: "80-100"}},
			host:      "example.com",
			port:      "99999999999999999999999999",
			wantAllow: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Allows(tc.rules, tc.host, tc.port)
			if got != tc.wantAllow {
				t.Fatalf("Allows(%v, %q, %q) = %v; want %v", tc.rules, tc.host, tc.port, got, tc.wantAllow)
			}
		})
	}
}

func TestAdversarialFingerprintConcurrency(t *testing.T) {
	t.Parallel()

	p := Policy{
		Entrypoint:  "/usr/bin/app",
		Interpreter: "python3",
		Args:        []string{"--verbose", "--port=8080"},
		Env:         []string{"LANG", "PATH", "HOME"},
		Read:        []string{"/etc", "/var/data"},
		Write:       []string{"/tmp/out"},
		Network: []NetworkRule{
			{Host: "api.example.com", Port: "443"},
			{Host: ".org", Port: "80-90"},
		},
		Exec: ExecNoneStrict,
		Limits: Limits{
			Memory: "256M",
			CPU:    "50%",
			PIDs:   100,
		},
	}

	initialHash := p.Fingerprint()
	if initialHash == "" {
		t.Fatal("Fingerprint returned empty hash")
	}

	var wg sync.WaitGroup
	const goroutines = 100
	const iterations = 50

	for range goroutines {
		wg.Go(func() {
			for range iterations {
				h := p.Fingerprint()
				if h != initialHash {
					t.Errorf("Fingerprint non-deterministic under concurrent access: got %q, want %q", h, initialHash)
				}
			}
		})
	}

	wg.Wait()
}

func FuzzPolicyValidation(f *testing.F) {
	f.Add("/bin/app", "python3", "LANG", "/data", "/out", "api.com", "443", "100M", "50%", 10)
	f.Add("", "", "", "", "", "", "", "", "", -1)
	f.Add("\x00", "\x1b[31m", "1ENV", "\u202E", "\ufeff", "127.1", "70000", "invalid", "NaN%", math.MinInt)

	f.Fuzz(func(t *testing.T, entry, interp, env, read, write, host, port, mem, cpu string, pids int) {
		p := Policy{
			Entrypoint:  entry,
			Interpreter: interp,
			Env:         []string{env},
			Read:        []string{read},
			Write:       []string{write},
			Network:     []NetworkRule{{Host: host, Port: port}},
			Limits:      Limits{Memory: mem, CPU: cpu, PIDs: pids},
		}
		// Validate must never panic on fuzz input.
		_ = p.Validate()
	})
}

func FuzzPortMatches(f *testing.F) {
	f.Add("443", "443")
	f.Add("*", "80")
	f.Add("80-90", "85")
	f.Add("100-200", "300")
	f.Add("invalid", "-1")
	f.Add("\x00", "9999999999999")

	f.Fuzz(func(t *testing.T, pattern, port string) {
		_ = PortMatches(pattern, port)
	})
}
