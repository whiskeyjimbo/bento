package policy

import (
	"fmt"
	"math"
	"net"
	"path/filepath"
	"strconv"
	"strings"
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
			errSubstr: `invalid size "100MB", want a plain byte count or a K/M/G suffix (e.g. "128M")`,
		},
		{
			name: "reject_limits_memory_negative",
			mutate: func(p *Policy) {
				p.Limits = Limits{Memory: "-1G"}
			},
			errSubstr: "cannot be negative",
		},
		{
			name: "detect_integer_overflow_memory_limit",
			mutate: func(p *Policy) {
				p.Limits = Limits{Memory: "8000000000000000000K"}
			},
			errSubstr: "is too large",
		},
		{
			// A bare count past int64 is spelled exactly the way the format advice would
			// tell it to be, so it has to reach the range answer rather than that advice.
			name: "detect_overlong_bare_byte_count",
			mutate: func(p *Policy) {
				p.Limits = Limits{Memory: "99999999999999999999"}
			},
			errSubstr: "is too large",
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

func FuzzPolicyValidation(f *testing.F) {
	f.Add("/bin/app", "python3", "LANG", "/data", "/out", "api.com", "443", "100M", "50%", 10)
	f.Add("", "", "", "", "", "", "", "", "", -1)
	f.Add("\x00", "\x1b[31m", "1ENV", "\u202E", "\ufeff", "127.1", "70000", "invalid", "NaN%", math.MinInt)
	// One bad field each, on an otherwise valid policy. The all-bad seed above reaches
	// the refusal on whichever check runs first, so it proves nothing about the rest;
	// these are what drive the acceptance side of the oracle at all.
	f.Add("/bin/app\u202E", "python3", "LANG", "/data", "/out", "api.com", "443", "100M", "50%", 10)
	f.Add("/bin/app", "python3", "LANG", "/data", "", "api.com", "443", "100M", "50%", 10)
	f.Add("/bin/app", "python3", "LANG", "/data", "~", "api.com", "443", "100M", "50%", 10)
	f.Add("/bin/app", "python3", "LANG", "/data", "~operator/keys", "api.com", "443", "100M", "50%", 10)
	f.Add("/bin/app", "python3", "LANG", "/data", "/out", "api.com", "0443", "100M", "50%", 10)
	f.Add("/bin/app", "python3", "LANG", "/data", "/out", "api.com", "500-100", "100M", "50%", 10)
	f.Add("/bin/app", "python3", "LANG", "/data", "/out", "api.com", "443", "100M", "50%", -1)
	// Surrounding whitespace is legal in a path, so this one is accepted - it is here to
	// give the non-mutation check something a normalising trim would visibly change.
	f.Add(" /bin/app ", "python3", "LANG", "/data", "/out", "api.com", "443", "100M", "50%", 10)

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
		before := fmt.Sprintf("%#v", p)
		err := p.Validate()

		// Validate is Problems' first element and nothing else, so a check that only one
		// of them runs cannot hide behind the other.
		probs := p.Problems()
		if (err != nil) != (len(probs) > 0) {
			t.Fatalf("Validate returned %v but Problems returned %d problems", err, len(probs))
		}
		if err != nil && err.Error() != probs[0].Error() {
			t.Fatalf("Validate returned %q, Problems' first is %q", err, probs[0])
		}
		// A normalising write would let a policy validate once and refuse the second time,
		// which is what every caller revalidating past the parse gate would then hit.
		if again := p.Validate(); (again != nil) != (err != nil) {
			t.Fatalf("Validate is not idempotent: first %v, second %v", err, again)
		}
		if after := fmt.Sprintf("%#v", p); after != before {
			t.Fatalf("Validate mutated the policy:\nbefore %s\nafter  %s", before, after)
		}
		if err != nil {
			return
		}
		// Past here the policy was ACCEPTED, which is the direction that matters: a
		// refusal that should have been an acceptance costs a run, an acceptance that
		// should have been a refusal is what the screens exist to stop. Each check below
		// is one the package documents as unconditional.
		for _, field := range []string{entry, interp, read, write} {
			if r, ok := FirstUnsafeRune(field); ok {
				t.Fatalf("accepted %q, which carries %s - the same rune the frontends echo verbatim", field, DescribeUnsafeRune(r))
			}
		}
		if entry == "" {
			t.Fatal("accepted an empty entrypoint")
		}
		for _, g := range []string{read, write} {
			if g == "" {
				t.Fatal("accepted an empty path grant, which resolves to the whole working directory")
			}
			if NamesOtherUserHome(g) {
				t.Fatalf("accepted grant %q, which names another user's home", g)
			}
		}
		if rest, ok := strings.CutPrefix(write, "~"); ok && filepath.Clean("/"+rest) == "/" {
			t.Fatalf("accepted write grant %q, which puts the shielded stores' parent in reach", write)
		}
		if pids < 0 {
			t.Fatalf("accepted limits.pids %d", pids)
		}
		if !wellFormedRulePort(port) {
			t.Fatalf("accepted network port %q, which is not \"*\", a plain decimal 1-65535, or an uninverted range of two", port)
		}
	})
}

// wellFormedRulePort is the rule-side port grammar validatePort defines, spelled here so
// the fuzz target measures Validate against the grammar rather than against itself.
func wellFormedRulePort(port string) bool {
	if port == "*" {
		return true
	}
	if lo, hi, ok := strings.Cut(port, "-"); ok {
		l, lok := canonicalPortNum(lo)
		h, hok := canonicalPortNum(hi)
		return lok && hok && l <= h
	}
	_, ok := canonicalPortNum(port)
	return ok
}

// canonicalPortNum accepts the plain-decimal 1-65535 spelling a rule must use. A
// non-canonical one ("+443", "08080") validates nowhere: it would match no CONNECT target
// the proxy admits, which is a dead allowlist entry rather than an error.
func canonicalPortNum(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil && n >= 1 && n <= 65535 && s == strconv.Itoa(n)
}

func FuzzPortMatches(f *testing.F) {
	f.Add("443", "443")
	f.Add("*", "80")
	f.Add("80-90", "85")
	f.Add("100-200", "300")
	f.Add("invalid", "-1")
	f.Add("\x00", "9999999999999")
	// Both range bounds, which no other seed reaches: an inclusive bound flipped to
	// exclusive is a rule that silently stops authorizing its own endpoint.
	f.Add("80-90", "90")
	f.Add("80-90", "80")
	f.Add("90-80", "85")
	// A range with an unparseable bound, which every other seed misses: a parser whose
	// failure does not reach the verdict turns "80-x" into an open-ended allow.
	f.Add("80-x", "85")

	f.Fuzz(func(t *testing.T, pattern, port string) {
		got := PortMatches(pattern, port)

		// The resolved-IP guard and the ordinary egress path have to apply one rule's port
		// the same way, or an IP-literal rule means two different things depending on which
		// of them judges the connection.
		if via := Allows([]NetworkRule{{Host: "host.example", Port: pattern}}, "host.example", port); via != got {
			t.Fatalf("PortMatches(%q, %q) = %v but Allows over the same rule = %v", pattern, port, got, via)
		}

		lo, hi, isRange := strings.Cut(pattern, "-")
		n, nok := lenientPortNum(port)
		l, lok := lenientPortNum(lo)
		h, hok := lenientPortNum(hi)

		switch {
		case pattern == "*":
			if !got {
				t.Fatalf("the wildcard pattern refused port %q", port)
			}
		case isRange:
			// The sound direction, asserted whatever the input's spelling: a wrong true
			// here is an egress hole, so a range may only ever admit a port that really
			// parses inside it.
			inside := nok && lok && hok && l <= n && n <= h
			if got && !inside {
				t.Fatalf("range %q admitted port %q, which is not a port inside [%q,%q]", pattern, port, lo, hi)
			}
			// The completing direction needs both sides parseable, which validatePort
			// guarantees for the rule and the proxy's CONNECT screen for the target.
			if !got && inside {
				t.Fatalf("range %q refused port %q, which is inside it", pattern, port)
			}
		default:
			if got != (pattern == port) {
				t.Fatalf("literal pattern %q against port %q = %v; a literal matches its own spelling and nothing else", pattern, port, got)
			}
		}
	})
}

// lenientPortNum is what the range branch's own parser documents itself as accepting:
// digits only, no sign, no more than 65535. Deliberately looser than canonicalPortNum -
// the hot path takes "0443" as 443, which is safe only because both sides were screened
// before they got there, and an oracle demanding canonical spelling would fire on it.
func lenientPortNum(s string) (int, bool) {
	if s == "" || strings.ContainsFunc(s, func(r rune) bool { return r < '0' || r > '9' }) {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	return n, err == nil && n <= 65535
}

func FuzzValidatedRuleMatchesItsOwnWitness(f *testing.F) {
	f.Add("*", "*", "api.example.com")
	f.Add(".example.com", "80-90", "api.example.com")
	f.Add("10.0.0.1", "443", "10.0.0.1")
	f.Add("::1", "443", "::1")
	f.Add("API.Example.COM", "443", "api.example.com")
	f.Add("xn--bcher-kva.example", "1-65535", "xn--bcher-kva.example")
	// The fold's own trap: U+212A folds onto ASCII 'k' under Unicode rules, so this pair
	// matches iff normalizeHost ever grows into strings.ToLower.
	f.Add("kelvin.example", "443", "Kelvin.example")
	// A doubled trailing dot, which normalizeHost deliberately does not idempotently
	// strip; the differential has to agree with it there, not with a tidier grammar.
	f.Add("example.com", "443", "example.com..")

	f.Fuzz(func(t *testing.T, host, port, target string) {
		r := NetworkRule{Host: host, Port: port}
		// matchHost's documented precondition (match.go:15-19). It is load-bearing rather
		// than decorative: without it the apex assertion below fires on pattern ".", which
		// matchHost reads as a suffix pattern normalizing to "" that suffix-matches
		// everything. Validate refuses ".", so that is the precondition working.
		if r.Validate() != nil {
			return
		}
		rules := []NetworkRule{r}
		np := normalizeHost(host)

		// The load-bearing assertion: matchHost against a restatement of its three-case
		// grammar AND of its ASCII-only fold, spelled out below rather than delegated, the
		// way wellFormedRulePort and lenientPortNum restate the two port grammars. The
		// witness checks further down mostly hold by construction - a witness built from
		// the rule's own text matches it however the grammar is spelled - so this is the
		// part that fails when the matcher's meaning drifts.
		if got, want := matchHost(host, normalizeHost(target)), referenceMatchHost(host, referenceNormalizeHost(target)); got != want {
			t.Fatalf("matchHost(%q, %q) = %v; the grammar restated says %v", host, target, got, want)
		}

		// match.go:76-79. Granting ".example.com" must not silently also grant the apex,
		// and must still grant a subdomain - a suffix rule that matches nothing is the
		// dead allowlist entry validateHostPattern exists to refuse.
		if apex, isSuffix := strings.CutPrefix(np, "."); isSuffix {
			if matchHost(host, normalizeHost(apex)) {
				t.Fatalf("suffix rule %q reached its own apex %q", host, apex)
			}
			if !matchHost(host, normalizeHost("sub"+np)) {
				t.Fatalf("suffix rule %q refused the subdomain %q it is written to grant", host, "sub"+np)
			}
		}

		// match.go:82-88. A v4-mapped target must not reach a v4 rule: the comparison is
		// textual, and making it IP-aware would widen a rule past what its author wrote.
		if ip := net.ParseIP(np); ip != nil && ip.To4() != nil {
			if mapped := "::ffff:" + np; matchHost(host, normalizeHost(mapped)) {
				t.Fatalf("v4 rule %q was reached by the v4-mapped target %q", host, mapped)
			}
		}

		// match.go:51-57. The fold is ASCII-only, so a target carrying a non-ASCII byte
		// cannot reach a literal ASCII rule. Under strings.ToLower it could: U+212A folds
		// onto 'k', and the proxy would dial the raw bytes it checked an ASCII name for.
		// Asked of the RAW target, not of what normalizeHost returned: under
		// strings.ToLower the fold is what turns U+212A into ASCII, so a check gated on
		// the normalized form being non-ASCII would be skipped by the very drift it names.
		if np != "*" && !strings.HasPrefix(np, ".") && isASCII(np) && !isASCII(target) {
			if matchHost(host, normalizeHost(target)) {
				t.Fatalf("literal ASCII rule %q was reached by the non-ASCII target %q", host, target)
			}
		}

		// Non-vacuity: the target the rule is written to authorize must be admitted. A rule
		// that validates and authorizes nothing is the dead allowlist entry both files'
		// comments say they are avoiding.
		witnessHost := np
		switch {
		case np == "*":
			witnessHost = "witness.example"
		case strings.HasPrefix(np, "."):
			witnessHost = "sub" + np
		}
		lo, hi, isRange := strings.Cut(port, "-")
		witnessPorts := []string{port}
		if port == "*" {
			witnessPorts = []string{"443"}
		} else if isRange {
			// Both bounds, not just one: an inclusive bound read as exclusive is a rule
			// that silently stops authorizing its own endpoint.
			witnessPorts = []string{lo, hi}
		}
		for _, wp := range witnessPorts {
			if !Allows(rules, witnessHost, wp) {
				t.Fatalf("rule %+v validated but refuses %q:%q, the target it is written to authorize", r, witnessHost, wp)
			}
		}
		if isRange && port != "*" {
			l, _ := canonicalPortNum(lo)
			h, _ := canonicalPortNum(hi)
			// Skipped at the domain edges, where the neighbour is not a port at all and
			// atoiPort would refuse it for a reason the range branch did not decide.
			if l > 1 && Allows(rules, witnessHost, strconv.Itoa(l-1)) {
				t.Fatalf("range %q admitted %d, below its low bound", port, l-1)
			}
			if h < 65535 && Allows(rules, witnessHost, strconv.Itoa(h+1)) {
				t.Fatalf("range %q admitted %d, above its high bound", port, h+1)
			}
		}
	})
}

// referenceMatchHost restates matchHost's three-case grammar, and referenceNormalizeHost
// its fold, so the differential measures the matcher against the grammar its comments
// state rather than against itself. It takes a host already normalized by its own
// normalizer, because Allows normalizes exactly once and normalizeHost is deliberately
// not idempotent on a doubled trailing dot (internal/proxy/proxy.go:1088).
func referenceMatchHost(pattern, normalizedHost string) bool {
	p := referenceNormalizeHost(pattern)
	switch {
	case p == "*":
		return true
	case strings.HasPrefix(p, "."):
		return strings.HasSuffix(normalizedHost, p)
	default:
		return p == normalizedHost
	}
}

// referenceNormalizeHost folds A-Z per byte and drops one trailing root dot. Per byte and
// not per rune: a fold that reaches beyond ASCII is the hole normalizeHost's comment names.
// A second spelling of the same three lines rather than an independent algorithm, because
// there is no other way to write them - what it buys is that a change to normalizeHost has
// to be made twice, which is what the differential catches.
func referenceNormalizeHost(host string) string {
	b := []byte(host)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return strings.TrimSuffix(string(b), ".")
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}
