package policy

import (
	"strings"
	"testing"
)

// valid is the minimal well-formed policy; tests mutate a copy to isolate one
// invariant at a time.
func valid() Policy {
	return Policy{Entrypoint: "./fetch.py", Interpreter: "python3"}
}

func TestValidateAcceptsWellFormedPolicy(t *testing.T) {
	p := valid()
	p.Env = []string{"LANG", "AWS_DEFAULT_REGION", "_UNDERSCORE1"}
	p.Read = []string{"."}
	p.Write = []string{"/tmp/out"}
	p.Network = []NetworkRule{
		{Host: "api.github.com", Port: "443"},
		{Host: ".example.com", Port: "8000-9000"},
		{Host: "*", Port: "*"},
		{Host: "10.0.0.1", Port: "5432"},
	}
	p.Exec = ExecNoneStrict
	p.Limits = Limits{Memory: "128M", CPU: "100%", PIDs: 32}

	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateEmptyExecModeDefaultsValid(t *testing.T) {
	p := valid()
	if err := p.Validate(); err != nil {
		t.Fatalf("empty exec mode should be valid (means none): %v", err)
	}
}

// Validate is the gate for Go embedders, who construct a Policy directly rather
// than parsing a manifest. Each case is a malformed policy that must never reach
// a backend.
func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Policy)
		want string
	}{
		{"no entrypoint", func(p *Policy) { p.Entrypoint = "" }, "entrypoint is required"},
		{"env with space", func(p *Policy) { p.Env = []string{"OUT = required"} }, "invalid env name"},
		{"env with arrow glyph", func(p *Policy) { p.Env = []string{"OUT ← note"} }, "invalid env name"},
		{"env starting with digit", func(p *Policy) { p.Env = []string{"1PATH"} }, "invalid env name"},
		{"bad exec mode", func(p *Policy) { p.Exec = ExecMode("yes") }, "invalid exec mode"},
		{"empty host", func(p *Policy) { p.Network = []NetworkRule{{Host: "", Port: "80"}} }, "empty host"},
		{"non-canonical ip", func(p *Policy) { p.Network = []NetworkRule{{Host: "127.1", Port: "80"}} }, "canonical IP"},
		{"integer ip", func(p *Policy) { p.Network = []NetworkRule{{Host: "2852039166", Port: "80"}} }, "canonical IP"},
		{"bad hostname", func(p *Policy) { p.Network = []NetworkRule{{Host: "a_b.com", Port: "80"}} }, "not a valid hostname"},
		{"host with newline", func(p *Policy) { p.Network = []NetworkRule{{Host: "a.com\nb", Port: "80"}} }, "control or reserved"},
		{"empty port", func(p *Policy) { p.Network = []NetworkRule{{Host: "a.com", Port: ""}} }, "empty port"},
		{"port out of range", func(p *Policy) { p.Network = []NetworkRule{{Host: "a.com", Port: "70000"}} }, "out of range"},
		{"inverted range", func(p *Policy) { p.Network = []NetworkRule{{Host: "a.com", Port: "900-100"}} }, "inverted"},
		{"negative pids", func(p *Policy) { p.Limits = Limits{PIDs: -1} }, "pids must not be negative"},
		{"cpu without percent", func(p *Policy) { p.Limits = Limits{CPU: "100"} }, "must be a percentage"},
		{"unparseable memory", func(p *Policy) { p.Limits = Limits{Memory: "lots"} }, "limits.memory"},
		{"escape in entrypoint", func(p *Policy) { p.Entrypoint = "/bin/true\x1b]0;PWNED\x07" }, "control character"},
		{"escape in interpreter", func(p *Policy) { p.Interpreter = "python3\x1b[31m" }, "control character"},
		{"escape in arg", func(p *Policy) { p.Args = []string{"--flag\x07"} }, "control character"},
		{"escape in read path", func(p *Policy) { p.Read = []string{"/data\nfoo"} }, "control character"},
		{"escape in write path", func(p *Policy) { p.Write = []string{"/out\x1b"} }, "control character"},
		{"c1 control in path", func(p *Policy) { p.Read = []string{"/data\u009b31m"} }, "control character"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := valid()
			tc.mut(&p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err, tc.want)
			}
		})
	}
}

func TestValidateNilPolicy(t *testing.T) {
	var p *Policy
	if err := p.Validate(); err == nil {
		t.Error("nil policy should not validate")
	}
}

func TestLimitsIsZero(t *testing.T) {
	if !(Limits{}).IsZero() {
		t.Error("empty Limits should be zero")
	}
	if (Limits{PIDs: 1}).IsZero() {
		t.Error("Limits with PIDs set should not be zero")
	}
}

func TestParseBytes(t *testing.T) {
	cases := map[string]int64{"1024": 1024, "1K": 1 << 10, "128M": 128 << 20, "2G": 2 << 30}
	for in, want := range cases {
		got, err := parseBytes(in)
		if err != nil {
			t.Errorf("parseBytes(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseBytes(%q) = %d, want %d", in, got, want)
		}
	}
	for _, bad := range []string{"", "lots", "-1", "12X3"} {
		if _, err := parseBytes(bad); err == nil {
			t.Errorf("parseBytes(%q) should fail", bad)
		}
	}
}
