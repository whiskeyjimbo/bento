package policy

import (
	"strings"
	"testing"
)

func TestLoadValid(t *testing.T) {
	src := `
entrypoint: ./fetch.py
interpreter: python3
args: [--verbose]
env: [LANG, AWS_DEFAULT_REGION]
read: [.]
write: [/tmp/out]
network:
  - host: api.github.com
    port: "443"
  - host: .example.com
    port: "8000-9000"
  - host: "*"
    port: "*"
exec: none-strict
limits: {memory: 128M, cpu: "100%", pids: 32}
`
	p, err := Load(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Entrypoint != "./fetch.py" || p.Interpreter != "python3" {
		t.Errorf("entrypoint/interpreter = %q/%q", p.Entrypoint, p.Interpreter)
	}
	if p.Exec != ExecNoneStrict {
		t.Errorf("exec = %q, want none-strict", p.Exec)
	}
	if len(p.Network) != 3 {
		t.Fatalf("network rules = %d, want 3", len(p.Network))
	}
	if p.Network[1] != (NetworkRule{Host: ".example.com", Port: "8000-9000"}) {
		t.Errorf("rule[1] = %+v", p.Network[1])
	}
	if p.Limits.Memory != "128M" || p.Limits.PIDs != 32 {
		t.Errorf("limits = %+v", p.Limits)
	}
}

func TestLoadExecDefaultsToNone(t *testing.T) {
	p, err := Load(strings.NewReader("entrypoint: ./x\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Exec != ExecNone {
		t.Errorf("exec = %q, want none", p.Exec)
	}
	if len(p.Network) != 0 {
		t.Errorf("network should default to empty (deny all egress), got %v", p.Network)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"missing entrypoint", "interpreter: python3\n", "entrypoint` is required"},
		{"unknown field", "entrypoint: ./x\nnetwrok: []\n", "field netwrok not found"},
		{"bad env name", "entrypoint: ./x\nenv: [\"OUT = required\"]\n", "invalid env name"},
		{"env with arrow glyph", "entrypoint: ./x\nenv: [\"OUT ← note\"]\n", "invalid env name"},
		{"bad exec mode", "entrypoint: ./x\nexec: yes\n", "invalid exec mode"},
		{"network bare string", "entrypoint: ./x\nnetwork: [\"api:443\"]\n", "must be a mapping"},
		{"non-canonical ip", "entrypoint: ./x\nnetwork:\n  - {host: \"127.1\", port: \"80\"}\n", "canonical IP"},
		{"bad host", "entrypoint: ./x\nnetwork:\n  - {host: \"a_b.com\", port: \"80\"}\n", "not a valid hostname"},
		{"port out of range", "entrypoint: ./x\nnetwork:\n  - {host: a.com, port: \"70000\"}\n", "out of range"},
		{"inverted range", "entrypoint: ./x\nnetwork:\n  - {host: a.com, port: \"900-100\"}\n", "inverted"},
		{"negative pids", "entrypoint: ./x\nlimits: {pids: -1}\n", "pids must not be negative"},
		{"bad cpu", "entrypoint: ./x\nlimits: {cpu: \"100\"}\n", "must be a percentage"},
		{"bad memory", "entrypoint: ./x\nlimits: {memory: \"lots\"}\n", "limits.memory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(tc.src))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestSuffixWildcardMatchesSubdomainNotBareDomain(t *testing.T) {
	// The ".example.com" form is a documented suffix wildcard; validation must
	// accept it as a rule pattern (matching semantics are enforced elsewhere).
	p, err := Load(strings.NewReader("entrypoint: ./x\nnetwork:\n  - {host: .example.com, port: \"443\"}\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Network[0].Host != ".example.com" {
		t.Errorf("host = %q", p.Network[0].Host)
	}
}
