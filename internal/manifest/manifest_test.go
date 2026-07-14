package manifest

import (
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento-v2/internal/policy"
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
	if p.Exec != policy.ExecNoneStrict {
		t.Errorf("exec = %q, want none-strict", p.Exec)
	}
	if len(p.Network) != 2 || p.Network[1] != (policy.NetworkRule{Host: ".example.com", Port: "8000-9000"}) {
		t.Errorf("network = %+v", p.Network)
	}
	if p.Limits != (policy.Limits{Memory: "128M", CPU: "100%", PIDs: 32}) {
		t.Errorf("limits = %+v", p.Limits)
	}
}

func TestLoadDefaults(t *testing.T) {
	p, err := Load(strings.NewReader("entrypoint: ./x\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Exec != policy.ExecNone {
		t.Errorf("exec = %q, want none (absent exec: must resolve to the deny default)", p.Exec)
	}
	if len(p.Network) != 0 {
		t.Errorf("network = %+v, want empty (absent network: denies all egress)", p.Network)
	}
}

// Strictness must hold at every level of the document. The nested case is the
// one that regresses silently: a custom unmarshaler written against a node or
// byte-slice API builds a fresh decoder and drops the strict flag, so a typo'd
// key inside a network rule would be accepted without complaint.
func TestUnknownFieldsRejectedAtEveryLevel(t *testing.T) {
	cases := map[string]string{
		"top level":            "entrypoint: ./x\nnetwrok: []\n",
		"inside network rule":  "entrypoint: ./x\nnetwork:\n  - {host: a.com, port: \"443\", bogus: 1}\n",
		"inside limits":        "entrypoint: ./x\nlimits: {memory: 1M, bogus: 1}\n",
		"misspelled rule key":  "entrypoint: ./x\nnetwork:\n  - {host: a.com, prt: \"443\"}\n",
		"misspelled limit key": "entrypoint: ./x\nlimits: {mem: 1M}\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(strings.NewReader(src)); err == nil {
				t.Fatal("expected an unknown/misspelled field to be rejected, got nil")
			}
		})
	}
}

func TestLoadRejects(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"bare host:port string", "entrypoint: ./x\nnetwork: [\"api.example.com:443\"]\n", "must be a mapping"},
		{"missing entrypoint", "interpreter: python3\n", "entrypoint is required"},
		{"bad env name", "entrypoint: ./x\nenv: [\"OUT ← note\"]\n", "invalid env name"},
		{"bad exec mode", "entrypoint: ./x\nexec: yes\n", "invalid exec mode"},
		{"non-canonical ip", "entrypoint: ./x\nnetwork:\n  - {host: \"127.1\", port: \"80\"}\n", "canonical IP"},
		{"port out of range", "entrypoint: ./x\nnetwork:\n  - {host: a.com, port: \"70000\"}\n", "out of range"},
		{"negative pids", "entrypoint: ./x\nlimits: {pids: -1}\n", "pids must not be negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(tc.src))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err, tc.want)
			}
		})
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	src := "entrypoint: ./fetch.py\ninterpreter: python3\nread: [.]\nnetwork:\n  - {host: api.github.com, port: \"443\"}\nexec: none\nprovenance:\n  generated-by: bento-test\n  approves: abc123\n"
	doc, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Provenance.Approves != "abc123" || doc.Provenance.GeneratedBy != "bento-test" {
		t.Fatalf("provenance not parsed: %+v", doc.Provenance)
	}

	out, err := Marshal(doc.Policy, doc.Provenance)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Re-parsing the marshalled form must yield the same policy fingerprint and
	// provenance — the machine-owned round trip is lossless for what matters.
	doc2, err := Parse(strings.NewReader(string(out)))
	if err != nil {
		t.Fatalf("re-Parse: %v\n%s", err, out)
	}
	if doc.Policy.Fingerprint() != doc2.Policy.Fingerprint() {
		t.Errorf("fingerprint changed across marshal round trip:\n%s", out)
	}
	if doc2.Provenance != doc.Provenance {
		t.Errorf("provenance changed across round trip: %+v vs %+v", doc2.Provenance, doc.Provenance)
	}
}
