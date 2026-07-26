package manifest

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/whiskeyjimbo/bento/policy"
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
	// provenance - the machine-owned round trip is lossless for what matters.
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

// A manifest is untrusted input, so a parse error must never carry the offending
// source line's control bytes to the terminal: goccy annotates errors by echoing
// that line, and a hostile manifest can plant ANSI/OSC escapes in it (title
// spoofing, hidden text). The error text must be free of ESC and BEL while still
// naming the problem.
func TestParseErrorStripsTerminalEscapes(t *testing.T) {
	// 7-bit ESC/OSC/BEL, and U+009B (CSI) / U+009D (OSC) as 8-bit C1 controls, which
	// a UTF-8 manifest can carry directly and a terminal honoring 8-bit controls acts
	// on without any ESC.
	src := "entrypoint: /bin/true\n" +
		"bogus: \"\x1b[31mINJECTED\x1b[0m\x1b]0;PWNED\x07\u009b31m\u009d0;C1\"\n"
	_, err := Load(strings.NewReader(src))
	if err == nil {
		t.Fatal("an unknown field must be rejected")
	}
	for _, r := range err.Error() {
		if r == '\n' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Fatalf("parse error carries control rune %#x to the terminal:\n%q", r, err.Error())
		}
	}
	// The error must still be useful.
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("sanitized error dropped the field name that identifies the problem: %q", err.Error())
	}
}

// Provenance is returned to the caller and echoed by frontends, so a deceiving
// character there must be rejected like one in a path field - a hostile manifest
// carries hostile provenance. Unlike the decoder-error path (which is sanitized),
// these strings would otherwise reach the caller verbatim.
func TestParseRejectsUnsafeProvenance(t *testing.T) {
	cases := map[string]string{
		"escape in generated-by": "entrypoint: ./x\nprovenance:\n  generated-by: \"tool\x1b]0;PWNED\x07\"\n",
		"bidi in generated-at":   "entrypoint: ./x\nprovenance:\n  generated-at: \"2026‮-01\"\n",
		"zero-width in approves": "entrypoint: ./x\nprovenance:\n  approves: \"abc​def\"\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(src))
			if err == nil {
				t.Fatal("expected unsafe provenance to be rejected, got nil")
			}
			if !strings.Contains(err.Error(), "provenance") {
				t.Errorf("error should name the provenance field: %q", err)
			}
			for _, r := range err.Error() {
				if r != '\n' && r != '\t' && (r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)) {
					t.Fatalf("rejection error itself carries a control rune %#x: %q", r, err.Error())
				}
			}
		})
	}
}

// A binary mistaken for a manifest (`bento run ./some-binary`) must fail with a
// clear "not a manifest" error, not a YAML decoder error that dumps the binary -
// which was also a delivery vector for the escape injection above.
func TestParseRejectsNonUTF8(t *testing.T) {
	bin := string([]byte{0x7f, 'E', 'L', 'F', 0x00, 0x01, 0xff, 0xfe, 0x1b, '[', '3', '1', 'm'})
	_, err := Load(strings.NewReader(bin))
	if err == nil {
		t.Fatal("a non-UTF-8 input must be rejected")
	}
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("error should name the cause; got %q", err.Error())
	}
	if strings.ContainsRune(err.Error(), 0x1b) {
		t.Errorf("error echoed a raw escape byte from the binary: %q", err.Error())
	}
}

// The size cap turns a huge mistyped file into a clear error rather than streaming
// it through the decoder.
func TestParseRejectsOversizeInput(t *testing.T) {
	_, err := Load(strings.NewReader(strings.Repeat("a: 1\n", (maxManifestBytes/5)+100)))
	if err == nil {
		t.Fatal("an input over the size cap must be rejected")
	}
	if !strings.Contains(err.Error(), "not a manifest") {
		t.Errorf("error should say it is not a manifest; got %q", err.Error())
	}
}

// A manifest is a single policy document; a second YAML document must be rejected,
// not silently ignored (bv2-6f7).
func TestParseRejectsMultipleDocuments(t *testing.T) {
	src := "entrypoint: ./x\nexec: none\n---\nentrypoint: ./y\nexec: all\n"
	if _, err := Parse(strings.NewReader(src)); err == nil {
		t.Fatal("a manifest with two YAML documents must be rejected")
	}
}

// An explicit tag decodes to a value the line does not show: read:
// [!!binary "L2V0Yy9zaGFkb3c="] yielded Read: [/etc/shadow]. approve fingerprints the
// DECODED policy, so the approval was genuine for a grant no reviewer could see. Every
// tag is refused, not only !!binary - a custom tag is the same divergence.
func TestParseRejectsExplicitTags(t *testing.T) {
	for name, src := range map[string]string{
		"binary hides a path":  "entrypoint: ./x\nread: [!!binary \"L2V0Yy9zaGFkb3c=\"]\n",
		"binary in entrypoint": "entrypoint: !!binary \"L2V0Yy9zaGFkb3c=\"\n",
		"str tag":              "entrypoint: !!str ./x\n",
		"custom tag":           "entrypoint: ./x\nargs: [!foo bar]\n",
	} {
		t.Run(name, func(t *testing.T) {
			doc, err := Parse(strings.NewReader(src))
			if err == nil {
				t.Fatalf("a tagged value must be rejected; got policy %+v", doc.Policy)
			}
			if !strings.Contains(err.Error(), "explicit YAML tag") {
				t.Errorf("error should name the cause; got %q", err)
			}
		})
	}
}

// Nested aliases expand geometrically inside the decoder, and maxManifestBytes caps the
// source, not the expansion - this input is ~1.3KB and exhausted memory before the scan.
// The scan lexes instead of decoding, which is linear, so the refusal is immediate.
func TestParseRejectsAnchorsAndAliases(t *testing.T) {
	var bomb strings.Builder
	bomb.WriteString("a0: &a0 [x]\n")
	for i := 1; i < 60; i++ {
		fmt.Fprintf(&bomb, "a%d: &a%d [*a%d, *a%d]\n", i, i, i-1, i-1)
	}
	bomb.WriteString("entrypoint: *a59\n")

	for name, src := range map[string]string{
		"alias bomb": bomb.String(),
		"anchor":     "entrypoint: &e ./x\n",
		"merge key":  "base: {exec: all}\nentrypoint: ./x\n<<: *base\n",
	} {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { _, err := Parse(strings.NewReader(src)); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("an anchor, alias, or merge key must be rejected")
				}
				if !strings.Contains(err.Error(), "anchor, alias, or merge key") {
					t.Errorf("error should name the cause; got %q", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Parse did not return: the input reached the decoder and is expanding")
			}
		})
	}
}

// The scan must not refuse what people legitimately write: '&', '*' and '!' are ordinary
// characters in a path, an argument, or a comment, and a byte scan for the indicators
// would reject every one of these.
func TestParseAcceptsIndicatorCharactersInValues(t *testing.T) {
	for name, src := range map[string]string{
		"glob in a read path":   "entrypoint: ./x\nread: [\"/data/*\"]\n",
		"ampersand in an arg":   "entrypoint: ./x\nargs: [\"a&b\"]\n",
		"bang in an arg":        "entrypoint: ./x\nargs: [\"--x=!y\"]\n",
		"indicators in comment": "# see *this and &that and !those\nentrypoint: ./x\n",
		"star inside a quote":   "entrypoint: \"./x*\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(src)); err != nil {
				t.Errorf("a legitimate manifest must not be refused: %v", err)
			}
		})
	}
}

// The scan runs on untrusted input before the decoder does, so it must fail rather than
// panic on anything - the lexer has no error return, which leaves its behavior on
// malformed source unstated by its signature.
func TestScreenSourceHandlesMalformedInput(t *testing.T) {
	for _, src := range []string{
		"", "!", "&", "*", "\"unterminated", "'unterminated", "[unclosed",
		"{unclosed", "a: [1, 2", "- - - -", "!!", "&&&", "***", ": :", "\t\t",
		strings.Repeat("[", 500), strings.Repeat("&a ", 200),
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("screenSource panicked on %q: %v", src, r)
				}
			}()
			_ = screenSource(src)
		}()
	}
}

// Marshal is the write side of the gate Parse applies on the way in, so a manifest bento
// writes is one bento can read back. Before this it wrote whatever it was handed: an ESC
// in a profiled target's pathname became a file the profile footer tells the operator to
// read, and the artifact was unloadable afterward because Parse screens what Marshal did
// not. A nil policy panicked in fromPolicy and an empty one marshalled to "{}" with no
// error at all.
func TestMarshalValidatesBeforeWriting(t *testing.T) {
	t.Run("nil policy", func(t *testing.T) {
		if _, err := Marshal(nil, Provenance{}); err == nil {
			t.Error("a nil policy must be refused, not dereferenced")
		}
	})
	t.Run("empty policy", func(t *testing.T) {
		if b, err := Marshal(&policy.Policy{}, Provenance{}); err == nil {
			t.Errorf("an empty policy must be refused, not written as %q", string(b))
		}
	})
	t.Run("control character in a path", func(t *testing.T) {
		p := &policy.Policy{Entrypoint: "/x.py", Read: []string{"/data/\x1b]0;PWNED\x07"}}
		b, err := Marshal(p, Provenance{})
		if err == nil {
			t.Fatalf("a path carrying an escape must not be written: %q", string(b))
		}
		// The refusal is printed to the same terminal the escape targeted.
		if strings.ContainsRune(err.Error(), 0x1b) {
			t.Errorf("error echoed a raw escape byte: %q", err.Error())
		}
	})
	t.Run("unsafe provenance", func(t *testing.T) {
		p := &policy.Policy{Entrypoint: "/x.py"}
		if _, err := Marshal(p, Provenance{GeneratedBy: "bento\x1b[31m"}); err == nil {
			t.Error("provenance must be screened on the way out as it is on the way in")
		}
	})
}

// Whatever Marshal writes, Parse must accept: the two gates are the same one, and a
// divergence means bento can emit an artifact it cannot load.
func TestMarshalOutputParses(t *testing.T) {
	p := &policy.Policy{
		Entrypoint: "/app/run.py", Interpreter: "python3",
		Args: []string{"--x", "a&b", "!y"}, Env: []string{"HOME"},
		Read: []string{"/data/*"}, Write: []string{"/out"},
		Network: []policy.NetworkRule{{Host: ".example.com", Port: "443"}},
		Exec:    policy.ExecNone, Limits: policy.Limits{Memory: "128M", CPU: "100%", PIDs: 32},
	}
	b, err := Marshal(p, Provenance{GeneratedBy: "bento profile", GeneratedAt: "2026-07-26T00:00:00Z"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := Parse(strings.NewReader(string(b))); err != nil {
		t.Fatalf("Parse rejected what Marshal wrote:\n%s\nerror: %v", b, err)
	}
}
