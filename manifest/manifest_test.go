package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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
		// The zero decodes to the same int as an absent key, so it emits no TasksMax and
		// the manifest reads as declaring a task ceiling it does not grant.
		{"zero pids", "entrypoint: ./x\nlimits: {memory: 128M, pids: 0}\n", "pids is zero"},
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

// A manifest with several malformed fields must name all of them, so the author fixes
// them in one pass instead of one per run.
func TestLoadReportsEveryProblem(t *testing.T) {
	src := "entrypoint: ./x\nenv: [\"OUT ← note\"]\nread: [\"\"]\nlimits: {pids: -1}\n"
	_, err := Load(strings.NewReader(src))
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	for _, want := range []string{"3 problems", "read[0] is empty", "invalid env name", "pids must not be negative"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want substring %q", err, want)
		}
	}
}

// A value carrying a deceiving character is echoed back in its own refusal, so it stays
// alone rather than being buried in a list of unrelated problems.
func TestLoadReportsAnUnsafeValueAlone(t *testing.T) {
	src := "entrypoint: \"./x\\u202Ey\"\nlimits: {pids: -1}\n"
	_, err := Load(strings.NewReader(src))
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "bidirectional") || strings.Contains(err.Error(), "problems") {
		t.Errorf("error = %q, want the unsafe-value refusal on its own", err)
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
	if !reflect.DeepEqual(doc2.Provenance, doc.Provenance) {
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
// not silently ignored.
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

// The decoder's cost grows faster than the source does in nesting depth alone - flat
// input of the same size is linear - so maxManifestBytes bounds nothing on a nested one:
// a megabyte of "[" took longer to decode than any operator would wait, on a file bento
// did not write. The depth screen is what bounds it, and each of these is a spelling of
// the same nesting the lexer must count as such: two flow collections and the block
// sequence entries a single line can stack.
func TestParseRejectsDeepNesting(t *testing.T) {
	for name, src := range map[string]string{
		"flow sequences":        strings.Repeat("[", maxManifestBytes/2),
		"flow mappings":         strings.Repeat("{", maxManifestBytes/2),
		"block sequence dashes": strings.Repeat("- ", maxManifestBytes/4),
	} {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { _, err := Parse(strings.NewReader(src)); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("input this deeply nested must be rejected")
				}
				if !strings.Contains(err.Error(), "levels deep") {
					t.Errorf("error should name the cause; got %q", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Parse did not return: the input reached the decoder and is nesting")
			}
		})
	}
}

// The depth screen must not refuse what people legitimately write. A manifest reaches
// four levels, so the cap has to sit well clear of that - and the block-entry count has
// to fall as entries close, or a long list would climb one level per item.
// The depth screen bounds the decode; it does not bound the error. goccy annotates a
// decoder error by echoing the offending source region, and building that is quadratic in
// the source size at any depth - a 256KB manifest two levels deep decoded in 128ms and
// then spent 7s rendering a 256KB error string, which the size cap does nothing about.
// This input is shallow and under the cap on purpose: it is the DoS the nesting screen
// cannot see, and the reason the decoder's error is rendered without its source.
func TestParseReturnsPromptlyOnAShallowDecoderError(t *testing.T) {
	src := "entrypoint: [" + strings.Repeat("x, ", (maxManifestBytes-60)/3) + "x]\n"
	done := make(chan error, 1)
	go func() { _, err := Parse(strings.NewReader(src)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a list where an entrypoint belongs must be rejected")
		}
		// The whole failure is the error carrying the source back, so an error the size of
		// the input is the defect even when it arrives in time.
		if len(err.Error()) > 1024 {
			t.Errorf("error is %d bytes; it is echoing the manifest back rather than naming the problem", len(err.Error()))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Parse did not return: the decoder's error is being annotated with the source")
	}
}

// Both spellings of a network list are covered because they reach the count by different
// tokens: the flow form adds a flow collection per entry, the block form - what the
// repo's own examples are written in - adds nothing but the entry, so only it would catch
// a pop condition that let sibling entries stack.
func TestParseAcceptsRealisticNesting(t *testing.T) {
	var flow, block strings.Builder
	flow.WriteString("entrypoint: ./x\nnetwork:\n")
	block.WriteString("entrypoint: ./x\nnetwork:\n")
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&flow, "  - {host: h%d.example.com, port: \"443\"}\n", i)
		fmt.Fprintf(&block, "  - host: h%d.example.com\n    port: \"443\"\n", i)
	}
	for name, src := range map[string]string{"flow": flow.String(), "block": block.String()} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(src)); err != nil {
				t.Errorf("a manifest at the depth people write must not be refused: %v", err)
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
	// Parse rejects a non-UTF-8 document whole, but that guard sits on the read side
	// only. Without the same screen here, Marshal writes a file it can never load back.
	t.Run("invalid UTF-8 provenance", func(t *testing.T) {
		p := &policy.Policy{Entrypoint: "/x.py"}
		if _, err := Marshal(p, Provenance{GeneratedBy: "bento\x9b"}); err == nil {
			t.Error("provenance carrying an undecodable byte must not be written")
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

// An interpreter naming a path must mean the same file regardless of the directory
// the tool was invoked from, since the backend LookPaths it on the host and the
// fingerprint cannot tell two invocations apart. A bare name stays a PATH search:
// it means "the host's python3", not a file beside the manifest.
func TestResolveResolvesInterpreter(t *testing.T) {
	cases := map[string]string{
		"venv/bin/python": "/work/proj/venv/bin/python",
		"./py":            "/work/proj/py",
		"python3":         "python3",
		"/usr/bin/python": "/usr/bin/python",
		"":                "",
	}
	for interp, want := range cases {
		p := &policy.Policy{Entrypoint: "run.py", Interpreter: interp}
		if err := Resolve(p, "/work/proj/m.yaml"); err != nil {
			t.Fatal(err)
		}
		if p.Interpreter != want {
			t.Errorf("interpreter %q resolved to %q, want %q", interp, p.Interpreter, want)
		}
	}
}

// Resolve anchors every path-shaped field to the manifest's own directory and leaves
// absolute ones alone, so the same manifest names the same files from any cwd.
func TestResolveAnchorsPathsToManifestDir(t *testing.T) {
	p := &policy.Policy{
		Entrypoint: "run.py",
		Read:       []string{"../shared", "/etc/hosts"},
		Write:      []string{"out"},
	}
	if err := Resolve(p, "/work/proj/m.yaml"); err != nil {
		t.Fatal(err)
	}
	if p.Entrypoint != "/work/proj/run.py" {
		t.Errorf("entrypoint = %q", p.Entrypoint)
	}
	if got, want := strings.Join(p.Read, ","), "/work/shared,/etc/hosts"; got != want {
		t.Errorf("read = %q, want %q", got, want)
	}
	if got, want := strings.Join(p.Write, ","), "/work/proj/out"; got != want {
		t.Errorf("write = %q, want %q", got, want)
	}
}

// A relative manifest path gives filepath.Dir the anchor ".", which would leave every
// grant relative all the way into the landlock rules and bind mounts - paths that mean
// whatever the resolving process's cwd meant. Resolve absolutizes its own anchor so no
// caller has to remember to.
func TestResolveAbsolutizesRelativeManifestPath(t *testing.T) {
	t.Chdir(t.TempDir())
	// Not t.TempDir() itself: on a host where the temp root is a symlink the two spell
	// the same directory differently, and Resolve reports the kernel's spelling.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	p := &policy.Policy{Entrypoint: "run.py", Read: []string{"data"}, Write: []string{"out"}}
	if err := Resolve(p, "./m.yaml"); err != nil {
		t.Fatal(err)
	}
	for _, got := range []string{p.Entrypoint, p.Read[0], p.Write[0]} {
		if !filepath.IsAbs(got) {
			t.Errorf("%q is not absolute", got)
		}
	}
	if want := filepath.Join(dir, "run.py"); p.Entrypoint != want {
		t.Errorf("entrypoint = %q, want %q", p.Entrypoint, want)
	}
}

// README documents `read: "~"` and `read: ~/.ssh/id_rsa` as working syntax, and the
// shielding guarantees are stated in terms of them. Unexpanded, a tilde is an ordinary
// relative path: it anchors under the manifest directory, names nothing, and grants
// nothing - so a manifest reads as granting home while granting nothing, and a test
// asserting a shielded path is unreadable under `read: "~"` passes vacuously.
func TestResolveExpandsHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	p := &policy.Policy{
		Entrypoint:  "~/bin/run.py",
		Interpreter: "~/venv/bin/python",
		Read:        []string{"~", "~/.ssh/id_rsa"},
		Write:       []string{"~/out"},
	}
	if err := Resolve(p, "/work/proj/m.yaml"); err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, "bin/run.py"); p.Entrypoint != want {
		t.Errorf("entrypoint = %q, want %q", p.Entrypoint, want)
	}
	if want := filepath.Join(home, "venv/bin/python"); p.Interpreter != want {
		t.Errorf("interpreter = %q, want %q", p.Interpreter, want)
	}
	if got, want := strings.Join(p.Read, ","), home+","+filepath.Join(home, ".ssh/id_rsa"); got != want {
		t.Errorf("read = %q, want %q", got, want)
	}
	if got, want := p.Write[0], filepath.Join(home, "out"); got != want {
		t.Errorf("write = %q, want %q", got, want)
	}
}

// A trailing slash in $HOME must not survive into a grant: the shield and grant
// comparisons downstream are exact string equality against filepath.Clean(home), so
// an unclean "~" would name home everywhere except where the shields are decided.
func TestResolveExpandsHomeCleanly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home+"/")

	p := &policy.Policy{Entrypoint: "run.py", Read: []string{"~", "~/x"}}
	if err := Resolve(p, "/work/proj/m.yaml"); err != nil {
		t.Fatal(err)
	}
	if p.Read[0] != home {
		t.Errorf("read[0] = %q, want %q", p.Read[0], home)
	}
	if want := filepath.Join(home, "x"); p.Read[1] != want {
		t.Errorf("read[1] = %q, want %q", p.Read[1], want)
	}
}

// policy.Validate is where the "~operator/keys" spelling is refused for anything that
// comes through a manifest; Resolve re-checks it because a Go embedder can hand it a
// policy built in code, where joining "operator/keys" onto the invoker's own home
// would grant a path nobody named. A relative or empty $HOME is
// refused for the same reason: the grant would land wherever the enforcing process's
// cwd points, which is the silent misplacement the expansion exists to fix.
func TestResolveRefusesUnexpandableTilde(t *testing.T) {
	for _, path := range []string{"~operator/keys", "~backup"} {
		p := &policy.Policy{Entrypoint: "run.py", Read: []string{path}}
		if err := Resolve(p, "/work/proj/m.yaml"); err == nil {
			t.Errorf("Resolve accepted read %q, resolving it to %q", path, p.Read[0])
		}
	}
	t.Setenv("HOME", "relative/home")
	p := &policy.Policy{Entrypoint: "run.py", Read: []string{"~/x"}}
	if err := Resolve(p, "/work/proj/m.yaml"); err == nil {
		t.Errorf("Resolve accepted a relative $HOME, resolving read to %q", p.Read[0])
	}
}

// Policy's character screen runs at Parse, over the manifest as written, so $HOME is
// the one value that reaches a policy path without passing it. The resolved path is
// what the shield warnings and --json envelopes echo, which is what the screen guards.
func TestResolveScreensHomeForUnsafeRunes(t *testing.T) {
	t.Setenv("HOME", "/home/‮esc")

	p := &policy.Policy{Entrypoint: "run.py", Read: []string{"~/x"}}
	if err := Resolve(p, "/work/proj/m.yaml"); err == nil {
		t.Errorf("Resolve accepted a $HOME carrying a bidi override, resolving read to %q", p.Read[0])
	}
}

// A bare "~" carries no separator, so the interpreter's PATH-search branch would hand
// it to exec.LookPath as a command name rather than expanding it.
func TestResolveExpandsBareTildeInterpreter(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	p := &policy.Policy{Entrypoint: "run.py", Interpreter: "~"}
	if err := Resolve(p, "/work/proj/m.yaml"); err != nil {
		t.Fatal(err)
	}
	if p.Interpreter != home {
		t.Errorf("interpreter = %q, want %q", p.Interpreter, home)
	}
}

// A nil policy is refused rather than skipped: silently succeeding would let a caller
// who lost their policy go on to enforce paths that were never anchored.
func TestResolveRefusesNilPolicy(t *testing.T) {
	if err := Resolve(nil, "/work/proj/m.yaml"); err == nil {
		t.Fatal("Resolve(nil, ...) returned no error")
	}
}

// interpreter_args survives the YAML round trip as a distinct list from args. Folding
// the two would move an interpreter option behind the entrypoint, where it becomes the
// script's argv and the run changes.
func TestInterpreterArgsRoundTrip(t *testing.T) {
	src := "entrypoint: ./run.sh\ninterpreter: /bin/sh\ninterpreter_args: [-eu]\nargs: [--verbose]\n"
	doc, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := doc.Policy.InterpreterArgs; !reflect.DeepEqual(got, []string{"-eu"}) {
		t.Fatalf("interpreter_args = %q", got)
	}
	if got := doc.Policy.Args; !reflect.DeepEqual(got, []string{"--verbose"}) {
		t.Fatalf("args = %q", got)
	}
	out, err := Marshal(doc.Policy, doc.Provenance)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	doc2, err := Parse(strings.NewReader(string(out)))
	if err != nil {
		t.Fatalf("re-Parse: %v\n%s", err, out)
	}
	if doc.Policy.Fingerprint() != doc2.Policy.Fingerprint() {
		t.Errorf("fingerprint changed across marshal round trip:\n%s", out)
	}
}

// NonAnchoring's whole value is being the exact inverse of the branch resolveAgainst
// takes to join a path to the manifest's directory, and its comment says the two cannot
// drift. Sitting next to each other does not make that true - this does: a path form
// added to one and not the other fails here.
func TestNonAnchoringInvertsResolveAgainst(t *testing.T) {
	base := filepath.Join(string(filepath.Separator), "checkout")
	paths := []string{
		"x", "./data", "../shared", "venv/bin/python",
		"/srv/corpus", "/", "~", "~/.cache/models",
		"$HOME/x", "./~x", "data/",
	}
	for _, p := range paths {
		got, err := resolveAgainst(base, p)
		if err != nil {
			// A ~ path on a host with no usable $HOME: it did not anchor, which is the
			// only thing being asserted.
			if !NonAnchoring(p) {
				t.Errorf("resolveAgainst(%q) failed (%v) but NonAnchoring says it anchors", p, err)
			}
			continue
		}
		// Compared against the join itself rather than a prefix test: "../shared" is
		// joined to the base like any relative path and then cleaned above it, so a
		// prefix test would call the one path that moves with the manifest non-anchoring.
		anchored := got == filepath.Join(base, p)
		if anchored == NonAnchoring(p) {
			t.Errorf("%q resolved to %q (anchored=%v) but NonAnchoring reports %v", p, got, anchored, NonAnchoring(p))
		}
	}
}
