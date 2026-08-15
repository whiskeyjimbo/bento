package manifest

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

func TestAdversarialManifestParsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		errSubstr string
	}{
		{
			name:      "reject_nil_reader",
			input:     "", // Special case handled directly in test runner
			errSubstr: "manifest: nil reader",
		},
		{
			name:      "reject_oversized_manifest",
			input:     strings.Repeat("a", maxManifestBytes+10),
			errSubstr: "input is larger than 1048576 bytes",
		},
		{
			name:      "reject_non_utf8_binary",
			input:     "\xff\xfe\x00\x00binary_data_stream\x80\x81",
			errSubstr: "input is not valid UTF-8 text",
		},
		{
			name:      "reject_multi_document_yaml",
			input:     "entrypoint: ./app\n---\nentrypoint: ./app2\n",
			errSubstr: "contains more than one YAML document",
		},
		{
			name:      "reject_unknown_field",
			input:     "entrypoint: ./app\nunknown_grant: true\n",
			errSubstr: "unknown field",
		},
		{
			name:      "reject_network_bare_string_rule",
			input:     "entrypoint: ./app\nnetwork:\n  - api.example.com:443\n",
			errSubstr: "must be a mapping",
		},
		{
			name:      "sanitize_terminal_escapes_in_decoder_error",
			input:     "entrypoint: ./app\n\x1b[31mBAD_KEY\x1b[0m: val\n",
			errSubstr: "manifest: ", // ensure it errors and doesn't leak escape sequence
		},
		{
			name:      "reject_provenance_unsafe_control_rune",
			input:     "entrypoint: ./app\nprovenance:\n  generated-by: \"tool\x07\"\n",
			errSubstr: "control character",
		},
		{
			name:      "reject_provenance_bidi_override",
			input:     "entrypoint: ./app\nprovenance:\n  generated-by: \"tool\u202E\"\n",
			errSubstr: "bidirectional formatting character",
		},
		{
			name:      "reject_provenance_zero_width_space",
			input:     "entrypoint: ./app\nprovenance:\n  generated-by: \"tool\u200B\"\n",
			errSubstr: "zero-width or invisible",
		},
		{
			name:      "handle_empty_reader",
			input:     "",
			errSubstr: "entrypoint is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var r io.Reader
			if tc.name == "reject_nil_reader" {
				r = nil
			} else {
				r = strings.NewReader(tc.input)
			}

			doc, err := Parse(r)
			if err == nil {
				t.Fatalf("expected Parse error containing %q, but Parse succeeded: %+v", tc.errSubstr, doc)
			}
			if !strings.Contains(err.Error(), tc.errSubstr) {
				t.Fatalf("expected error containing %q, got: %v", tc.errSubstr, err)
			}

			// Ensure ANSI escape sequences like ESC (\x1b) or BEL (\x07) were sanitized
			if strings.Contains(err.Error(), "\x1b") || strings.Contains(err.Error(), "\x07") {
				t.Fatalf("Parse error contained raw control characters: %q", err.Error())
			}
		})
	}
}

func FuzzParseManifest(f *testing.F) {
	f.Add([]byte("entrypoint: ./app\nread:\n  - /tmp\n"))
	f.Add([]byte("entrypoint: ./app\nnetwork:\n  - {host: example.com, port: \"443\"}\n"))
	f.Add([]byte("\xff\xfe\x00\x00"))
	f.Add([]byte("entrypoint: \x1b[31mBAD\x1b[0m"))
	// The 8-bit control the input can carry directly because a manifest is UTF-8 text:
	// U+009B is CSI with no ESC in front of it, so a C0-only filter passes it through
	// and the terminal acts on it anyway. Seeded rather than left to the mutator, which
	// has no reason to construct a two-byte encoding of one codepoint.
	f.Add([]byte("entrypoint: \u009b31mBAD:\n\tbad"))

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		doc, err := Parse(r)
		if err == nil && doc != nil {
			if doc.Policy == nil {
				t.Fatal("Parse returned non-nil Document with nil Policy without returning error")
			}
			return
		}
		// The property Parse's refusal path exists for: the input is a file bento did not
		// write, the decoder quotes stretches of it back in its line/caret annotation, and
		// the error goes to a terminal. A raw C0/C1 control there reprograms that terminal
		// - which is what sanitizeControl strips, and what only a hand-written table
		// pinned until now. Random bytes reach malformed YAML constantly, so this is the
		// oracle that bites on []byte input where a round-trip never would.
		//
		// Tab and newline are exempt because sanitizeControl keeps them on purpose: the
		// decoder lays its annotation out with both and neither reprograms anything.
		for _, r := range err.Error() {
			if r == '\n' || r == '\t' {
				continue
			}
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
				t.Fatalf("Parse error carries the raw control character %U, which the terminal it is printed to acts on: %q", r, err.Error())
			}
		}
	})
}

// FuzzManifestRoundTrip is the typed half of the manifest fuzzing, and it exists because
// the []byte target above cannot reach here: a manifest is a structured format, so random
// bytes essentially never form one and spend their whole budget on the door.
//
// The oracle is a shipped regression, recorded in Marshal's own doc comment - Marshal
// used to write files Parse would then refuse, and an empty policy marshalled to "{}"
// with no error at all. So the guarantee is that anything Marshal accepts, Parse reads
// back as the same policy: these are the two halves of bento's own file format, and a
// disagreement between them breaks `bento profile` and `bento approve` writing a manifest
// the next run cannot load.
//
// The field tuple is FuzzPolicyValidation's, for the reason that fuzzer chose it: it is
// the set of scalars the format carries, and its corpus is already tuned to sit on the
// accept/refuse boundary where a marshalled policy is interesting.
func FuzzManifestRoundTrip(f *testing.F) {
	f.Add("/bin/app", "python3", "LANG", "/data", "/out", "api.com", "443", "100M", "50%", 10)
	f.Add("", "", "", "", "", "", "", "", "", 0)
	f.Add("/bin/app", "python3", "LANG", "~/data", "~/out", "api.com", "443", "100M", "50%", 10)
	// Whitespace and a colon are legal in a path and are what a naive serializer emits
	// unquoted, producing a document that parses back as a different shape.
	f.Add(" /bin/app ", "python3", "LANG", "/data: x", "/out", "api.com", "443", "100M", "50%", 10)
	f.Add("/bin/app", "python3", "LANG", "/data", "/out", "*.example.com", "1-1024", "1G", "100%", 1)

	f.Fuzz(func(t *testing.T, entry, interp, env, read, write, host, port, mem, cpu string, pids int) {
		p := &policy.Policy{
			Entrypoint:  entry,
			Interpreter: interp,
			Env:         []string{env},
			Read:        []string{read},
			Write:       []string{write},
			Network:     []policy.NetworkRule{{Host: host, Port: port}},
			// Spelled rather than left zero: an absent exec: key means the deny-subprocesses
			// default, which toPolicy fills in, so a policy carrying "" would come back
			// different for a reason that is the format working as designed.
			Exec:   policy.ExecNone,
			Limits: policy.Limits{Memory: mem, CPU: cpu, PIDs: pids},
		}
		data, err := Marshal(p, Provenance{})
		if err != nil {
			return // Marshal refuses exactly what Validate refuses; nothing was written
		}
		doc, err := Parse(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("Marshal accepted a policy and wrote a manifest Parse refuses: %v\nmanifest:\n%s", err, data)
		}
		if !reflect.DeepEqual(doc.Policy, p) {
			t.Fatalf("the policy did not survive the round trip:\nbefore %#v\nafter  %#v\nmanifest:\n%s", p, doc.Policy, data)
		}
	})
}
