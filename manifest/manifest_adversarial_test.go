package manifest

import (
	"bytes"
	"io"
	"strings"
	"testing"
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
		tc := tc
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

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		doc, err := Parse(r)
		if err == nil && doc != nil {
			if doc.Policy == nil {
				t.Fatal("Parse returned non-nil Document with nil Policy without returning error")
			}
		}
	})
}
