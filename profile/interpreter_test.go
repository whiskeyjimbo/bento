package profile

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The script's own shebang wins over its extension: a .sh file that asks for /bin/sh
// must not be profiled under bash, or the manifest records an interpreter the author
// never chose and the run it describes is not the run the author wrote.
func TestGuessInterpreterPrefersTheShebang(t *testing.T) {
	cases := []struct {
		name       string // file basename (the extension matters)
		body       string
		want       string
		wantArgs   []string
		wantSource string
	}{
		{"s.sh", "#!/bin/sh\n", "/bin/sh", nil, "the script's shebang"},
		{"s.py", "#!/usr/bin/env -S python3 -u\nprint(1)\n", "python3", []string{"-u"}, "the script's shebang"},

		// env with `-S`/`--split-string` (the multi-arg idiom) must resolve the real
		// interpreter, not the "-S" option.
		{"a", "#!/usr/bin/env -S python3 -u\n", "python3", []string{"-u"}, "the script's shebang"},
		{"c", "#!/usr/bin/env --split-string python3 -u\n", "python3", []string{"-u"}, "the script's shebang"},
		{"d", "#!/usr/bin/env -S FOO=bar python3\n", "python3", nil, "the script's shebang"},                                      // skip a bare assignment
		{"d2", "#!/usr/bin/env -S PATH=/opt/bin python3\n", "python3", nil, "the script's shebang"},                               // assignment value with a slash
		{"d3", "#!/usr/bin/env -S /usr/local/bin/python3 -u\n", "/usr/local/bin/python3", []string{"-u"}, "the script's shebang"}, // absolute interp after -S
		{"e", "#!/usr/bin/env python3\n", "python3", nil, "the script's shebang"},

		// env options that take a separate word: without consuming it, the variable name
		// or directory reads as the interpreter.
		{"u1", "#!/usr/bin/env -S -u PATH python3 -u\n", "python3", []string{"-u"}, "the script's shebang"},
		{"u2", "#!/usr/bin/env -S --unset PATH python3\n", "python3", nil, "the script's shebang"},
		{"u3", "#!/usr/bin/env -S -C /tmp python3\n", "python3", nil, "the script's shebang"},
		{"u4", "#!/usr/bin/env -S --unset=PATH python3\n", "python3", nil, "the script's shebang"}, // attached form needs no consume

		// -S can carry its payload attached. Skipping the whole word would drop the
		// interpreter and fall through to the extension, silently profiling under bash.
		{"S1.sh", "#!/usr/bin/env -Spython3 -u\n", "python3", []string{"-u"}, "the script's shebang"},
		{"S2.sh", "#!/usr/bin/env --split-string=python3 -u\n", "python3", []string{"-u"}, "the script's shebang"},
		{"S3", "#!/usr/bin/env -SFOO=bar python3\n", "python3", nil, "the script's shebang"}, // payload is an assignment
		{"S4.py", "#!/usr/bin/env --split-string=\n", "python3", nil, "the .py extension"},   // empty payload names nothing

		// Linux does not tokenize a shebang: everything after the interpreter is one
		// argument, which is why a multi-arg shebang has to go through `env -S`.
		{"g", "#!/usr/bin/python3 -u\n", "/usr/bin/python3", []string{"-u"}, "the script's shebang"},
		{"g2", "#!/bin/sh -eu\n", "/bin/sh", []string{"-eu"}, "the script's shebang"},
		{"g3", "#!/bin/sh -e -u\n", "/bin/sh", []string{"-e -u"}, "the script's shebang"},

		// No usable shebang: the extension is the fallback, since the kernel would
		// refuse to exec these on their own.
		{"h.py", "print(1)\n", "python3", nil, "the .py extension"},
		{"i.sh", "echo hi\n", "bash", nil, "the .sh extension"},
		{"j.rb", "puts 1\n", "ruby", nil, "the .rb extension"},
		{"k.py", "#!/usr/bin/env\n", "python3", nil, "the .py extension"}, // env naming no interpreter

		// Nothing to go on: a compiled binary is its own interpreter.
		{"bin", "not a script\n", "", nil, ""},
	}
	for _, tc := range cases {
		p := filepath.Join(t.TempDir(), tc.name)
		if err := os.WriteFile(p, []byte(tc.body), 0o755); err != nil {
			t.Fatal(err)
		}
		got, args, source := GuessInterpreter(p)
		if got != tc.want || source != tc.wantSource || !slices.Equal(args, tc.wantArgs) {
			t.Errorf("GuessInterpreter(%q for %q) = %q %q from %q, want %q %q from %q",
				tc.body, tc.name, got, args, source, tc.want, tc.wantArgs, tc.wantSource)
		}
	}
}
