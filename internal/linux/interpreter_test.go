//go:build linux

package linux

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveInterpreter(t *testing.T) {
	cases := []struct {
		name string // file basename (extension matters)
		body string
		want string
	}{
		// Extension wins before the shebang is read.
		{"s.py", "#!/usr/bin/env -S python3 -u\nprint(1)\n", "python3"},
		{"s.sh", "#!/bin/sh\n", "bash"},

		// env with `-S`/`--split-string` (the multi-arg idiom) must resolve the real
		// interpreter, not the "-S" option.
		{"a", "#!/usr/bin/env -S python3 -u\n", "python3"},
		{"b", "#!/usr/bin/env -S python3\n", "python3"},
		{"c", "#!/usr/bin/env --split-string python3 -u\n", "python3"},
		{"d", "#!/usr/bin/env -S FOO=bar python3\n", "python3"},                           // skip a bare assignment
		{"d2", "#!/usr/bin/env -S PATH=/opt/bin python3\n", "python3"},                    // assignment value with a slash
		{"d3", "#!/usr/bin/env -S /usr/local/bin/python3 -u\n", "/usr/local/bin/python3"}, // absolute interp after -S

		// Plain forms still work.
		{"e", "#!/usr/bin/env python3\n", "python3"},
		{"f", "#!/bin/sh\n", "/bin/sh"},
		{"g", "#!/usr/bin/python3 -u\n", "/usr/bin/python3"},

		// Degenerate: env with no interpreter, and no shebang.
		{"h", "#!/usr/bin/env\n", ""},
		{"i", "not a script\n", ""},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		p := filepath.Join(dir, tc.name)
		if err := os.WriteFile(p, []byte(tc.body), 0o755); err != nil {
			t.Fatal(err)
		}
		if got := ResolveInterpreter(p); got != tc.want {
			t.Errorf("ResolveInterpreter(%q for %q) = %q, want %q", tc.body, tc.name, got, tc.want)
		}
	}
}
