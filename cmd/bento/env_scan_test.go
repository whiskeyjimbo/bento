package main

import (
	"reflect"
	"sort"
	"testing"
)

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func TestReferencedShellVars(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "local assignments are not host env",
			src: `#!/usr/bin/env bash
SRC="${1:-/tmp/x}"
OUT="/tmp/backup-$(date +%s).tar.gz"
SIZE=$(du -h "$OUT" | cut -f1)
echo "$SRC -> $OUT ($SIZE)"
`,
			want: nil,
		},
		{
			name: "default-providing expansions suppress the note",
			src: `#!/usr/bin/env bash
echo "${TARGET:-https://default.example.com}"
echo "${ALT-fallback}"
echo "${REQUIRED:?must be set}"
`,
			want: nil,
		},
		{
			name: "plain reference without local assign is a real host env read",
			src: `#!/usr/bin/env bash
echo "connecting to $DATABASE_URL"
echo "deploy id: ${DEPLOY_ID}"
`,
			want: []string{"DATABASE_URL", "DEPLOY_ID"},
		},
		{
			name: "single-quoted strings and comments are stripped",
			src: `#!/usr/bin/env bash
echo '$NOT_A_VAR'
# also $NOT_A_VAR_2 in a comment
echo "$REAL_VAR"
`,
			want: []string{"REAL_VAR"},
		},
		{
			name: "exported assignment is still local",
			src: `#!/usr/bin/env bash
export FOO=bar
readonly BAZ=qux
declare -x QUUX=1
local LOCAL_X=2
echo "$FOO $BAZ $QUUX $LOCAL_X"
`,
			want: nil,
		},
		{
			name: "read NAME binds names",
			src: `#!/usr/bin/env bash
read A B C
echo "$A $B $C"
`,
			want: nil,
		},
		{
			name: "for/select loop targets are local",
			src: `#!/usr/bin/env bash
for ITEM in a b c; do echo "$ITEM"; done
select OPT in x y; do echo "$OPT"; break; done
`,
			want: nil,
		},
		{
			name: "HOME/PATH/PWD always skipped",
			src: `echo "$HOME $PATH $PWD $LANG"`,
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := referencedShellVars([]byte(tc.src))
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(sorted(got), sorted(tc.want)) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReferencedShellVarsAll(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "defaulted forms surface (unlike strict scanner)",
			src: `#!/usr/bin/env bash
echo "${TARGET:-https://default.example.com}"
echo "${ALT-fallback}"
`,
			want: []string{"TARGET", "ALT"},
		},
		{
			name: "self-referential default idiom surfaces despite the assignment",
			src: `#!/usr/bin/env bash
OUT="${OUT:-./releases.json}"
SUMMARY="${SUMMARY:-./summary.txt}"
echo "$OUT $SUMMARY"
`,
			want: []string{"OUT", "SUMMARY"},
		},
		{
			name: "pure-local assignment without self-default stays filtered",
			src: `#!/usr/bin/env bash
TMP="/tmp/x"
echo "$TMP"
`,
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := referencedShellVarsAll([]byte(tc.src))
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(sorted(got), sorted(tc.want)) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPickEnvForLostWrite(t *testing.T) {
	defaults := map[string]string{
		"OUT":     "./releases.json",
		"SUMMARY": "./summary.txt",
	}
	referenced := []string{"OUT", "SUMMARY"}

	// Lost write basename matches SUMMARY's default basename.
	if got := pickEnvForLostWrite([]string{"/sandbox/summary.txt"}, defaults, referenced); got != "SUMMARY" {
		t.Errorf("lost summary.txt: got %q, want SUMMARY", got)
	}
	// Lost write basename matches OUT's default basename.
	if got := pickEnvForLostWrite([]string{"/sandbox/releases.json"}, defaults, referenced); got != "OUT" {
		t.Errorf("lost releases.json: got %q, want OUT", got)
	}
	// No basename match → fall back to pickOutputEnvName (prefers OUT).
	if got := pickEnvForLostWrite([]string{"/sandbox/other.bin"}, defaults, referenced); got != "OUT" {
		t.Errorf("no match: got %q, want OUT (output-shaped fallback)", got)
	}
	// Empty defaults → fall back.
	if got := pickEnvForLostWrite([]string{"/sandbox/summary.txt"}, map[string]string{}, referenced); got != "OUT" {
		t.Errorf("empty defaults: got %q, want OUT", got)
	}
}

func TestShellEnvDefaults(t *testing.T) {
	src := []byte(`#!/usr/bin/env bash
OUT="${OUT:-./releases.json}"
SUMMARY="${SUMMARY:-./summary.txt}"
ALT="${ALT-fallback}"
ASSIGN_DEFAULT="${ASSIGN_DEFAULT:=/tmp/x}"
ERRORED="${ERRORED:?must be set}"
echo "$OUT $SUMMARY $ALT $ASSIGN_DEFAULT $ERRORED"
`)
	got := shellEnvDefaults(src)
	want := map[string]string{
		"OUT":            "./releases.json",
		"SUMMARY":        "./summary.txt",
		"ALT":            "fallback",
		"ASSIGN_DEFAULT": "/tmp/x",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestPythonEnvDefaults(t *testing.T) {
	src := []byte(`import os
out = os.environ.get("OUT", "./releases.json")
city = os.getenv("CITY", "London")
no_default = os.getenv("API_TOKEN")
`)
	got := pythonEnvDefaults(src)
	want := map[string]string{
		"OUT":  "./releases.json",
		"CITY": "London",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReferencedPythonEnvVars(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "default args suppress the note",
			src: `import os
city = os.environ.get("CITY", "London")
mode = os.getenv("MODE", "prod")
port = int(os.getenv("PORT", "8080"))
`,
			want: nil,
		},
		{
			name: "subscript is always counted (raises if unset)",
			src: `import os
t = os.environ["API_TOKEN"]
`,
			want: []string{"API_TOKEN"},
		},
		{
			name: "no-default getenv counted; defaulted not",
			src: `import os
a = os.getenv("A")
b = os.getenv("B", "fallback")
`,
			want: []string{"A"},
		},
		{
			name: "no-default get counted; defaulted not",
			src: `import os
a = os.environ.get("A")
b = os.environ.get("B", "fallback")
`,
			want: []string{"A"},
		},
		{
			name: "trailing comma/whitespace inside default is tolerated",
			src: `import os
x = os.getenv("X", {"k": "v"})
y = os.getenv("Y", [1, 2, 3])
`,
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := referencedPythonEnvVars([]byte(tc.src))
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(sorted(got), sorted(tc.want)) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
