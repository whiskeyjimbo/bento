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
