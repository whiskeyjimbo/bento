//go:build unix

package gate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/gate"
	"github.com/whiskeyjimbo/bento/policy"
)

// A run keeps its manifest read-only with one bind over the file, and a bind holds only
// its own name: the kernel refuses to rename or unlink a mount point, not a directory
// above one or another name for the same inode. Each case here is a way a write grant
// reaches the manifest around that bind, so the run cannot promise the file stays put.
func TestManifestProblemsNamesEveryWayAroundTheBind(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	m := filepath.Join(sub, "m.yaml")
	if err := os.WriteFile(m, []byte("entrypoint: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(sub, "link.yaml")
	if err := os.Symlink("m.yaml", link); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "elsewhere")
	// A symlinked DIRECTORY on the way to the manifest, in a tree a write grant covers
	// that is not an ancestor of the manifest's real directory.
	side := filepath.Join(root, "side")
	if err := os.Mkdir(side, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sub, filepath.Join(side, "alias")); err != nil {
		t.Fatal(err)
	}
	viaDir := filepath.Join(side, "alias", "m.yaml")

	for name, tc := range map[string]struct {
		given       string
		read, write []string
		hardlink    bool
		want        string
	}{
		"write grant at its directory":                   {given: m, write: []string{sub}},
		"read grant at its directory under write":        {given: m, read: []string{sub}, write: []string{root}, want: "renamed"},
		"write grants at and above its directory":        {given: m, write: []string{sub, root}, want: "renamed"},
		"no write grant reaches it":                      {given: m, write: []string{other}},
		"directory renameable under a wider write":       {given: m, write: []string{root}, want: "renamed"},
		"named through a symlink":                        {given: link, write: []string{sub}, want: "symlink"},
		"through a symlinked directory":                  {given: viaDir, write: []string{sub, side}, want: "symlink"},
		"through a symlinked directory no grant reaches": {given: viaDir, write: []string{sub}},
		"another hard link":                              {given: m, write: []string{sub}, hardlink: true, want: "hard link"},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.hardlink {
				h := filepath.Join(sub, "hard.yaml")
				if err := os.Link(m, h); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(h)
			}
			got := gate.ManifestProblems(tc.given, &policy.Policy{Read: tc.read, Write: tc.write})
			if tc.want == "" {
				if len(got) != 0 {
					t.Errorf("want no problem, got %q", got)
				}
				return
			}
			if len(got) == 0 || !strings.Contains(strings.Join(got, "\n"), tc.want) {
				t.Errorf("want a problem mentioning %q, got %q", tc.want, got)
			}
		})
	}
}
