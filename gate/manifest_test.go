//go:build linux

package gate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/gate"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/trust"
)

// inspect opens name and locates it the way the CLI's manifest load does.
func inspect(t *testing.T, name string) trust.Manifest {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := trust.Inspect(f, name)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

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
			got := gate.ManifestProblems(tc.given, inspect(t, tc.given), &policy.Policy{Read: tc.read, Write: tc.write})
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

// Another name for the manifest's inode can sit under a write grant's mount even when the
// manifest itself sits under none, and the read-only bind covers only the one name.
func TestManifestProblemsHardLinkOutsideEveryGrant(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	safe, w := filepath.Join(root, "safe"), filepath.Join(root, "w")
	for _, d := range []string{safe, w} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	m := filepath.Join(safe, "m.yaml")
	if err := os.WriteFile(m, []byte("entrypoint: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(m, filepath.Join(w, "copy.yaml")); err != nil {
		t.Fatal(err)
	}
	got := gate.ManifestProblems(m, inspect(t, m), &policy.Policy{Write: []string{w}})
	if !strings.Contains(strings.Join(got, "\n"), "hard link") {
		t.Errorf("want a hard-link problem for a manifest also named under %s, got %q", w, got)
	}
}

// The kernel resolves x/lnk/../m.yaml by following lnk and stepping out of its target, so
// the gate has to judge that file, not the x/m.yaml a lexical clean of the name lands on.
func TestManifestProblemsDotDotAfterSymlink(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := filepath.Join(root, "w")
	deep := filepath.Join(w, "sub", "deeper")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w, "sub", "m.yaml"), []byte("entrypoint: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	x := filepath.Join(root, "x")
	if err := os.Mkdir(x, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(x, "m.yaml"), []byte("decoy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(deep, filepath.Join(x, "lnk")); err != nil {
		t.Fatal(err)
	}
	got := gate.ManifestProblems(x+"/lnk/../m.yaml", inspect(t, x+"/lnk/../m.yaml"), &policy.Policy{Write: []string{w}})
	if !strings.Contains(strings.Join(got, "\n"), "renamed") {
		t.Errorf("want the write grant above %s/sub reported, got %q", w, got)
	}
}

// The verdict is about the manifest that was loaded. A name swapped between the load and
// the gate - here a symlink under the write grant replaced by a plain file at the grant's
// top, which on its own is safe - must not launder the symlink the load went through.
func TestManifestProblemsJudgesTheLoadedFileNotTheNameAgain(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := filepath.Join(root, "w")
	if err := os.Mkdir(w, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(root, "m.yaml")
	if err := os.WriteFile(real, []byte("entrypoint: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(w, "m.yaml")
	if err := os.Symlink(real, name); err != nil {
		t.Fatal(err)
	}
	loaded := inspect(t, name)
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("entrypoint: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := gate.ManifestProblems(name, loaded, &policy.Policy{Write: []string{w}})
	if !strings.Contains(strings.Join(got, "\n"), "symlink") {
		t.Errorf("want the symlink the load followed reported, got %q", got)
	}
}

// Off Linux trust cannot locate a manifest, and validate there only lints; a blocking
// problem would fail every manifest with a write grant in a macOS CI. The zero Manifest is
// what trust.Inspect returns in that case.
func TestManifestProblemsDefersAnUnlocatedManifest(t *testing.T) {
	if got := gate.ManifestProblems("m.yaml", trust.Manifest{}, &policy.Policy{Write: []string{"/"}}); len(got) != 0 {
		t.Errorf("want no problem for an unlocated manifest, got %q", got)
	}
}
