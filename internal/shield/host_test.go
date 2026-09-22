//go:build unix

package shield_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/shield"
)

// A verdict resolves every workspace rule it is handed, and the gate and the clamp ask one
// per grant against the same rules, so an unmemoized Host paid each rule's whole symlink
// walk once per grant. One answer per path for the life of the FS is also the answer a Set
// already gives for its own rules, which it resolves once at assembly - so the memo is what
// makes the workspace half agree with the rest of the set rather than a cache beside it.
func TestHostResolvesEachPathOncePerFS(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	for _, d := range []string{first, second} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(first, link); err != nil {
		t.Fatal(err)
	}

	fs := shield.Host()
	if got := fs.Resolve(link); got != first {
		t.Fatalf("Resolve(%q) = %q, want %q", link, got, first)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second, link); err != nil {
		t.Fatal(err)
	}
	if got := fs.Resolve(link); got != first {
		t.Errorf("a second Resolve of the same path on one FS walked the link again: got %q, want the first answer %q", got, first)
	}
	// A fresh FS is a fresh view: the memo lives with the FS, not the process.
	if got := shield.Host().Resolve(link); got != second {
		t.Errorf("a new Host FS answered %q from an earlier FS's memo; want %q", got, second)
	}
}

// BenchmarkWriteVerdictsOnHost is the gate's write loop over the real filesystem: every
// write grant judged against the workspace shields derived from all of them.
func BenchmarkWriteVerdictsOnHost(b *testing.B) {
	dir := b.TempDir()
	home := filepath.Join(dir, "home")
	var grants []string
	var workspace []denylist.Rule
	for i := range 16 {
		g := filepath.Join(dir, "work", fmt.Sprintf("p%d", i))
		if err := os.MkdirAll(filepath.Join(g, ".git", "hooks"), 0o755); err != nil {
			b.Fatal(err)
		}
		grants = append(grants, g)
		workspace = append(workspace, denylist.Workspace(g)...)
	}
	b.ReportAllocs()
	for b.Loop() {
		s := shield.Assemble(shield.Host(), []string{home}, filepath.Join(dir, "run"), nil)
		for _, g := range grants {
			s.Contains(g, shield.Write, nil, workspace)
		}
	}
}
