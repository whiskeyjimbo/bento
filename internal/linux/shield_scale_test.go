package linux

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
)

// submoduleMonorepo builds a checkout whose .git/modules holds n submodule gitdirs,
// each with the object store a real one accumulates - the walk descends every real
// subdirectory, so the store is the bulk of what it costs.
func submoduleMonorepo(tb testing.TB, n int) string {
	root := tb.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git", "modules"), 0o755); err != nil {
		tb.Fatal(err)
	}
	for i := range n {
		gd := filepath.Join(root, ".git", "modules", "sub"+string(rune('a'+i%26))+string(rune('a'+i/26)))
		for _, d := range []string{"objects/pack", "objects/info", "refs/heads", "refs/tags", "logs/refs/heads", "hooks", "info"} {
			if err := os.MkdirAll(filepath.Join(gd, d), 0o755); err != nil {
				tb.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(gd, "config"), []byte("[core]\n"), 0o644); err != nil {
			tb.Fatal(err)
		}
	}
	return root
}

// The memo's whole claim is that it changes nothing a caller can see. Two checkouts in
// one run, each asked for twice, must produce exactly what the uncached walk produces
// and must not answer for each other - a cache keyed too loosely would hand one
// checkout's gitdir shields to the other, shielding paths that do not exist and leaving
// the real ones open.
func TestWorkspaceShieldCacheIsTransparent(t *testing.T) {
	sb := sandbox{
		homes:     []string{"/home/u"},
		emptyFile: "/tmp/shield",
		exists:    hostExists,
		isDir:     hostIsDir,
		listDir:   hostListDir,
		resolve:   hostResolve,
	}
	first, second := submoduleMonorepo(t, 2), submoduleMonorepo(t, 3)

	cached := sb
	cached.workspaceShieldCache = map[string][]denylist.Rule{}
	for _, root := range []string{first, second, first, second} {
		want, got := workspaceShields(sb, root), workspaceShields(cached, root)
		if !slices.Equal(want, got) {
			t.Errorf("%s: cached shields differ from the uncached walk\n got %v\nwant %v", root, got, want)
		}
	}
}

// BenchmarkWorkspaceShieldWalk measures one run's worth of workspace-shield derivation
// over a submodule monorepo: shieldRules twice (denyArgs and createdShields) plus the
// two grant checks that build the same rules again, all against several write grants
// under one checkout. Nothing memoizes the walk, so the cost is per call site times
// grants.
func BenchmarkWorkspaceShieldWalk(b *testing.B) {
	root := submoduleMonorepo(b, 24)
	sb := sandbox{
		homes:     []string{"/home/u"},
		emptyFile: "/tmp/shield",
		exists:    hostExists,
		isDir:     hostIsDir,
		listDir:   hostListDir,
		resolve:   hostResolve,
	}
	writes := []string{root, filepath.Join(root, "build"), filepath.Join(root, "dist")}
	for _, w := range writes[1:] {
		if err := os.MkdirAll(w, 0o755); err != nil {
			b.Fatal(err)
		}
	}
	run := func(b *testing.B, memo bool) {
		for b.Loop() {
			sb := sb
			if memo {
				// Fresh per iteration: the memo is a one-run cache, so carrying it
				// across iterations would measure a hit rate no run ever sees.
				sb.workspaceShieldCache = map[string][]denylist.Rule{}
			}
			shieldRules(sb, writes)
			shieldRules(sb, writes)
			// A refusal here means the benchmark is timing a path the real caller
			// would never reach.
			if err := checkWorkspaceShieldNotRedirected(sb, writes); err != nil {
				b.Fatal(err)
			}
			if err := checkWriteNotUnderReadOnlyShield(sb, writes); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Run("nomemo", func(b *testing.B) { run(b, false) })
	b.Run("memo", func(b *testing.B) { run(b, true) })
}
