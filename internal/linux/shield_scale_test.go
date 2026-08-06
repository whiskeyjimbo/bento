package linux

import (
	"os"
	"path/filepath"
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
			checkWorkspaceShieldNotRedirected(sb, writes)
			checkWriteNotUnderReadOnlyShield(sb, writes)
		}
	}
	b.Run("nomemo", func(b *testing.B) { run(b, false) })
	b.Run("memo", func(b *testing.B) { run(b, true) })
}
