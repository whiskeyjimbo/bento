//go:build linux

package linux

import (
	"fmt"
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
		want, _ := workspaceShields(sb, root)
		got, _ := workspaceShields(cached, root)
		if !slices.Equal(want, got) {
			t.Errorf("%s: cached shields differ from the uncached walk\n got %v\nwant %v", root, got, want)
		}
	}
}

// projectTree builds a checkout holding nested checkouts and project config the way a
// monorepo or a directory of cloned projects does: projects directories, every fourth one
// a git checkout of its own, each with agent and editor config. Beside the submodule
// store, this is what makes derivedWorkspaceRules loop at all - a tree without it never
// reaches the per-entry work, which is how a 271x regression there once read as +0.08%.
func projectTree(tb testing.TB, submodules, projects int) string {
	root := submoduleMonorepo(tb, submodules)
	for i := range projects {
		p := filepath.Join(root, "projects", fmt.Sprintf("p%d", i))
		dirs := []string{".claude", ".vscode", "src"}
		if i%4 == 0 {
			dirs = append(dirs, ".git/hooks")
		}
		for _, d := range dirs {
			if err := os.MkdirAll(filepath.Join(p, d), 0o755); err != nil {
				tb.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(p, ".mcp.json"), []byte("{}"), 0o644); err != nil {
			tb.Fatal(err)
		}
	}
	return root
}

// workspaceBenchSandbox is a sandbox over the host as newSandbox builds one for a run:
// production seams under their bound, the workspace walk done by findWorkspaceEntries,
// and - when memo is set - the per-run caches allocated as construction allocates them.
// Fresh per iteration, since every cache here is a one-run cache and carrying one across
// iterations would measure a hit rate no run ever sees.
func workspaceBenchSandbox(tb testing.TB, root string, memo bool) sandbox {
	sb := sandbox{
		homes:     []string{"/home/u"},
		emptyFile: "/tmp/shield",
		exists:    hostExists,
		isDir:     hostIsDir,
		listDir:   hostListDir,
		resolve:   hostResolve,
		deadMount: &deadMount{},
	}
	sb = boundHostSeams(sb)
	checkouts, config, err := findWorkspaceEntries(root)
	if err != nil {
		tb.Fatal(err)
	}
	sb.nestedCheckouts = map[string][]string{root: checkouts}
	sb.projectConfig = map[string][]denylist.Rule{root: config}
	if memo {
		sb.workspaceShieldCache = map[string][]denylist.Rule{}
		sb.shieldCache = &shieldMemo{}
	}
	return sb
}

// BenchmarkWorkspaceShieldWalk measures one run's worth of workspace-shield derivation
// over a monorepo with submodules, nested checkouts and project config: shieldRules twice
// (denyArgs and createdShields) plus the two grant checks that derive the same rules
// again, against several write grants under one checkout. nomemo is a sandbox with none of
// the per-run caches, memo one allocated as newSandbox allocates it.
func BenchmarkWorkspaceShieldWalk(b *testing.B) {
	root := projectTree(b, 24, 64)
	writes := []string{root, filepath.Join(root, "build"), filepath.Join(root, "dist")}
	for _, w := range writes[1:] {
		if err := os.MkdirAll(w, 0o755); err != nil {
			b.Fatal(err)
		}
	}
	// Checked once, outside the timing: a fixture whose derived shields went missing would
	// time the short path and report it as a speedup.
	got := rulePaths(shieldRules(workspaceBenchSandbox(b, root, true), writes))
	for _, want := range []string{
		filepath.Join(root, "projects", "p1", ".claude"),
		filepath.Join(root, "projects", "p63", ".mcp.json"),
		filepath.Join(root, "projects", "p60", ".git", "hooks"),
	} {
		if !slices.Contains(got, want) {
			b.Fatalf("the fixture's derived shields do not include %s, so the benchmark would not reach the per-entry work", want)
		}
	}
	run := func(b *testing.B, memo bool) {
		b.ReportAllocs()
		for b.Loop() {
			b.StopTimer()
			sb := workspaceBenchSandbox(b, root, memo)
			b.StartTimer()
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
